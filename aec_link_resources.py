"""Native model names with cached full-file identities; never load or generate weights."""

import re
import threading
from pathlib import Path

import aec_link_device_tools as device_tools
import aec_link_utils as utils

_dirty = threading.Event()
_dirty.set()
KINDS = {"checkpoint": "checkpoints", "lora": "loras", "vae": "vae", "embedding": "embeddings"}


def request_refresh():
    _dirty.set()


def native_catalog(refresh):
    import folder_paths

    if refresh:
        folder_paths.filename_list_cache.clear()
    catalog, roots = [], []
    for kind, folder in KINDS.items():
        roots.extend((kind, Path(root)) for root in folder_paths.get_folder_paths(folder))
        for name in folder_paths.get_filename_list(folder):
            path = folder_paths.get_full_path(folder, name)
            if path:
                catalog.append((kind, name.replace("\\", "/"), Path(path)))
    return catalog, roots


def collect():
    refresh = _dirty.is_set()
    _dirty.clear()
    catalog, roots = native_catalog(refresh)
    with utils._CACHE_LOCK:
        cache = dict(utils._ensure_cache())
    maintenance = dict(device_tools._hash_cache)
    known = {(kind, str(path.resolve())): name for kind, name, path in catalog}
    files = {(kind, path.resolve()) for kind, _, path in catalog}
    for kind, root in roots:
        resolved_root = root.resolve()
        for raw in {*cache, *maintenance}:
            path = Path(raw).resolve()
            if path.is_relative_to(resolved_root) and path.is_file():
                files.add((kind, path))
    # A newly installed file may not yet have a hash cache entry or a native loader.
    # Discover its presence without loading weights or hashing the library on every report.
    discovery_complete = True
    for kind, root in roots:
        try:
            if root.is_dir():
                files.update(
                    (kind, path.resolve())
                    for path in root.rglob("*")
                    if path.is_file() and path.suffix.lower() in utils.MODEL_EXTS
                )
        except OSError:
            discovery_complete = False
    entries, complete, used = [], discovery_complete, set()
    for kind, path in sorted(files, key=lambda item: ((item[0], str(item[1])) not in known, item[0], str(item[1]))):
        try:
            stat = path.stat()
            entry = cache.get(str(path), {})
            cached = maintenance.get(str(path))
            digest = (
                entry.get("hash")
                if (entry.get("mtime_ns"), entry.get("size")) == (stat.st_mtime_ns, stat.st_size)
                else None
            )
            if not digest and cached and cached[:2] == (stat.st_mtime_ns, stat.st_size):
                digest = cached[2]
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                complete = False
                continue
            name = known.get((kind, str(path)))
            selectable = name is not None
            if name is None:
                root = next(
                    root.resolve()
                    for item_kind, root in roots
                    if item_kind == kind and path.is_relative_to(root.resolve())
                )
                name = path.relative_to(root).as_posix()
            if (kind, name) in used:
                complete = False
                continue
            used.add((kind, name))
            entries.append(
                {
                    "kind": kind,
                    "sha256": digest,
                    "selectionName": name,
                    "sizeBytes": stat.st_size,
                    "selectable": selectable,
                }
            )
        except (OSError, StopIteration):
            complete = False
    if len(entries) > 10000:
        entries, complete = entries[:10000], False
    return {"schemaVersion": 1, "complete": complete, "entries": entries}


def has_verified_file(digest):
    """A historical hash alone cannot prove a file still exists on this device."""
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        return False
    with utils._CACHE_LOCK:
        cache = dict(utils._ensure_cache())
    candidates = [
        (path, entry.get("mtime_ns"), entry.get("size"))
        for path, entry in cache.items()
        if isinstance(entry, dict) and entry.get("hash") == digest
    ]
    candidates.extend(
        (path, entry[0], entry[1]) for path, entry in dict(device_tools._hash_cache).items() if entry[2] == digest
    )
    for path, mtime_ns, size in candidates:
        try:
            stat = Path(path).stat()
            if Path(path).is_file() and (stat.st_mtime_ns, stat.st_size) == (mtime_ns, size):
                return True
        except OSError:
            pass
    return False


def report(client, runtime_id):
    inventory = collect()
    with client.SESSION.post(
        f"{client.BASE_URL}/resources/inventory",
        json={"runtimeId": runtime_id, "inventory": inventory},
        headers=client.headers(),
        timeout=20,
        allow_redirects=False,
    ) as response:
        response.raise_for_status()
