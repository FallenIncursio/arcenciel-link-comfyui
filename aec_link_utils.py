import hashlib
import json
import os
import re
import threading
from pathlib import Path
from typing import Dict, Generator, Iterable, List

import requests

from aec_link_config import get_storage_dir

_DEFAULT_USER_AGENT = "ArcEnCiel-Link/ComfyUI"
_SESSION: requests.Session | None = None

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9 _.,#@!$%^&()+=\u00A0-\u024F-]+$")

MODEL_EXTS = {".safetensors", ".ckpt", ".pt", ".sft", ".gguf"}

_CACHE_LOCK = threading.Lock()
_CACHE_DATA: Dict[str, Dict] | None = None

CACHE_DIR = get_storage_dir() / "cache"
CACHE_FILE = CACHE_DIR / "hashes.json"


def _resolve_user_agent() -> str:
    override = os.getenv("ARCENCIEL_LINK_UA")
    if override:
        trimmed = override.strip()
        if trimmed:
            return trimmed
    return _DEFAULT_USER_AGENT


def get_http_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        session = requests.Session()
        session.headers["User-Agent"] = _resolve_user_agent()
        _SESSION = session
    return _SESSION


def download_file(url: str, dst: Path, progress_cb) -> None:
    session = get_http_session()
    with session.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        chunk = 1024 * 1024
        with open(dst, "wb") as f:
            done = 0
            for part in r.iter_content(chunk_size=chunk):
                f.write(part)
                done += len(part)
                if total:
                    progress_cb(done / total)


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_folder_paths(name: str) -> list[str]:
    try:
        import folder_paths

        return folder_paths.get_folder_paths(name)
    except Exception:
        return []


def _kind_to_folder_name(kind: str) -> str:
    lowered = kind.lower()
    if lowered in ("checkpoint", "checkpoints", "stable-diffusion", "stable_diffusion"):
        return "checkpoints"
    if lowered == "lora":
        return "loras"
    if lowered in ("vae", "vaes"):
        return "vae"
    if lowered in ("embedding", "embeddings", "emb"):
        return "embeddings"
    raise ValueError("Unsupported model category.")


def list_subfolders(kind: str) -> list[str]:
    roots = _get_folder_paths(_kind_to_folder_name(kind))
    results: set[str] = set()

    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for dirpath, dirnames, _ in os.walk(base):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            if Path(dirpath) == base:
                continue
            rel = Path(dirpath).relative_to(base).as_posix()
            if not rel or rel.startswith("."):
                continue
            if any(seg.startswith(".") for seg in rel.split("/")):
                continue
            results.add(rel)

    return sorted(results, key=lambda s: s.lower())


def _ensure_safe_segment(segment: str) -> None:
    if segment in (".", ".."):
        raise ValueError("Target path contains traversal segments.")
    if not _SAFE_SEGMENT.match(segment):
        raise ValueError("Target path contains unsupported characters.")


def resolve_target_path(target_path: str) -> Path:
    if not isinstance(target_path, str):
        raise ValueError("Target path must be a string.")

    normalized = target_path.replace("\\", "/").strip()
    normalized = normalized.lstrip("/").rstrip("/")
    if not normalized:
        raise ValueError("Target path is required.")
    if normalized.startswith("../"):
        raise ValueError("Target path escapes allowed folders.")

    parts = [p for p in normalized.split("/") if p.strip()]
    if not parts:
        raise ValueError("Target path is required.")

    first = parts[0].lower()
    if first in ("embeddings", "embedding"):
        folder_name = "embeddings"
        offset = 1
    elif first == "models":
        if len(parts) < 2:
            raise ValueError("Target path must include a model category.")
        folder_name = _kind_to_folder_name(parts[1])
        offset = 2
    else:
        raise ValueError("Target path must start with embeddings or models.")

    roots = _get_folder_paths(folder_name)
    if not roots:
        raise ValueError("Target path folder is unavailable.")

    base = Path(roots[0])
    combined = base
    for segment in parts[offset:]:
        _ensure_safe_segment(segment)
        combined = combined / segment

    resolved = combined.resolve()
    base_resolved = base.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("Target path escapes allowed directories.") from exc

    return resolved


def _load_cache() -> Dict[str, Dict]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_cache(data: Dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    global _CACHE_DATA
    _CACHE_DATA = data


def _ensure_cache() -> Dict[str, Dict]:
    global _CACHE_DATA
    if _CACHE_DATA is None:
        _CACHE_DATA = _load_cache()
    return _CACHE_DATA


def _iter_model_files(roots: Iterable[Path]) -> Generator[Path, None, None]:
    for root in roots:
        if not root.exists():
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                ext = Path(filename).suffix.lower()
                if ext in MODEL_EXTS:
                    yield Path(dirpath) / filename


def _inventory_roots() -> list[Path]:
    roots: list[Path] = []
    for kind in ("checkpoints", "loras", "vae", "embeddings"):
        roots.extend(Path(p) for p in _get_folder_paths(kind))
    return roots


def list_model_hashes() -> List[str]:
    with _CACHE_LOCK:
        cache = _ensure_cache()

        updated = False
        result: List[str] = []

        roots = _inventory_roots()

        for path in _iter_model_files(roots):
            mtime = int(path.stat().st_mtime)
            key = str(path.resolve())
            entry = cache.get(key)

            if entry and entry.get("mtime") == mtime:
                h = entry.get("hash")
            else:
                h = sha256_of_file(path)
                cache[key] = {"mtime": mtime, "hash": h}
                updated = True

            if h:
                result.append(h)

        orphan_keys = [k for k in cache if not Path(k).exists()]
        for k in orphan_keys:
            del cache[k]
            updated = True

        if updated:
            _save_cache(cache)

        return result


def update_cached_hash(path: Path, hash_value: str) -> List[str]:
    resolved = path.resolve()
    with _CACHE_LOCK:
        cache = _ensure_cache()
        try:
            mtime = int(resolved.stat().st_mtime)
        except FileNotFoundError:
            return list_model_hashes()

        cache[str(resolved)] = {"mtime": mtime, "hash": hash_value}
        _save_cache(cache)

        hashes = []
        for entry in cache.values():
            h = entry.get("hash")
            if h:
                hashes.append(h)

        return hashes
