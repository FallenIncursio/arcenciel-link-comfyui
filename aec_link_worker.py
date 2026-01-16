from __future__ import annotations

import base64
import json
import logging
import os
import queue
import random
import re
import shutil
import sys
import threading
import time
from io import BytesIO
from logging.handlers import RotatingFileHandler
from pathlib import Path
from textwrap import dedent
from urllib.parse import urljoin, urlparse, urlunparse, unquote

import websocket

from aec_link_config import get_storage_dir, load_config, save_config
from aec_link_utils import (
    download_file,
    get_http_session,
    list_model_hashes,
    list_subfolders,
    resolve_target_path,
    sha256_of_file,
    update_cached_hash,
)

try:
    from PIL import Image

    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

_LOG_FILE = get_storage_dir() / "client-debug.log"

_LOGGER = None

_LINK_KEY_REGEX = re.compile(r"^lk_[A-Za-z0-9_-]{32}$")

_cfg = load_config()

DEV_MODE = bool(_cfg.get("_dev_mode"))

BASE_URL = ""
_WS_URL = ""
LINK_KEY = ""
API_KEY = ""
MIN_FREE_MB = 2048
MAX_RETRIES = 5
BACKOFF_BASE = 2
SAVE_HTML_PREVIEW = False

TIMEOUT = 15
HEARTBEAT_INTERVAL = 5
SLEEP_AFTER_ERROR = 5
PROGRESS_MIN_STEP = 2
PROGRESS_MIN_INTERVAL = 1.5

RUNNING = threading.Event()
SESSION = get_http_session()

_socket_enabled = False
_runner_started = False
_credentials_dirty = False
_reconnect_attempts = 0
_last_connected_at = 0.0
_RECONNECT_BASE_DELAY = 1
_RECONNECT_MAX_DELAY = 10

_runner_lock = threading.Lock()
_PUBLIC_LABEL = "arcenciel.io"

_sock = None
_job_queue: queue.Queue = queue.Queue()
_open_evt = threading.Event()

_connection_state = "idle"
_health_state: str | None = None
_last_error: str | None = None
_suspend_until = 0.0
_suspend_notice_logged = False

WS_CLOSE_CODE_UNAUTHORIZED = 4401
WS_CLOSE_CODE_RATE_LIMITED = 4429
WS_CLOSE_CODE_SERVICE_DISABLED = 1013
_DEFAULT_RATE_LIMIT_WAIT = 900.0

KNOWN_HASHES: set[str] = set()


def _get_logger():
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    try:
        handler = RotatingFileHandler(
            _LOG_FILE, maxBytes=262_144, backupCount=1, encoding="utf-8"
        )
        formatter = logging.Formatter("%(asctime)s %(message)s")
        handler.setFormatter(formatter)
        logger = logging.getLogger("arcenciel_link.client")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.propagate = False
        _LOGGER = logger
    except Exception:
        _LOGGER = None
    return _LOGGER


def _debug(msg: str) -> None:
    logger = _get_logger()
    if logger is not None:
        logger.info(msg)


def _normalise_base_url(raw: str, *, allow_insecure: bool) -> str:
    trimmed = (raw or "").strip()
    if not trimmed:
        raise ValueError("base_url cannot be empty")
    if trimmed.startswith(("ws://", "wss://")):
        parsed = urlparse(trimmed.replace("wss://", "https://").replace("ws://", "http://"))
    else:
        parsed = urlparse(trimmed)
    if parsed.scheme not in ("https", "http"):
        raise ValueError("base_url must start with https://")
    if parsed.scheme == "http" and not allow_insecure:
        secure = parsed._replace(scheme="https")
        secure_url = urlunparse(secure)
        print(
            "[AEC-LINK] insecure base_url overridden to HTTPS; enable ARCENCIEL_DEV for http:// usage.",
            file=sys.stderr,
        )
        trimmed = secure_url
    return trimmed.rstrip("/")


def _refresh_ws_url() -> None:
    global _WS_URL
    _WS_URL = (
        BASE_URL.replace("https://", "wss://").replace("http://", "ws://").rstrip("/")
        + "/ws"
    )


def _encode_protocol_value(value: str) -> str:
    if not value:
        return ""
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _ws_subprotocols() -> list[str] | None:
    if LINK_KEY.strip():
        return [f"aec-link.link-key.{_encode_protocol_value(LINK_KEY)}"]
    if API_KEY.strip():
        return [f"aec-link.api-key.{_encode_protocol_value(API_KEY)}"]
    return None


def _display_target() -> str:
    if DEV_MODE:
        return BASE_URL
    parsed = urlparse(BASE_URL)
    host = parsed.netloc or ""
    if not host or host.endswith("arcenciel.io"):
        return _PUBLIC_LABEL
    return host


def update_credentials(
    *, base_url: str | None = None, link_key: str | None = None, api_key: str | None = None
) -> None:
    global BASE_URL, LINK_KEY, API_KEY, _credentials_dirty, _suspend_until, _suspend_notice_logged
    ws_needs_refresh = False
    credentials_changed = False

    if base_url is not None:
        try:
            normalized = _normalise_base_url(base_url, allow_insecure=DEV_MODE)
        except ValueError as exc:
            print(f"[AEC-LINK] base_url rejected: {exc}", file=sys.stderr)
        else:
            if normalized != BASE_URL:
                BASE_URL = normalized
                ws_needs_refresh = True
                _credentials_dirty = True
                credentials_changed = True

    if link_key is not None:
        stripped = link_key.strip()
        if stripped != LINK_KEY:
            LINK_KEY = stripped
            _credentials_dirty = True
            credentials_changed = True

    if api_key is not None:
        stripped = api_key.strip()
        if stripped != API_KEY:
            API_KEY = stripped
            _credentials_dirty = True
            credentials_changed = True

    if ws_needs_refresh:
        _refresh_ws_url()

    if credentials_changed:
        _suspend_until = 0.0
        _suspend_notice_logged = False


def _apply_config(cfg: dict) -> None:
    global MIN_FREE_MB, MAX_RETRIES, BACKOFF_BASE, SAVE_HTML_PREVIEW, _cfg, DEV_MODE
    _cfg = cfg
    DEV_MODE = bool(cfg.get("_dev_mode"))
    MIN_FREE_MB = int(cfg.get("min_free_mb", 2048))
    MAX_RETRIES = int(cfg.get("max_retries", 5))
    BACKOFF_BASE = int(cfg.get("backoff_base", 2))
    SAVE_HTML_PREVIEW = bool(cfg.get("save_html_preview"))
    update_credentials(
        base_url=cfg.get("base_url", BASE_URL),
        link_key=cfg.get("link_key", ""),
        api_key=cfg.get("api_key", ""),
    )


def _sanitize_link_key(value):
    if value is None:
        return None
    key = str(value).strip()
    if not key:
        return ""
    if not _LINK_KEY_REGEX.fullmatch(key):
        raise ValueError("Invalid link key format")
    return key


def headers() -> dict:
    if LINK_KEY:
        return {"x-link-key": LINK_KEY}
    if API_KEY:
        return {"x-api-key": API_KEY}
    return {}


def _send_ws_payload(payload: dict, *, default_type: str | None = None) -> None:
    if not isinstance(payload, dict):
        return
    if default_type and "type" not in payload:
        payload["type"] = default_type
    if not _open_evt.is_set():
        return
    try:
        if _sock is not None:
            _sock.send(json.dumps(payload))
    except Exception as exc:
        _debug(f"failed to send payload: {exc}")


def _send_worker_state(running: bool | None = None) -> None:
    if running is None:
        running = RUNNING.is_set()
    _send_ws_payload({"type": "worker_state", "running": bool(running)})


def _send_control_ack(payload: dict) -> None:
    _send_ws_payload(payload, default_type="control_ack")


def _apply_worker_state(enable: bool, *, link_key=None, api_key=None) -> bool:
    cfg = load_config()
    changed = False

    sanitized_link = _sanitize_link_key(link_key)
    if sanitized_link is not None and sanitized_link != cfg.get("link_key", ""):
        cfg["link_key"] = sanitized_link
        changed = True

    if api_key is not None:
        stripped_api = api_key.strip() if isinstance(api_key, str) else ""
        if stripped_api != cfg.get("api_key", ""):
            cfg["api_key"] = stripped_api
            changed = True

    if cfg.get("enabled") != bool(enable):
        cfg["enabled"] = bool(enable)
        changed = True

    if changed:
        save_config(cfg)
        _apply_config(cfg)

    if enable:
        set_connection_enabled(True, silent=True)
        toggle_worker(True)
        force_reconnect()
        _send_worker_state(True)
    else:
        toggle_worker(False)
        set_connection_enabled(True, silent=True)
        _send_worker_state(False)

    return RUNNING.is_set()


def apply_worker_state(enable: bool, *, link_key: str | None = None, api_key: str | None = None) -> bool:
    return _apply_worker_state(enable, link_key=link_key, api_key=api_key)


def _set_connection_state(state: str, message: str) -> None:
    global _connection_state
    if state != _connection_state:
        print(message, flush=True)
        _connection_state = state
        _debug(message)


def _parse_retry_after(reason: str | None) -> float:
    if not reason:
        return 0.0
    if reason.startswith("RATE_LIMITED:"):
        try:
            return float(reason.split(":", 1)[1])
        except ValueError:
            return 0.0
    return 0.0


def _on_open(ws) -> None:
    global _reconnect_attempts, _credentials_dirty, _last_connected_at, _suspend_until, _suspend_notice_logged
    _open_evt.set()
    _reconnect_attempts = 0
    _credentials_dirty = False
    _last_connected_at = time.monotonic()
    _suspend_until = 0.0
    _suspend_notice_logged = False
    _set_connection_state("connected", f"[AEC-LINK] connected to {_display_target()}")
    _send_worker_state()
    ws.send('{"type":"poll"}')


def _on_close(ws, code=None, msg=None) -> None:
    global _suspend_until, _suspend_notice_logged
    _open_evt.clear()
    reason = msg
    if isinstance(reason, bytes):
        try:
            reason_text = reason.decode("utf-8", "ignore")
        except Exception:
            reason_text = ""
    elif isinstance(reason, str):
        reason_text = reason
    else:
        reason_text = ""
    _debug(f"close event code={code} msg={reason_text!r}")

    if code is not None:
        detail = f" reason={reason_text}" if reason_text else ""
        print(f"[AEC-LINK] websocket closed (code={code}{detail})")

    if reason_text.startswith("LINK_SCOPE_MISSING"):
        _set_connection_state(
            "blocked",
            "[AEC-LINK] access key missing required permissions; update scopes in dashboard.",
        )
        set_connection_enabled(False, silent=True)
        return

    if code == WS_CLOSE_CODE_UNAUTHORIZED:
        _set_connection_state(
            "blocked",
            "[AEC-LINK] authentication failed; update API key or link key and re-enable the worker.",
        )
        set_connection_enabled(False, silent=True)
        return

    if code == WS_CLOSE_CODE_RATE_LIMITED:
        wait_seconds = _parse_retry_after(reason_text) or _DEFAULT_RATE_LIMIT_WAIT
        _suspend_until = time.monotonic() + wait_seconds
        _suspend_notice_logged = False
        _set_connection_state(
            "blocked", f"[AEC-LINK] rate limited; retrying in {int(wait_seconds)}s."
        )
        return

    if code == WS_CLOSE_CODE_SERVICE_DISABLED:
        wait_seconds = max(30.0, _RECONNECT_BASE_DELAY)
        _suspend_until = time.monotonic() + wait_seconds
        _suspend_notice_logged = False
        _set_connection_state(
            "blocked",
            "[AEC-LINK] link service temporarily disabled by server; retrying shortly.",
        )
        return

    _set_connection_state("disconnected", "[AEC-LINK] disconnected; retrying...")


def _on_error(ws, err) -> None:
    global _last_error
    err_type = err.__class__.__name__ if hasattr(err, "__class__") else type(err).__name__
    msg = f"{err_type}: {err}"
    if msg != _last_error:
        print("[AEC-LINK] websocket error:", msg, file=sys.stderr)
        _last_error = msg
        _debug(f"[AEC-LINK] websocket error: {msg}")
    _set_connection_state("error", "[AEC-LINK] websocket error")


def _on_msg(ws, raw) -> None:
    try:
        msg = json.loads(raw)
    except Exception:
        return
    if msg.get("type") == "job":
        _job_queue.put(msg.get("data"))
    elif msg.get("type") == "control":
        _handle_control(msg)


def _handle_control(msg: dict) -> None:
    command = msg.get("command")
    request_id = msg.get("requestId")
    response = {"command": command}
    if request_id is not None:
        response["requestId"] = request_id
    if command == "set_worker_state":
        raw_enable = msg.get("enable")
        enable = not (raw_enable in (False, "false", 0))
        response["enable"] = enable
        try:
            running = _apply_worker_state(
                enable,
                link_key=msg.get("linkKey"),
                api_key=msg.get("apiKey"),
            )
            response.update({"ok": True, "running": running})
        except Exception as exc:
            response.update({"ok": False, "message": str(exc)})
        _send_control_ack(response)
    elif command == "list_subfolders":
        kind = str(msg.get("kind") or "").lower().strip()
        allowed = {"checkpoint", "lora", "vae", "embedding"}
        if kind not in allowed:
            _send_ws_payload(
                {
                    "type": "folders_result",
                    "requestId": request_id,
                    "ok": False,
                    "error": f"Unsupported kind '{kind}'",
                }
            )
            return
        try:
            folders = list_subfolders(kind)
            _send_ws_payload(
                {
                    "type": "folders_result",
                    "requestId": request_id,
                    "ok": True,
                    "kind": kind,
                    "folders": folders,
                }
            )
        except Exception as exc:
            _send_ws_payload(
                {
                    "type": "folders_result",
                    "requestId": request_id,
                    "ok": False,
                    "error": str(exc),
                    "kind": kind,
                }
            )
    else:
        response.update({"ok": False, "message": "unknown command"})
        _send_control_ack(response)


def _on_ping(ws, data) -> None:
    try:
        sock = getattr(ws, "sock", None)
        if sock and getattr(sock, "connected", False):
            sock.pong(data)
        else:
            ws.send(data, opcode=websocket.ABNF.OPCODE_PONG)
        _debug("sent pong frame")
    except Exception as exc:
        _debug(f"failed to send pong: {exc}")


def _ensure_socket() -> None:
    global _sock, _reconnect_attempts
    if not _socket_enabled:
        _debug("ensure_socket skipped: disabled")
        return
    if _sock and _open_evt.is_set():
        return

    def _runner() -> None:
        global _sock, _reconnect_attempts, _suspend_until, _suspend_notice_logged
        while True:
            if not _socket_enabled:
                if _sock is not None:
                    try:
                        _sock.close()
                    except Exception:
                        pass
                    _sock = None
                _open_evt.clear()
                _debug("runner sleeping - disabled")
                time.sleep(1)
                continue

            if _suspend_until:
                remaining = _suspend_until - time.monotonic()
                if remaining > 0:
                    if not _suspend_notice_logged:
                        print(
                            f"[AEC-LINK] waiting {int(remaining)}s before reconnect..."
                        )
                        _debug(f"suspend_until active, {remaining:.1f}s remaining")
                        _suspend_notice_logged = True
                    time.sleep(min(remaining, 5))
                    continue
                _suspend_until = 0.0
                _suspend_notice_logged = False

            params: list[str] = ["mode=worker"]
            headers: list[str] = []
            if LINK_KEY:
                headers.append(f"x-link-key: {LINK_KEY}")
            elif API_KEY:
                headers.append(f"x-api-key: {API_KEY}")
            query = "?" + "&".join(params)
            url = _WS_URL + query
            protocols = _ws_subprotocols()
            try:
                _set_connection_state(
                    "connecting", f"[AEC-LINK] connecting to {_display_target()}"
                )
                _debug(f"connecting via {url}")
                _sock = websocket.WebSocketApp(
                    url,
                    header=headers or None,
                    subprotocols=protocols,
                    on_open=_on_open,
                    on_close=_on_close,
                    on_error=_on_error,
                    on_message=_on_msg,
                    on_ping=_on_ping,
                )
                _sock.run_forever(ping_interval=0, ping_timeout=None)
            except Exception as e:
                global _last_error
                _set_connection_state("error", "[AEC-LINK] connection error")
                msg = str(e)
                if msg != _last_error:
                    print(
                        "[AEC-LINK] websocket reconnect failed:", msg, file=sys.stderr
                    )
                    _last_error = msg
                    _debug(f"websocket reconnect failed: {msg}")
            finally:
                _open_evt.clear()
                _sock = None
            delay = min(
                _RECONNECT_MAX_DELAY, _RECONNECT_BASE_DELAY * (2**_reconnect_attempts)
            )
            _reconnect_attempts = min(_reconnect_attempts + 1, 6)
            _debug(f"reconnect back-off: {delay:.1f}s")
            time.sleep(delay)

    global _runner_started
    if not _runner_started:
        with _runner_lock:
            if not _runner_started:
                threading.Thread(target=_runner, daemon=True).start()
                _runner_started = True
                _debug("runner started")
    time.sleep(0.2)


def check_backend_health() -> bool:
    global _health_state
    try:
        r = SESSION.get(f"{BASE_URL}/health", headers=headers(), timeout=TIMEOUT)
        r.raise_for_status()
        if _health_state != "up":
            target = _display_target()
            if DEV_MODE:
                print(f"[AEC-LINK] connected to {BASE_URL}")
            else:
                print(f"[AEC-LINK] connected to {target}")
            _debug(f"connected to {BASE_URL}")
        _health_state = "up"
        return True
    except Exception as e:
        if _health_state != "down":
            if DEV_MODE:
                print(f"[AEC-LINK] backend not reachable: {e}", file=sys.stderr)
            else:
                print("[AEC-LINK] backend not reachable; retrying...", file=sys.stderr)
            _debug(f"backend not reachable: {e}")
        _health_state = "down"
        return False


def queue_next_job():
    _ensure_socket()
    try:
        return _job_queue.get(timeout=HEARTBEAT_INTERVAL + 5)
    except queue.Empty:
        if _open_evt.is_set():
            try:
                _sock.send('{"type":"poll"}')
            except Exception:
                pass
        return None


def report_progress(job_id: int, *, progress: int = None, state: str = None, message: str | None = None):
    if _open_evt.is_set():
        _sock.send(
            json.dumps(
                {
                    "type": "progress",
                    "jobId": job_id,
                    "progress": progress,
                    "state": state,
                    "message": message,
                }
            )
        )
        if state == "DONE":
            _sock.send('{"type":"poll"}')
    else:
        payload = {
            k: v
            for k, v in [("progress", progress), ("state", state), ("message", message)]
            if v is not None
        }
        SESSION.patch(
            f"{BASE_URL}/queue/{job_id}/progress",
            json=payload,
            headers=headers(),
            timeout=TIMEOUT,
        )


def push_inventory(hashes: list[str]) -> None:
    if _open_evt.is_set():
        _sock.send(json.dumps({"type": "inventory", "hashes": hashes}))
    else:
        SESSION.post(
            f"{BASE_URL}/inventory",
            json={"hashes": hashes},
            headers=headers(),
            timeout=TIMEOUT,
        )


def set_connection_enabled(enabled: bool, *, silent: bool = False) -> None:
    global _socket_enabled, _sock
    _socket_enabled = enabled
    _debug(f"set_connection_enabled({enabled}, silent={silent})")
    if not enabled:
        if _sock is not None:
            try:
                _sock.close()
            except Exception:
                pass
            _sock = None
        _open_evt.clear()
        if not silent:
            _set_connection_state("disconnected", "[AEC-LINK] worker offline")
    else:
        _ensure_socket()


def force_reconnect() -> None:
    global _reconnect_attempts, _last_connected_at, _suspend_until, _suspend_notice_logged
    _debug("force_reconnect() invoked")
    if _suspend_until and time.monotonic() < _suspend_until:
        remaining = _suspend_until - time.monotonic()
        print(
            f"[AEC-LINK] reconnect paused for {int(remaining)}s due to previous error."
        )
        _debug(f"force_reconnect blocked by suspend_until ({remaining:.1f}s)")
        return
    if not _socket_enabled:
        set_connection_enabled(True, silent=True)
        return
    if not _open_evt.is_set():
        _debug("force_reconnect: socket not open, ensuring connection")
        _ensure_socket()
        return
    if _credentials_dirty or _sock is None:
        _debug("force_reconnect: credentials changed, closing socket")
        _reconnect_attempts = 0
        try:
            if _sock is not None:
                _sock.close()
        except Exception:
            pass
        return
    if time.monotonic() - _last_connected_at < 5:
        _debug("force_reconnect: recent connection, sending poll instead of reconnect")
        try:
            _sock.send('{"type":"poll"}')
        except Exception as exc:
            _debug(f"force_reconnect poll failed: {exc}")
        return
    _debug("force_reconnect: refreshing socket connection")
    _reconnect_attempts = 0
    try:
        _sock.close()
    except Exception:
        pass


def _download_with_retry(url: str, tmp: Path, progress_cb) -> None:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            download_file(url, tmp, progress_cb)
            return
        except Exception:
            tmp.unlink(missing_ok=True)
            if attempt == MAX_RETRIES:
                raise
            time.sleep(BACKOFF_BASE ** attempt + random.uniform(0, 1))


_RND_PREFIX = re.compile(
    r"^(?:\d+_|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_)",
    re.I,
)


def _clean(name: str) -> str:
    return _RND_PREFIX.sub("", name, count=1)


def _unique_filename(dir_: Path, name: str) -> Path:
    stem, ext = os.path.splitext(name or "_")
    candidate = name
    idx = 1
    while (dir_ / candidate).exists() or (dir_ / (candidate + ".part")).exists():
        candidate = f"{stem}_{idx}{ext}"
        idx += 1
    return dir_ / candidate


def _enough_free_space(path: Path, min_mb: int = MIN_FREE_MB) -> bool:
    free = shutil.disk_usage(path).free // (1024 * 1024)
    return free >= min_mb


def _save_preview(url: str, model_path: Path) -> str | None:
    if not url:
        return None
    preview_file = model_path.with_suffix(".preview.png")
    if preview_file.exists():
        preview_file = _unique_filename(preview_file.parent, preview_file.stem + ".png")

    try:
        print(f"[AEC-LINK] downloading preview: {url}", flush=True)
        r = SESSION.get(url, timeout=20)
        r.raise_for_status()

        if _HAS_PIL:
            img = Image.open(BytesIO(r.content)).convert("RGBA")
            img.save(preview_file, format="PNG")
        else:
            with open(preview_file, "wb") as f:
                f.write(r.content)
        print(f"[AEC-LINK] preview saved as {preview_file}", flush=True)
        return preview_file.name
    except Exception as e:
        print(f"[AEC-LINK] preview download failed: {e}", flush=True)
        return None


def _write_info_json(meta: dict, sha_local: str, preview_name: str | None, model_path: Path) -> None:
    info = {
        "schema": 1,
        "modelId": meta.get("modelId"),
        "versionId": meta.get("versionId"),
        "name": meta.get("modelTitle"),
        "type": meta.get("type"),
        "about": meta.get("aboutThisVersion") or meta.get("about"),
        "description": meta.get("modelDescription") or meta.get("description"),
        "activation text": " || ".join(meta.get("activationTags") or []),
        "sha256": sha_local,
        "previewFile": preview_name,
        "arcencielUrl": f"https://arcenciel.io/models/{meta.get('modelId')}",
    }
    (model_path.parent / (model_path.stem + ".arcenciel.info")).write_text(
        json.dumps(info, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )

    sd_meta = {
        "description": info["about"],
        "sd version": "unknown",
        "activation text": " || ".join(meta.get("activationTags") or []),
        "preferred weight": 1.0,
        "notes": info["arcencielUrl"],
    }
    sd_file = model_path.parent / (model_path.stem + ".json")
    sd_file.write_text(
        json.dumps(sd_meta, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )


def _write_html(meta: dict, preview_name: str | None, model_path: Path) -> None:
    title = meta.get("modelTitle", "ArcEnCiel Model")
    html = dedent(
        f"""
        <!doctype html><html lang="en"><meta charset="utf-8">
        <title>{title}</title>
        <style>
          body{{font-family:system-ui, sans-serif; max-width:720px; margin:2rem auto; line-height:1.5}}
          img{{max-width:100%; border-radius:8px; box-shadow:0 2px 8px #0003}}
          pre{{background:#f8f8f8; padding:0.75rem 1rem; border-radius:6px; overflow:auto}}
          .tag{{display:inline-block; background:#eef; color:#226; padding:2px 6px;
                border-radius:4px; margin:2px; font-size:90%}}
        </style>
        <h1>{title}</h1>
        """
    )
    if preview_name:
        html += f'<img src="{preview_name}" alt="preview">'
    if meta.get("aboutThisVersion"):
        html += f"<h2>About this version</h2><p>{meta['aboutThisVersion']}</p>"
    if (tags := meta.get("activationTags")):
        html += "<h2>Activation Tags</h2>" + "".join(
            f'<span class="tag">{t}</span>' for t in tags
        )
    html += f"""
        <hr><p><small>Generated by <b>Arc en Ciel Link</b><br>
        sha256: {meta.get('sha256','')}</small></p></html>
        """
    (model_path.parent / (model_path.stem + ".arcenciel.html")).write_text(
        html,
        encoding="utf-8",
    )


def _already_have(hash_: str | None) -> bool:
    return hash_ in KNOWN_HASHES if hash_ else False


def _sync_inventory(hashes: list[str]) -> None:
    unique_count = len(KNOWN_HASHES)
    if len(hashes) == unique_count and KNOWN_HASHES.issuperset(hashes):
        return
    KNOWN_HASHES.clear()
    KNOWN_HASHES.update(hashes)
    push_inventory(hashes)


def _heartbeat() -> None:
    if _open_evt.is_set():
        try:
            _sock.send('{"type":"poll"}')
        except Exception:
            pass


def _worker() -> None:
    last_hb = 0
    while True:
        RUNNING.wait()

        now = time.time()
        if now - last_hb > HEARTBEAT_INTERVAL:
            _heartbeat()
            last_hb = now

        try:
            job = queue_next_job()
            if job is None:
                time.sleep(2)
                continue
        except Exception:
            time.sleep(SLEEP_AFTER_ERROR)
            continue

        try:
            ver = job.get("version") or {}
            meta = ver.get("meta") or {}
            url_raw = ver.get("externalDownloadUrl") or ver.get("filePath")

            if url_raw and not url_raw.startswith(("http://", "https://")):
                root = BASE_URL.split("/api/")[0].rstrip("/")
                url_raw = urljoin(root + "/", url_raw.lstrip("/"))

            if not url_raw:
                raise RuntimeError("No download URL provided by server")

            url_path = unquote(urlparse(url_raw).path)

            sha_server = ver.get("sha256")
            try:
                dst_dir = resolve_target_path(job.get("targetPath") or "")
            except ValueError as exc:
                report_progress(job.get("id", 0), state="ERROR", message=str(exc))
                continue

            dst_dir.mkdir(parents=True, exist_ok=True)
            raw_name = Path(url_path).name
            clean_name = _clean(raw_name)
            dst_path = _unique_filename(dst_dir, clean_name)

            if not _enough_free_space(dst_path.parent):
                report_progress(
                    job.get("id", 0),
                    state="ERROR",
                    message=f"Less than {MIN_FREE_MB} MB free",
                )
                continue

            if sha_server and _already_have(sha_server):
                report_progress(job.get("id", 0), state="DONE", progress=100)
                continue

            tmp_path = dst_path.with_suffix(".part")
            report_progress(job.get("id", 0), state="DOWNLOADING", progress=0)
            last_progress = {"pct": 0, "ts": time.monotonic()}

            def _progress_cb(frac: float) -> None:
                pct = max(0, min(100, int(frac * 100)))
                now = time.monotonic()
                delta = pct - last_progress["pct"]
                elapsed = now - last_progress["ts"]
                if pct not in (0, 100) and delta < PROGRESS_MIN_STEP and elapsed < PROGRESS_MIN_INTERVAL:
                    return
                last_progress["pct"] = pct
                last_progress["ts"] = now
                report_progress(job.get("id", 0), progress=pct)

            _download_with_retry(url_raw, tmp_path, _progress_cb)

            sha_local = sha256_of_file(tmp_path)
            if sha_server and sha_local != sha_server:
                tmp_path.unlink(missing_ok=True)
                raise RuntimeError("SHA-256 mismatch")

            tmp_path.rename(dst_path)

            preview_name = _save_preview(meta.get("preview"), dst_path)
            _write_info_json(meta, sha_local, preview_name, dst_path)
            if SAVE_HTML_PREVIEW:
                _write_html(meta | {"sha256": sha_local}, preview_name, dst_path)

            hashes = update_cached_hash(dst_path, sha_local)
            _sync_inventory(hashes)
            report_progress(job.get("id", 0), state="DONE", progress=100)
        except Exception as e:
            print(f"[AEC-LINK] worker error: {e}")
            report_progress(job.get("id", 0), state="ERROR", message=str(e))
            time.sleep(SLEEP_AFTER_ERROR)


def toggle_worker(enable: bool) -> None:
    if enable and not RUNNING.is_set():
        RUNNING.set()
        print("[AEC-LINK] worker ENABLED", flush=True)
    elif not enable and RUNNING.is_set():
        RUNNING.clear()
        print("[AEC-LINK] worker DISABLED by user", flush=True)


def start_worker() -> None:
    threading.Thread(target=_worker, daemon=True).start()


def list_subfolders_roots(kind: str) -> list[Path]:
    try:
        import folder_paths

        mapping = {
            "checkpoints": "checkpoints",
            "loras": "loras",
            "vae": "vae",
            "embeddings": "embeddings",
        }
        roots = folder_paths.get_folder_paths(mapping.get(kind, kind))
        return [Path(p) for p in roots if p]
    except Exception:
        return []


def _inventory_watch_dirs() -> set[Path]:
    roots = set()
    for kind in ("checkpoints", "loras", "vae", "embeddings"):
        for root in list_subfolders_roots(kind):
            roots.add(root)
    return roots


def _inventory_signature() -> tuple[tuple[str, int], ...]:
    signature: list[tuple[str, int]] = []
    for root in _inventory_watch_dirs():
        try:
            stat = root.stat()
            newest = getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))
            try:
                for child in root.iterdir():
                    try:
                        child_stat = child.stat()
                    except (FileNotFoundError, PermissionError):
                        continue
                    child_mtime = getattr(child_stat, "st_mtime_ns", int(child_stat.st_mtime * 1_000_000_000))
                    if child_mtime > newest:
                        newest = child_mtime
            except (FileNotFoundError, PermissionError):
                pass
            signature.append((str(root), int(newest)))
        except FileNotFoundError:
            signature.append((str(root), 0))
    return tuple(sorted(signature))


def _inventory_worker() -> None:
    last_signature: tuple[tuple[str, int], ...] | None = None
    while True:
        try:
            signature = _inventory_signature()
            if signature != last_signature:
                hashes = list_model_hashes()
                _sync_inventory(hashes)
                last_signature = signature
        except Exception:
            pass
        time.sleep(3600)


def schedule_inventory_push() -> None:
    threading.Thread(target=_inventory_worker, daemon=True).start()


def generate_sidecars_for_existing() -> None:
    cache_hashes = list(dict.fromkeys(list_model_hashes()))
    if not cache_hashes:
        return

    try:
        request_headers = headers() or {}
        resp = SESSION.post(
            BASE_URL.rstrip("/") + "/sidecars/meta",
            json={"hashes": cache_hashes},
            headers=request_headers,
            timeout=30,
        )
        resp.raise_for_status()
        metas = resp.json()
    except Exception as e:
        print("[AEC-LINK] sidecar-meta fetch failed", e)
        return

    for h, path in _iter_cached_paths().items():
        meta = metas.get(h)
        if not meta:
            continue

        dst_path = Path(path)
        if (dst_path.with_suffix(".arcenciel.info")).exists():
            continue

        print(f"[AEC-LINK] sidecars for {dst_path.name}")
        preview = _save_preview(meta.get("preview"), dst_path)
        _write_info_json(meta, h, preview, dst_path)
        if SAVE_HTML_PREVIEW:
            _write_html(meta | {"sha256": h}, preview, dst_path)


def _iter_cached_paths() -> dict[str, str]:
    from aec_link_utils import _ensure_cache

    cache = _ensure_cache()
    model_files = {
        v["hash"]: k
        for k, v in cache.items()
        if isinstance(v, dict) and v.get("hash") and Path(k).exists()
    }
    return model_files


def cancel_job(job_id: int) -> None:
    r = SESSION.patch(f"{BASE_URL}/queue/{job_id}/cancel", headers=headers(), timeout=TIMEOUT)
    r.raise_for_status()


def initialize() -> None:
    _apply_config(_cfg)
    start_worker()
    schedule_inventory_push()
    if LINK_KEY or API_KEY:
        set_connection_enabled(True, silent=True)
    if _cfg.get("enabled"):
        toggle_worker(True)


def shutdown() -> None:
    toggle_worker(False)
    set_connection_enabled(False, silent=True)


_refresh_ws_url()
