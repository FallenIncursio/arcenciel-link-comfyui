import json
import os
from pathlib import Path

_DEFAULT_CONFIG = {
    "base_url": "https://link.arcenciel.io/api/link",
    "link_key": "",
    "api_key": "",
    "enabled": False,
    "min_free_mb": 2048,
    "max_retries": 5,
    "backoff_base": 2,
    "save_html_preview": False,
    "allow_private_origins": False,
    "bridge_port": 8000,
}

_DEV_URL = "http://localhost:3000/api/link"


def _detect_dev_mode() -> bool:
    return bool(os.getenv("ARCENCIEL_DEV"))


def _config_path() -> Path:
    try:
        import folder_paths

        user_dir = folder_paths.get_user_directory()
    except Exception:
        user_dir = None

    if user_dir:
        return Path(user_dir) / "arcenciel-link" / "config.json"

    return Path(__file__).with_name("config.json")


def get_storage_dir() -> Path:
    path = _config_path().parent
    path.mkdir(parents=True, exist_ok=True)
    return path


def _apply_env_overrides(cfg: dict) -> None:
    if os.getenv("ARCENCIEL_LINK_URL"):
        cfg["base_url"] = os.getenv("ARCENCIEL_LINK_URL", "").strip().rstrip("/")
    if os.getenv("ARCENCIEL_LINK_KEY"):
        cfg["link_key"] = os.getenv("ARCENCIEL_LINK_KEY", "").strip()
    if os.getenv("ARCENCIEL_API_KEY"):
        cfg["api_key"] = os.getenv("ARCENCIEL_API_KEY", "").strip()


def load_config() -> dict:
    cfg = dict(_DEFAULT_CONFIG)
    path = _config_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                cfg.update(data)
        except Exception:
            pass

    dev_mode = _detect_dev_mode()
    if dev_mode and cfg.get("base_url") == _DEFAULT_CONFIG["base_url"]:
        cfg["base_url"] = _DEV_URL

    _apply_env_overrides(cfg)
    cfg["_dev_mode"] = dev_mode
    return cfg


def save_config(cfg: dict) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(cfg)
    payload.pop("_dev_mode", None)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
