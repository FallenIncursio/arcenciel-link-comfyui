import json
import sys
from types import SimpleNamespace

import pytest

import aec_link_bridge
import aec_link_config
import aec_link_utils
import aec_link_worker


def test_private_download_grant_is_bound_to_configured_origin(monkeypatch):
    monkeypatch.setattr(aec_link_worker, "BASE_URL", "https://link.arcenciel.io/api/link")
    monkeypatch.setattr(aec_link_worker, "DEV_MODE", False)
    job = {
        "downloadGrant": "header.payload.signature",
        "downloadGrantHeader": "x-arcenciel-link-grant",
    }

    headers, redirects = aec_link_worker._private_download_options(
        job,
        "https://link.arcenciel.io/api/link/queue/7/download/model.safetensors?v=3",
    )

    assert headers == {"x-arcenciel-link-grant": "header.payload.signature"}
    assert redirects is False
    with pytest.raises(RuntimeError, match="configured Arc en Ciel origin"):
        aec_link_worker._private_download_options(
            job,
            "https://evil.example/api/link/queue/7/download/model.safetensors",
        )
    with pytest.raises(RuntimeError, match="forbidden"):
        aec_link_worker._private_download_options(
            job,
            "https://user@link.arcenciel.io/api/link/queue/7/download/model.safetensors",
        )


def test_download_retry_forwards_grant_and_disables_redirects(monkeypatch, tmp_path):
    calls = []

    def fake_download(url, target, progress, **options):
        calls.append((url, target, options))

    monkeypatch.setattr(aec_link_worker, "download_file", fake_download)
    aec_link_worker._download_with_retry(
        "https://link.arcenciel.io/model",
        tmp_path / "model.part",
        lambda _fraction: None,
        request_headers={"x-arcenciel-link-grant": "grant"},
        allow_redirects=False,
    )

    assert calls[0][2] == {
        "request_headers": {"x-arcenciel-link-grant": "grant"},
        "allow_redirects": False,
    }


def test_html_sidecar_escapes_remote_metadata(tmp_path):
    model = tmp_path / "model.safetensors"
    aec_link_worker._write_html(
        {
            "modelTitle": "<script>alert(1)</script>",
            "aboutThisVersion": "<img src=x onerror=alert(1)>",
            "activationTags": ["<b>tag</b>"],
            "sha256": "hash",
        },
        'preview" onerror="alert(1).png',
        model,
    )

    rendered = model.with_suffix(".arcenciel.html").read_text()
    assert "<script>" not in rendered
    assert '<img src="preview" onerror=' not in rendered
    assert "&lt;script&gt;" in rendered


def test_hash_cache_update_does_not_reenter_inventory_lock(monkeypatch, tmp_path):
    model = tmp_path / "model.safetensors"
    model.write_bytes(b"tiny model")
    cache_file = tmp_path / "hashes.json"
    monkeypatch.setattr(aec_link_utils, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(aec_link_utils, "CACHE_FILE", cache_file)
    monkeypatch.setattr(aec_link_utils, "_CACHE_DATA", {})

    hashes = aec_link_utils.update_cached_hash(model, "a" * 64)

    assert hashes == ["a" * 64]
    assert json.loads(cache_file.read_text())[str(model.resolve())]["hash"] == "a" * 64


def test_config_removes_retired_credentials_and_writes_private_file(monkeypatch, tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "base_url": "https://link.arcenciel.io/api/link",
                "link_key": "lk_" + "a" * 32,
                "api_key": "retired-secret",
            }
        )
    )
    monkeypatch.setattr(aec_link_config, "_config_path", lambda: config_file)

    loaded = aec_link_config.load_config()
    assert "api_key" not in loaded
    assert "api_key" not in json.loads(config_file.read_text())
    aec_link_config.save_config(loaded)
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_default_browser_bridge_stays_enabled(monkeypatch, tmp_path):
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(aec_link_config, "_config_path", lambda: config_file)

    loaded = aec_link_config.load_config()

    assert loaded["bridge_port"] == 8000


def test_native_comfy_routes_are_registered(monkeypatch):
    registered = []

    class Routes:
        def _register(self, method, path):
            def decorator(handler):
                registered.append((method, path, handler))
                return handler

            return decorator

        def get(self, path):
            return self._register("GET", path)

        def post(self, path):
            return self._register("POST", path)

        def options(self, path):
            return self._register("OPTIONS", path)

    fake_server = SimpleNamespace(PromptServer=SimpleNamespace(instance=SimpleNamespace(routes=Routes())))
    monkeypatch.setitem(sys.modules, "server", fake_server)
    monkeypatch.setattr(aec_link_bridge, "_native_routes_registered", False)

    assert aec_link_bridge.register_prompt_server_routes(allow_private=False) is True
    assert ("GET", "/arcenciel-link/ping") in [(method, path) for method, path, _handler in registered]
    assert ("POST", "/arcenciel-link/toggle_link") in [(method, path) for method, path, _handler in registered]
