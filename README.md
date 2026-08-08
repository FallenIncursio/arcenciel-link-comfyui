# ArcEnCiel Link for ComfyUI

ArcEnCiel Link sends one-click model downloads from [arcenciel.io](https://arcenciel.io) into ComfyUI.

## Version 2.0

- Link Keys (`lk_...`) are the only supported Link credential.
- The local control API is registered on ComfyUI's native server, normally `http://127.0.0.1:8188`.
- Private downloads use a short-lived header grant bound to the configured ArcEnCiel HTTPS origin; redirects are refused.
- Inventory reconciliation performs a complete hourly scan across every Comfy model root.
- Generated HTML sidecars escape all remote metadata.

## Installation

Preferred: search for **ArcEnCiel Link** by publisher `fallenincursio` in ComfyUI Manager. Registry page: [arcenciel-link-comfy](https://registry.comfy.org/publishers/fallenincursio/nodes/arcenciel-link-comfy).

Manual installation:

```bash
cd ComfyUI/custom_nodes
git clone https://github.com/FallenIncursio/arcenciel-link-comfyui.git ArcEnCielLink
python -m pip install -r ArcEnCielLink/requirements.txt
```

Restart ComfyUI after installation.

## Connect

1. Start ComfyUI with the node installed.
2. Open the ArcEnCiel Link panel on [arcenciel.io](https://arcenciel.io).
3. Generate or select a Link Key and press **Connect**.
4. Select the detected `8188` endpoint if multiple WebUIs are running.

There is no separate ArcEnCiel settings node. Fallback configuration is stored at `ComfyUI/user/arcenciel-link/config.json`.

## Configuration

```json
{
  "base_url": "https://link.arcenciel.io/api/link",
  "link_key": "",
  "enabled": false,
  "min_free_mb": 2048,
  "max_retries": 5,
  "backoff_base": 2,
  "save_html_preview": false,
  "allow_private_origins": false,
  "bridge_port": 0
}
```

`bridge_port: 0` uses native ComfyUI routes only. An explicitly configured positive port keeps the older loopback bridge available during migration. HTTP ArcEnCiel endpoints and private origins require `ARCENCIEL_DEV=1`.

Environment overrides:

- `ARCENCIEL_LINK_URL`
- `ARCENCIEL_LINK_KEY`
- `ARCENCIEL_DEV=1`

Old retired credential fields are removed when the configuration is loaded and saved. The fallback configuration file is written with mode `0600` where supported.

## Local routes

- `GET /arcenciel-link/ping`
- `POST /arcenciel-link/toggle_link`
- `GET /arcenciel-link/folders/{kind}`
- `POST /arcenciel-link/generate_sidecars`

These routes emit scoped CORS and browser Private Network Access headers without changing global ComfyUI middleware.

## Development and release

```bash
python -m pip install -r requirements.txt pytest ruff
ruff format --check .
ruff check .
pytest -q
```

CI verifies Python 3.11. A `vX.Y.Z` tag must match `pyproject.toml` and `aec_link_version.py`; it creates a GitHub Release and publishes through the pinned `Comfy-Org/publish-node-action` when `REGISTRY_ACCESS_TOKEN` is configured.

## License

[MIT](LICENSE)
