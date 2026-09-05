# ArcEnCiel Link for ComfyUI

ArcEnCiel Link sends one-click model downloads from [arcenciel.io](https://arcenciel.io) into ComfyUI.

## Version 2.3

- Link Keys (`lk_...`) are the only supported Link credential.
- The browser-facing control API uses a dedicated loopback-only bridge on `http://127.0.0.1:8000`.
- Native ComfyUI routes on port `8188` remain available for compatible same-origin setups.
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
4. Select the detected `8000` endpoint if multiple WebUIs are running.

There is no separate ArcEnCiel settings node. Fallback configuration is stored at `ComfyUI/user/arcenciel-link/config.json`.

## Hosted configuration (2.1.0)

All three Link workers use the same runtime variables. Set them **before starting the host**:

| Variable                 | Meaning                                                                    |
| ------------------------ | -------------------------------------------------------------------------- |
| `ARCENCIEL_LINK_URL`     | HTTPS API base; normally `https://link.arcenciel.io/api/link`.             |
| `ARCENCIEL_LINK_KEY`     | Dedicated Link Key from Colab Secrets or your runtime secret store.        |
| `ARCENCIEL_LINK_ENABLED` | Startup preference: `1/true/yes/on` or `0/false/no/off`, case-insensitive. |

Explicit environment variables override saved desktop settings, including explicitly empty values. An empty key never falls back to a saved key. Missing/invalid credentials or an invalid enabled value prevent automatic downloads and produce a value-free diagnostic. Environment values are not written to the extension config or OS keyring when you pause or resume; previous desktop settings remain available after removing the overrides.

Pause/resume works during the current process. On restart, `ARCENCIEL_LINK_ENABLED` takes effect again. Changing an environment-managed key through the browser is rejected: update the runtime secret and restart the host. Existing desktop installations with valid settings need no migration. Protocol 2 and the browser toggle payload are unchanged.

For an existing notebook host, use the [versioned Link setup notebook](https://github.com/FallenIncursio/arcenciel-link-webui/blob/v2.4.1/notebooks/ArcEnCiel_Link_Setup.ipynb). It supports WebUI/Forge, ComfyUI, and SwarmUI, validates the host checkout, installs the tagged extension, and loads Colab Secrets. It does not install a model or the host itself. Select **Remote / Colab** on the website and keep the bridge private. A health-probe log alone is not proof of an authenticated worker or a completed download.

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
  "bridge_port": 8000
}
```

ComfyUI's global origin guard rejects requests from `arcenciel.io` before native custom-node routes run. The default loopback-only bridge therefore keeps browser integration working without weakening ComfyUI's middleware for other routes. Set `bridge_port` to `0` only when ComfyUI itself is launched with an explicit compatible CORS configuration. HTTP ArcEnCiel endpoints and private origins require `ARCENCIEL_DEV=1`.

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

CI verifies Python 3.11. A `vX.Y.Z` tag must match `pyproject.toml` and `aec_link_version.py`; it creates a GitHub Release and publishes through the pinned `Comfy-Org/publish-node-action` when `REGISTRY_ACCESS_TOKEN` is configured. Retry a failed registry publish without moving the tag by dispatching `publish.yml` with `release_tag=vX.Y.Z`; the workflow checks out and revalidates that immutable tag before publishing.

## License

[MIT](LICENSE)

## Reliable download attempts (2.2.0)

The worker negotiates `job_lease_v1` with ArcEnCiel. Each device accepts one reserved download at a time and
acknowledges the attempt before opening a file. A fresh runtime identity, periodic heartbeats and attempt IDs
prevent stale workers from changing completed or cancelled jobs. The server retries expired attempts at most
three times, then reports an actionable error. Restarting a lost transfer currently downloads the file again.

Cancel interrupts the stream, hash check and retry wait, cleans this attempt's partial file and confirms cleanup.
If cancellation arrives after the atomic file commit, the installed model stays on disk. Legacy server compatibility
is retained; automatic recovery requires the updated ArcEnCiel server. Keep each device on its own Link Key.

## Guided setup (2.4.0)

Open [Link Hub](https://arcenciel.io/link) to choose your host and location, create or import a device key, and verify the setup. Local discovery runs only when requested; another computer or Google Colab connects directly without a local browser scan. Existing keys and downloads remain compatible.

Workers advertise `setup_check_v1`. A setup check transfers a fixed 4 KiB file into the selected native model folder, flushes and reads it back, verifies SHA-256, and deletes the temporary file. The result is bound to one key and runtime; shared keys, paused or busy workers cannot complete the check. Stable errors explain storage, write, transfer and cleanup failures. The check does not install a model or alter download history. The `Finish setup` button appears only after verification.

## Device tools (2.4.0)

Select this device in [Link Hub](https://arcenciel.io/link) and open **Device tools** to scan its library, inspect its download
subfolders or repair missing sidecars. The same actions work on another computer and in Google Colab through the outbound
Link connection. Use a separate Link key with inventory permission for each host/runtime.

Scans publish empty inventories as well as changes. Repair fills missing metadata and previews for models visible to your
account, preserves existing sidecars and never changes model bytes. A sidecar failure after download leaves the model completed
and shows a warning; correct permissions and retry repair. Tools show progress and support cancellation. Reconnect and start a
new scan after a timeout; interrupted work is not replayed automatically. Upgrade and restart the host to advertise `device_tools_v1`.
A small native Link panel shows the extension version and latest operation. Folder choices use the native download destination;
inventories also include other configured model roots.

## Release verification (2.4.1)

The broker reports its source revision and active deployment color. A broker retirement reconnects the worker without changing its runtime ID or cancelling an acknowledged download. Existing 2.4.0 workers remain compatible. The Link operations runbook records tested host/browser versions and transfer evidence; a healthy socket alone is not a completed-download check.
