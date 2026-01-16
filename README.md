# ArcEnCiel Link - ComfyUI Extension

Bring your ArcEnCiel models straight into ComfyUI with one click. Includes
Link Key support, remote worker control, inventory sync, and sidecar generation.

---

## Features

- One-click download from ArcEnCiel model cards.
- Model-aware routing for checkpoints, LoRAs, VAEs, and embeddings.
- Background worker with retry back-off, disk-space guard, and SHA-256 verify.
- Inventory sync so the dashboard knows what you already have.
- Optional preview PNG, `.arcenciel.info`, and HTML quick-view sidecars.

---

## Installation (ComfyUI)

1. Clone into:

```
ComfyUI/custom_nodes/ArcEnCielLink
```

2. Install dependencies in the ComfyUI venv (Windows example):

```
ComfyUI\venv\Scripts\python.exe -m pip install -r ComfyUI\custom_nodes\ArcEnCielLink\requirements.txt
```

3. Restart ComfyUI.

---

## First-time setup

1. On arcenciel.io open Link Access and create a Link Key (`lk_...`).
2. On arcenciel.io open the Link panel and connect. The site calls the local bridge on `http://127.0.0.1:8000`.
3. Alternative: set the Link Key in `ComfyUI/user/arcenciel-link/config.json`.

Note: there is no ComfyUI UI panel yet; the bridge/config handles credentials.

---

## Credentials and security

- Link Keys are the preferred credential.
- API keys are supported for legacy workflows, but Link Keys unlock remote worker controls.
- Config lives at:

```
ComfyUI/user/arcenciel-link/config.json
```

Default schema:

```
{
  "base_url": "https://link.arcenciel.io/api/link",
  "link_key": "",
  "api_key": "",
  "enabled": false,
  "min_free_mb": 2048,
  "max_retries": 5,
  "backoff_base": 2,
  "save_html_preview": false,
  "allow_private_origins": false,
  "bridge_port": 8000
}
```

Environment overrides:
- `ARCENCIEL_LINK_URL` - base API URL.
- `ARCENCIEL_LINK_KEY` - Link Key.
- `ARCENCIEL_API_KEY` - legacy API key.
- `ARCENCIEL_DEV=1` - allow HTTP endpoints and private origins for testing.

---

## How to use

- Press Download on any ArcEnCiel model card.
- The job appears in the ArcEnCiel Link queue.
- Inventory sync runs periodically and the dashboard skips duplicates.

---

## Local API surface

- GET `/arcenciel-link/ping`
- POST `/arcenciel-link/toggle_link`
- GET `/arcenciel-link/folders/{kind}`
- POST `/arcenciel-link/generate_sidecars`

---

## Advanced configuration

- `min_free_mb`, `max_retries`, and `backoff_base` live in config.json.
- `save_html_preview` enables HTML quick-views next to model files.
- `allow_private_origins` permits non-arcenciel origins for local testing.
- `bridge_port` changes the local bridge listen port (default 8000).

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Worker stays offline | Ensure the Link Key is saved and enable the worker. |
| Browser reports private network blocked | Accept the Private Network Access prompt or enable `allow_private_origins`. |
| Download stuck at 0% | Check disk space and write permissions. |
| Repeated SHA256 mismatch | Network instability or corrupted mirror. |
