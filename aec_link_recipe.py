"""Native node capability discovery without queueing a workflow."""

import threading
import time

import aec_link_drafts as drafts
import aec_link_resources as resources


def build_profile():
    import nodes

    required = ["CheckpointLoaderSimple", "CLIPTextEncode", "KSampler", "EmptyLatentImage", "VAEDecode", "SaveImage"]
    sampler = nodes.NODE_CLASS_MAPPINGS.get("KSampler")
    inputs = sampler.INPUT_TYPES()["required"] if sampler else {}
    return {
        "schemaVersion": 1,
        "draftSelection": 1,
        "host": "comfyui",
        "fields": [
            "prompt",
            "negativePrompt",
            "seed",
            "steps",
            "cfg",
            "width",
            "height",
            "sampler",
            "scheduler",
            "checkpoint",
        ]
        + (["loras"] if "LoraLoader" in nodes.NODE_CLASS_MAPPINGS else []),
        "samplers": list(inputs.get("sampler_name", [[]])[0]),
        "schedulers": list(inputs.get("scheduler", [[]])[0]),
        # JavaScript graph widget values cannot represent arbitrary uint64 seeds exactly.
        "maxSeed": "9007199254740991",
        "templates": ["basic_checkpoint_v1"] if all(n in nodes.NODE_CLASS_MAPPINGS for n in required) else [],
    }


_report_started = False
_report_lock = threading.Lock()
REPORT_STATE = "Waiting for the host"


def start_reporting(client, runtime_id):
    """Read native options without generating, hashing libraries or changing the editor."""
    global _report_started
    with _report_lock:
        if _report_started:
            return
        _report_started = True

    def run():
        global REPORT_STATE
        while True:
            if client._open_evt.is_set():
                try:
                    profile = build_profile()
                    with client.SESSION.post(
                        f"{client.BASE_URL}/recipe/profile",
                        json={"runtimeId": runtime_id, "profile": profile},
                        headers=client.headers(),
                        timeout=15,
                    ) as response:
                        response.raise_for_status()
                    REPORT_STATE = "Recipe check ready"
                    try:
                        resources.report(client, runtime_id)
                    except Exception:
                        REPORT_STATE = "Recipe ready; resource inventory needs a refresh"
                    drafts.post(client, runtime_id, "inbox", {"receiveOnly": True})
                except Exception:
                    # Never include requests, prompts, keys or provider errors in logs.
                    REPORT_STATE = "Recipe check unavailable; refresh after reconnecting"
            else:
                REPORT_STATE = "Waiting for connection"
            time.sleep(30)

    threading.Thread(target=run, name="aec-link-recipes", daemon=True).start()
