import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.append(ROOT)

import aec_link_runtime  # noqa: E402

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}
WEB_DIRECTORY = "./web"

# Package discovery (tests, build tools, registry tooling) must not start a host worker.
if getattr(getattr(sys.modules.get("server"), "PromptServer", None), "instance", None) is not None:
    aec_link_runtime.startup()
