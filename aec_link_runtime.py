import atexit

from aec_link_bridge import BridgeServer, register_prompt_server_routes
from aec_link_config import load_config
from aec_link_worker import initialize as worker_initialize
from aec_link_worker import shutdown as worker_shutdown

_started = False
_bridge: BridgeServer | None = None


def startup() -> None:
    global _started, _bridge
    if _started:
        return
    cfg = load_config()
    allow_private = bool(cfg.get("_dev_mode") or cfg.get("allow_private_origins"))
    register_prompt_server_routes(allow_private=allow_private)
    port = int(cfg.get("bridge_port") or 0)
    if port > 0:
        _bridge = BridgeServer(port, allow_private=allow_private)
        _bridge.start()
    worker_initialize()
    _started = True


def shutdown() -> None:
    global _started, _bridge
    if _bridge:
        _bridge.stop()
        _bridge = None
    worker_shutdown()
    _started = False


atexit.register(shutdown)
