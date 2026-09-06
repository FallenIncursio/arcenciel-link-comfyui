import asyncio
import ipaddress
import threading

from aiohttp import web

from aec_link_origins import is_private_host, normalize_origin
from aec_link_utils import list_subfolders
from aec_link_worker import RUNNING, apply_worker_state, generate_sidecars_for_existing

_native_routes_registered = False


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _client_ip(request: web.Request) -> str | None:
    if request.remote:
        return request.remote
    if request.transport:
        peer = request.transport.get_extra_info("peername")
        if isinstance(peer, tuple) and peer:
            return peer[0]
    return None


def _apply_cors_headers(resp: web.Response, origin: str | None) -> None:
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Private-Network"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "content-type"
    resp.headers["Access-Control-Max-Age"] = "600"
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"


def _allowed_origin(request: web.Request, *, allow_private: bool) -> tuple[bool, str | None]:
    origin = request.headers.get("Origin")
    if origin:
        normalized = normalize_origin(origin, allow_private=allow_private)
        return normalized is not None, normalized

    client_host = _client_ip(request)
    if not client_host:
        return False, None
    return (
        _is_loopback_host(client_host) or (allow_private and is_private_host(client_host)),
        None,
    )


async def _toggle_link(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except Exception:
        payload = None

    if not isinstance(payload, dict):
        return web.json_response({"error": "payload required"}, status=400)
    unknown = set(payload) - {"enable", "linkKey"}
    if unknown:
        return web.json_response({"error": "unsupported payload field"}, status=400)
    if "enable" not in payload:
        return web.json_response({"error": "enable flag required"}, status=400)

    link_key = payload.get("linkKey")
    enable = payload.get("enable") not in (False, "false", 0)
    try:
        apply_worker_state(enable, link_key=link_key)
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    except Exception:
        return web.json_response({"error": "Failed to toggle worker"}, status=500)

    if enable:
        for _ in range(60):
            if RUNNING.is_set():
                break
            await asyncio.sleep(0.05)
    return web.json_response({"ok": True, "workerOnline": RUNNING.is_set()})


async def _folders(request: web.Request) -> web.Response:
    kind = request.match_info.get("kind") or ""
    try:
        folders = list_subfolders(kind)
        return web.json_response({"folders": folders})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=400)


async def _generate_sidecars(_request: web.Request) -> web.Response:
    threading.Thread(target=generate_sidecars_for_existing, daemon=True).start()
    return web.json_response({"ok": True})


async def _device_status(_request: web.Request) -> web.Response:
    import aec_link_device_tools as device_tools
    import aec_link_job_attempt as job_attempt
    import aec_link_recipe as recipe
    import aec_link_worker as worker
    from aec_link_version import VERSION

    return web.json_response(
        {
            "version": VERSION,
            "connected": worker._open_evt.is_set(),
            "running": worker.RUNNING.is_set(),
            "runtimeId": job_attempt.RUNTIME_ID,
            "tool": device_tools.status(),
            "recipeStatus": recipe.REPORT_STATE,
        },
        headers={"Cache-Control": "no-store"},
    )


def register_prompt_server_routes(*, allow_private: bool) -> bool:
    """Register the bridge on ComfyUI's own HTTP server (normally port 8188)."""

    global _native_routes_registered
    if _native_routes_registered:
        return True
    try:
        from server import PromptServer
    except (ImportError, AttributeError):
        return False

    routes = PromptServer.instance.routes

    def guarded(handler):
        async def wrapped(request: web.Request) -> web.Response:
            allowed, origin = _allowed_origin(request, allow_private=allow_private)
            if not allowed:
                response = web.Response(status=403)
            elif request.method == "OPTIONS":
                response = web.Response(status=204)
            else:
                response = await handler(request)
            _apply_cors_headers(response, origin)
            return response

        return wrapped

    async def ping(_request: web.Request) -> web.Response:
        return web.Response(text="ok")

    async def draft_editor(request: web.Request) -> web.Response:
        # Native server only; never registered on the Arc-origin CORS bridge.
        if request.headers.get("X-AEC-Link-Editor") != "1" or request.headers.get("Sec-Fetch-Site") != "same-origin":
            return web.json_response({"code": "NATIVE_EDITOR_REQUIRED"}, status=403)
        raw = await request.read()
        if len(raw) > 100_000:
            return web.json_response({"code": "EVENT_TOO_LARGE"}, status=413)
        import json

        import aec_link_drafts as drafts
        import aec_link_job_attempt as job_attempt
        import aec_link_worker as worker

        try:
            body = json.loads(raw)
        except ValueError:
            return web.json_response({"code": "INVALID_EVENT"}, status=400)
        data, status = await asyncio.to_thread(
            drafts.post, worker, job_attempt.RUNTIME_ID, request.match_info["action"], body
        )
        return web.json_response(data, status=status, headers={"Cache-Control": "no-store"})

    routes.post("/arcenciel-link/editor/{action}")(draft_editor)
    routes.get("/arcenciel-link/ping")(guarded(ping))
    routes.get("/arcenciel-link/status")(guarded(_device_status))
    routes.options("/arcenciel-link/{tail:.*}")(guarded(ping))
    routes.post("/arcenciel-link/toggle_link")(guarded(_toggle_link))
    routes.get("/arcenciel-link/folders/{kind}")(guarded(_folders))
    routes.post("/arcenciel-link/generate_sidecars")(guarded(_generate_sidecars))
    _native_routes_registered = True
    return True


class BridgeServer:
    def __init__(self, port: int, *, allow_private: bool) -> None:
        self._port = port
        self._allow_private = allow_private
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    def start(self) -> None:
        if self._thread:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._loop or not self._runner:
            return
        self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self._shutdown()))

    async def _shutdown(self) -> None:
        try:
            if self._site:
                await self._site.stop()
            if self._runner:
                await self._runner.cleanup()
        finally:
            if self._loop:
                self._loop.stop()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        app = self._build_app()
        self._runner = web.AppRunner(app, access_log=None)
        loop.run_until_complete(self._runner.setup())
        self._site = web.TCPSite(self._runner, "127.0.0.1", self._port)
        loop.run_until_complete(self._site.start())
        print(f"[AEC-LINK] bridge server listening on http://127.0.0.1:{self._port}")
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(self._runner.cleanup())
            loop.close()

    def _build_app(self) -> web.Application:
        @web.middleware
        async def cors_middleware(request: web.Request, handler):
            allowed, allowed_origin = _allowed_origin(request, allow_private=self._allow_private)
            if not allowed:
                return web.Response(status=403)

            if request.method == "OPTIONS":
                resp = web.Response(status=204)
            else:
                resp = await handler(request)
            _apply_cors_headers(resp, allowed_origin)
            return resp

        app = web.Application(middlewares=[cors_middleware])

        async def ping(_request: web.Request) -> web.Response:
            return web.Response(text="ok")

        app.router.add_route("GET", "/arcenciel-link/ping", ping)
        app.router.add_route("GET", "/arcenciel-link/status", _device_status)
        app.router.add_route("OPTIONS", "/arcenciel-link/{tail:.*}", ping)
        app.router.add_route("POST", "/arcenciel-link/toggle_link", _toggle_link)
        app.router.add_route("GET", "/arcenciel-link/folders/{kind}", _folders)
        app.router.add_route("POST", "/arcenciel-link/generate_sidecars", _generate_sidecars)

        return app
