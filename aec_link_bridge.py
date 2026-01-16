import asyncio
import ipaddress
import threading
import time
from aiohttp import web

from aec_link_origins import normalize_origin, is_private_host
from aec_link_worker import apply_worker_state, generate_sidecars_for_existing, RUNNING
from aec_link_utils import list_subfolders


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
            origin = request.headers.get("Origin")
            allowed_origin = None
            if origin:
                allowed_origin = normalize_origin(origin, allow_private=self._allow_private)
                if not allowed_origin:
                    return web.Response(status=403)
            else:
                client_host = _client_ip(request)
                if client_host:
                    if _is_loopback_host(client_host):
                        allowed_origin = None
                    elif self._allow_private and is_private_host(client_host):
                        allowed_origin = None
                    else:
                        return web.Response(status=403)
                else:
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

        async def toggle_link(request: web.Request) -> web.Response:
            try:
                payload = await request.json()
            except Exception:
                payload = None

            if not isinstance(payload, dict):
                return web.json_response({"error": "payload required"}, status=400)

            if "enable" not in payload:
                return web.json_response({"error": "enable flag required"}, status=400)

            link_key = payload.get("linkKey")
            api_key = payload.get("apiKey")
            enable = not (payload.get("enable") in (False, "false", 0))

            try:
                apply_worker_state(enable, link_key=link_key, api_key=api_key)
            except ValueError as exc:
                return web.json_response({"error": str(exc)}, status=400)
            except Exception:
                return web.json_response({"error": "Failed to toggle worker"}, status=500)

            if enable:
                t0 = time.perf_counter()
                while not RUNNING.is_set() and time.perf_counter() - t0 < 3:
                    time.sleep(0.05)

            return web.json_response({"ok": True, "workerOnline": RUNNING.is_set()})

        async def folders(request: web.Request) -> web.Response:
            kind = request.match_info.get("kind") or ""
            try:
                folders = list_subfolders(kind)
                return web.json_response({"folders": folders})
            except Exception as exc:
                return web.json_response({"error": str(exc)}, status=400)

        async def generate_sidecars(_request: web.Request) -> web.Response:
            threading.Thread(target=generate_sidecars_for_existing, daemon=True).start()
            return web.json_response({"ok": True})

        app.router.add_route("GET", "/arcenciel-link/ping", ping)
        app.router.add_route("OPTIONS", "/arcenciel-link/{tail:.*}", ping)
        app.router.add_route("POST", "/arcenciel-link/toggle_link", toggle_link)
        app.router.add_route("GET", "/arcenciel-link/folders/{kind}", folders)
        app.router.add_route("POST", "/arcenciel-link/generate_sidecars", generate_sidecars)

        return app
