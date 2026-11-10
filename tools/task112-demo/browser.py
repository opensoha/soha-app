"""Serve the existing App frontend and a separate Task112 simulator on loopback."""
from http.cookies import CookieError, SimpleCookie
from http.server import ThreadingHTTPServer
from mimetypes import guess_type
from pathlib import Path
from urllib.parse import unquote, urlsplit
import json
import secrets

import server as simulator

ROOT = Path(__file__).resolve().parent / "runtime" / "browser-dist"
HOST, PORT = "127.0.0.1", 18113
ORIGIN = f"http://{HOST}:{PORT}"
DEVICE = "task112-browser-device"
simulator.HOST, simulator.PORT, simulator.ORIGIN = HOST, PORT, ORIGIN
simulator.COOKIE = "soha_task112_browser_refresh"
simulator.COOKIE_ATTRIBUTES = "; Path=/; HttpOnly; SameSite=Strict"


class BrowserHandler(simulator.Handler):
    def serve(self):
        path = urlsplit(self.path).path
        if self.command == "GET" and not path.startswith(("/api/", "/app/", "/auth/browser-handoff/")):
            if self.headers.get("Host") != f"{HOST}:{PORT}":
                self.send_error(403)
                return
            file = (ROOT / unquote(path).lstrip("/")).resolve()
            if not file.is_relative_to(ROOT):
                self.send_error(404)
                return
            if not file.is_file() and "." not in file.name:
                file = ROOT / "index.html"
            if not file.is_file():
                self.send_error(404)
                return
            payload = file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", guess_type(file)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(payload)
            return
        super().serve()

    def dispatch(self):
        origin = self.headers.get("Origin", "")
        if self.headers.get("Host") != f"{HOST}:{PORT}" or (origin and origin != ORIGIN):
            return simulator.problem(403, "demo_origin_denied", "Use the Task112 local preview.")
        if self.command != "GET" and origin != ORIGIN:
            return simulator.problem(403, "demo_origin_required", "Use the same-origin Task112 preview.")
        path = urlsplit(self.path).path
        if self.command == "GET" and path == "/app/v1/state":
            return simulator.data({"serverUrl": ORIGIN, "configurationSource": "environment",
                                   "managedByEnvironment": True, "app": {
                                       "name": "Soha Task112 Browser Demo", "version": "0.2.0-task112.demo",
                                       "platform": "darwin", "arch": "arm64", "deviceId": DEVICE,
                                       "logDirectory": "", "updateSupported": False}})
        if self.command == "POST" and path == "/app/v1/connections/check":
            return simulator.data({"status": "online", "serverUrl": ORIGIN})
        if self.command == "POST" and path == "/app/v1/session/clear":
            return 200, {"data": {}}, {"Set-Cookie": f"{simulator.COOKIE}={simulator.COOKIE_ATTRIBUTES}; Max-Age=0"}
        if path.startswith(simulator.NATIVE + "/"):
            try:
                cookie = SimpleCookie(self.headers.get("Cookie", "")).get(simulator.COOKIE)
            except CookieError:
                cookie = None
            demo = self.server.demo
            with demo.lock:
                if not cookie or not demo.refresh or not secrets.compare_digest(cookie.value, demo.refresh):
                    return simulator.UNAUTHORIZED
                try:
                    body = self.read_json()
                except (ValueError, TimeoutError, RecursionError):
                    return simulator.INVALID
                return demo.native(self.command, path.removeprefix(simulator.NATIVE), body)
        return super().dispatch()

    def read_json(self):
        encoded = self.headers.get("X-Soha-App-Body")
        if encoded is None:
            return super().read_json()
        if len(encoded) > 65536 or self.headers.get("Content-Length", "0") != "0":
            raise ValueError("invalid App bridge body")
        value = json.loads(unquote(encoded))
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = serve


if __name__ == "__main__":
    if not (ROOT / "index.html").is_file():
        raise SystemExit("Build the Task112 browser frontend first.")
    with ThreadingHTTPServer((HOST, PORT), BrowserHandler) as http:
        http.demo = simulator.Demo(secrets.token_urlsafe(32))
        http.demo.device_id = DEVICE
        print(f"Task112 browser preview listening on {ORIGIN}", flush=True)
        http.serve_forever()
