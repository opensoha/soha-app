#!/usr/bin/env python3
"""Loopback-only Task112 desktop demo. All service and network observations are fixtures."""

from datetime import datetime, timezone
from html import escape
import hmac
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
from threading import Lock
from time import monotonic
from urllib.parse import parse_qs, urlsplit


HOST, PORT = "127.0.0.1", 18112
ORIGIN = f"http://{HOST}:{PORT}"
LOGIN, PASSWORD = "demo", "task112-demo-only"
COOKIE = "soha_refresh_token"
COOKIE_ATTRIBUTES = "; Path=/api/v1/auth; HttpOnly; SameSite=Lax"
NATIVE = "/app/v1/network"
API = "/api/v1"
HANDOFF = "/auth/browser-handoff/"
GROUP = "demo-egress"
NODES = {"demo-node-a": "Demo Edge A", "demo-node-b": "Demo Edge B"}
VPN_PROFILE = "demo-office-vpn"
VPN_ENTRANCES = {
    "demo-vpn-hong-kong": ("香港 / Hong Kong", 24),
    "demo-vpn-singapore": ("新加坡 / Singapore", 57),
    "demo-vpn-tokyo": ("东京 / Tokyo", 89),
}
VPN_API = "/network-access/vpn/"
PRINCIPAL = {
    "userId": "task112-demo-user", "userName": LOGIN, "email": "demo@example.invalid",
    "displayName": "Soha Demo", "permissionKeys": ["identity.portal.view"],
}
NETWORK_OPTIONS = [
    {"siteId": "demo-site", "siteName": "演示办公区 / Demo Office", "accessMedium": medium,
     "authentication": "radius_802_1x", "accessProfile": "full", "policyVersion": 1,
     **({"ssid": "Soha Demo Wi-Fi"} if medium == "wifi" else {})}
    for medium in ("wifi", "wired")
]
APPLICATIONS = {
    "sql-platform": ("SQL 平台", "数据工具", "oidc", "查询数据库、管理变更与审批。"),
    "pangu-system": ("盘古系统", "内部系统", "saml", "管理业务流程与日常运营。"),
    "mall-admin": ("商城管理后台", "电商运营", "proxy", "管理商品、订单、库存和售后。"),
}
APP_ICON_PATHS = {
    f"/demo-icons/{app_id}.svg": Path(__file__).resolve().parent / "icons" / f"{app_id}.svg"
    for app_id in APPLICATIONS
}


def timestamp(value=None):
    date = datetime.now(timezone.utc) if value is None else datetime.fromtimestamp(value, timezone.utc)
    return date.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def problem(status, code, message):
    return status, {"error": {"code": code, "message": message}}, {}


def data(payload):
    return 200, {"data": payload}, {}


def readback(connected, nas):
    return {"localReadback": "associated" if connected else "idle", "nasSession": "observed" if nas else "pending",
            **({"nasSessionId": nas} if nas else {})}


NOT_FOUND = problem(404, "demo_route_unavailable", "This route is unavailable in the Task112 demo.")
UNAUTHORIZED = problem(401, "unauthorized", "Sign in with the Task112 demo account.")
INVALID = problem(400, "invalid_demo_input", "This input is invalid for the Task112 demo.")
NO_CONTENT = (204, None, {})


class Demo:
    def __init__(self, key):
        self.key = key.encode()
        self.lock = Lock()
        self.access = self.refresh = ""
        self.favorites = set()
        self.handoffs = {}
        self.created = timestamp()
        self.device_id = "task112-demo-device"
        self.profiles = {
            f"demo-{option['accessMedium']}": {
                "id": f"demo-{option['accessMedium']}", "siteId": option["siteId"],
                "accessMedium": option["accessMedium"], "adapterId": f"adapter-{option['accessMedium']}",
                "state": "installed", "supported": True,
                **({"ssid": option["ssid"], "eapMethod": "tls"} if "ssid" in option else
                   {"eapMethod": "ttls", "innerMethod": "pap", "credentialInteraction": "system-prompt"}),
            } for option in NETWORK_OPTIONS
        }
        self.linked = ""
        self.nas = ""
        self.linked_at = 0.0
        self.registered = False
        self.started = None
        self.started_at = ""
        self.epoch = ""
        self.upload = self.download = 0
        self.selected = next(iter(NODES))
        self.vpn_intent = None
        self.vpn_connection = None

    def issue_session(self):
        self.access, self.refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        return (200, {"data": {"user": PRINCIPAL, "tokens": {"accessToken": self.access}}},
                {"Set-Cookie": f"{COOKIE}={self.refresh}{COOKIE_ATTRIBUTES}"})

    def application(self, app_id):
        name, category, provider, description = APPLICATIONS[app_id]
        return {"id": app_id, "slug": app_id, "name": name, "category": category, "providerType": provider,
                "iconUrl": f"{API}/demo-icons/{app_id}.svg",
                "description": description, "status": "active", "launchAllowed": True, "portalVisible": True,
                "createdAt": self.created, "updatedAt": self.created, "favorite": app_id in self.favorites,
                "tags": [provider.upper(), "Demo"], "metadata": {"demo": True}}

    def core(self, method, path, headers, body, query):
        route = (method, path)
        if method == "GET" and path in APP_ICON_PATHS:
            return 200, APP_ICON_PATHS[path].read_text(encoding="utf-8"), {"Content-Type": "image/svg+xml"}
        if route == ("GET", "/healthz"):
            return 200, {"status": "ok"}, {}
        if route == ("GET", "/readyz"):
            return 200, {"status": "ready"}, {}
        if route == ("GET", "/auth/login-options"):
            return data({"verification": {"sliderEnabled": False}, "localPasswordLoginEnabled": True})
        if route == ("GET", "/auth/providers"):
            return 200, {"items": []}, {}
        if route == ("POST", "/auth/login"):
            if body.get("login") != LOGIN or body.get("password") != PASSWORD:
                return UNAUTHORIZED
            self.handoffs.clear()
            self.vpn_intent = None
            return self.issue_session()
        if method == "POST" and path in ("/auth/refresh", "/auth/logout"):
            cookie = SimpleCookie()
            try:
                cookie.load(headers.get("Cookie", ""))
            except CookieError:
                return UNAUTHORIZED
            refresh = cookie.get(COOKIE)
            if path == "/auth/refresh":
                if not self.refresh or not refresh or refresh.value != self.refresh:
                    return UNAUTHORIZED
                return self.issue_session()
            if self.refresh and refresh and refresh.value == self.refresh:
                self.access = self.refresh = ""
                self.handoffs.clear()
                self.vpn_intent = None
            return 204, None, {"Set-Cookie": f"{COOKIE}={COOKIE_ATTRIBUTES}; Max-Age=0"}
        device = re.fullmatch(r"/network-access/devices/([A-Za-z0-9_-]+)/registration", path)
        portal = re.fullmatch(r"/portal/applications/([a-z-]+)(?:/(launch|favorite))?", path)
        core_reads = ("/auth/bootstrap", "/announcements/inbox", "/network-access/connection-options", "/portal/bootstrap")
        if not ((method == "GET" and path in core_reads) or (method == "PUT" and device) or portal or path.startswith(VPN_API)):
            return NOT_FOUND
        if not self.access or headers.get("Authorization") != f"Bearer {self.access}":
            return UNAUTHORIZED
        if path.startswith(VPN_API):
            return self.vpn_core(method, path.removeprefix(VPN_API), body, query)
        if route == ("GET", "/auth/bootstrap"):
            return data({"user": PRINCIPAL, "currentUser": PRINCIPAL, "branding": {},
                         "permissionSnapshot": {"permissionKeys": PRINCIPAL["permissionKeys"]}})
        if route == ("GET", "/announcements/inbox"):
            return data({"items": [], "unreadCount": 0})
        if route == ("GET", "/network-access/connection-options"):
            return 200, {"items": NETWORK_OPTIONS}, {}
        if method == "PUT" and device:
            if self.device_id != device[1]:
                self.vpn_intent = self.vpn_connection = None
                self.device_id = device[1]
            self.registered = True
            return data({"id": self.device_id, "name": body.get("name", "Task112 demo"),
                         "platform": body.get("platform", "darwin")})
        if route == ("GET", "/portal/bootstrap"):
            apps = [self.application(app_id) for app_id in APPLICATIONS]
            return data({"principal": PRINCIPAL, "applications": apps, "recent": [],
                         "favorites": [app for app in apps if app["favorite"]],
                         "categories": [app["category"] for app in apps],
                         "security": {"principal": PRINCIPAL, "mfaEnabled": False,
                                      "linkedSources": [], "activeSession": 1}})
        app_id, action = portal.groups()
        if app_id not in APPLICATIONS:
            return NOT_FOUND
        if method == "GET" and action is None:
            return data(self.application(app_id))
        if action == "favorite":
            if method == "POST":
                self.favorites.add(app_id)
                return data(self.application(app_id))
            if method == "DELETE":
                self.favorites.discard(app_id)
                return NO_CONTENT
        if method == "POST" and action == "launch":
            if body != {"surface": "desktop"}:
                return INVALID
            now = monotonic()
            self.handoffs = {token: grant for token, grant in self.handoffs.items() if grant[1] > now}
            nonce = secrets.token_urlsafe(24)
            self.handoffs[nonce] = (app_id, now + 120)
            app = self.application(app_id)
            expires_at = timestamp(datetime.now(timezone.utc).timestamp() + 120)
            return data({"application": app, "providerType": app["providerType"], "decision": "allow",
                         "launchUrl": HANDOFF + nonce, "handoffExpiresAt": expires_at})
        return NOT_FOUND

    def handoff(self, nonce):
        app_id, expiry = self.handoffs.pop(nonce, (None, 0))
        if monotonic() >= expiry:
            return problem(410, "demo_handoff_expired", "This demo handoff has expired or was already opened.")
        app = self.application(app_id)
        name = escape(app["name"])
        protocol = app["providerType"].upper()
        page = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} · Soha Task112 Demo</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
body {{ display: grid; min-height: 100vh; margin: 0; place-items: center; }}
main {{ max-width: 36rem; margin: 1.5rem; padding: 2.25rem; border: 1px solid gray; border-radius: 1rem; }}
.eyebrow {{ font-size: .875rem; font-weight: 700; }}
</style><main><p class="eyebrow">Soha Task112 · 本地模拟 / Local simulation</p>
<h1>{name}</h1><p>{protocol} 单点登录演示 / Simulated {protocol} handoff</p>
<p>一次性启动票据已使用。此页面在本机生成。<br>The one-time launch ticket was redeemed on this device.</p></main></html>"""
        return 200, page, {"Content-Type": "text/html; charset=utf-8",
                           "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"}

    def admission(self):
        adapters = [{"id": f"adapter-{medium}", "name": f"Demo {'Wi-Fi' if medium == 'wifi' else 'Ethernet'}",
                     "medium": medium, "macAddress": f"02:00:00:00:01:{index:02x}", "enabled": True,
                     "linkUp": self.linked == f"demo-{medium}"}
                    for index, medium in enumerate(("wifi", "wired"), 1)]
        return {"supported": True, "profiles": [profile.copy() for profile in self.profiles.values()],
                "adapters": adapters, "demo": readback(self.linked, self.nas)}

    def observe_nas(self):
        if self.linked and not self.nas:
            self.nas = "demo-nas-" + secrets.token_hex(4)

    def admission_action(self, method, action, body):
        if method == "POST" and action == "/check" and not body:
            self.observe_nas()
        elif (method, action) in (("POST", "/prepare"), ("POST", "/connect"), ("DELETE", "")):
            profile_id = body.get("profileId")
            profile = self.profiles.get(profile_id) if isinstance(profile_id, str) else None
            if not profile or body.keys() - ({"profileId", "adapterId"} if action == "/prepare" else {"profileId"}):
                return INVALID
            adapter = f"adapter-{profile['accessMedium']}"
            if action == "/prepare":
                if body.get("adapterId") != adapter:
                    return INVALID
                profile.update(adapterId=adapter, state="installed")
            elif action == "/connect":
                if profile["state"] != "installed":
                    return problem(409, "demo_profile_unprepared", "Prepare this demo profile before connecting.")
                if self.linked != profile_id:
                    self.linked, self.linked_at, self.nas = profile_id, monotonic(), ""
            else:
                profile.pop("adapterId", None)
                profile["state"] = "available"
                if self.linked == profile_id:
                    self.linked = self.nas = ""
        else:
            return NOT_FOUND
        return 200, self.admission(), {}

    def link(self):
        payload = {"connected": bool(self.linked), "dnsServers": [], "demo": readback(self.linked, self.nas)}
        if self.linked:
            medium = self.profiles[self.linked]["accessMedium"]
            payload.update(medium=medium, interfaceName=f"adapter-{medium}",
                           ipAddress="192.0.2.12" if medium == "wifi" else "192.0.2.22",
                           gateway="192.0.2.1", dnsServers=["192.0.2.53"])
        return payload

    def vpn_core(self, method, path, body, query):
        if method == "GET":
            if parse_qs(query).get("deviceId") != [self.device_id]:
                return INVALID
            if path == "current-connection":
                return data(self.vpn_connection)
            if path == "connection-options":
                candidates = [{"gatewayId": key, "name": name, "region": name, "providerCode": "demo",
                               "providerName": "Demo", "available": True, "reasonCode": "", "priority": index}
                              for index, (key, (name, _)) in enumerate(VPN_ENTRANCES.items(), 1)]
                return 200, {"items": [{"profileId": VPN_PROFILE, "profileRevision": 1,
                    "name": "演示办公内网 / Demo Office VPN", "siteId": "demo-site",
                    "networkSpaceId": "demo-vpn-space", "mode": "external_vpn",
                    "allowManualSelection": True, "selectionPolicyId": "demo-vpn-policy",
                    "selectionPolicyRevision": 1, "selectionStrategy": "latency",
                    "available": True, "reasonCode": "", "candidates": candidates}]}, {}
        if method != "POST" or path != "connection-intents":
            return NOT_FOUND
        if body.get("deviceId") != self.device_id or body.get("profileId") != VPN_PROFILE:
            return INVALID
        selection, gateway = body.get("selection"), body.get("gatewayId")
        if selection == "auto" and "gatewayId" not in body:
            gateway = min(VPN_ENTRANCES, key=lambda key: VPN_ENTRANCES[key][1])
        elif selection != "manual" or not isinstance(gateway, str) or gateway not in VPN_ENTRANCES:
            return INVALID
        intent_id, token = secrets.token_urlsafe(16), secrets.token_urlsafe(32)
        self.vpn_intent = (intent_id, token, selection, gateway, monotonic() + 120)
        return data({"intentId": intent_id, "token": token,
                     "expiresAt": timestamp(datetime.now(timezone.utc).timestamp() + 120)})

    def vpn_connect(self, body):
        intent = self.vpn_intent
        token = body.get("intentToken")
        if (not intent or intent[0] != body.get("intentId") or not isinstance(token, str)
                or not token.isascii() or not hmac.compare_digest(intent[1], token) or monotonic() >= intent[4]):
            return problem(409, "demo_vpn_intent_invalid", "Request a new demo VPN connection.")
        self.vpn_intent = None
        _, _, selection, gateway, _ = intent
        self.vpn_connection = {
            "state": "connected", "sessionId": secrets.token_urlsafe(16), "profileId": VPN_PROFILE,
            "profileRevision": 1, "gatewayId": gateway, "gatewayName": VPN_ENTRANCES[gateway][0],
            "siteId": "demo-site", "networkSpaceId": "demo-vpn-space", "mode": "external_vpn",
            "selection": selection, "connectedAt": timestamp(), "tunnelIP": "192.0.2.42",
            "measuredAt": timestamp(),
        }
        return 200, self.network_status(), {}

    def network_status(self):
        payload = {"state": "disconnected", "runtimeId": "task112-demo-runtime", "deviceId": self.device_id,
                   "configurationVersion": 1, "policyVersion": 1, "uptimeSeconds": 0,
                   "presenceState": "healthy" if self.registered else "unavailable",
                   "probeMeasuredAt": timestamp(),
                   "probeResults": [{"gatewayId": key, "sentCount": 3, "rttSamplesMs": [rtt - 1, rtt, rtt + 1]}
                                    for key, (_, rtt) in VPN_ENTRANCES.items()],
                   "demo": readback(self.linked, self.nas)}
        if self.vpn_connection:
            payload.update(self.vpn_connection)
        if self.registered:
            payload.update(presenceLastReceivedAt=timestamp(), presenceEpoch=1)
        return payload

    def proxy_status(self):
        running = self.started is not None
        if running:
            elapsed = monotonic() - self.started
            self.upload = int(elapsed * 4096)
            self.download = int(elapsed * 24576)
        observed = timestamp()
        state = "running" if running else "stopped"
        return {
            "engine": "mihomo", "mode": "app_subscription", "deliveryMode": "mapped_nodes", "state": state,
            "profileId": "demo-mihomo", "bundleId": "demo-bundle", "revision": 1, "orgRevision": 1,
            "personalRevision": 0,
            "process": {"ownership": "soha_owned", "state": state, "processEpoch": self.epoch,
                        "desiredRunning": running, **({"startedAt": self.started_at} if running else {})},
            "capabilities": [{"name": "process_control", "state": "available"},
                             {"name": "select", "state": "available" if running else "unavailable"}],
            "nodes": [{"nodeId": node_id, "label": label} for node_id, label in NODES.items()],
            "groups": [{"groupId": GROUP, "label": "演示出口 / Demo egress", "type": "select",
                        "nodeIds": list(NODES), "selectedNodeId": self.selected}],
            "rules": {"orgRevision": 1, "personalRevision": 0, "rules": [], "effectiveRules": [], "conflicts": []},
            "maskedRules": [],
            "traffic": {"processEpoch": self.epoch, "observedAt": observed, "uploadTotal": self.upload,
                        "downloadTotal": self.download, "uploadBytesPerSecond": 4096 if running else None,
                        "downloadBytesPerSecond": 24576 if running else None,
                        "state": "fresh" if running else "unavailable"},
            "connections": {"processEpoch": self.epoch, "observedAt": observed, "totalActive": 0,
                            "returnedCount": 0, "truncated": False, "items": []},
            "logs": [], "dns": [],
            "diagnostics": [{"code": "demo_simulation", "state": "simulated",
                             "message": "本地模拟进程和流量 / Simulated process and traffic"}],
        }

    def proxy_action(self, body):
        kind = body.get("kind")
        if kind == "select":
            node_id = body.get("nodeId")
            if (body.keys() != {"kind", "groupId", "nodeId"} or body["groupId"] != GROUP
                    or not isinstance(node_id, str) or node_id not in NODES):
                return INVALID
            if self.started is None:
                return problem(409, "demo_proxy_stopped", "Start the simulated proxy before changing its node.")
            self.selected = node_id
        elif kind in ("start", "stop", "restart", "refresh_status") and body.keys() == {"kind"}:
            if kind == "restart" or (kind == "start" and self.started is None):
                self.started, self.started_at = monotonic(), timestamp()
                self.epoch = "demo-process-" + secrets.token_hex(4)
            if kind == "stop" and self.started is not None:
                self.proxy_status()
                self.started = None
        else:
            return INVALID
        return 200, self.proxy_status(), {}

    def native(self, method, path, body):
        if self.linked and monotonic() - self.linked_at >= 2:
            self.observe_nas()
        if method == "GET":
            if path == "/admission":
                return 200, self.admission(), {}
            if path == "/link":
                return 200, self.link(), {}
            if path == "/status":
                return 200, self.network_status(), {}
            if path == "/proxy":
                return 200, self.proxy_status(), {}
            if path == "/proxy/interception":
                return 200, {"generation": 0, "desiredSystemProxy": False, "desiredTUN": False,
                             "systemProxy": False, "tun": False, "state": "inactive", "cleanupPending": False,
                             "observedAt": timestamp(), "capabilities": {"systemProxy": False, "tun": False},
                             "impact": {"ipv4": False, "ipv6": False, "dns": False}}, {}
        if path == "/admission" or path.startswith("/admission/"):
            return self.admission_action(method, path.removeprefix("/admission"), body)
        if method == "POST" and path == "/proxy/actions":
            return self.proxy_action(body)
        if method == "POST" and path == "/connect":
            return self.vpn_connect(body)
        if method == "POST" and path == "/disconnect":
            self.vpn_intent = self.vpn_connection = None
            return 200, self.network_status(), {}
        return NOT_FOUND


class Handler(BaseHTTPRequestHandler):
    timeout = 5

    def log_message(self, *_):
        pass

    def serve(self):
        status, body, headers = self.dispatch()
        if isinstance(body, str):
            payload = body.encode()
        elif body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode()
            headers = {"Content-Type": "application/json; charset=utf-8", **headers}
        else:
            payload = b""
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def dispatch(self):
        if self.headers.get("Host") != f"{HOST}:{PORT}" or self.headers.get("Origin", ORIGIN) != ORIGIN:
            return problem(403, "demo_origin_denied", "Task112 demo is available only on its fixed loopback origin.")
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            return INVALID
        if parsed.netloc or parsed.scheme or parsed.fragment:
            return INVALID
        path = parsed.path
        demo = self.server.demo
        native = path.startswith(NATIVE + "/")
        if native and not hmac.compare_digest(self.headers.get("X-Soha-Demo-Key", "").encode(), demo.key):
            return problem(403, "demo_key_required", "The Task112 App demo key is required.")
        try:
            body = self.read_json()
        except (ValueError, TimeoutError, RecursionError):
            return INVALID
        with demo.lock:
            if native:
                return demo.native(self.command, path.removeprefix(NATIVE), body)
            if path.startswith(API + "/"):
                return demo.core(self.command, path.removeprefix(API), self.headers, body, parsed.query)
            if self.command == "GET" and path.startswith(HANDOFF) and not parsed.query:
                return demo.handoff(path.removeprefix(HANDOFF))
        return NOT_FOUND

    def read_json(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("unsupported body transfer")
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        if not 0 < length <= 65536 or self.headers.get_content_type() != "application/json":
            raise ValueError("unsupported JSON body")
        body = json.loads(self.rfile.read(length))
        if not isinstance(body, dict):
            raise ValueError("object required")
        return body

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = serve


def main():
    key = os.environ.get("SOHA_TASK112_DEMO_KEY", "")
    if len(key) < 24:
        raise SystemExit("Set SOHA_TASK112_DEMO_KEY to a demo-only key of at least 24 characters.")
    with ThreadingHTTPServer((HOST, PORT), Handler) as server:
        server.demo = Demo(key)
        print(f"Task112 simulator listening on {ORIGIN}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
