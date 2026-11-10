#!/usr/bin/env python3
"""Start, check and stop a disposable Task112 simulator on its fixed port."""

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from time import sleep

from server import API, COOKIE, GROUP, HOST, LOGIN, NATIVE, PASSWORD, PORT


def run(key):
    def request(path, expected=200, *, method="GET", body=None, headers=None, native=False):
        headers = dict(headers or {})
        if native:
            path = NATIVE + path
            headers.setdefault("X-Soha-Demo-Key", key)
        if body is not None:
            body = json.dumps(body)
            headers["Content-Type"] = "application/json"
        conn = HTTPConnection(HOST, PORT, timeout=5)
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            raw = response.read()
            assert response.status == expected, (method, path, response.status, expected, raw)
            assert response.getheader("Access-Control-Allow-Origin") is None
            if response.getheader("Content-Type", "").startswith("application/json"):
                return json.loads(raw), response.headers
            return raw, response.headers
        finally:
            conn.close()

    def post(path, body=None, headers=None, expected=200, native=False):
        return request(path, expected, method="POST", body=body, headers=headers, native=native)

    assert request(API + "/healthz")[0]["status"] == "ok"
    assert request(API + "/readyz")[0]["status"] == "ready"
    assert request(API + "/auth/login-options")[0]["data"]["localPasswordLoginEnabled"]
    assert request(API + "/auth/providers")[0]["items"] == []
    post(API + "/auth/refresh", expected=401)
    post(API + "/auth/login", {"login": LOGIN, "password": "wrong"}, expected=401)
    session, headers = post(API + "/auth/login", {"login": LOGIN, "password": PASSWORD})
    cookie = headers["Set-Cookie"]
    assert "Path=/api/v1/auth" in cookie and "HttpOnly" in cookie
    cookie = cookie.split(";", 1)[0]
    assert cookie.startswith(COOKIE + "=")
    rotated, headers = post(API + "/auth/refresh", headers={"Cookie": cookie})
    current_cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert current_cookie != cookie and rotated["data"]["user"] == session["data"]["user"]
    post(API + "/auth/refresh", headers={"Cookie": cookie}, expected=401)
    authorization = {"Authorization": "Bearer " + rotated["data"]["tokens"]["accessToken"]}
    assert request(API + "/auth/bootstrap", headers=authorization)[0]["data"]["permissionSnapshot"]["permissionKeys"] == ["identity.portal.view"]
    assert request(API + "/announcements/inbox?limit=5", headers=authorization)[0]["data"] == {"items": [], "unreadCount": 0}
    request(API + "/network-access/devices/smoke-device/registration", 200, method="PUT", body={}, headers=authorization)
    assert request("/status", native=True)[0]["deviceId"] == "smoke-device"
    options = request(API + "/network-access/connection-options?deviceId=smoke-device", headers=authorization)[0]["items"]
    assert {option["accessMedium"] for option in options} == {"wifi", "wired"}

    portal = request(API + "/portal/bootstrap", headers=authorization)[0]["data"]
    assert {app["providerType"] for app in portal["applications"]} == {"oidc", "saml", "proxy"}
    for app in portal["applications"]:
        path = API + "/portal/applications/" + app["id"]
        assert request(path, headers=authorization)[0]["data"] == app
        assert post(path + "/favorite", headers=authorization)[0]["data"]["favorite"]
        assert request(API + "/portal/bootstrap", headers=authorization)[0]["data"]["favorites"][0]["id"] == app["id"]
        request(path + "/favorite", 204, method="DELETE", headers=authorization)
        handoff = post(path + "/launch", {"surface": "desktop"}, authorization)[0]["data"]["launchUrl"]
        assert handoff.startswith("/auth/browser-handoff/")
        page, headers = request(handoff)
        assert b"Local simulation" in page and app["providerType"].upper().encode() in page
        assert headers["Cache-Control"] == "no-store"
        request(handoff, 410)
    post(API + "/auth/logout", headers={"Cookie": current_cookie}, expected=204)
    request(API + "/portal/bootstrap", 401, headers=authorization)

    request(NATIVE + "/admission", 403)
    request("/admission", 403, headers={"X-Soha-Demo-Key": "wrong"}, native=True)
    request("/admission", 403, headers={"Origin": "https://example.invalid"}, native=True)
    request("/admission", 403, headers={"Host": "example.invalid"}, native=True)
    request("/proxy/interception", 404, method="POST", native=True)
    assert request("/link", native=True)[0]["dnsServers"] == []
    assert request("/status", native=True)[0]["presenceState"] == "healthy"
    profiles = request("/admission", native=True)[0]["profiles"]
    assert profiles[0]["eapMethod"] == "tls" and profiles[1]["innerMethod"] == "pap"
    assert profiles[1]["credentialInteraction"] == "system-prompt"
    for profile in profiles:
        choice = {"profileId": profile["id"]}
        post("/admission/prepare", {**choice, "adapterId": profile["adapterId"]}, native=True)
        post("/admission/connect", {**choice, "password": "unexpected"}, expected=400, native=True)
        pending = post("/admission/connect", choice, native=True)[0]["demo"]
        assert pending == {"localReadback": "associated", "nasSession": "pending"}
        observed = post("/admission/check", {}, native=True)[0]["demo"]
        assert observed["nasSession"] == "observed" and observed["nasSessionId"].startswith("demo-nas-")
        link = request("/link", native=True)[0]
        assert link["connected"] and link["medium"] == profile["accessMedium"] and link["dnsServers"]
        assert link["demo"] == observed

    select_node = {"kind": "select", "groupId": GROUP, "nodeId": "demo-node-b"}
    post("/proxy/actions", select_node, expected=409, native=True)
    started = post("/proxy/actions", {"kind": "start"}, native=True)[0]
    assert started["process"]["state"] == "running" and started["traffic"]["state"] == "fresh"
    post("/proxy/actions", select_node, native=True)
    sleep(0.02)
    running = request("/proxy", native=True)[0]
    assert running["groups"][0]["selectedNodeId"] == "demo-node-b"
    assert running["traffic"]["uploadTotal"] > started["traffic"]["uploadTotal"]
    assert running["traffic"]["downloadBytesPerSecond"] > 0
    stopped = post("/proxy/actions", {"kind": "stop"}, native=True)[0]
    assert stopped["process"]["state"] == "stopped" and stopped["traffic"]["uploadBytesPerSecond"] is None


def main():
    key = secrets.token_hex(24)
    with subprocess.Popen([sys.executable, "-B", str(Path(__file__).with_name("server.py"))],
                          env={**os.environ, "SOHA_TASK112_DEMO_KEY": key},
                          stdout=subprocess.PIPE, text=True) as process:
        try:
            assert process.stdout.readline().strip() == f"Task112 simulator listening on http://{HOST}:{PORT}"
            run(key)
        finally:
            if process.poll() is None:
                process.terminate()
    print("Task112 simulator smoke passed")


if __name__ == "__main__":
    main()
