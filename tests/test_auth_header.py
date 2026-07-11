"""--header auth injection: a supplied header (Cookie / Authorization) reaches the target so the
runner crawls and probes the authenticated surface behind a session/SSO wall, not just the login page.
"""
import http.server
import re
import threading

from hacklet_runner.discovery import discover


class _Gated(http.server.BaseHTTPRequestHandler):
    """Serves the authed surface only when the right bearer token is present; otherwise a 401 wall."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer test-token":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'<a href="/vip">vip</a>' if self.path == "/" else b"vip area"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Gated)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_auth_header_unlocks_authenticated_surface():
    srv = _serve()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        anon = discover(url)                                              # no header -> only the 401 wall
        authed = discover(url, headers={"Authorization": "Bearer test-token"})
        assert "/vip" not in anon.routes
        assert "/vip" in authed.routes  # the header reached the target and unlocked the authed crawl
    finally:
        srv.shutdown()


class _Rotating(http.server.BaseHTTPRequestHandler):
    """Rotates the session cookie on EVERY request (only the current value is authed) — the DVWA/PHP
    pattern. /step is reachable only if a SECOND request stayed authed (i.e. the crawl followed the
    rotation), and /vault is only linked from an authed /step."""
    state = {"cur": "s0", "n": 0}

    def log_message(self, *a):
        pass

    def do_GET(self):
        m = re.search(r"session=([^;]+)", self.headers.get("Cookie", ""))
        if (m.group(1) if m else None) != _Rotating.state["cur"]:
            self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers(); return
        _Rotating.state["n"] += 1
        newv = "s%d" % _Rotating.state["n"]
        _Rotating.state["cur"] = newv
        body = {"/": b'<a href="/step">s</a>', "/step": b'<a href="/vault">v</a>'}.get(self.path, b"ok")
        self.send_response(200)
        self.send_header("Set-Cookie", "session=%s; Path=/" % newv)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_cookie_header_seeds_jar_and_follows_session_rotation():
    _Rotating.state.update(cur="s0", n=0)
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Rotating)  # single-threaded: rotation is sequential
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        # /vault is only linked from /step, and /step is authed only if the jar absorbed the rotated
        # Set-Cookie from '/'. A static Cookie header would 401 on /step and never discover /vault.
        prof = discover(url, headers={"Cookie": "session=s0"})
        assert "/vault" in prof.routes
    finally:
        srv.shutdown()
