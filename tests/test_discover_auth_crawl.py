"""Authenticated crawl: with auth_crawl=True, discover() registers a throwaway account and carries its
session cookie INTO the browser render, so an SPA's real surface (behind login) is actually crawled instead
of the crawl only mapping the login page. Off by default (no behavior change for existing callers)."""
import http.server
import json
import threading

from hacklet_runner.discovery import discover


class _SpaBehindLogin(http.server.BaseHTTPRequestHandler):
    """GET -> a login form; the real registration is POST /api/auth/register (needs `name`, sets a cookie)."""
    def log_message(self, *a):
        pass

    def _s(self, code, body=b"", ct="text/html", ck=None):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        if ck:
            self.send_header("Set-Cookie", ck)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._s(200, b"<html><body><form><input type='email' name='email'>"
                     b"<input type='password' name='password'></form></body></html>")

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        if self.path == "/api/auth/register":
            if not json.loads(raw or b"{}").get("name"):
                self._s(500)
                return
            self._s(200, b'{"ok":1}', "application/json",
                    ck="borrow_session=sess-abc; Path=/; HttpOnly; SameSite=Lax")
            return
        self._s(200, b"shell")


def _serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpaBehindLogin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def _capture_render():
    seen = {}

    def render(_b, _paths, headers=None, **_kw):   # records the headers the crawl renders with
        seen.setdefault("headers", headers or {})
        return {}
    return render, seen


def test_auth_crawl_registers_and_carries_the_session_into_the_render():
    srv, base = _serve()
    render, seen = _capture_render()
    try:
        discover(base, render=render, auth_crawl=True)
        assert "Cookie" in seen.get("headers", {}), "the crawl was not authenticated"
        assert "borrow_session" in seen["headers"]["Cookie"]
    finally:
        srv.shutdown()


def test_auth_crawl_off_by_default_leaves_the_crawl_unauthenticated():
    srv, base = _serve()
    render, seen = _capture_render()
    try:
        discover(base, render=render)   # auth_crawl defaults False -> no register, no crawl cookie
        assert "Cookie" not in seen.get("headers", {})
    finally:
        srv.shutdown()
