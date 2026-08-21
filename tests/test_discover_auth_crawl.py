"""Authenticated crawl: with auth_crawl=True, discover() registers a throwaway account and carries its
session cookie INTO the browser render, so an SPA's real surface (behind login) is actually crawled instead
of the crawl only mapping the login page. Off by default (no behavior change for existing callers)."""
import http.server
import json
import threading

from sloptic.discovery import discover


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


# --- route-mining: recover a code-split /login the crawl never linked to (v21 investigation) ---------------

def _mock_client_serving(text):
    import httpx
    from sloptic import discovery

    def fake_make_client(base_url, headers=None, **k):
        return httpx.Client(base_url=base_url, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=text)))
    return fake_make_client


def test_mine_auth_routes_finds_a_code_split_login(monkeypatch):
    from sloptic import discovery
    monkeypatch.setattr(discovery, "make_client",
                        _mock_client_serving('nav("/dashboard");route({path:"/login"});go("/register")'))
    login, signup = discovery._mine_auth_routes("http://app.test", None, ["/_next/static/chunks/app-abc.js"])
    assert login and signup


def test_mine_auth_routes_next_app_router_chunk_paths(monkeypatch):
    from sloptic import discovery
    monkeypatch.setattr(discovery, "make_client",
                        _mock_client_serving('"/_next/static/chunks/app/login/page-1.js","/app/signup/page-2.js"'))
    assert discovery._mine_auth_routes("http://app.test", None, ["/a.js"]) == (True, True)


def test_mine_auth_routes_no_false_positive_on_non_auth_routes(monkeypatch):
    from sloptic import discovery
    monkeypatch.setattr(discovery, "make_client",
                        _mock_client_serving('go("/about");route("/pricing");x("/loginsreport")'))
    assert discovery._mine_auth_routes("http://app.test", None, ["/a.js"]) == (False, False)


def test_mine_auth_routes_empty_without_js_chunks():
    from sloptic import discovery
    assert discovery._mine_auth_routes("http://app.test", None, []) == (False, False)
    assert discovery._mine_auth_routes("http://app.test", None, ["/style.css"]) == (False, False)
