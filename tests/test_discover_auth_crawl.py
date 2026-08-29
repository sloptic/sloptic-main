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
    login, signup, login_path, signup_path = discovery._mine_auth_routes(
        "http://app.test", None, ["/_next/static/chunks/app-abc.js"])
    assert login and signup
    assert login_path == "/login" and signup_path == "/register"   # Part 2: the actual route strings, captured


def test_mine_auth_routes_next_app_router_chunk_paths(monkeypatch):
    from sloptic import discovery
    monkeypatch.setattr(discovery, "make_client",
                        _mock_client_serving('"/_next/static/chunks/app/login/page-1.js","/app/signup/page-2.js"'))
    login, signup, _lp, _sp = discovery._mine_auth_routes("http://app.test", None, ["/a.js"])
    assert login and signup


def test_mine_auth_routes_captures_a_non_standard_login_path(monkeypatch):
    from sloptic import discovery
    # a conventional auth SEGMENT under a non-conventional PREFIX -- the conventional-route render walks only
    # top-level /login etc., so /portal/login is exactly what Part 2 recovers.
    monkeypatch.setattr(discovery, "make_client",
                        _mock_client_serving('router.push("/portal/login?next=/app")'))
    login, _s, login_path, _sp = discovery._mine_auth_routes("http://app.test", None, ["/a.js"])
    assert login and login_path == "/portal/login"                 # full non-standard path, query stripped


def test_mine_auth_routes_no_false_positive_on_non_auth_routes(monkeypatch):
    from sloptic import discovery
    monkeypatch.setattr(discovery, "make_client",
                        _mock_client_serving('go("/about");route("/pricing");x("/loginsreport")'))
    assert discovery._mine_auth_routes("http://app.test", None, ["/a.js"]) == (False, False, None, None)


def test_mine_auth_routes_empty_without_js_chunks():
    from sloptic import discovery
    assert discovery._mine_auth_routes("http://app.test", None, []) == (False, False, None, None)
    assert discovery._mine_auth_routes("http://app.test", None, ["/style.css"]) == (False, False, None, None)


def test_clean_mined_path_normalises_quote_query_and_trailing_slash():
    from sloptic import discovery
    assert discovery._clean_mined_path("/login/") == "/login"
    assert discovery._clean_mined_path("/auth-gateway?next=/x") == "/auth-gateway"
    assert discovery._clean_mined_path("login") == "/login"


class _CodeSplitApp(http.server.BaseHTTPRequestHandler):
    """A landing page with NO form and NO auth CTA, just a code-split chunk that names a non-standard login route
    (/app/login). The conventional-route render would never walk it; Part 2 mines the string and renders it."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/chunk.js":
            body, ct = b'router.push("/app/login")', "application/javascript"
        elif self.path == "/":
            body, ct = (b'<html><body><script src="/chunk.js"></script><p>marketing</p></body></html>', "text/html")
        else:
            body, ct = b"nope", "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_route_mining_part2_renders_the_mined_route_and_harvests_its_form():
    from sloptic import discovery
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CodeSplitApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    rendered_paths = []

    def fake_render(_b, paths, headers=None, **k):
        rendered_paths.extend(paths)
        if any("/app/login" in p for p in paths):    # Part 2 asks to render the mined route -> serve its form
            return {"/app/login": "<html><form action='/app/login'>"
                                   "<input name='email'><input type='password' name='password'></form></html>"}
        return {}
    try:
        prof = discovery.discover(base, render=fake_render)
        assert "/app/login" in rendered_paths                          # the MINED non-standard route was rendered
        assert prof.capabilities.get("any_form_has_password") is True   # ... and its password form was harvested
        assert prof.capabilities.get("has_auth_entrypoint") is True     # ... unlocking the auth cluster
    finally:
        srv.shutdown()


# --- Gap B: the crawl now registers a client-rendered SPA login via the browser lane ------------------------

def test_crawl_auth_headers_uses_the_browser_lane_for_a_cta_only_login():
    from sloptic import discovery
    # a CTA-only login (no server-side <form>) -> the browser lane must still run (has_auth_surface via the
    # login trigger) and its session must come back as crawl headers, so the render maps the authed surface.
    def fake_browser_register(base_url, email=None):
        return {"cookies": [{"name": "sessionid", "value": "S", "httponly": True, "secure": False,
                             "samesite": False}]}
    hdrs = discovery._crawl_auth_headers("http://127.0.0.1:1", forms=[], auth=(True, False),
                                         browser_register=fake_browser_register)
    assert "Cookie" in hdrs and "sessionid=S" in hdrs["Cookie"]


def test_crawl_auth_headers_empty_when_nothing_establishes_a_session():
    from sloptic import discovery
    assert discovery._crawl_auth_headers("http://127.0.0.1:1", forms=[], auth=(False, False)) == {}


def test_crawl_auth_headers_populates_the_session_sink_for_reuse():
    from sloptic import discovery
    # UNIFICATION: the crawl's established session is stashed as a replayable snapshot so the PROBES reuse it
    # (ctx.register) instead of registering a SECOND time. The snapshot shape must match probes._snapshot_session.
    def fake_browser_register(base_url, email=None):
        return {"cookies": [{"name": "sessionid", "value": "S", "httponly": True, "secure": False,
                             "samesite": False}]}
    sink: dict = {}
    discovery._crawl_auth_headers("http://127.0.0.1:1", forms=[], auth=(True, False),
                                  browser_register=fake_browser_register, session_sink=sink)
    sess = sink.get("session")
    assert sess is not None
    assert set(sess) == {"headers", "username", "password", "response", "storage_exposed"}
    assert "sessionid=S" in sess["headers"].get("Cookie", "")
