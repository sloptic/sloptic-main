"""Self-registration on a modern Next.js app, and the Secure-cookie-over-http trap behind it.

Measured on OopsSec Store (intentionally-vulnerable Next.js + React + SQLite, self-registerable) at
http://localhost:3000. Two independent defects, each of which alone turns the whole authed half of the
catalog dark, and neither of which reports anything: the probes just read N/A.

1. REGISTRATION NEVER HAPPENED. `/signup` is a page route that answers 200 to any method because it renders
   HTML, so the form POST looks fine and creates nothing. The JSON fallback existed but its path list had no
   `/api/auth/signup`. The crawl DID observe `GET /api/auth/logout`, which names the auth namespace, so the
   sibling is inferable — better than growing a hardcoded list forever, since it works for whatever prefix an
   app chose.

2. THE SESSION WAS NEVER SENT. The app sets `authToken=...; Secure; HttpOnly; SameSite=lax` and we grade over
   http. httpx STORES that cookie (so _has_session correctly says we are in) and never transmits it. Measured:
   401 on /api/wishlists from the client while the identical cookie sent by hand got 200. Retained is not sent.
"""
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

from hacklet_runner import auth  # noqa: E402
from hacklet_runner.schema import Endpoint, Form, Profile  # noqa: E402

_TOKEN = "eyJhbGciOiJIUzI1NiJ9.hl-probe-session.sig"


def _serve_nextjs_shaped():
    """A Next.js-shaped app: page routes 200 on any method, registration is JSON under /api/auth/, and the
    session cookie is Secure. `/api/private` is the authed surface."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _page(self):
            b = b"<!doctype html><html><body>page shell</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _json(self, code, obj, cookie=False):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if cookie:
                self.send_header("Set-Cookie",
                                 f"authToken={_TOKEN}; Path=/; Max-Age=604800; Secure; HttpOnly; SameSite=lax")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/private":
                if _TOKEN in (self.headers.get("Cookie") or ""):
                    return self._json(200, {"items": ["mine"]})
                return self._json(401, {"error": "Unauthorized"})
            if path == "/api/auth/logout":       # the namespace clue the crawl observes
                return self._json(200, {"ok": True})
            return self._page()

        def do_POST(self):
            path = self.path.split("?")[0]
            if path == "/api/auth/signup":
                return self._json(200, {"user": {"id": "u1", "role": "CUSTOMER"}}, cookie=True)
            return self._page()                  # a page route 200s any method and creates NOTHING

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _profile(base):
    return Profile(base_url=base, routes=["/", "/signup", "/login"],
                   endpoints=[Endpoint(path="/api/auth/logout", raw_path="/api/auth/logout",
                                       method="get", query_params=[])])


# ------------------------------------------------------------------ sibling inference

def test_an_observed_auth_namespace_implies_its_register_sibling():
    prof = _profile("http://x")
    inferred = auth._sibling_auth_paths(prof, auth._REGISTER_KW)
    assert "/api/auth/signup" in inferred and "/api/auth/register" in inferred


def test_the_login_sibling_is_inferred_from_the_same_namespace():
    assert "/api/auth/login" in auth._sibling_auth_paths(_profile("http://x"), auth._LOGIN_KW)


def test_any_prefix_works_not_just_slash_api():
    # the point of inferring rather than hardcoding: /backend/v2/auth/* is as valid as /api/auth/*
    prof = Profile(base_url="http://x", routes=["/backend/v2/auth/session"])
    assert "/backend/v2/auth/signup" in auth._sibling_auth_paths(prof, auth._REGISTER_KW)


def test_a_route_set_with_no_auth_namespace_infers_nothing():
    prof = Profile(base_url="http://x", routes=["/", "/products/1", "/api/cart/items"])
    assert auth._sibling_auth_paths(prof, auth._REGISTER_KW) == []


def test_a_single_segment_path_is_not_a_namespace():
    prof = Profile(base_url="http://x", routes=["/", "/login"])
    assert auth._sibling_auth_paths(prof, auth._REGISTER_KW) == []


def test_the_conventional_path_list_covers_the_next_js_spelling():
    # belt and braces for an app whose crawl surfaced no auth route at all
    assert "/api/auth/signup" in auth._JSON_REGISTER_PATHS


# ------------------------------------------------------------------ Secure over http

def test_a_secure_cookie_is_re_sent_over_http():
    c = httpx.Client(base_url="http://x")
    c.cookies.set("authToken", _TOKEN)
    auth._carry_secure_cookies_over_http("http://x", c)
    assert c.headers.get("Cookie") == "authToken=" + _TOKEN
    c.close()


def test_an_https_target_keeps_httpx_behaviour_untouched():
    # over https httpx sends the cookie itself; duplicating it into a header would be pointless and could
    # shadow a rotated cookie
    c = httpx.Client(base_url="https://x")
    c.cookies.set("authToken", _TOKEN)
    auth._carry_secure_cookies_over_http("https://x", c)
    assert c.headers.get("Cookie") is None
    c.close()


def test_a_caller_supplied_cookie_header_is_never_clobbered():
    # --header (Option B) hands us ONE identity on purpose; overwriting it would silently change who we are
    c = httpx.Client(base_url="http://x", headers={"Cookie": "session=theirs"})
    c.cookies.set("authToken", _TOKEN)
    auth._carry_secure_cookies_over_http("http://x", c)
    assert c.headers.get("Cookie") == "session=theirs"
    c.close()


def test_an_empty_jar_adds_no_header():
    c = httpx.Client(base_url="http://x")
    auth._carry_secure_cookies_over_http("http://x", c)
    assert c.headers.get("Cookie") is None
    c.close()


# ------------------------------------------------------------------ end to end

def test_registration_reaches_the_authed_surface_on_a_next_js_shaped_app():
    """Both defects at once, which is how they appeared: the form POST 200s and creates nothing, the JSON
    endpoint is only findable by inference, and the cookie it returns is Secure over http."""
    srv = _serve_nextjs_shaped()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        acct = auth.register_account(base, _profile(base))
        assert acct is not None and auth._has_session(acct) is True
        r = acct.client.get("/api/private")
        assert r.status_code == 200, "authenticated then made every request anonymously"
        assert r.json()["items"] == ["mine"]
        acct.client.close()
    finally:
        srv.shutdown()


def test_the_page_route_post_alone_would_have_established_nothing():
    """Guards the reason this was invisible: the HTML-form path gets a 200 from a page route, so only
    _has_session (not the status) can tell registration failed."""
    srv = _serve_nextjs_shaped()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        # a React signup form: action is the PAGE, fields carry no name attributes so they are typed-derived
        prof = Profile(base_url=base, routes=["/", "/signup"],
                       forms=[Form(action="/signup", method="post", fields=["email", "password"])])
        acct = auth._register_httpx(base, prof)   # the HTML-form path, which is all this profile offers
        assert acct is None or auth._has_session(acct) is False
        if acct is not None:
            assert acct.register_response.status_code == 200   # a 200 that means nothing
            acct.client.close()
    finally:
        srv.shutdown()
