"""sec-ratelimit-001 (login_no_rate_limit): fire N wrong-password logins at the login endpoint; slop if
none is throttled (429/423). v20 FP hardening (two classes that survived the shell-gate):
  1. a GET-method 'login form' is NOT tested via the HTML path (it is an onSubmit stub / creds-in-query,
     not the credential-processing POST endpoint) -> JSON fallback, not a GET-fetch phantom;
  2. a transport redirect (http->https / www-canonical, same path) is NOT an auth rejection, so it can no
     longer make `saw_auth` true and phantom-fire "never throttled" on an endpoint that never saw the login.
"""
import http.server
import threading
from urllib.parse import urlparse

import httpx
import pytest

from sloptic.net import make_client
from sloptic.probes import _looks_like_auth_reject, login_no_rate_limit
from sloptic.schema import Form, Profile


# ---------------- Fix 2: _looks_like_auth_reject transport-redirect exclusion (unit) ----------------

def _resp(status, location=None, req="https://app.com/login", ctype=None, text=""):
    headers = {}
    if location:
        headers["location"] = location
    if ctype:
        headers["content-type"] = ctype
    return httpx.Response(status, headers=headers, text=text, request=httpx.Request("POST", req))


def test_auth_reject_status_and_json():
    assert _looks_like_auth_reject(_resp(401)) is True
    assert _looks_like_auth_reject(_resp(403)) is True
    assert _looks_like_auth_reject(_resp(200, ctype="application/json")) is True
    assert _looks_like_auth_reject(_resp(200, ctype="text/html", text="<html></html>")) is False
    assert _looks_like_auth_reject(_resp(404)) is False


def test_transport_redirect_is_not_a_rejection():
    # http -> https upgrade to the SAME login path: canonicalization, not a credential rejection
    assert _looks_like_auth_reject(_resp(301, location="https://app.com/login", req="http://app.com/login")) is False
    # www / apex host canonicalization, same path
    assert _looks_like_auth_reject(_resp(302, location="https://www.app.com/login", req="https://app.com/login")) is False
    # relative scheme-relative canonicalization to same path on a different host
    assert _looks_like_auth_reject(_resp(308, location="https://api.app.com/login", req="https://app.com/login")) is False


def test_real_reject_redirect_still_fires():
    # same-origin redirect back to /login with an error query = a real rejection (protect the TP, no FN)
    assert _looks_like_auth_reject(_resp(302, location="/login?error=invalid")) is True
    # same-origin flash re-render to the same /login path (no query) is still counted (flash-error pattern)
    assert _looks_like_auth_reject(_resp(302, location="/login")) is True
    # redirect to a distinct error / auth page
    assert _looks_like_auth_reject(_resp(303, location="/auth/error")) is True


# ---------------- Fix 1: POST-only gate + end-to-end fire/clean (integration) ----------------

def _login_server(throttle_after=None):
    class H(http.server.BaseHTTPRequestHandler):
        hits = {"n": 0}

        def log_message(self, *a):
            pass

        def _s(self, code, body=b"no", ctype="text/html"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if urlparse(self.path).path == "/":
                return self._s(200, b"<html>home</html>")
            return self._s(404)                                   # honest host: real 404 for unknown paths

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            if urlparse(self.path).path == "/login":
                H.hits["n"] += 1
                if throttle_after and H.hits["n"] > throttle_after:
                    return self._s(429, b"slow down")             # brute-force protection kicks in
                return self._s(401, b"invalid credentials")       # honest auth reject, never throttled
            return self._s(404)
    return H


class _P:
    probe = {"attempts": 6}


def _ctx(url, client, forms):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url, forms=forms),
                          "headers": None, "client": client, "evidence": {}})()


def _get_only_login_server():
    """The ONLY credential-shaped response is a GET on a non-standard path: no POST endpoint answers a login,
    and the JSON fallback's guessed paths all 404. So a fire here can only be the HTML path GET-fetching the
    form action (the bug the POST gate removes)."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _s(self, code, body=b"no", ctype="text/html"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = urlparse(self.path).path
            if p == "/":
                return self._s(200, b"<html>home</html>")
            if p == "/portal/signin":
                return self._s(401, b"invalid")          # a GET-fetch here WOULD look like an auth reject
            return self._s(404)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            return self._s(404)                          # no credential-processing POST anywhere
    return H


@pytest.fixture
def server():
    servers = []

    def _make(throttle_after=None, handler=None):
        h = handler or _login_server(throttle_after)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), h)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


def test_fires_on_post_login_never_throttled(server):
    url = server()
    with make_client(url, None) as c:
        form = Form(action="/login", method="post", fields=["email", "password"])
        assert login_no_rate_limit(_ctx(url, c, [form]), _P()) is True


def test_clean_when_throttled(server):
    url = server(throttle_after=3)
    with make_client(url, None) as c:
        form = Form(action="/login", method="post", fields=["email", "password"])
        assert login_no_rate_limit(_ctx(url, c, [form]), _P()) is False


def test_get_method_login_form_does_not_fire_html_path(server):
    # a GET 'login form' (SPA onSubmit / no method attr -> Form.method defaults to "get") must NOT GET-fetch
    # and phantom-fire; the HTML path is skipped and the JSON fallback finds no login endpoint here -> N/A.
    # (The action's GET returns 401, so WITHOUT the gate this would fire True -- that is the FP being closed.)
    url = server(handler=_get_only_login_server())
    with make_client(url, None) as c:
        form = Form(action="/portal/signin", method="get", fields=["email", "password"])
        assert login_no_rate_limit(_ctx(url, c, [form]), _P()) is None
