"""qa-input-001 (declared_constraint_unenforced) fires only on an INPUT-DEPENDENT type-enforcement gap: an
invalid value is accepted like a valid one AND an all-empty body is rejected (the field is really processed).
A static shell / auth-guard / catch-all that answers ANY body identically is input-INDEPENDENT -> clean. That
was the entire v18 fire set (~100% FP: 39 static-shell action=/ + 12 auth 3xx + 6 sub-path 200s)."""
import http.server
import threading
import urllib.parse

from sloptic.discovery import discover
from sloptic.probes import declared_constraint_unenforced

_FORM = ('<!doctype html><html lang=en><head><title>t</title></head><body>'
         '<form action="/register" method="post">'
         '<input name="username"><input name="email" type="email" required>'
         '<button type="submit">go</button></form></body></html>')


def _reply(h, code, msg="ok"):
    b = msg.encode()
    h.send_response(code)
    h.send_header("Content-Length", str(len(b)))
    h.end_headers()
    h.wfile.write(b)


def _serve(on_post, catch_all=False):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if not catch_all and self.path != "/":
                return _reply(self, 404, "nope")   # honest 404s -> not a soft-404 shell (passes the live gate)
            b = _FORM.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            on_post(self, self.path, self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Probe:
    probe = {"target": "/"}


def _verdict(on_post, catch_all=False):
    srv = _serve(on_post, catch_all)
    try:
        url = "http://127.0.0.1:%d" % srv.server_address[1]
        prof = discover(url)                                   # real discovery -> the form + its constraints
        ctx = type("C", (), {"base_url": url, "headers": None, "client": None,
                             "evidence": {}, "profile": prof})()
        return declared_constraint_unenforced(ctx, _Probe())
    finally:
        srv.shutdown()


def test_fires_on_input_dependent_type_gap():
    # /register requires the field (empty body -> 400) but never validates the email TYPE (invalid -> 200): the
    # real flaw. Sibling paths 404, so it passes the live gate; the empty body is rejected -> input-dependent -> fires.
    def on_post(h, path, body):
        if path != "/register":
            return _reply(h, 404, "nope")
        _reply(h, 200 if urllib.parse.parse_qs(body).get("username", [""])[0] else 400, "created")
    assert _verdict(on_post) is True


def test_clean_on_input_independent_shell():
    # a static SPA shell / catch-all: 200 to ANY path/body -> caught as not-live (the v18 action=/ FP class)
    assert _verdict(lambda h, path, body: _reply(h, 200, "shell"), catch_all=True) is not True


def test_clean_on_auth_guard_redirect():
    # a live endpoint (siblings 404) that 302s -> /login for ANY body: the input-dependence gate catches it
    # (an empty body also redirects away) -> clean. This is the v18 auth-redirect FP class (307/302 to a login).
    def on_post(h, path, body):
        if path != "/register":
            return _reply(h, 404, "nope")
        h.send_response(302)
        h.send_header("Location", "/login")
        h.send_header("Content-Length", "0")
        h.end_headers()
    assert _verdict(on_post) is not True
