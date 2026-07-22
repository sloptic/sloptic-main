"""The innocence check: on a catch-all / soft-404 host that serves the SAME 200 shell for every path, the
phantom-sensitive probes (rate-limit / sqli / csrf) must read N/A — not fire — because there's no real
endpoint. But on an HONEST host they must STILL fire on a genuine issue (the check must not cost recall)."""
import http.server
import pathlib
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import (  # noqa: E402
    _endpoint_is_live, _same_resource_redirect, api_sqli, crash_resistance, csrf_missing, login_no_rate_limit)
from hacklet_runner.schema import Endpoint, Form, Profile  # noqa: E402

_SHELL = b"<html><body>App shell - client-side routing, nothing here server-side</body></html>"


class _CatchAll(http.server.BaseHTTPRequestHandler):
    """SPA host: the same 200 HTML shell for EVERY path (GET and POST) — no real server 404."""
    def log_message(self, *a): pass

    def _shell(self):
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_SHELL))); self.end_headers(); self.wfile.write(_SHELL)

    def do_GET(self): self._shell()

    def do_POST(self):
        try: self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        except Exception: pass
        self._shell()


class _Honest(http.server.BaseHTTPRequestHandler):
    """Well-behaved host: a real 404 for nonexistent paths, and a real /login that never throttles."""
    def log_message(self, *a): pass

    def _send(self, code, body=b"nope"):
        self.send_response(code); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        self._send(401, b"invalid credentials") if urlparse(self.path).path == "/login" else self._send(404)

    def do_POST(self):
        try: self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        except Exception: pass
        self._send(401, b"invalid credentials") if urlparse(self.path).path == "/login" else self._send(404)


class _ClientSideAuth(http.server.BaseHTTPRequestHandler):
    """SPA with CLIENT-SIDE auth (Supabase/Firebase from the browser): honest 404s (NOT a catch-all, so the
    phantom-shell check doesn't apply), and the /login POST just re-serves a 200 page with NO server-side
    auth rejection — there's no backend of the app's to rate-limit, so a 'no rate limiting' fire is phantom."""
    def log_message(self, *a): pass

    def _send(self, code, body=b"", ctype="text/html"):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self): self._send(404, b"not found")       # honest 404 -> not a catch-all host

    def do_POST(self):
        try: self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        except Exception: pass
        self._send(200, b"<html>dashboard</html>")        # client-side auth: no server rejection to see


def _serve(cls):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Probe:
    probe = {"attempts": 3, "max_attempts": 20, "time_delay": 1}


def _ctx(url, profile, headers=None):
    return _Ctx(url, make_client(url, headers, timeout=10.0, follow_redirects=True), profile, headers)


def _run(cls, profile, probe_fn, headers=None):
    srv = _serve(cls)
    ctx = _ctx(f"http://127.0.0.1:{srv.server_address[1]}", profile, headers)
    ctx.profile.base_url = ctx.base_url
    try:
        return probe_fn(ctx, _Probe())
    finally:
        ctx.client.close(); srv.shutdown()


def test_rate_limit_reads_na_on_a_catch_all_shell():
    prof = Profile(base_url="x", forms=[Form(action="/login", method="post", fields=["username", "password"])])
    assert _run(_CatchAll, prof, login_no_rate_limit) is None      # POSTs echo the shell -> no real handler


def test_sqli_reads_na_on_a_catch_all_shell():
    prof = Profile(base_url="x", endpoints=[
        Endpoint(path="/api/search", method="get", raw_path="/api/search", query_params=["q"])])
    assert _run(_CatchAll, prof, api_sqli) is None                 # baseline IS the shell -> phantom sink


def test_csrf_reads_na_on_a_catch_all_shell():
    prof = Profile(base_url="x", forms=[Form(action="/api/settings", method="post", fields=["email", "role"])])
    assert _run(_CatchAll, prof, csrf_missing, headers={"Cookie": "sid=abc"}) is None


class _RootFormShell(http.server.BaseHTTPRequestHandler):
    """Honest 404s (so '/' is genuinely LIVE and the liveness gate PASSES), but a <form> whose action defaults
    to '/' whose POST just RE-SERVES the homepage — an SPA/framework quirk, NOT a state change. The liveness
    gate can't catch this (/ is a real endpoint); only the shell-diff (accepted 2xx == a plain GET of the path)."""
    _HOME = b"<html><body>home" + b" x" * 300 + b"</body></html>"

    def log_message(self, *a): pass

    def _send(self, code, body):
        self.send_response(code); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        self._send(200, self._HOME) if urlparse(self.path).path == "/" else self._send(404, b"nf")

    def do_POST(self):
        try: self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        except Exception: pass
        self._send(200, self._HOME) if urlparse(self.path).path == "/" else self._send(404, b"nf")


def test_csrf_reads_na_on_a_form_that_just_reserves_the_homepage():
    # the aesthesis/study-sync FP: a <form> whose action defaults to '/' whose POST RE-SERVES the homepage
    # (SPA shell, not a state change). '/' is honestly live (its 404 sibling is distinct) so the liveness gate
    # passes; only the shell-diff (accepted 2xx == a plain GET of the same path) rejects it as a non-mutation.
    prof = Profile(base_url="x", forms=[Form(action="/", method="post", fields=["state", "connection"])])
    assert _run(_RootFormShell, prof, csrf_missing, headers={"Cookie": "sid=abc"}) is not True


class _HttpsUpgradeForm(http.server.BaseHTTPRequestHandler):
    """'/' and '/pay' are honestly live (their 404 siblings are distinct, so the liveness gate passes), but a
    cross-site POST to /pay gets a 308 to the https version of the SAME path — a transport upgrade the app never
    PROCESSED, not an accepted state change (the covermypharma/passtheplate FP: an http:// url 30x-upgrades)."""
    def log_message(self, *a): pass

    def _send(self, code, body=b"", loc=None):
        self.send_response(code); self.send_header("Content-Type", "text/html")
        if loc: self.send_header("Location", loc)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path).path
        self._send(200, b"page " + p.encode()) if p in ("/", "/pay") else self._send(404, b"nf")

    def do_POST(self):
        try: self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        except Exception: pass
        p = urlparse(self.path).path
        if p == "/pay":
            self._send(308, loc="https://%s/pay" % self.headers.get("Host", "x"))   # transport upgrade, not a mutation
        else:
            self._send(404, b"nf")


def test_same_resource_redirect_flags_transport_not_real_acceptance():
    assert _same_resource_redirect("http://x.com/pay", "https://x.com/pay")           # http->https upgrade
    assert _same_resource_redirect("http://x.com/pay", "https://x.com/pay/")          # + trailing slash
    assert _same_resource_redirect("http://x.com/", "https://www.x.com/")             # + www
    assert not _same_resource_redirect("http://x.com/", "https://x.com/dashboard")    # different resource -> real
    assert not _same_resource_redirect("http://x.com/", "")                           # no Location


def test_csrf_does_not_fire_on_a_get_form():
    # a GET is un-adjudicable black-box (mutation vs search both return a differing 200), so we skip it — the
    # missed state-changing-GET CSRF is the accepted FN (AfroSecured/passtheplate: GET '/' -> 30x nav)
    prof = Profile(base_url="x", forms=[Form(action="/pay", method="get", fields=["amount"])])
    assert _run(_HttpsUpgradeForm, prof, csrf_missing, headers={"Cookie": "sid=abc"}) is not True


def test_csrf_does_not_fire_on_an_http_to_https_upgrade_redirect():
    # covermypharma/passtheplate FP: a cross-site POST to an http:// url gets a 308 to https (SAME resource) —
    # a transport upgrade the app never processed, must NOT be read as 'state change accepted'.
    prof = Profile(base_url="x", forms=[Form(action="/pay", method="post", fields=["amount", "to"])])
    assert _run(_HttpsUpgradeForm, prof, csrf_missing, headers={"Cookie": "sid=abc"}) is not True


def test_rate_limit_STILL_fires_on_an_honest_host():
    # the check must not cost recall: an honest /login that never throttles is real slop, must still fire
    prof = Profile(base_url="x", forms=[Form(action="/login", method="post", fields=["username", "password"])])
    assert _run(_Honest, prof, login_no_rate_limit) is True


def test_rate_limit_reads_na_on_client_side_auth():
    # client-side (Supabase/Firebase) login: the POST reaches no server auth backend, so no attempt returns
    # an auth-shaped rejection -> N/A, not a phantom 'no rate limiting' (the big under-the-radar FP class).
    prof = Profile(base_url="x", forms=[Form(action="/login", method="post", fields=["username", "password"])])
    assert _run(_ClientSideAuth, prof, login_no_rate_limit) is None


def test_endpoint_liveness_gate_primitive():
    # _endpoint_is_live is the single gate the phantom-sensitive probes route through. An honest host's real
    # endpoint is live (its nonexistent sibling 404s -> distinct); a catch-all host's endpoint is NOT (every
    # path, incl the sibling, is the same shell).
    srv = _serve(_Honest)
    ctx = _ctx(f"http://127.0.0.1:{srv.server_address[1]}", Profile(base_url="x"))
    ctx.profile.base_url = ctx.base_url
    try:
        real = ctx.client.get("/login")   # _Honest: /login -> 401 "invalid credentials" (a real handler)
        assert _endpoint_is_live(ctx, ctx.client, "/login", "get", real) is True
    finally:
        ctx.client.close(); srv.shutdown()

    srv = _serve(_CatchAll)
    ctx = _ctx(f"http://127.0.0.1:{srv.server_address[1]}", Profile(base_url="x"))
    ctx.profile.base_url = ctx.base_url
    try:
        shell = ctx.client.get("/whatever")   # 200 catch-all shell for every path
        assert _endpoint_is_live(ctx, ctx.client, "/whatever", "get", shell) is False
    finally:
        ctx.client.close(); srv.shutdown()


class _CatchAll5xxOnMalformed(http.server.BaseHTTPRequestHandler):
    """A per-prefix catch-all: benign input and the nonexistent sibling both return the 200 shell, but a
    malformed value 5xx's (a platform edge choking, not the app's own handler). WITHOUT the liveness gate
    crash-resistance false-fires on that 5xx; WITH it the endpoint is a phantom (benign == sibling) and is
    skipped."""
    def log_message(self, *a): pass

    def do_GET(self):
        from urllib.parse import parse_qs
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        nasty = any(ch in q for ch in "<>'\";{}")           # a _CRASH_VALUES-style malformed value
        self.send_response(500 if nasty else 200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_SHELL))); self.end_headers(); self.wfile.write(_SHELL)


def test_crash_does_not_phantom_fire_on_a_catch_all_that_5xxs_on_malformed():
    # the exact FP the liveness gate prevents: a catch-all whose /api/x 200-shells benign input but 5xx's on
    # a malformed value. Without the gate crash fires on the 5xx; with it the phantom endpoint is skipped, so
    # crash never returns True (the platform 5xx is not the app's crash).
    prof = Profile(base_url="x", endpoints=[
        Endpoint(path="/api/x", method="get", raw_path="/api/x", query_params=["q"])])
    assert _run(_CatchAll5xxOnMalformed, prof, crash_resistance) is not True
