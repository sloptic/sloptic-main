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
from hacklet_runner.probes import api_sqli, csrf_missing, login_no_rate_limit  # noqa: E402
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


def test_rate_limit_STILL_fires_on_an_honest_host():
    # the check must not cost recall: an honest /login that never throttles is real slop, must still fire
    prof = Profile(base_url="x", forms=[Form(action="/login", method="post", fields=["username", "password"])])
    assert _run(_Honest, prof, login_no_rate_limit) is True


def test_rate_limit_reads_na_on_client_side_auth():
    # client-side (Supabase/Firebase) login: the POST reaches no server auth backend, so no attempt returns
    # an auth-shaped rejection -> N/A, not a phantom 'no rate limiting' (the big under-the-radar FP class).
    prof = Profile(base_url="x", forms=[Form(action="/login", method="post", fields=["username", "password"])])
    assert _run(_ClientSideAuth, prof, login_no_rate_limit) is None
