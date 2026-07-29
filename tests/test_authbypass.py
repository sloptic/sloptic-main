"""sec-authbypass-001 (CVE-2025-29927): the Next.js `x-middleware-subrequest` header makes Next SKIP its
middleware, so a route the middleware gates becomes reachable with no credentials. The probe fires when the
gate flips (anon baseline 401/redirect-to-login -> 200 real content WITH the header), reads clean when a
patched Next ignores the header, and N/A on non-Next apps. Deterministic mock Next server; no real network."""
import http.server
import pathlib
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import _MW_PAYLOADS, middleware_auth_bypass  # noqa: E402
from sloptic.schema import Profile  # noqa: E402

_HDR = "x-middleware-subrequest"
_DASH = '<html><body><h1>Dashboard</h1><p>secret account balance $4,200</p></body></html>'
_LOGIN = '<html><body><h1>Sign in</h1><form><input type="password" name="password"></form></body></html>'
_HOME_NEXT = '<html><body><script src="/_next/static/chunks/main.js"></script><h1>Home</h1></body></html>'
_HOME_PLAIN = '<html><body><h1>Home</h1></body></html>'


def _make(mode):   # mode: "vuln" | "patched" | "notnext"
    nextish = mode in ("vuln", "patched")

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, extra=None):
            b = body.encode()
            self.send_response(code)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/", ""):                                  # entry: carry (or not) a Next.js signal
                extra = {"X-Powered-By": "Next.js"} if nextish else {}
                return self._send(200, _HOME_NEXT if nextish else _HOME_PLAIN, extra)
            if path.startswith("/login"):
                return self._send(200, _LOGIN)
            if path == "/dashboard":                              # the middleware-gated route
                has_bypass = self.headers.get(_HDR) is not None
                if mode == "vuln" and has_bypass:                 # middleware skipped -> the handler runs
                    return self._send(200, _DASH)
                return self._send(307, "", {"Location": "/login"})   # gate: anon -> redirect to login
            return self._send(404, "nope")
    return H


def _run(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
               Profile(base_url=url, routes=["/", "/dashboard"]), None)
    try:
        verdict = middleware_auth_bypass(ctx, type("P", (), {"probe": {}})())
        return verdict, dict(ctx.evidence)
    finally:
        ctx.client.close()
        srv.shutdown()


def test_fires_when_the_header_opens_a_gated_route():
    verdict, ev = _run("vuln")
    assert verdict is True                                        # protected route reachable with no creds
    assert ev["bypassed"] is True and ev["route"] == "/dashboard" and ev["header"] == _HDR
    assert ev["baseline_status"] == 307 and ev["payload"] in _MW_PAYLOADS   # auditable: which payload opened it


def test_clean_when_patched_next_ignores_the_header():
    verdict, ev = _run("patched")
    assert verdict is False                                       # gate held under every payload -> not slop
    assert ev["bypassed"] is False and ev["gated_routes_tested"] >= 1   # it DID find + test a real gate


def test_na_on_a_non_next_app():
    verdict, ev = _run("notnext")
    assert verdict is None                                        # header is Next-specific -> nothing to test
    assert "Next.js" in ev["na_reason"]
