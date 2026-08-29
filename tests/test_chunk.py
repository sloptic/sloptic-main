"""qa-chunk-001: the served HTML references a JS bundle that doesn't resolve — the app can't render. Fires on
an honest 404 AND on a catch-all/SPA host that serves the HTML shell where JS should be; clean when the bundle
resolves to JavaScript; N/A when the HTML references no same-origin script."""
import http.server
import pathlib
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import dead_bundle_chunk  # noqa: E402
from sloptic.schema import Profile  # noqa: E402


def _make_app(mode):   # dead | shell | ok | none
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if urlparse(self.path).path == "/":
                if mode == "none":
                    script = ""
                elif mode == "dev":
                    script = "<script src='/livereload.js'></script>"   # a dev-only artifact, not the app's bundle
                else:
                    script = "<script src='/app.abc123.js'></script>"
                return self._send(200, "<html><body>%s hi</body></html>" % script, "text/html")
            # the bundle request:
            if mode in ("dead", "dev"):
                return self._send(404, "not found", "text/plain")   # dev: /livereload.js 404s but is SKIPPED
            if mode == "shell":
                return self._send(200, "<html><body>app shell</body></html>", "text/html")   # catch-all host
            return self._send(200, "console.log(1)", "application/javascript")                # ok
    return H


def _run(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True), Profile(base_url=url), None)

    class _P:
        probe = {}
    try:
        return dead_bundle_chunk(ctx, _P())
    finally:
        ctx.client.close()
        srv.shutdown()


def test_fires_on_404_bundle():
    assert _run("dead") is True


def test_fires_when_shell_served_for_bundle():
    assert _run("shell") is True        # catch-all host: HTML where JS should be


def test_clean_when_bundle_resolves_to_js():
    assert _run("ok") is False


def test_na_without_a_script_bundle():
    assert _run("none") is None


def test_dev_artifact_script_is_skipped():
    # a dev-server / HMR artifact (livereload.js, /@vite/, /node_modules/, *.local.js) 404ing in a static deploy
    # does NOT stop the app rendering -> skipped, not a dead chunk. Only script -> N/A (would fire without the skip).
    assert _run("dev") is None


def test_registrable_domain_distinguishes_move_from_canonical_redirect():
    # a bundle fetch that redirects to a DIFFERENT registrable domain is a parked/moved site, not a dead chunk of
    # THIS app -> skipped (basementhost -> tensordock, veridian.fyi -> sfjc.dev). But an apex<->www canonical
    # redirect is the SAME site, so a real dead chunk there still fires (no recall loss). (Loopback can't model
    # different registrable domains -- both are 127.0.0.1 -- so the discriminator is unit-tested directly.)
    from sloptic.probes import _registrable
    assert _registrable("basementhost.com") != _registrable("www.tensordock.com")   # moved -> skip
    assert _registrable("veridian.fyi") != _registrable("sfjc.dev")                 # moved -> skip
    assert _registrable("wix-vibe.com") != _registrable("wix-vibe-site.com")        # moved -> skip
    assert _registrable("foo.com") == _registrable("www.foo.com")                   # canonical -> NOT skipped
    assert _registrable("app.foo.com") == _registrable("foo.com")                   # subdomain -> same site
    assert _registrable("127.0.0.1:8000") == _registrable("127.0.0.1:9000")         # same IP host -> same
