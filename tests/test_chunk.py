"""qa-chunk-001: the served HTML references a JS bundle that doesn't resolve — the app can't render. Fires on
an honest 404 AND on a catch-all/SPA host that serves the HTML shell where JS should be; clean when the bundle
resolves to JavaScript; N/A when the HTML references no same-origin script."""
import http.server
import pathlib
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import dead_bundle_chunk  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402


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
                script = "" if mode == "none" else "<script src='/app.abc123.js'></script>"
                return self._send(200, "<html><body>%s hi</body></html>" % script, "text/html")
            # the bundle request:
            if mode == "dead":
                return self._send(404, "not found", "text/plain")
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
