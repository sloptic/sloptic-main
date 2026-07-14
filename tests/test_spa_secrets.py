"""SPA-native security: mine the CLIENT bundle for a leaked SERVER secret, and flag an exposed source map.
The two make-or-break properties: (1) a MINIFIED single-line bundle is scanned (the source scanner skips giant
lines), and (2) public-by-design keys (Supabase anon / Firebase AIza / Stripe pk_) are NEVER flagged."""
import http.server
import json
import pathlib
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import bundle_leaks_secret, source_map_exposed  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402
from hacklet_runner.secretscan import scan_blob  # noqa: E402

# a realistic MINIFIED bundle: one long line, a leaked Stripe SECRET key, a sourceMappingURL comment
_SECRET_BUNDLE = ('const cfg={api:"/api",debug:!1,k:"sk_live_' + "A" * 24
                  + '"};function f(){}//# sourceMappingURL=app.js.map').encode()
# public-by-design keys ONLY: Stripe publishable, Firebase AIza, a Supabase anon JWT — must never fire
_CLEAN_BUNDLE = ('const cfg={pub:"pk_live_' + "A" * 24 + '",fb:"AIzaSy' + "B" * 33
                 + '",anon:"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"};').encode()
_MAP = json.dumps({"version": 3, "sources": ["src/App.tsx"],
                   "sourcesContent": ["export default function App(){ return null }"]}).encode()


def _handler(bundle, serve_map):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _send(self, body, ct, code=200):
            self.send_response(code); self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            p = urlparse(self.path).path
            if p == "/":
                self._send(b"<html><script src=/app.js></script></html>", "text/html")
            elif p == "/app.js":
                self._send(bundle, "application/javascript")
            elif p == "/app.js.map" and serve_map:
                self._send(_MAP, "application/json")
            else:
                self._send(b"not found", "text/plain", 404)
    return H


def _run(bundle, serve_map, fn):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(bundle, serve_map))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
               Profile(base_url=url, routes=["/", "/app.js"]), None)
    try:
        return fn(ctx, type("P", (), {"probe": {}})())
    finally:
        ctx.client.close(); srv.shutdown()


def test_scan_blob_finds_a_secret_in_a_minified_single_line():
    assert "stripe-secret" in scan_blob(_SECRET_BUNDLE.decode())     # the giant-line case the source scan skips


def test_scan_blob_never_flags_public_by_design_keys():
    assert scan_blob(_CLEAN_BUNDLE.decode()) == []                   # pk_ / AIza / anon JWT are public -> clean


def test_bundle_leaks_secret_fires_on_a_leaked_server_key():
    assert _run(_SECRET_BUNDLE, False, bundle_leaks_secret) is True


def test_bundle_leaks_secret_clean_when_only_public_keys():
    assert _run(_CLEAN_BUNDLE, False, bundle_leaks_secret) is False


def test_source_map_exposed_fires_when_the_map_is_served():
    assert _run(_SECRET_BUNDLE, True, source_map_exposed) is True


def test_source_map_clean_when_no_map_is_served():
    assert _run(_CLEAN_BUNDLE, False, source_map_exposed) is False
