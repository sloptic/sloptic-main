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
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import bundle_leaks_secret, source_map_exposed  # noqa: E402
from sloptic.schema import Profile  # noqa: E402
from sloptic.secretscan import scan_blob  # noqa: E402

# a realistic MINIFIED bundle: one long line, a leaked Stripe SECRET key, a sourceMappingURL comment
_SECRET_BUNDLE = ('const cfg={api:"/api",debug:!1,k:"sk_live_' + "A" * 24
                  + '"};function f(){}//# sourceMappingURL=app.js.map').encode()
# public-by-design keys ONLY: Stripe publishable, Firebase AIza, a Supabase anon JWT — must never fire
_CLEAN_BUNDLE = ('const cfg={pub:"pk_live_' + "A" * 24 + '",fb:"AIzaSy' + "B" * 33
                 + '",anon:"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"};').encode()
# a REAL app-source leak: several of the app's OWN files reconstructed (business logic, not just a shell)
_MAP = json.dumps({"version": 3, "sources": ["src/App.tsx", "src/api.ts", "src/lib/auth.ts"],
                   "sourcesContent": ["export default function App(){ return null }", "//api", "//auth"]}).encode()
# the v18 FP shapes (114 of 164 fires): a Next.js chunk whose only source is a vendored polyfill, and the base44
# platform `badge.js` widget (one app file + two image assets). Neither reconstructs the APP's business logic.
_VENDOR_MAP = json.dumps({"version": 3,
                          "sources": ["turbopack:///frontend/node_modules/next/dist/build/polyfills/polyfill.js"],
                          "sourcesContent": ["/*polyfill*/"]}).encode()
_BADGE_MAP = json.dumps({"version": 3,
                         "sources": ["../../../src/badge/assets/cover.png", "../../../src/badge/assets/text.png",
                                     "../../../src/badge/badge.ts"],
                         "sourcesContent": ["", "", "//badge"]}).encode()


def _handler(bundle, serve_map, map_body=_MAP):
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
                self._send(map_body, "application/json")
            else:
                self._send(b"not found", "text/plain", 404)
    return H


def _run(bundle, serve_map, fn, map_body=_MAP):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(bundle, serve_map, map_body))
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
    # a real app-source leak: >= 2 of the app's own files (App.tsx / api.ts / lib/auth.ts) are reconstructable
    assert _run(_SECRET_BUNDLE, True, source_map_exposed) is True


def test_source_map_clean_when_no_map_is_served():
    assert _run(_CLEAN_BUNDLE, False, source_map_exposed) is False


def test_source_map_clean_when_only_vendored_source_is_exposed():
    # the dominant v18 FP (104 fires): the Next.js chunk whose one source is a node_modules polyfill. Vendored
    # code is already public on npm -> no app business logic, no secrets -> not a disclosure.
    assert _run(_SECRET_BUNDLE, True, source_map_exposed, map_body=_VENDOR_MAP) is False


def test_source_map_clean_on_a_platform_widget_with_one_app_file():
    # the base44 `badge.js` widget (10 v18 fires): three sources, but two are image assets and only one is code
    # (badge.ts). One app file below the >= 2 floor -> a platform widget, not the app's reconstructed source.
    assert _run(_SECRET_BUNDLE, True, source_map_exposed, map_body=_BADGE_MAP) is False
