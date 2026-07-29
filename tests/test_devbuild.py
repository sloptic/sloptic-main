"""qa-devbuild-001: the deployment is running a DEV BUILD, proven by a served HMR client.

Bundlers strip HMR statically — Vite replaces `import.meta.hot`, webpack `module.hot` — so these markers
cannot survive a production build even when the guard is in source. Presence proves the artifact was produced
in dev mode, which is why this is categorical rather than heuristic.

The precision tests carry the weight here. A string-matching probe on a corpus full of project write-ups will
false-fire on any page that MENTIONS `/@vite/client` in a code block, so matching is restricted to script
context: a <script src>, or the runtime markers inside fetched same-origin JavaScript. Never raw page text.
"""
import http.server
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import development_build_served  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402

_PROD_BUNDLE = b"function e(t){return t+1}export default e;/*# minified prod chunk */"
_DEV_BUNDLE = b'import.meta.hot;window.$RefreshReg$=function(){};/* react refresh */'


def _serve(routes, headers=None):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            # RAW path (query included) wins, so a route keyed "/x.js?v=1" is reachable ONLY if the probe
            # preserved the query — a probe that fetches the bare path gets a 404 here, as on a real dev server.
            key = self.path if self.path in routes else urllib.parse.urlparse(self.path).path
            if key not in routes:
                self.send_response(404); self.end_headers(); self.wfile.write(b"nope"); return
            ctype, body = routes[key]
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(routes, headers=None, landing="/"):
    srv = _serve(routes, headers)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, routes=["/"], landing_path=landing)
    ctx = _Ctx(base, make_client(base, None, timeout=8.0, follow_redirects=True), prof, None)
    try:
        return development_build_served(ctx, type("P", (), {"probe": {"target": "/"}})()), dict(ctx.evidence)
    finally:
        ctx.client.close()
        srv.shutdown()


# ------------------------------------------------------------------ must fire

def test_a_vite_dev_client_script_tag_fires():
    hit, ev = _run({"/": ("text/html", b'<html><script type="module" src="/@vite/client"></script></html>')})
    assert hit is True
    assert ev["signal"] == "hmr-client-script" and "@vite/client" in ev["script"]
    assert "HMR client" in ev["repro"]["matched"]


def test_webpack_dev_server_and_react_refresh_entrypoints_fire():
    for src in ("/sockjs-node/info", "/webpack-dev-server.js", "/@react-refresh",
                "/node_modules/react-refresh/runtime.js", "/webpack/hot/dev-server.js"):
        hit, _ = _run({"/": ("text/html", ('<html><script src="%s"></script></html>' % src).encode())})
        assert hit is True, src


def test_the_dev_runtime_INSIDE_a_bundle_fires_even_with_an_innocent_script_name():
    """The realistic shape: the script tag looks ordinary, and the dev-only transform output is in the file."""
    hit, ev = _run({"/": ("text/html", b'<html><script src="/assets/index.js"></script></html>'),
                    "/assets/index.js": ("application/javascript", _DEV_BUNDLE)})
    assert hit is True
    assert ev["signal"] == "hmr-runtime-in-bundle" and ev["marker"].startswith("$RefreshReg")


def test_a_versioned_script_url_keeps_its_query_when_fetched():
    """Vite serves pre-bundled deps as `/node_modules/.vite/deps/react.js?v=1a2b3c`, and cache-busted prod
    assets use the same shape. Dropping `?v=` fetches a path that may 404 — which would leave nothing
    inspected and report N/A, a dev build wearing a pass. The fixture serves the versioned URL ONLY."""
    hit, ev = _run({"/": ("text/html", b'<html><script src="/deps/react.js?v=1a2b3c"></script></html>'),
                    "/deps/react.js?v=1a2b3c": ("application/javascript", _DEV_BUNDLE)})
    assert hit is True, "query dropped on fetch -> %r" % ev
    assert ev["signal"] == "hmr-runtime-in-bundle"


# ------------------------------------------------------------------ must stay silent

def test_a_production_bundle_reads_clean():
    hit, ev = _run({"/": ("text/html", b'<html><script src="/assets/index-a1b2c3.js"></script></html>'),
                    "/assets/index-a1b2c3.js": ("application/javascript", _PROD_BUNDLE)})
    assert hit is False and ev["dev_build"] is False and ev["scripts_checked"] == 1


def test_a_page_that_merely_TALKS_about_vite_does_not_fire():
    """THE false-positive vector this probe is most exposed to. A tutorial, changelog or project write-up that
    shows `/@vite/client` in a code block is not a dev build — and hackathon submissions are full of write-ups.
    Matching is script-context only for exactly this reason."""
    page = (b'<html><body><h1>How our build works</h1>'
            b'<pre><code>&lt;script src="/@vite/client"&gt;&lt;/script&gt;</code></pre>'
            b'<p>We removed sockjs-node and webpack-dev-server when we shipped.</p>'
            b'<script src="/assets/app.js"></script></body></html>')
    hit, ev = _run({"/": ("text/html", page),
                    "/assets/app.js": ("application/javascript", _PROD_BUNDLE)})
    assert hit is False, "fired on prose mentioning an HMR path: %r" % ev


def test_a_dev_header_alone_never_fires():
    """Corroboration, not evidence. `vite`, `webpack-dev-server` and `werkzeug` all appear on production
    stacks, so the header is recorded and never fired on."""
    hit, ev = _run({"/": ("text/html", b'<html><script src="/assets/app.js"></script></html>'),
                    "/assets/app.js": ("application/javascript", _PROD_BUNDLE)},
                   headers={"X-Powered-By": "Vite", "Server": "webpack-dev-server/4.0"})
    assert hit is False
    assert ev["dev_header"] is True, "the signature should still be RECORDED"


def test_a_third_party_cdn_script_is_not_the_apps_build():
    """An off-origin script belongs to someone else; its contents are not evidence about this submission."""
    hit, _ = _run({"/": ("text/html",
                         b'<html><script src="https://cdn.example.test/react-refresh/runtime.js"></script>'
                         b'<script src="/assets/app.js"></script></html>'),
                   "/assets/app.js": ("application/javascript", _PROD_BUNDLE)})
    assert hit is False


# ------------------------------------------------------------------ N/A, not clean

def test_no_script_at_all_is_NA():
    verdict, ev = _run({"/": ("text/html", b"<html><body>static page</body></html>")})
    assert verdict is None and "references no script" in ev["na_reason"]


def test_scripts_that_cannot_be_inspected_are_NA_not_clean():
    """A catch-all SPA host serves the HTML shell where JS should be. We inspected nothing, so we must not
    report clean — that would be a false negative wearing a pass."""
    verdict, ev = _run({"/": ("text/html", b'<html><script src="/assets/app.js"></script></html>'),
                        "/assets/app.js": ("text/html", b"<html>shell</html>")})
    assert verdict is None and "no same-origin JavaScript" in ev["na_reason"]


def test_a_sub_path_deployment_is_graded_at_its_own_landing_page():
    """The most-repeated bug family in this codebase. An app served at /app must be inspected there, not at
    the origin root — resolving against '/' would grade the host's not-found shell."""
    hit, ev = _run({"/app": ("text/html", b'<html><script src="/@vite/client"></script></html>'),
                    "/": ("text/html", b"<html>404 not found</html>")}, landing="/app")
    assert hit is True and ev["signal"] == "hmr-client-script"
