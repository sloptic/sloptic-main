"""qa-deeplink-001: on a catch-all SPA host, a route loaded DIRECTLY must render its own content, not the
fallback. A broken app (router ignores the URL -> every route renders the same) fires; an app that paints
route-specific content reads clean. Needs a headless browser."""
import http.server
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import browser  # noqa: E402
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import deep_link_shell  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402

# broken: the client IGNORES the URL and always paints the same view (every route == fallback)
_BROKEN_JS = "document.getElementById('app').innerHTML = 'This is the home welcome dashboard about page content view';"
# ok: the client paints route-specific content from the path
_OK_JS = "document.getElementById('app').innerHTML = 'This is the ' + location.pathname.replace(/\\//g,' ') + ' page content view here';"


def _make_app(mode):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):     # catch-all: 200 HTML shell for EVERY path
            js = _BROKEN_JS if mode == "broken" else _OK_JS
            body = ("<html><body><div id='app'></div><script>%s</script></body></html>" % js).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def _serve(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _P:
    probe = {}


def _run(mode, routes=("/dashboard", "/about")):
    srv = _serve(mode)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
               Profile(base_url=url, routes=["/"] + list(routes)), None)
    try:
        return deep_link_shell(ctx, _P())
    finally:
        ctx.client.close()
        srv.shutdown()


browsermark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@browsermark
def test_fires_when_route_renders_only_the_fallback():
    assert _run("broken") is True


@browsermark
def test_clean_when_route_renders_its_own_content():
    assert _run("ok") is False


@browsermark
def test_na_without_a_non_root_route():
    assert _run("broken", routes=()) is None      # only "/" -> nothing to deep-link test


def test_na_when_routes_are_only_api_or_assets():
    # /api/* and media aren't client VIEW routes (an API path renders the shell CORRECTLY) -> filtered out ->
    # nothing left to deep-link test -> N/A, not a fire. No browser needed (filtered before the render).
    assert _run("broken", routes=("/api/broadcast", "/v1/accounts", "/hero/clip.mp4")) is None
