"""Unminified CSS/JS shipped to prod -- a sizeable SAME-ORIGIN asset with formatted (not packed) source.
Cross-origin CDN files are excluded; small files are skipped; a page with no sizeable same-origin asset is N/A."""
import http.server
import threading

import pytest

from sloptic.probes import _minified, _same_origin_assets, unminified_assets
from sloptic.schema import Profile

_MINJS = "var x=" + "1+" * 6000 + "1;"                                      # one long line (~12KB) -> minified
_PRETTYJS = "\n".join("  var line_%d = %d;" % (i, i * 7) for i in range(1200))   # ~26KB, ~22 chars/line -> not


def test_minified_detects_packed_vs_formatted_source():
    assert _minified(_MINJS) is True
    assert _minified(_PRETTYJS) is False


def test_same_origin_assets_excludes_cross_origin_and_non_assets():
    html = ('<script src="/static/app.js?v=abc"></script>'
            '<script src="https://cdn.other.io/lib.js"></script>'          # cross-origin -> excluded
            '<link rel="stylesheet" href="/style.css">'
            '<link rel="icon" href="/fav.png">')                          # not a stylesheet -> excluded
    got = _same_origin_assets(html, "https://app.example.com/")
    assert set(got) == {"https://app.example.com/static/app.js?v=abc", "https://app.example.com/style.css"}


# ---- the probe end to end ---------------------------------------------------------------------------

_PAGES = {
    "/gap": '<html><head><script src="/pretty.js"></script></head></html>',
    "/clean": '<html><head><script src="/min.js"></script></head></html>',
    "/na": '<html><head><script src="/tiny.js"></script></head></html>',
}
_ASSETS = {"/pretty.js": _PRETTYJS, "/min.js": _MINJS, "/tiny.js": "var a=1;"}


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in _ASSETS:
            body, ct = _ASSETS[path].encode(), "application/javascript"
        else:
            body, ct = _PAGES.get(path, "<html><body>ok</body></html>").encode(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": None, "evidence": {}})()


def _probe(target):
    return type("P", (), {"probe": {"target": target, "max_attempts": 6}})()


def test_fires_on_unminified_same_origin_asset(app):
    ctx = _ctx(app)
    assert unminified_assets(ctx, _probe("/gap")) is True
    assert ctx.evidence["unminified"] == [app + "/pretty.js"] and ctx.evidence["assets_checked"] == 1


def test_clean_when_asset_is_minified(app):
    assert unminified_assets(_ctx(app), _probe("/clean")) is False


def test_na_when_only_small_assets(app):
    assert unminified_assets(_ctx(app), _probe("/na")) is None
