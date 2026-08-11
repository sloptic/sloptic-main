"""v2.0 Family 4: a web font without a non-blocking font-display (swap/optional/fallback) -> FOIT. Checks
@font-face (inline + same-origin CSS) and Google Fonts <link>s. A page with no web font is N/A; a page where
every web font sets a good display is clean."""
import http.server
import threading

import pytest

from sloptic.probes import font_display_missing
from sloptic.schema import Profile

_GF = "https://fonts.googleapis.com/css2?family=Roboto"
_FACE = "@font-face { font-family: X; src: url(/x.woff2) format('woff2'); %s }"

_PAGES = {
    "/gf-gap": '<html><head><link rel="stylesheet" href="%s"></head></html>' % _GF,
    "/gf-clean": '<html><head><link rel="stylesheet" href="%s&display=swap"></head></html>' % _GF,
    "/face-gap": "<html><head><style>%s</style></head></html>" % (_FACE % ""),
    "/face-clean": "<html><head><style>%s</style></head></html>" % (_FACE % "font-display: swap;"),
    "/na": "<html><head><style>body{font-family:system-ui}</style></head><body>hi</body></html>",
}


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = _PAGES.get(self.path.split("?")[0], "<html><body>ok</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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
    return type("P", (), {"probe": {"target": target}})()


def test_fires_on_google_fonts_without_display(app):
    assert font_display_missing(_ctx(app), _probe("/gf-gap")) is True


def test_clean_on_google_fonts_with_display_swap(app):
    assert font_display_missing(_ctx(app), _probe("/gf-clean")) is False


def test_fires_on_font_face_without_font_display(app):
    ctx = _ctx(app)
    assert font_display_missing(ctx, _probe("/face-gap")) is True
    assert ctx.evidence["web_fonts"] == 1


def test_clean_on_font_face_with_font_display_swap(app):
    assert font_display_missing(_ctx(app), _probe("/face-clean")) is False


def test_na_when_no_web_font(app):
    assert font_display_missing(_ctx(app), _probe("/na")) is None
