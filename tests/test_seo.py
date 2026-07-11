"""SEO/meta — objective presence checks for viewport + description. Fires when either is missing; clean
when both are present; N/A on a non-HTML response."""
import http.server
import threading

import pytest

from hacklet_runner.probes import seo_meta_missing

VIEWPORT = '<meta name="viewport" content="width=device-width, initial-scale=1">'
DESC = '<meta name="description" content="a page">'
_BODY = {
    "missing_viewport": "<html><head><title>t</title>" + DESC + "</head><body>x</body></html>",
    "missing_desc": "<html><head><title>t</title>" + VIEWPORT + "</head><body>x</body></html>",
    "both": "<html><head><title>t</title>" + VIEWPORT + DESC + "</head><body>x</body></html>",
}


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if mode == "json":
                b, ctype = b'{"ok":true}', "application/json"
            else:
                b, ctype = _BODY[mode].encode(), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(mode):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(mode))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {"target": "/"}


def _ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()


@pytest.mark.parametrize("mode", ["missing_viewport", "missing_desc"])
def test_seo_fires_when_a_meta_is_missing(server, mode):
    assert seo_meta_missing(_ctx(server(mode)), _Probe()) is True


def test_seo_clean_when_both_present(server):
    assert seo_meta_missing(_ctx(server("both")), _Probe()) is False


def test_seo_na_on_non_html(server):
    assert seo_meta_missing(_ctx(server("json")), _Probe()) is None
