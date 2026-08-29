"""HTTP conformance — an HTML response must declare a charset, in the Content-Type header OR a <meta> in the
document's first 1024 bytes (the browser's encoding-prescan window). Fires only when NEITHER declares one;
clean when either does; N/A on a non-HTML response (no page charset to declare)."""
import http.server
import threading

import pytest

from sloptic.probes import http_conformance


def _handler(ctype, body=None):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = body if body is not None else (b'{"ok":1}' if "json" in ctype else b"<html><body>ok</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(ctype, body=None):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(ctype, body))
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


def test_conformance_fires_on_html_without_charset(server):
    # no header charset AND no <meta> charset -> the browser must guess -> fires
    assert http_conformance(_ctx(server("text/html")), _Probe()) is True


def test_conformance_clean_with_charset(server):
    assert http_conformance(_ctx(server("text/html; charset=utf-8")), _Probe()) is False


def test_conformance_clean_with_meta_charset(server):
    # THE 89%-FP fix: charset declared by <meta charset> (no header charset) is a valid declaration -> clean
    body = b'<!doctype html><html><head><meta charset="utf-8"><title>t</title></head><body>ok</body></html>'
    assert http_conformance(_ctx(server("text/html", body)), _Probe()) is False


def test_conformance_clean_with_meta_http_equiv_content_type(server):
    # the legacy form is equally valid
    body = (b'<!doctype html><html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
            b'</head><body>ok</body></html>')
    assert http_conformance(_ctx(server("text/html", body)), _Probe()) is False


def test_conformance_fires_when_meta_charset_is_beyond_the_prescan_window(server):
    # a <meta charset> past the first 1024 bytes is NOT honored by the browser prescan -> still a real ambiguity
    # -> fires (the v18 case with charset declared at byte ~18k).
    body = b"<!doctype html><html><head>" + b"<!-- pad -->" * 120 + b'<meta charset="utf-8"></head><body>x</body></html>'
    assert len(b"<!doctype html><html><head>" + b"<!-- pad -->" * 120) > 1024   # guard: padding really exceeds the window
    assert http_conformance(_ctx(server("text/html", body)), _Probe()) is True


def test_conformance_na_on_non_html(server):
    assert http_conformance(_ctx(server("application/json")), _Probe()) is None
