"""HTTP conformance — an HTML response must declare a charset. Fires when text/html omits charset;
clean when it's present; N/A on a non-HTML response (no page charset to declare)."""
import http.server
import threading

import pytest

from hacklet_runner.probes import http_conformance


def _handler(ctype):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = b'{"ok":1}' if "json" in ctype else b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(ctype):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(ctype))
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
    assert http_conformance(_ctx(server("text/html")), _Probe()) is True


def test_conformance_clean_with_charset(server):
    assert http_conformance(_ctx(server("text/html; charset=utf-8")), _Probe()) is False


def test_conformance_na_on_non_html(server):
    assert http_conformance(_ctx(server("application/json")), _Probe()) is None
