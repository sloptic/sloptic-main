"""Host-header injection — a client-controlled Host reflected into a redirect Location / URL. Fires when
the marker host comes back; clean when the app builds the redirect from a fixed value."""
import http.server
import threading

import pytest

from hacklet_runner.probes import host_header_injection
from hacklet_runner.schema import Profile


def _handler(reflect):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/account":
                loc = "http://" + self.headers.get("Host", "x") + "/login" if reflect else "/login"
                self.send_response(302)
                self.send_header("Location", loc)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            b = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(reflect):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(reflect))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {}


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": None, "evidence": {}})()


def test_host_header_fires_when_reflected(server):
    assert host_header_injection(_ctx(server(True)), _Probe()) is True


def test_host_header_clean_when_fixed(server):
    assert host_header_injection(_ctx(server(False)), _Probe()) is False
