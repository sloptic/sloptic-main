"""HTTP response splitting — CRLF in a param reflected into a response header. Fires when the injected
marker header appears in the response; clean when the app rejects CRLF. N/A with no input surface."""
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import http_response_splitting
from hacklet_runner.schema import Endpoint, Profile


def _handler(sanitize):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            dest = parse_qs(urlparse(self.path).query).get("next", [""])[0]
            if sanitize and ("\r" in dest or "\n" in dest):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(302)
            self.send_header("Location", dest)     # raw reflection -> CRLF splits the response
            self.send_header("Content-Length", "0")
            self.end_headers()
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(sanitize):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(sanitize))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {}


def _ctx(url):
    ep = Endpoint(path="/", method="get", query_params=["next"], raw_path="/")
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url, endpoints=[ep]),
                          "headers": None, "client": None, "evidence": {}})()


def test_response_splitting_fires_on_raw_reflection(server):
    assert http_response_splitting(_ctx(server(sanitize=False)), _Probe()) is True


def test_response_splitting_clean_when_crlf_rejected(server):
    assert http_response_splitting(_ctx(server(sanitize=True)), _Probe()) is False
