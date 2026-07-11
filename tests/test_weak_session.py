"""Weak / predictable session IDs — a sequential (or short/numeric) token is guessable; a long random
token reads clean; no token issued -> N/A."""
import http.server
import threading
from urllib.parse import urlparse

import pytest

from hacklet_runner.probes import weak_session_id
from hacklet_runner.schema import Profile

_N = {"c": 0}


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        cookie = None
        if "weaksession" in path:                       # incrementing counter -> sequential/numeric
            _N["c"] += 1
            cookie = "sessionid=%d" % _N["c"]
        elif "strongsession" in path:                   # long random-looking hex -> strong
            cookie = "sessionid=9f2c1a7be4d80356af19c2e7b4d6108f"
        body = b"ok"
        self.send_response(200)
        if cookie:
            self.send_header("Set-Cookie", cookie + "; Path=/")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def app():
    _N["c"] = 0
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {}


def _ctx(url, routes):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url, routes=routes),
                          "headers": None, "client": None, "evidence": {}})()


def test_weak_session_sequential(app):
    assert weak_session_id(_ctx(app, ["/weaksession"]), _Probe()) is True


def test_weak_session_clean_on_strong_token(app):
    assert weak_session_id(_ctx(app, ["/strongsession"]), _Probe()) is False


def test_weak_session_na_when_no_token(app):
    assert weak_session_id(_ctx(app, ["/plain"]), _Probe()) is None
