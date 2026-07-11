"""Crash-resistance — malformed input must yield a graceful 4xx, not an unhandled 5xx. A fragile app
(500s on oversized input / malformed JSON) fires; a robust app (400s) stays clean."""
import http.server
import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import crash_resistance
from hacklet_runner.schema import Endpoint, Form, Profile


def _handler(crash: bool):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _s(self, code):
            self.send_response(code)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):
            u = urlparse(self.path)
            x = parse_qs(u.query).get("x", [""])[0]
            if u.path in ("/get",) and len(x) > 1000:
                self._s(500 if crash else 400)      # oversized: crash -> 5xx, robust -> 4xx
            else:
                self._s(200 if u.path == "/get" else 404)   # unknown/malformed paths -> graceful 404

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                json.loads(body)
                self._s(200)
            except Exception:
                self._s(500 if crash else 400)      # malformed JSON: crash -> 5xx, robust -> 4xx
    return _H


@pytest.fixture
def fragile():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(True))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def robust():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"max_attempts": 120}


def _ctx(url, **pk):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url, **pk),
                          "headers": None, "client": None, "evidence": {}})()


def test_crash_fires_on_oversized_input_5xx(fragile):
    assert crash_resistance(_ctx(fragile, forms=[Form("/get", "get", ["x"])]), _Probe()) is True


def test_crash_fires_on_malformed_json_5xx(fragile):
    ep = Endpoint(path="/post", method="post", raw_path="/post")
    assert crash_resistance(_ctx(fragile, endpoints=[ep]), _Probe()) is True


def test_crash_clean_on_robust_4xx(robust):
    assert crash_resistance(_ctx(robust, forms=[Form("/get", "get", ["x"])],
                                 endpoints=[Endpoint(path="/post", method="post", raw_path="/post")]),
                            _Probe()) is False
