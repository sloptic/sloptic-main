"""Crash-resistance — malformed input must yield a graceful 4xx, not an unhandled 5xx. A fragile app
(500s on oversized input / malformed JSON) fires; a robust app (400s) stays clean."""
import http.server
import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from sloptic.net import make_client
from sloptic.probes import crash_resistance
from sloptic.schema import Endpoint, Form, Profile


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


# --- decode-path branch (v20): only an HONEST host, and a 500 specifically (not gateway 502/503) ---

_DECODE_ESCAPES = ("%ff", "%c0", "%00", "%e0")


def _decode_handler(status, catchall):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _s(self, code, body=b"ok", ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            low = self.path.lower()
            if any(x in low for x in _DECODE_ESCAPES):
                self._s(status)                                    # the router's status on a decode-crashing path
            elif catchall:
                self._s(200, b"<html>shell</html>", "text/html")   # catch-all: a 200 shell for anything else
            else:
                self._s(404)                                       # honest host: real 404 for unknown paths
    return _H


@pytest.fixture
def decode_server():
    servers = []

    def _make(status, catchall=False):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _decode_handler(status, catchall))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


def test_decode_path_fires_on_honest_500(decode_server):
    # honest host (real 404s), the app router 500s on a malformed encoding -> a real unhandled crash
    assert crash_resistance(_ctx(decode_server(500)), _Probe()) is True


def test_decode_path_ignores_gateway_5xx(decode_server):
    # a 502/503 is the proxy/CDN rejecting the malformed URL, not the app crashing -> must NOT fire
    assert crash_resistance(_ctx(decode_server(502)), _Probe()) is False
    assert crash_resistance(_ctx(decode_server(503)), _Probe()) is False


def test_decode_path_skipped_on_catch_all_host(decode_server):
    # a catch-all/builder host: a decode 5xx is the platform edge, not the app's router -> branch skipped -> N/A
    url = decode_server(500, catchall=True)
    with make_client(url, None) as client:
        ctx = type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                             "headers": None, "client": client, "evidence": {}})()
        assert crash_resistance(ctx, _Probe()) is None


# --- v20 follow-up: base44 vendor-namespace skip (FP) + real-server catch-all recovery (FN) ---

def test_vendor_platform_namespace_is_skipped():
    from sloptic.probes import _VENDOR_PLATFORM_NS
    # base44's managed platform API: a 5xx there is the vendor's SDK, not the participant's endpoint -> skip
    assert _VENDOR_PLATFORM_NS.search("/api/apps/68d9abc0123456789/entities/Booking")
    assert _VENDOR_PLATFORM_NS.search("/api/apps/0123456789abcdef/analytics/track/batch")
    # a real participant endpoint must NOT be skipped
    assert not _VENDOR_PLATFORM_NS.search("/api/bookings/end")
    assert not _VENDOR_PLATFORM_NS.search("/api/apps/list")     # no hex app-id segment


def test_real_server_hosts_recover_catch_all_crashers():
    from sloptic.probes import _REAL_SERVER_HOSTS
    # real-server PaaS: the catch-all IS the participant's own router -> the decode branch should still run there
    for h in ("langtour-production.up.railway.app", "x--y.modal.run", "app.onrender.com", "svc.fly.dev", "api.run.app"):
        assert h.endswith(_REAL_SERVER_HOSTS), h
    # static-builder / SPA hosts must NOT be recovered (their catch-all is a platform edge, not the app's router)
    for h in ("foo.lovable.app", "bar.retool.app", "baz.netlify.app", "127.0.0.1"):
        assert not h.endswith(_REAL_SERVER_HOSTS), h
