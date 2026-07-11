"""Caching — a static asset must be cacheable AND revalidatable. The probe fires when an asset ships no
cache validators, says no-store, or advertises a validator the server won't honor with a 304; it stays
clean when the asset is properly cacheable, and is N/A when the page references no static asset. One
reference server per technique = a CI lock on each, per the comprehensive-coverage principle."""
import http.server
import threading

import pytest

from hacklet_runner.probes import caching_ineffective

HOME = b'<html><body><script src="/app.js"></script></body></html>'
ASSET = b'console.log(1);\n'
ETAG = '"v1"'


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _w(self, code, body, ctype, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/":
                home = b"<html><body><p>hi</p></body></html>" if mode == "no_assets" else HOME
                return self._w(200, home, "text/html; charset=utf-8")
            if self.path == "/app.js":
                if mode == "robust" and self.headers.get("If-None-Match") == ETAG:
                    return self._w(304, b"", "application/javascript",
                                   {"ETag": ETAG, "Cache-Control": "public, max-age=3600"})
                extra = {
                    "none": {},                                     # no caching affordance at all
                    "no_store": {"Cache-Control": "no-store"},       # actively un-cacheable
                    "decorative": {"ETag": ETAG},                    # advertises a validator, never 304s
                    "robust": {"Cache-Control": "public, max-age=3600", "ETag": ETAG},
                }[mode]
                return self._w(200, ASSET, "application/javascript", extra)
            self.send_response(404)
            self.end_headers()
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
    probe = {"max_attempts": 20, "target": "/"}


def _ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()


@pytest.mark.parametrize("mode", ["none", "no_store", "decorative"])
def test_caching_fires_on_uncacheable_asset(server, mode):
    assert caching_ineffective(_ctx(server(mode)), _Probe()) is True


def test_caching_clean_on_cacheable_asset(server):
    assert caching_ineffective(_ctx(server("robust")), _Probe()) is False


def test_caching_na_when_no_static_assets(server):
    assert caching_ineffective(_ctx(server("no_assets")), _Probe()) is None
