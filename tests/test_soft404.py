"""Soft-404 — a nonexistent STATIC ASSET must return 404, never 2xx. Fires on a catch-all that serves
200 for a missing .js/.css/.png; clean when missing assets 404. The SPA cases lock the SPA-safety: a
correctly-configured SPA (routes -> 200 index, but assets -> 404) must NOT fire, while a misconfigured
one that serves index.html even for assets must."""
import http.server
import threading

import pytest

from hacklet_runner.probes import http_soft_404


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            is_asset = path.rsplit(".", 1)[-1].lower() in ("js", "css", "png", "webp", "svg", "woff2")
            code = {
                "correct": 404,                          # missing anything -> 404
                "soft404": 200,                          # missing anything -> 200 (classic soft-404)
                "spa_ok": 404 if is_asset else 200,      # SPA done right: assets 404, routes 200 index
                "spa_broken": 200,                       # SPA catch-all serves index even for assets
            }[mode]
            body = b"<html>index</html>"
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
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
    probe = {}


def _ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()


@pytest.mark.parametrize("mode", ["soft404", "spa_broken"])
def test_soft_404_fires_on_2xx_for_missing_asset(server, mode):
    assert http_soft_404(_ctx(server(mode)), _Probe()) is True


@pytest.mark.parametrize("mode", ["correct", "spa_ok"])
def test_soft_404_clean_when_missing_asset_404s(server, mode):
    assert http_soft_404(_ctx(server(mode)), _Probe()) is False
