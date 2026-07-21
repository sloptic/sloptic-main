"""Soft-404 — a nonexistent STATIC ASSET must return 404, never 2xx. Fires on a catch-all that serves
200 for a missing .js/.css/.png; clean when missing assets 404. The SPA cases lock the SPA-safety: a
correctly-configured SPA (routes -> 200 index, but assets -> 404) must NOT fire, while a misconfigured
one that serves index.html even for assets must."""
import http.server
import threading

import pytest

from hacklet_runner.discovery import _CATCHALL_PROBE
from hacklet_runner.net import make_client
from hacklet_runner.probes import http_soft_404


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            is_asset = path.rsplit(".", 1)[-1].lower() in ("js", "css", "png", "webp", "svg", "woff2")
            ctype, body = "text/html; charset=utf-8", b"<html>index</html>"
            if mode == "correct":                        # missing anything -> 404
                code = 404
            elif mode == "soft404":                      # missing anything -> 200 index shell (classic soft-404)
                code = 200
            elif mode == "spa_ok":                       # SPA done right: assets 404, routes 200 index
                code = 404 if is_asset else 200
            elif mode == "spa_broken":                   # SPA catch-all serves index even for assets
                code = 200
            elif mode == "asset_gen":                    # root dynamic-asset generator: any /<x>.svg -> 200 IMAGE
                code = 200
                if is_asset:
                    ctype, body = "image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'/>"
            elif mode == "html_notshell":                # 200 HTML, but the asset body != the root catch-all shell
                code = 200
                body = (b"<html>SHELL PAGE</html>" if path == _CATCHALL_PROBE
                        else b"<html>a totally different page body</html>")
            else:
                code = 404
            self.send_response(code)
            self.send_header("Content-Type", ctype)
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


def _ctx(url, client=None):
    return type("C", (), {"base_url": url, "headers": None, "client": client, "evidence": {}})()


@pytest.mark.parametrize("mode", ["soft404", "spa_broken"])
def test_soft_404_fires_on_2xx_for_missing_asset(server, mode):
    assert http_soft_404(_ctx(server(mode)), _Probe()) is True


@pytest.mark.parametrize("mode", ["correct", "spa_ok"])
def test_soft_404_clean_when_missing_asset_404s(server, mode):
    assert http_soft_404(_ctx(server(mode)), _Probe()) is False


def test_soft_404_ignores_generated_image_asset(server):
    # FP class: a root dynamic-asset generator (avatar / OG-image / placeholder answering /<anything>.svg|.png
    # with a generated 200 IMAGE) is a real asset, not a soft-404 shell -> must NOT fire (content-type not html)
    assert http_soft_404(_ctx(server("asset_gen")), _Probe()) is False


def test_soft_404_requires_body_to_match_root_shell(server):
    # with the live client available, a 200 HTML asset whose body does NOT match the root catch-all shell is
    # not the soft-404 shell -> must NOT fire (the sig gate, consistent with discovery's catch-all detector)
    url = server("html_notshell")
    with make_client(url, None) as client:
        assert http_soft_404(_ctx(url, client), _Probe()) is False


def test_soft_404_fires_when_html_body_matches_root_shell(server):
    # the classic SPA catch-all: the nonexistent asset AND the catch-all probe both return the SAME index
    # shell -> the body signature matches -> fires even with the live client + sig gate active
    url = server("soft404")
    with make_client(url, None) as client:
        assert http_soft_404(_ctx(url, client), _Probe()) is True
