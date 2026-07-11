"""SSRF — the server fetches an attacker-supplied URL (confirmed out-of-band via the collaborator);
an app that never fetches the param stays clean."""
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from hacklet_runner.probes import ssrf
from hacklet_runner.schema import Endpoint, Profile


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        url = parse_qs(u.query).get("url", [""])[0]
        if u.path == "/fetch" and url.startswith("http"):     # VULNERABLE: fetches the supplied URL
            try:
                httpx.get(url, timeout=0.6)
            except Exception:
                pass
        body = b"done"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"oob_wait": 3}


def _ctx(url, path):
    prof = Profile(base_url=url, endpoints=[Endpoint(path=path, method="get", query_params=["url"], raw_path=path)])
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def test_ssrf_fires_on_server_side_fetch(app):
    assert ssrf(_ctx(app, "/fetch"), _Probe()) is True


def test_ssrf_clean_when_url_not_fetched(app):
    assert ssrf(_ctx(app, "/safe"), _Probe()) is False


def test_ssrf_na_without_url_param(app):
    prof = Profile(base_url=app, endpoints=[Endpoint(path="/x", method="get", query_params=["name"], raw_path="/x")])
    ctx = type("C", (), {"base_url": app, "profile": prof, "headers": None, "client": None, "evidence": {}})()
    assert ssrf(ctx, _Probe()) is None
