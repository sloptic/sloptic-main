"""No-TLS origin -- a PUBLIC origin served over plain http:// that doesn't upgrade to https. The public-host
fire path can't be exercised against a loopback server (127.0.0.1 is always "local"), so the verdict logic is
unit-tested via the pure _no_tls_decision helper; the live probe is checked for the local-exempt / N/A path."""
import http.server
import threading

import pytest

from sloptic.probes import _is_local_host, _no_tls_decision, no_tls_origin
from sloptic.schema import Profile


def test_local_and_private_hosts_are_local():
    for h in ("localhost", "127.0.0.1", "127.1.2.3", "0.0.0.0", "10.0.0.5",
              "192.168.1.9", "172.16.4.2", "app.local", "preview.test"):
        assert _is_local_host(h), h


def test_public_hosts_are_not_local():
    for h in ("example.com", "myapp.vercel.app", "93.184.216.34", "172.15.0.1", "sub.domain.io"):
        assert not _is_local_host(h), h


def test_decision_public_http_no_upgrade_is_slop():
    assert _no_tls_decision("http://example.com", 200, "") is True
    assert _no_tls_decision("http://example.com", 302, "http://example.com/x") is True   # redirects but stays http


def test_decision_http_upgrading_to_https_is_clean():
    assert _no_tls_decision("http://example.com", 301, "https://example.com/") is False


def test_decision_blocked_or_errored_status_is_na():
    # a WAF 403 / rate-limit 429 / server error 5xx / not-found masks the real TLS behavior (netlify's
    # http->https 301 came back as a 403 to the probe) -> can't assess -> N/A, not a false "no TLS" fire
    for st in (401, 403, 404, 429, 500, 503):
        assert _no_tls_decision("http://example.com", st, "") is None, st


def test_decision_https_origin_is_na():
    assert _no_tls_decision("https://example.com", 200, "") is None


def test_decision_local_origin_is_na():
    assert _no_tls_decision("http://localhost:3000", 200, "") is None
    assert _no_tls_decision("http://192.168.0.4", 200, "") is None


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = b"<h1>ok</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_probe_na_on_a_local_http_target(app):
    # a loopback target is http by nature -> not a deploy failure -> N/A (and no network call is made)
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app),
                         "headers": None, "client": None, "evidence": {}})()
    assert no_tls_origin(ctx, type("P", (), {"probe": {"target": "/"}})()) is None
