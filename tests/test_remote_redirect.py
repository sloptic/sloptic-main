"""RemoteDeployer redirect settling + http fallback.

Two behaviours a redirecting or http-only target needs. A same-host http->https upgrade is adopted as the
graded origin, so probes that do not follow redirects stop under-grading it and the hosted worker's origin
scope stops refusing the port change. And an https target whose connection fails outright falls back to http
once, so an http-only app (or one a caller defaulted to https) is graded instead of called dead.
"""
import http.server
import socketserver
import threading

import pytest

from sloptic.deploy import RemoteDeployer, _http_variant, _settle_origin


# ── the settle decision (pure) ──────────────────────────────────────────────────────────────────────────
def test_a_same_host_https_upgrade_is_adopted():
    # the app answered over TLS on the same host: grade https, keep the path
    assert _settle_origin("http://app.com/portal.php", "https://app.com/portal.php") == "https://app.com/portal.php"
    assert _settle_origin("http://app.com", "https://app.com/") == "https://app.com"


def test_a_plain_http_origin_that_does_not_upgrade_is_left_alone():
    # no upgrade -> stays http, so no_tls_origin (sec-tls-001) still fires on it
    assert _settle_origin("http://app.com", "http://app.com/home") == "http://app.com"


def test_an_https_origin_is_never_downgraded_or_moved():
    assert _settle_origin("https://app.com", "https://app.com/home") == "https://app.com"


def test_a_redirect_to_a_different_host_is_not_adopted():
    # a link shortener / parked domain bouncing elsewhere: grading the destination would grade a DIFFERENT
    # app than the one submitted, which is never what the caller asked for
    assert _settle_origin("http://bit.ly/x", "https://someone-elses-app.com/landing") == "http://bit.ly/x"
    assert _settle_origin("https://a.com", "https://b.com") == "https://a.com"


def test_http_variant_only_exists_for_an_https_target():
    assert _http_variant("https://app.com") == "http://app.com"
    assert _http_variant("http://app.com") is None


# ── the http fallback (live, loopback) ──────────────────────────────────────────────────────────────────
class _Ok(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<!doctype html><html><body>plain http app</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def plain_http_server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Ok)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()


def test_https_target_on_an_http_only_app_falls_back_to_http(plain_http_server):
    """An app served only over http, reached as https (the web layer defaults a bare host to https), fails
    the TLS handshake on every https attempt and must be graded over http rather than called dead."""
    port = plain_http_server
    handle = RemoteDeployer(f"https://127.0.0.1:{port}", health_timeout=1.5).deploy()
    assert handle.base_url == f"http://127.0.0.1:{port}"     # fell back to http
    assert handle.submitted_url == f"https://127.0.0.1:{port}"   # audit trail keeps what was asked for


def test_a_reachable_target_records_the_submitted_url(plain_http_server):
    port = plain_http_server
    handle = RemoteDeployer(f"http://127.0.0.1:{port}").deploy()
    assert handle.base_url == f"http://127.0.0.1:{port}"
    assert handle.submitted_url == f"http://127.0.0.1:{port}"


def test_a_truly_dead_target_still_raises(plain_http_server):
    # nothing on this port at all: no https, no http -> DNF as before, not a spurious rescue
    with pytest.raises(RuntimeError, match="did not respond"):
        RemoteDeployer("https://127.0.0.1:1", health_timeout=0.6).deploy()
