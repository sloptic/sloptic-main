"""Mixed content — an HTTPS page loading an http:// subresource. Which refs count is a pure function
(locked directly); the https-gate (N/A over plain http) needs no server; the full fetch path is locked
end-to-end against a real self-signed HTTPS server (skipped where openssl is unavailable)."""
import http.server
import shutil
import ssl
import subprocess
import threading

import pytest

from hacklet_runner.probes import _http_subresources, mixed_content

BASE = "https://site.example/page"


def test_detects_active_and_passive_http_subresources():
    assert _http_subresources('<script src="http://cdn.x/a.js"></script>', BASE) == ["http://cdn.x/a.js"]
    assert _http_subresources('<img src="http://cdn.x/i.png">', BASE) == ["http://cdn.x/i.png"]
    assert _http_subresources('<link rel="stylesheet" href="http://cdn.x/s.css">', BASE) == ["http://cdn.x/s.css"]
    assert _http_subresources('<iframe src="http://cdn.x/f"></iframe>', BASE) == ["http://cdn.x/f"]


def test_ignores_secure_relative_and_navigation():
    html = ('<script src="https://cdn.x/a.js"></script>'                 # already https
            '<img src="//cdn.x/i.png">'                                  # protocol-relative -> inherits https
            '<script src="/local.js"></script>'                          # relative -> inherits https
            '<a href="http://other/page">nav</a>'                        # a link is not a loaded subresource
            '<link rel="canonical" href="http://site.example/page">')    # canonical is metadata, not loaded
    assert _http_subresources(html, BASE) == []


def test_na_when_page_is_not_https():
    # the scheme gate returns N/A before any fetch -> no server needed
    ctx = type("C", (), {"base_url": "http://127.0.0.1:1", "headers": None, "client": None, "evidence": {}})()
    assert mixed_content(ctx, type("P", (), {"probe": {}})()) is None


# ---- end-to-end over a real self-signed HTTPS server ----
HAVE_OPENSSL = shutil.which("openssl") is not None


@pytest.fixture
def https_serve(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(crt),
                    "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1"], check=True, capture_output=True)
    servers = []

    def _make(html):
        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                b = html.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(crt), str(key))
        srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "https://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {"target": "/"}


def _ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()


@pytest.mark.skipif(not HAVE_OPENSSL, reason="no openssl to mint a self-signed cert")
def test_fires_end_to_end_over_https(https_serve):
    url = https_serve('<html><body><script src="http://cdn.evil/x.js"></script></body></html>')
    assert mixed_content(_ctx(url), _Probe()) is True


@pytest.mark.skipif(not HAVE_OPENSSL, reason="no openssl to mint a self-signed cert")
def test_clean_end_to_end_when_all_secure(https_serve):
    url = https_serve('<html><body><script src="https://cdn/x.js"></script><img src="/y.png"></body></html>')
    assert mixed_content(_ctx(url), _Probe()) is False
