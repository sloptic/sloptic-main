"""End-to-end pipeline over TLS -- the coverage the plain-http references can't give. RemoteDeployer
points the real pipeline (deploy health-gate -> discover -> probe) at a running self-signed HTTPS
target; the https-gated mixed-content probe fires/clears end-to-end. Proves the grader connects to a
self-signed cert (verify=False) all the way through. Skipped without openssl to mint the cert."""
import http.server
import pathlib
import shutil
import ssl
import subprocess
import threading

import pytest

from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import RemoteDeployer
from hacklet_runner.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
HAVE_OPENSSL = shutil.which("openssl") is not None
pytestmark = pytest.mark.skipif(not HAVE_OPENSSL, reason="no openssl to mint a self-signed cert")

_HEAD = ('<!doctype html><html lang="en"><head><title>t</title>'
         '<meta name="viewport" content="width=device-width"><meta name="description" content="d"></head>')
MIXED = _HEAD + '<body><h1>hi</h1><script src="http://cdn.insecure/x.js"></script></body></html>'
SECURE = MIXED.replace("http://cdn.insecure/x.js", "https://cdn.secure/x.js")


@pytest.fixture
def https_target(tmp_path):
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


def _mixed_catalog():
    return [p for p in load_catalog(CATALOG) if p.id == "sec-mixed-001"]


def test_pipeline_grades_https_target_mixed_content_fires(https_target):
    report = run(RemoteDeployer(https_target(MIXED)), _mixed_catalog())
    assert report.by_id["sec-mixed-001"] == "slop_detected"   # http:// subresource on an https page


def test_pipeline_grades_https_target_clean_when_secure(https_target):
    report = run(RemoteDeployer(https_target(SECURE)), _mixed_catalog())
    assert report.by_id["sec-mixed-001"] == "clean"           # every subresource https -> no mixed content
