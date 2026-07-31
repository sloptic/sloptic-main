"""XXE — the XML parser resolves an external entity to an attacker URL (confirmed out-of-band); an app
that ignores entities stays clean."""
import http.server
import re
import threading

import httpx
import pytest

from sloptic.probes import xxe
from sloptic.schema import Form, Profile


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", "replace")
        out = b"processed"
        if self.path == "/xml":                               # VULNERABLE OOB: fetches external entities
            m = re.search(r'SYSTEM\s+"([^"]+)"', body)
            if m:
                try:
                    httpx.get(m.group(1), timeout=0.6)
                except Exception:
                    pass
        elif self.path == "/xml-inband":                      # VULNERABLE in-band: resolves a file:// entity and
            #  REFLECTS the file's content (classic in-band XXE; works on egress-blocked hosts, no callback needed)
            m = re.search(r'SYSTEM\s+"file://([^"]+)"', body)
            if m and "passwd" in m.group(1):
                out = b"<r>root:x:0:0:root:/root:/bin/bash</r>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"oob_wait": 3}


def _ctx(url, action):
    prof = Profile(base_url=url, forms=[Form(action=action, method="post", fields=["data"])])
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def test_xxe_fires_on_external_entity_resolution(app):
    assert xxe(_ctx(app, "/xml"), _Probe()) is True


def test_xxe_fires_in_band_on_file_read(app):
    # an egress-blocked host can't send an OOB callback, but a resolved file:// entity reflects /etc/passwd
    # content straight back -> in-band XXE, deterministic and FP-resistant (the app cannot fabricate the file).
    assert xxe(_ctx(app, "/xml-inband"), _Probe()) is True


def test_xxe_clean_when_entities_ignored(app):
    assert xxe(_ctx(app, "/safe"), _Probe()) is False


def test_xxe_na_without_post_endpoint(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert xxe(ctx, _Probe()) is None
