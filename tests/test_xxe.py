"""XXE — the XML parser resolves an external entity to an attacker URL (confirmed out-of-band); an app
that ignores entities stays clean."""
import http.server
import re
import threading

import httpx
import pytest

from hacklet_runner.probes import xxe
from hacklet_runner.schema import Form, Profile


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", "replace")
        if self.path == "/xml":                               # VULNERABLE: resolves external entities
            m = re.search(r'SYSTEM\s+"([^"]+)"', body)
            if m:
                try:
                    httpx.get(m.group(1), timeout=0.6)
                except Exception:
                    pass
        out = b"processed"
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


def test_xxe_clean_when_entities_ignored(app):
    assert xxe(_ctx(app, "/safe"), _Probe()) is False


def test_xxe_na_without_post_endpoint(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert xxe(ctx, _Probe()) is None
