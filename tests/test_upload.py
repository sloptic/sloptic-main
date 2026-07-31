"""Insecure file upload — a webshell that EXECUTES server-side is RCE; a store-but-serve-as-source
app (no execution) must stay clean, since the probe fires only on the executed salt-hash digest."""
import hashlib
import http.server
import re
import threading

import pytest

from sloptic.probes import file_upload
from sloptic.schema import Form, Profile

_STORE = {}   # basename -> the embedded salt (str) if the stored bytes look like an executable webshell, else None


def _basename_and_salt(body: bytes):
    m = re.search(rb'filename="([^"]*)"', body)
    name = (m.group(1).decode() if m else "").split("\x00")[0].split("/")[-1]
    is_shell = b"<?php" in body or b"getInstance" in body or b"BitConverter" in body   # php / jsp / aspx source
    sm = re.search(rb"hlup[0-9a-f]+", body)
    return name, (sm.group(0).decode() if (is_shell and sm) else None)


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        name, salt = _basename_and_salt(body)
        _STORE[name] = salt
        pfx = "/up/" if self.path == "/upload" else "/src/"   # /upload executes, /safe serves source
        self._send("saved to %s%s" % (pfx, name))

    def do_GET(self):
        if self.path.startswith("/up/"):                      # EXECUTES the shell -> outputs the salt's digest
            salt = _STORE.get(self.path[4:])
            self._send(hashlib.sha256(salt.encode()).hexdigest() if salt else "not found")
        elif self.path.startswith("/src/"):                   # serves the raw SOURCE (literal hash() call), never executes
            salt = _STORE.get(self.path[5:])
            self._send(("<?php echo hash('sha256','%s');?>" % salt) if salt else "not found")
        else:
            self._send("ok")


@pytest.fixture
def app():
    _STORE.clear()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {}


def _ctx(url, action):
    form = Form(action=action, method="post", fields=["uploaded"],
                enctype="multipart/form-data", file_fields=["uploaded"])
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url, forms=[form]),
                          "headers": None, "client": None, "evidence": {}})()


def test_file_upload_executes_webshell(app):
    ctx = _ctx(app, "/upload")
    assert file_upload(ctx, _Probe()) is True
    repro = ctx.evidence.get("repro")                 # the executing fetch is captured, replayable in Burp
    assert repro and repro["method"] == "GET"


def test_file_upload_clean_when_served_as_source(app):
    # stored + retrievable but NOT executed -> the source shows the literal hash() call, the digest never
    # appears -> clean (reflection of the payload cannot forge the salt's digest)
    assert file_upload(_ctx(app, "/safe"), _Probe()) is False


def test_file_upload_na_without_upload_form(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert file_upload(ctx, _Probe()) is None
