"""Insecure file upload — a webshell that EXECUTES server-side is RCE; a store-but-serve-as-source
app (no execution) must stay clean, since the probe fires only on the executed arithmetic marker."""
import http.server
import re
import threading

import pytest

from hacklet_runner.probes import file_upload
from hacklet_runner.schema import Form, Profile

_STORE = {}   # basename -> True if the stored bytes look like PHP


def _basename_and_php(body: bytes):
    m = re.search(rb'filename="([^"]*)"', body)
    name = (m.group(1).decode() if m else "").split("\x00")[0].split("/")[-1]
    return name, (b"<?php" in body)


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
        name, is_php = _basename_and_php(body)
        _STORE[name] = is_php
        pfx = "/up/" if self.path == "/upload" else "/src/"   # /upload executes, /safe serves source
        self._send("saved to %s%s" % (pfx, name))

    def do_GET(self):
        if self.path.startswith("/up/"):                      # executes PHP
            self._send("hlup49x" if _STORE.get(self.path[4:]) else "not found")
        elif self.path.startswith("/src/"):                   # serves the raw source, never executes
            self._send("<?php echo 'hlup'.(7*7).'x'; ?>" if _STORE.get(self.path[5:]) else "not found")
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
    # stored + retrievable but NOT executed -> the arithmetic marker never resolves -> clean
    assert file_upload(_ctx(app, "/safe"), _Probe()) is False


def test_file_upload_na_without_upload_form(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert file_upload(ctx, _Probe()) is None
