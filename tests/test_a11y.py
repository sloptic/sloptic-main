"""Accessibility hard-fails — objective WCAG pass/fail checks read from static HTML (no browser). One
reference document per technique (missing lang / alt / control name / title / contrast below the 3:1
floor) locks each in CI; a fully-accessible document stays clean. Each fault modifies exactly one aspect
of CLEAN so the failing check is isolated."""
import http.server
import threading

import pytest

from hacklet_runner.probes import a11y_hard_fails

CLEAN = ('<!doctype html><html lang="en"><head><title>ok</title></head><body>'
         '<h1>hi</h1><img src="/a.png" alt="a">'
         '<form><label for="q">Query</label><input id="q" name="q"></form>'
         '</body></html>')
FAULTS = {
    "lang": CLEAN.replace('<html lang="en">', "<html>"),
    "alt": CLEAN.replace('<img src="/a.png" alt="a">', '<img src="/a.png">'),
    "title": CLEAN.replace("<head><title>ok</title></head>", "<head></head>"),
    "label": CLEAN.replace('<form><label for="q">Query</label><input id="q" name="q"></form>',
                           '<form><input name="q"></form>'),
    "contrast": CLEAN.replace("<h1>hi</h1>",
                              '<h1>hi</h1><p style="color:#999;background:#aaa">low contrast</p>'),
}


def _handler(body):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    return _H


@pytest.fixture
def serve():
    servers = []

    def _make(body):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(body))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {"target": "/"}


def _ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()


@pytest.mark.parametrize("fault", ["lang", "alt", "title", "label", "contrast"])
def test_a11y_fires_on_each_hard_fail(serve, fault):
    assert a11y_hard_fails(_ctx(serve(FAULTS[fault])), _Probe()) is True


def test_a11y_clean_on_accessible_document(serve):
    assert a11y_hard_fails(_ctx(serve(CLEAN)), _Probe()) is False
