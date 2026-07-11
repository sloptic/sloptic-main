"""Debug-mode-in-production — an error surfaces the framework's full interactive debugger / DEBUG page
(not just a stack trace). Fires on the Werkzeug/Django/Rails/Laravel debug UI at the error route, and on
a live Werkzeug debugger resource reachable without an error; clean on a generic error page."""
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.net import make_client
from hacklet_runner.probes import _DEBUG_FINGERPRINT, debug_mode_enabled
from hacklet_runner.schema import Profile

_WERKZEUG_CRASH = (b"<!DOCTYPE html><html><head><title>ValueError // Werkzeug Debugger</title></head>"
                   b"<body><h1>Werkzeug Debugger</h1><pre>Traceback (most recent call last)</pre></body></html>")
_DJANGO_CRASH = (b"<html><body><h1>ValueError</h1><p>You're seeing this error because you have "
                 b"<code>DEBUG = True</code> in your settings.</p></body></html>")
_GENERIC_CRASH = b"Internal Server Error"
_DEBUGGER_JS = b"// Werkzeug Debugger resource\nvar DEBUG = true;"


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            # a live Werkzeug debugger answers its resource request with javascript, without any error
            if mode == "werkzeug_resource" and q.get("__debugger__") == ["yes"] and "cmd" in q:
                return self._send(200, "application/javascript", _DEBUGGER_JS)
            if u.path == "/crash":
                if mode == "werkzeug_crash":
                    return self._send(500, "text/html; charset=utf-8", _WERKZEUG_CRASH)
                if mode == "django_crash":
                    return self._send(500, "text/html; charset=utf-8", _DJANGO_CRASH)
                return self._send(500, "text/plain", _GENERIC_CRASH)
            return self._send(200, "text/html; charset=utf-8", b"<html><body>home</body></html>")
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(mode):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(mode))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {"target": "/crash"}


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": make_client(url), "evidence": {}})()


def test_debug_mode_fires_on_werkzeug_debugger_page(server):
    assert debug_mode_enabled(_ctx(server("werkzeug_crash")), _Probe()) is True


def test_debug_mode_fires_on_django_debug_page(server):
    assert debug_mode_enabled(_ctx(server("django_crash")), _Probe()) is True


def test_debug_mode_fires_on_live_werkzeug_resource(server):
    # /crash is a generic error here; detection comes from the debugger resource served without an error
    ctx = _ctx(server("werkzeug_resource"))
    assert debug_mode_enabled(ctx, _Probe()) is True
    assert ctx.evidence.get("framework") == "werkzeug"


def test_debug_mode_clean_on_generic_error(server):
    assert debug_mode_enabled(_ctx(server("clean")), _Probe()) is False


def test_debug_fingerprint_matches_each_framework_but_not_benign_content():
    assert _DEBUG_FINGERPRINT.search("... Werkzeug Debugger ...")
    assert _DEBUG_FINGERPRINT.search("You're seeing this error because you have DEBUG = True")
    assert _DEBUG_FINGERPRINT.search("Better Errors caught this")
    assert _DEBUG_FINGERPRINT.search("Whoops, looks like something went wrong.")
    assert not _DEBUG_FINGERPRINT.search("<html><body>Welcome to our shop</body></html>")
    assert not _DEBUG_FINGERPRINT.search("Internal Server Error")  # a generic 500 is not debug mode
