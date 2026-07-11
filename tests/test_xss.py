"""Comprehensive XSS detection — reflected (body + attribute contexts), stored, and the precision
guards (an escaping app and a JSON API must stay clean). One inline app exposes each context; the
predicate is driven against a hand-built Profile so each technique is exercised in isolation."""
import html
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import xss_injectable
from hacklet_runner.schema import Endpoint, Form, Profile


class _App(http.server.BaseHTTPRequestHandler):
    stored = {"msg": ""}

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html; charset=utf-8"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if path == "/reflect":                                   # reflected, HTML body, no escaping
            self._send("<html><body>Results: %s</body></html>" % q)
        elif path == "/attr":                                    # attribute value; escapes <> but NOT "
            self._send('<input value="%s">' % q.replace("<", "&lt;").replace(">", "&gt;"))
        elif path == "/safe":                                    # fully escaped -> no XSS
            self._send("<body>%s</body>" % html.escape(q))
        elif path == "/api/echo":                                # JSON echo -> not HTML -> not XSS
            self._send('{"q": "%s"}' % q, ctype="application/json")
        elif path == "/guest":                                   # shows whatever was stored, unescaped
            self._send("<body>Messages: %s</body>" % _App.stored["msg"])
        else:
            self._send("<body>home</body>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        _App.stored["msg"] = parse_qs(self.rfile.read(n).decode()).get("msg", [""])[0]
        self._send("<body>saved</body>")


@pytest.fixture
def app():
    _App.stored["msg"] = ""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"max_attempts": 150}


def _ctx(url, **profile_kw):
    prof = Profile(base_url=url, **profile_kw)
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def test_xss_reflected_in_html_body(app):
    assert xss_injectable(_ctx(app, forms=[Form("/reflect", "get", ["q"])]), _Probe()) is True


def test_xss_attribute_context_breakout(app):
    # escapes <> but not " -> only the attribute event-handler payload (no '<') should catch it
    assert xss_injectable(_ctx(app, forms=[Form("/attr", "get", ["q"])]), _Probe()) is True


def test_xss_stored(app):
    # POST persists the payload; a fresh GET of the page shows it unescaped -> stored XSS
    assert xss_injectable(_ctx(app, forms=[Form("/guest", "post", ["msg"])]), _Probe()) is True


def test_xss_clean_when_escaped(app):
    assert xss_injectable(_ctx(app, forms=[Form("/safe", "get", ["q"])]), _Probe()) is False


def test_xss_no_false_positive_on_json_api(app):
    # a JSON endpoint that echoes the payload is NOT XSS (JSON isn't rendered as HTML)
    ep = Endpoint(path="/api/echo", method="get", query_params=["q"], raw_path="/api/echo")
    assert xss_injectable(_ctx(app, endpoints=[ep]), _Probe()) is False


def test_xss_na_when_no_input_surface(app):
    assert xss_injectable(_ctx(app), _Probe()) is None
