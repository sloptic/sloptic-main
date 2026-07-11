"""Server-side template / eval code injection — the injected 7*7 is EVALUATED (marker+49 appears); an
app that merely reflects the literal (or escapes it) stays clean (reflection != evaluation)."""
import http.server
import re
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import ssti_injectable
from hacklet_runner.schema import Endpoint, Profile


def _render(val: str) -> str:
    """A tiny template engine: evaluate {{N*M}} / ${N*M} expressions (like Jinja/Freemarker)."""
    def mul(match):
        return str(int(match.group(1)) * int(match.group(2)))
    val = re.sub(r"\{\{\s*(\d+)\*(\d+)\s*\}\}", mul, val)
    val = re.sub(r"\$\{\s*(\d+)\*(\d+)\s*\}", mul, val)
    return val


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        name = parse_qs(u.query).get("name", [""])[0]
        if u.path == "/tmpl":                      # input rendered THROUGH the template engine -> SSTI
            self._send("<h1>Hello %s</h1>" % _render(name))
        elif u.path == "/safe":                    # input echoed as data, never evaluated
            self._send("<h1>Hello %s</h1>" % name)
        else:
            self._send("ok")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"max_attempts": 160}


def _ctx(url, path):
    prof = Profile(base_url=url, endpoints=[Endpoint(path=path, method="get", query_params=["name"], raw_path=path)])
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def test_ssti_fires_when_expression_is_evaluated(app):
    assert ssti_injectable(_ctx(app, "/tmpl"), _Probe()) is True


def test_ssti_clean_on_reflection_only(app):
    # /safe reflects "<marker>{{7*7}}" verbatim but never computes 49 -> not injectable
    assert ssti_injectable(_ctx(app, "/safe"), _Probe()) is False


def test_ssti_na_when_no_input(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert ssti_injectable(ctx, _Probe()) is None
