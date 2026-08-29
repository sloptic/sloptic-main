"""Server-side template / eval code injection — the injected HASH gadget is EXECUTED (the salt's exact digest
appears); an app that merely reflects the literal, or an LLM that fabricates a hash, stays clean."""
import hashlib
import http.server
import re
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from sloptic.probes import ssti_injectable
from sloptic.schema import Endpoint, Profile


def _render(val: str) -> str:
    """A tiny vulnerable engine: when the input carries a hash/exec gadget it EXECUTES it and returns the salt's
    real digest (what genuine server-side execution produces); otherwise it reflects the input unchanged."""
    salt = re.search(r"hlssti[0-9a-f]+", val)
    gadget = re.search(r"sha256sum|md5sum|hash\('sha256'|sha256\(b?'|md5\(|system\(|popen\(|Execute|`printf", val)
    if salt and gadget:
        return hashlib.sha256(salt.group(0).encode()).hexdigest()
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
        elif u.path == "/jinja":                   # ONLY the Jinja2 gadget (contains `cycler`) executes here,
            salt = re.search(r"hlssti[0-9a-f]+", name)   # so the engine must be identified specifically as jinja2
            hit = salt and "cycler" in name
            self._send("<h1>%s</h1>" % (hashlib.sha256(salt.group(0).encode()).hexdigest() if hit else name))
        elif u.path == "/safe":                    # input echoed as data, never evaluated
            self._send("<h1>Hello %s</h1>" % name)
        elif u.path == "/ai":                      # an LLM endpoint: echoes and even FABRICATES a plausible
            #  wrong 64-hex hash, but cannot hash the salt, so the salt's real digest never appears -> no FP.
            self._send("<h1>%s</h1>" % ("b" * 64 if re.search(r"hlssti[0-9a-f]+", name) else name))
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


def test_ssti_fires_when_gadget_is_executed(app):
    # /tmpl runs the hash gadget and returns the salt's real digest -> injectable
    ctx = _ctx(app, "/tmpl")
    assert ssti_injectable(ctx, _Probe()) is True
    assert ctx.evidence.get("engine")             # the winning gadget names the engine that executed it


def test_ssti_identifies_the_engine(app):
    # /jinja executes ONLY the Jinja2 gadget -> the recorded engine fingerprint must be jinja2 specifically
    ctx = _ctx(app, "/jinja")
    assert ssti_injectable(ctx, _Probe()) is True
    assert ctx.evidence.get("engine") == "jinja2"


def test_ssti_clean_on_reflection_only(app):
    # /safe reflects the gadget payload verbatim but never executes it -> no digest -> not injectable
    assert ssti_injectable(_ctx(app, "/safe"), _Probe()) is False


def test_ssti_clean_on_llm_endpoint(app):
    # an LLM endpoint echoes and even fabricates a plausible wrong hash, but cannot hash an arbitrary salt, so
    # the salt's exact digest that only a real engine produces never appears -> the LLM can't fake a fire.
    assert ssti_injectable(_ctx(app, "/ai"), _Probe()) is False


def test_ssti_na_when_no_input(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert ssti_injectable(ctx, _Probe()) is None
