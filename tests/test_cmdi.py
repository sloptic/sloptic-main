"""Command injection — in-band hash oracle (across shell separators / substitution) and blind time-based,
plus the precision guard: an app that REFLECTS the payload, or an LLM that fabricates a hash, must stay clean."""
import hashlib
import http.server
import re
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest

from sloptic.probes import command_injection
from sloptic.schema import Form, Profile


def _fake_shell(val: str) -> str:
    """Mini POSIX-shell emulation: only 'runs' when a shell metacharacter is present (i.e. injection happened).
    It HASHES `printf SALT | sha256sum|md5sum` EXACTLY (the deterministic execution oracle only a real shell can
    produce) and honors `sleep` for dose-response. Returns the command's stdout."""
    if not any(ch in val for ch in ";|&`$\n"):
        return ""                                   # no metachar -> no injection -> no command ran
    if "sleep" in val:
        m = re.search(r"sleep\s+(\d+)", val)
        if m:
            time.sleep(min(int(m.group(1)), 4))     # a real sleep so dose-response scales (capped for test speed)
        return ""
    m = re.search(r"printf\s+(\S+)\s*\|\s*(sha256sum|md5sum)", val)
    if m:
        h = hashlib.sha256 if m.group(2) == "sha256sum" else hashlib.md5
        return "%s  -" % h(m.group(1).encode()).hexdigest()   # coreutils stdout: "<digest>  -"
    return ""


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _val(self):
        return parse_qs(urlparse(self.path).query).get("cmd", [""])[0]

    def _send(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path, v = urlparse(self.path).path, self._val()
        if path == "/exec":                          # vulnerable: input reaches a shell
            self._send("<pre>%s</pre>" % _fake_shell(v))
        elif path == "/safe":                        # reflects the literal only, never executes
            self._send("<pre>you searched: %s</pre>" % v)
        elif path == "/ai":                          # an LLM endpoint: echoes and even FABRICATES a plausible
            #  wrong hash (right length), but cannot hash an arbitrary salt, so the real digest never appears -> no FP.
            self._send("Result: %s" % re.sub(r"printf\s+(\S+)\s*\|\s*(sha256sum|md5sum)",
                                             lambda m: "a" * (64 if m.group(2) == "sha256sum" else 32), v))
        elif path.startswith("/api/"):               # a catch-all: EVERY path under /api serves the same shell,
            #  so a nonexistent sibling answers identically and the liveness gate must suppress the fire.
            self._send("<pre>%s</pre>" % _fake_shell(v))
        else:
            self._send("ok")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"max_attempts": 120, "time_delay": 1}


def _ctx(url, form):
    prof = Profile(base_url=url, forms=[form])
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def test_command_injection_in_band_hash(app):
    # a separator/substitution `printf SALT | sha256sum` executes -> the salt's exact digest appears
    assert command_injection(_ctx(app, Form("/exec", "get", ["cmd"])), _Probe()) is True


def test_command_injection_clean_on_reflection_only(app):
    # /safe echoes the literal payload (incl. "printf SALT | sha256sum") but never runs a shell -> not injectable
    assert command_injection(_ctx(app, Form("/safe", "get", ["cmd"])), _Probe()) is False


def test_command_injection_clean_on_llm_endpoint(app):
    # the AI-corpus FP: an LLM endpoint echoes and even fabricates a plausible wrong hash, but cannot hash an
    # arbitrary salt, so the exact digest that only a real shell produces never appears -> the LLM can't fake a fire.
    assert command_injection(_ctx(app, Form("/ai", "get", ["cmd"])), _Probe()) is False


def test_command_injection_gated_on_catch_all_phantom(app):
    # a catch-all / soft-404 host serves the same shell for every path, so an injected marker would "fire" on
    # an endpoint that does not exist server-side. The liveness gate compares the endpoint to a nonexistent
    # sibling under its own prefix; they answer identically, so the phantom is suppressed (never reaches injection).
    assert command_injection(_ctx(app, Form("/api/run", "get", ["cmd"])), _Probe()) is None


def test_command_injection_na_when_no_input(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert command_injection(ctx, _Probe()) is None
