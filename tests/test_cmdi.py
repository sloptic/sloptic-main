"""Command injection — output-based (across shell separators / substitution) and blind time-based,
plus the precision guard: an app that merely REFLECTS the payload (no shell) must stay clean."""
import http.server
import re
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import command_injection
from hacklet_runner.schema import Form, Profile


def _fake_shell(val: str) -> str:
    """Mini POSIX-shell emulation: only 'runs' when a shell metacharacter is present (i.e. injection
    happened), evaluating $((13*13)) and honoring `echo`. Returns the command's stdout."""
    if not any(ch in val for ch in ";|&`$\n"):
        return ""                                   # no metachar -> no injection -> no command ran
    s = val.replace("$((13*13))", "169")            # arithmetic evaluation
    if "sleep" in s:
        m = re.search(r"sleep\s+(\d+)", s)
        if m:
            time.sleep(min(int(m.group(1)), 3))
        return ""
    m = re.search(r"echo\s+(\S+)", s)
    return m.group(1) if m else ""


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


def test_command_injection_output_based(app):
    # a separator/substitution echo of an arithmetic expr executes -> the RESULT (169) appears
    assert command_injection(_ctx(app, Form("/exec", "get", ["cmd"])), _Probe()) is True


def test_command_injection_clean_on_reflection_only(app):
    # /safe echoes the literal payload (incl. "$((13*13))") but never runs a shell -> not injectable
    assert command_injection(_ctx(app, Form("/safe", "get", ["cmd"])), _Probe()) is False


def test_command_injection_na_when_no_input(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert command_injection(ctx, _Probe()) is None
