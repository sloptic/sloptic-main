"""Phantom-SQLi guard: a host that serves a per-prefix catch-all shell (a distinct shell under /api/ than
at /) must NOT produce a SQL-injection finding. The endpoint's benign baseline differs from the ROOT
catch-all (so _is_phantom_shell alone lets it through — the the-angle FP that fired sec-sqli-004 at
penalty 40), but a guaranteed-nonexistent SIBLING under the same prefix answers identically, proving the
endpoint is indistinguishable from a nonexistent path -> a phantom sink, N/A. A REAL sink whose sibling
404s must still fire (recall preserved — covered by test_api_injection.py against the jsonapi reference)."""
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import api_sqli
from hacklet_runner.schema import Endpoint, Profile

_ROOT_SHELL = b"<html><body>root landing shell</body></html>"
_API_SHELL = b"<html><body>api client-routed shell, distinct from root, same for every /api path</body></html>"


class _PrefixCatchAll(http.server.BaseHTTPRequestHandler):
    """A per-prefix catch-all SPA: `/` serves one shell, EVERY `/api/...` path (real or nonexistent) serves
    a DIFFERENT but internally-identical shell — except a lone quote elicits a SQL-error string (the trap
    that would false-fire _tech_error without the sibling guard)."""
    def log_message(self, *a): pass

    def _send(self, body):
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if not u.path.startswith("/api/"):
            return self._send(_ROOT_SHELL)                       # root catch-all shell
        q = parse_qs(u.query).get("q", [""])[0]
        if "'" in q:                                             # the trap: a quote -> a SQL-error signature
            return self._send(b"<html>SQL syntax error near \"'\"</html>")
        self._send(_API_SHELL)                                   # benign + nonexistent sibling: identical shell


class _Probe:
    probe = {"max_attempts": 80, "time_delay": 1}


class _Ctx:
    def __init__(self, base_url, profile):
        self.base_url, self.profile = base_url, profile
        self.headers = None
        self.client = None          # _serves_prefix_catchall uses api_sqli's own client, not this
        self.evidence = {}


@pytest.fixture
def host():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PrefixCatchAll)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_sqli_na_on_per_prefix_catchall(host):
    # /api/search's benign baseline (_API_SHELL) != root shell, so it slips the root phantom gate; but a
    # nonexistent sibling under /api/ answers _API_SHELL too -> indistinguishable -> N/A, not a phantom fire.
    prof = Profile(base_url=host, endpoints=[
        Endpoint(path="/api/search", method="get", raw_path="/api/search", query_params=["q"])])
    assert api_sqli(_Ctx(host, prof), _Probe()) is None
