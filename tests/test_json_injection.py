"""JSON-API body injection: command_injection / ssti_injectable / path_traversal now reach POST JSON
endpoint body fields — the SPA sink the form/query enumeration missed. A vulnerable JSON endpoint (evaluates
the arithmetic / reads the file) fires; a safe endpoint that only echoes the literal reads clean; no JSON
endpoint reads N/A. The arithmetic-result / file-signature oracles are content-type-agnostic, so a JSON echo
of the literal payload (no evaluation) never false-fires."""
import http.server
import json
import pathlib
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import command_injection, path_traversal, ssti_injectable  # noqa: E402
from hacklet_runner.schema import Endpoint, Profile  # noqa: E402


def _make_app(vuln):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _j(self, obj):
            b = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            path = urlparse(self.path).path
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
            if path == "/api/run":                       # shell sink
                cmd = str(body.get("cmd", ""))
                if vuln and "hlci$((13*13))" in cmd:
                    return self._j({"out": "hlci169"})   # a shell EVALUATED the arithmetic
                return self._j({"out": cmd})             # safe: echo the literal (no 'hlci169')
            if path == "/api/render":                    # template sink
                tpl = str(body.get("tpl", ""))
                return self._j({"out": tpl.replace("{{7*7}}", "49") if vuln else tpl})
            if path == "/api/read":                      # file sink
                p = str(body.get("path", ""))
                if vuln and (".." in p or "etc/passwd" in p):
                    return self._j({"data": "root:x:0:0:root:/root:/bin/bash"})   # served the file
                return self._j({"data": p})
            return self._j({})
    return H


def _serve(vuln):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(vuln))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _P:
    probe = {}


_EPS = [Endpoint(path="/api/run", method="post", raw_path="/api/run", body_fields=["cmd"]),
        Endpoint(path="/api/render", method="post", raw_path="/api/render", body_fields=["tpl"]),
        Endpoint(path="/api/read", method="post", raw_path="/api/read", body_fields=["path"])]


def _run(pred, vuln, endpoints=_EPS):
    srv = _serve(vuln)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
               Profile(base_url=url, forms=[], endpoints=endpoints), None)
    try:
        return pred(ctx, _P())
    finally:
        ctx.client.close()
        srv.shutdown()


def test_cmdi_fires_on_json_body():
    assert _run(command_injection, True) is True


def test_cmdi_clean_on_safe_json():
    assert _run(command_injection, False) is False


def test_ssti_fires_on_json_body():
    assert _run(ssti_injectable, True) is True


def test_ssti_clean_on_safe_json():
    assert _run(ssti_injectable, False) is False


def test_lfi_fires_on_json_body():
    assert _run(path_traversal, True) is True


def test_lfi_clean_on_safe_json():
    assert _run(path_traversal, False) is False


def test_na_without_any_json_endpoint():
    assert _run(command_injection, True, endpoints=[]) is None
