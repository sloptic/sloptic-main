"""sec-xss-002: stored XSS via a JSON API + client render. POST an executing payload into a create endpoint,
render the page, and fire ONLY if it EXECUTES (the stored value was reflected UNESCAPED into the DOM). An app
that escapes on output reads clean. Needs a headless browser; N/A without a JSON create endpoint."""
import html as _html
import http.server
import json
import pathlib
import sys
import threading
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import browser  # noqa: E402
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import stored_xss_api  # noqa: E402
from hacklet_runner.schema import Endpoint, Profile  # noqa: E402


def _make_app(vuln):
    items = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):     # the feed: renders stored items RAW (vulnerable) or HTML-escaped (safe)
            lis = "".join("<li><div>%s</div></li>" % (i if vuln else _html.escape(i)) for i in items)
            self._send(200, "<html><body><ul>%s</ul></body></html>" % lis, "text/html")

        def do_POST(self):
            if urlparse(self.path).path == "/api/items":
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
                items.append(str(body.get("text", "")))
                return self._send(201, '{"id":1}', "application/json")
            self._send(404, "{}", "application/json")   # no register endpoint -> ctx.register() -> unauth client
    return H


def _serve(vuln):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(vuln))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _P:
    probe = {}


def _ctx(url, endpoints=None):
    eps = endpoints if endpoints is not None else [
        Endpoint(path="/api/items", method="post", raw_path="/api/items", body_fields=["text"])]
    return _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
                Profile(base_url=url, forms=[], endpoints=eps, routes=["/"]), None)


def _run(vuln, endpoints=None):
    srv = _serve(vuln)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _ctx(url, endpoints)
    try:
        return stored_xss_api(ctx, _P())
    finally:
        ctx.client.close()
        srv.shutdown()


browsermark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@browsermark
def test_fires_when_stored_value_executes():
    assert _run(vuln=True) is True       # stored payload rendered raw -> onerror fires in the browser


@browsermark
def test_clean_when_output_is_escaped():
    assert _run(vuln=False) is False      # feed HTML-escapes the stored value -> nothing executes


def test_na_without_json_create_endpoint():
    assert _run(vuln=True, endpoints=[]) is None
