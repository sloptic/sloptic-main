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
from sloptic import browser  # noqa: E402
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import stored_xss_api  # noqa: E402
from sloptic.schema import Endpoint, Profile  # noqa: E402


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


# ---- browser-create fallback: reaches SPA/auth-gated creates the httpx POST can't store --------------------

def test_browser_create_fallback_fires_confirmed_execution(monkeypatch):
    # no JSON create endpoint the httpx path can POST, but a browser + content form: the browser-create lane
    # drives the create and CONFIRMS execution -> fire, via="browser-create".
    from sloptic import probes
    monkeypatch.setattr(probes.browser, "create_and_check_execution",
                        lambda base, payload, marker, headers=None, timeout=12.0: True)
    ctx = _ctx("http://127.0.0.1:1", endpoints=[])
    ctx.profile.capabilities["browser"] = True
    try:
        assert stored_xss_api(ctx, _P()) is True
        assert ctx.evidence.get("via") == "browser-create" and ctx.evidence.get("execution_confirmed")
    finally:
        ctx.client.close()


def test_browser_create_fallback_when_httpx_post_is_rejected(monkeypatch):
    # a create endpoint exists but the httpx POST can't store it (404/401/JS-fetch-only) -> the browser-create
    # lane still reaches it and confirms execution -> fire.
    from sloptic import probes
    monkeypatch.setattr(probes.browser, "create_and_check_execution",
                        lambda base, payload, marker, headers=None, timeout=12.0: True)
    srv = _serve(vuln=True)                                   # app only accepts POST /api/items
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _ctx(url, endpoints=[Endpoint(path="/api/other", method="post",   # 404 on POST -> not stored via httpx
                                        raw_path="/api/other", body_fields=["text"])])
    ctx.profile.capabilities["browser"] = True
    try:
        assert stored_xss_api(ctx, _P()) is True
        assert ctx.evidence.get("via") == "browser-create"
    finally:
        ctx.client.close()
        srv.shutdown()


def test_browser_create_fallback_no_false_fire(monkeypatch):
    # the browser lane never confirmed execution -> no fire, honest N/A (never a false clean either).
    from sloptic import probes
    monkeypatch.setattr(probes.browser, "create_and_check_execution",
                        lambda base, payload, marker, headers=None, timeout=12.0: False)
    ctx = _ctx("http://127.0.0.1:1", endpoints=[])
    ctx.profile.capabilities["browser"] = True
    try:
        assert stored_xss_api(ctx, _P()) is None
    finally:
        ctx.client.close()
