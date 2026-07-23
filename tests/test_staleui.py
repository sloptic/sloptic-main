"""qa-staleui-001 — 'saved but the page doesn't reflect it until refresh'. Two layers:
(1) the predicate maps the browser verdict (stale -> fire; reflected/not_saved -> clean; inconclusive/no-form
    -> N/A) — deterministic, always runs;
(2) the browser oracle (check_create_reflection) against a mock SPA: a stale app (writes durable, DOM not
    refetched) fires; an app that reflects the create live reads clean — needs a headless browser."""
import http.server
import json
import pathlib
import sys
import threading
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import browser  # noqa: E402
from hacklet_runner.probes import stale_ui_after_create  # noqa: E402
from hacklet_runner.schema import Form, Profile  # noqa: E402


class _P:
    probe = {}


def _ctx(forms):
    c = type("C", (), {})()
    c.base_url = "http://x"
    c.profile = Profile(base_url="http://x", forms=forms)
    c.headers = None
    c.evidence = {}
    c.register = lambda suffix="": None    # no session needed for the mapping test
    return c


_FORM = [Form(action="/create", method="post", fields=["title"])]


# ---- (1) predicate verdict mapping (no browser) ----
def test_fires_when_ui_is_stale(monkeypatch):
    monkeypatch.setattr(browser, "check_create_reflection", lambda *a, **k: "stale")
    ctx = _ctx(_FORM)
    assert stale_ui_after_create(ctx, _P()) is True
    assert ctx.evidence["verdict"] == "stale"


def test_clean_when_reflected(monkeypatch):
    monkeypatch.setattr(browser, "check_create_reflection", lambda *a, **k: "reflected")
    assert stale_ui_after_create(_ctx(_FORM), _P()) is False


def test_clean_when_not_saved(monkeypatch):
    # absent live AND after reload -> not durable -> data-integrity's finding, not stale-UI
    monkeypatch.setattr(browser, "check_create_reflection", lambda *a, **k: "not_saved")
    assert stale_ui_after_create(_ctx(_FORM), _P()) is False


def test_na_when_browser_inconclusive(monkeypatch):
    monkeypatch.setattr(browser, "check_create_reflection", lambda *a, **k: "inconclusive")
    assert stale_ui_after_create(_ctx(_FORM), _P()) is None


def test_na_without_a_create_form():
    assert stale_ui_after_create(_ctx([]), _P()) is None


# ---- (2) the real browser oracle against a mock SPA ----
_PAGE = """<!doctype html><html><body>
<h1>Notes</h1>
<input type="text" name="title" placeholder="new note">
<button type="button" id="add">Add</button>
<ul id="list">%s</ul>
<script>
document.getElementById('add').onclick = async () => {
  const v = document.querySelector('input[name=title]').value;
  await fetch('/add', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({title:v})});
  %s
};
</script></body></html>"""


def _spa(reflect):
    items = []
    reflect_js = "document.getElementById('list').innerHTML += '<li>'+v+'</li>';" if reflect else "/* no refetch */"

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = (_PAGE % ("".join("<li>%s</li>" % i for i in items), reflect_js)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if urlparse(self.path).path == "/add":
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
                items.append(data.get("title", ""))          # the write IS durable (shows on the next GET)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def _serve(reflect):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _spa(reflect))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


browsermark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@browsermark
def test_browser_oracle_flags_a_stale_app():
    srv = _serve(reflect=False)          # durable write, but the DOM never refetches -> stale until reload
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert browser.check_create_reflection(url, "hlsuimark7") == "stale"
    finally:
        srv.shutdown()


@browsermark
def test_browser_oracle_clean_when_app_reflects_live():
    srv = _serve(reflect=True)           # the create is appended to the DOM immediately -> reflected
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert browser.check_create_reflection(url, "hlsuimark7") == "reflected"
    finally:
        srv.shutdown()
