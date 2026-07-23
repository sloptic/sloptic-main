"""qa-backnav-001: after an in-app navigation, the browser BACK button must restore the prior view (URL AND
content). A broken SPA (pushState with no popstate handler -> URL pops back but content stays on the new view)
fires; a correct app (native nav, or a router that restores) reads clean. Needs a headless browser."""
import http.server
import pathlib
import sys
import threading
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import browser  # noqa: E402

_BROKEN = """<html><body>
<h1>Alpha unique-alpha-token</h1><a id="nav" href="/b">go to beta</a>
<script>
document.getElementById('nav').addEventListener('click', function(e){
  e.preventDefault();
  history.replaceState({}, '', '/b');   // REPLACES the entry -> there is no back entry to restore
  document.body.innerHTML = '<h1>Beta unique-beta-token</h1>';
});
</script></body></html>"""

_OK_A = "<html><body><h1>Alpha unique-alpha-token</h1><a href='/b'>go to beta</a></body></html>"
_OK_B = "<html><body><h1>Beta unique-beta-token</h1><a href='/'>home</a></body></html>"


def _make_app(mode):   # broken | ok
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _html(self, body):
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = urlparse(self.path).path
            if mode == "broken":
                self._html(_BROKEN)                       # client-side nav; /b never hit on the server
            else:
                self._html(_OK_B if path == "/b" else _OK_A)
    return H


def _run(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        return browser.back_button_broken(url)
    finally:
        srv.shutdown()


browsermark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@browsermark
def test_broken_when_back_does_not_restore_view():
    assert _run("broken") == "broken"    # URL pops to / but content stays on Beta


@browsermark
def test_ok_when_back_restores_view():
    assert _run("ok") == "ok"            # native nav -> browser restores Alpha
