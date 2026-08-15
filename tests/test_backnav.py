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
from sloptic import browser  # noqa: E402

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

# a NORMAL page whose header carries a "Log in" nav LINK (no password field) -- must NOT read as auth-gated
# (the toyota/findmyseat over-suppression: matching "log in" TEXT flagged ordinary landing pages). Native nav,
# so Back restores Alpha -> "ok", proving the login-text-in-nav does not trip the gate.
_LINK_A = ("<html><body><nav><a href='/login'>Log in</a> <a href='/signup'>Sign up</a></nav>"
           "<h1>Alpha unique-alpha-token</h1><a href='/b'>go to beta</a></body></html>")
_LINK_B = ("<html><body><nav><a href='/login'>Log in</a></nav>"
           "<h1>Beta unique-beta-token</h1><a href='/'>home</a></body></html>")

# auth-gated Back: pushState nav works, but pressing BACK triggers popstate -> the app renders a LOGIN screen
# (the v18 back->/login FP). We can't observe whether Back restores the view (the gate intercepted) -> N/A.
_LOGIN_BACK = """<html><body>
<h1>Alpha unique-alpha-token</h1><a id="nav" href="/b">go to beta</a>
<script>
document.getElementById('nav').addEventListener('click', function(e){
  e.preventDefault(); history.pushState({}, '', '/b');
  document.body.innerHTML = '<h1>Beta unique-beta-token</h1>';
});
window.addEventListener('popstate', function(){
  document.body.innerHTML = '<input type="password"> Please sign in to continue';
});
</script></body></html>"""

# an entry that paints essentially nothing -> can't be judged for restoration -> N/A (not a partial-render fire)
_BLANK = "<html><body></body></html>"


def _make_app(mode):   # broken | ok | login_back | blank
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
            elif mode == "login_back":
                self._html(_LOGIN_BACK)
            elif mode == "blank":
                self._html(_BLANK)
            elif mode == "ok_login_link":
                self._html(_LINK_A if path == "/" else _LINK_B)
            else:
                self._html(_OK_B if path == "/b" else _OK_A)
    return H


def _run(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        return browser.back_button_broken(url)[0]   # (verdict, detail) -> verdict
    finally:
        srv.shutdown()


browsermark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@browsermark
def test_broken_when_back_does_not_restore_view():
    assert _run("broken") == "broken"    # URL pops to / but content stays on Beta


@browsermark
def test_ok_when_back_restores_view():
    assert _run("ok") == "ok"            # native nav -> browser restores Alpha


@browsermark
def test_inconclusive_when_back_hits_an_auth_gate():
    # Back lands on a login screen = the app gated the Back nav; we never observe restoration -> N/A, not "broken"
    # (the ~10 back->/login v18 fires). Mirrors the deep-link login-gate.
    assert _run("login_back") == "inconclusive"


@browsermark
def test_inconclusive_when_the_entry_renders_blank():
    # an entry that paints ~nothing can't be judged for restoration -> N/A, not a partial-render fire
    # (findmyseat/nexia fired in v18 from a mid-load entry fingerprint; the settle+guard make it reproducible)
    assert _run("blank") == "inconclusive"


@browsermark
def test_a_login_nav_link_does_not_count_as_auth_gated():
    # THE over-suppression guard: a normal page with a "Log in" nav LINK (no password field) must NOT read as
    # auth-gated (toyota's marketing page / findmyseat were wrongly suppressed by matching "log in" TEXT). Native
    # nav restores Alpha -> "ok"; the gate keys on a password FIELD, not the nav text.
    assert _run("ok_login_link") == "ok"
