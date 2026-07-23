"""qa-noerror-001: a save action whose request is FORCED to fail must show the user a failure indication. An
app that shows nothing on failure fires ('silent'); an app that shows an error reads clean ('handled'). Needs
a headless browser; the predicate is N/A without a create form."""
import http.server
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import browser  # noqa: E402
from hacklet_runner.probes import no_error_state  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402

# silent: on a failed save, do nothing (success-only handling); handled: paint a visible error
_SILENT = "if (r.ok) { document.body.innerHTML += '<div>saved!</div>'; }"
_HANDLED = "if (!r.ok) { document.body.innerHTML += '<div class=\"error-banner\">Save failed, please try again</div>'; }"

_PAGE = """<html><body>
<input type="text" name="title" placeholder="new item">
<button id="save">Save</button>
<script>
document.getElementById('save').onclick = async () => {
  const r = await fetch('/api/save', {method:'POST', headers:{'Content-Type':'application/json'},
                                      body: JSON.stringify({title: document.querySelector('input').value})});
  %s
};
</script></body></html>"""


def _make_app(mode):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = (_PAGE % (_SILENT if mode == "silent" else _HANDLED)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):    # never actually reached — the probe intercepts + forces 500 client-side
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
    return H


def _run(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        return browser.silent_failure_on_action(url)
    finally:
        srv.shutdown()


browsermark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@browsermark
def test_silent_when_no_error_shown():
    assert _run("silent") == "silent"


@browsermark
def test_handled_when_error_shown():
    assert _run("handled") == "handled"


def test_predicate_na_without_a_create_form():
    ctx = type("C", (), {})()
    ctx.profile = Profile(base_url="http://x")   # no forms
    ctx.headers = None
    ctx.evidence = {}
    ctx.register = lambda suffix="": None
    assert no_error_state(ctx, type("P", (), {"probe": {}})()) is None
