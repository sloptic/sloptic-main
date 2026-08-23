"""browser.create_and_read_back: the SPA write round-trip httpx can't observe -- fill a create/content form in a
browser, submit via the app's own JS, re-render, and read the value back from the client-rendered DOM. The
form-selection logic is unit-tested against a mock page here; the end-to-end drive is a browser integration test
that runs only where a headless browser exists (the grading box), skipped on the dev box."""
import http.server
import threading

import pytest

from sloptic import browser


# ---- mock-page unit tests (no browser) --------------------------------------------------------------------

class _El:
    def __init__(self, tag="input", attrs=None, text="", visible=True, children=None):
        self.tag, self.attrs, self.text, self._visible = tag, attrs or {}, text, visible
        self.children = children or []
        self.filled = None
        self.submitted = False

    def is_visible(self):
        return self._visible

    def get_attribute(self, n):
        return self.attrs.get(n)

    def inner_text(self):
        return self.text

    def fill(self, v):
        self.filled = v

    def evaluate(self, js):
        if "requestSubmit" in js or "submit" in js:
            self.submitted = True
            return None
        if "TEXTAREA" in js:
            return self.tag.upper() == "TEXTAREA"
        return None

    def query_selector(self, sel):
        if "password" in sel:
            return next((c for c in self.children if c.attrs.get("type") == "password"), None)
        return next(iter(self.children), None)

    def query_selector_all(self, sel):
        return [c for c in self.children if c.tag in ("input", "textarea")]


class _Page:
    def __init__(self, forms):
        self.forms = forms

    def query_selector_all(self, sel):
        return self.forms if sel == "form" else []

    def wait_for_timeout(self, ms):
        pass


def _form(children, text="", visible=True):
    return _El(tag="form", text=text, visible=visible, children=children)


def test_fills_a_content_form_target_field_and_submits():
    text = _El(attrs={"type": "text"})
    form = _form([text])
    assert browser._fill_content_form(_Page([form]), "CANARY123", 1.0) is True
    assert text.filled == "CANARY123" and form.submitted


def test_skips_a_credential_form():
    pw = _form([_El(attrs={"type": "text"}), _El(attrs={"type": "password"})])
    assert browser._fill_content_form(_Page([pw]), "X", 1.0) is False   # a login/signup form, not content
    assert not pw.submitted


def test_skips_a_destructive_form():
    form = _form([_El(attrs={"type": "text"})], text="Delete your account")   # _NO_CLICK
    assert browser._fill_content_form(_Page([form]), "X", 1.0) is False


def test_other_fields_get_benign_values_only_the_text_field_gets_the_marker():
    txt = _El(attrs={"type": "text"})
    email = _El(attrs={"type": "email"})
    area = _El(tag="textarea")
    form = _form([email, txt, area])
    assert browser._fill_content_form(_Page([form]), "MARKERval", 1.0) is True
    # the FIRST text-ish field carries the marker; the rest are benign
    assert txt.filled == "MARKERval" and email.filled == "hl.probe@example.com" and area.filled == "hlprobe"


def test_returns_false_when_no_form_has_a_text_field():
    form = _form([_El(attrs={"type": "checkbox"})])
    assert browser._fill_content_form(_Page([form]), "X", 1.0) is False


# ---- end-to-end browser drive (grading box only) ----------------------------------------------------------

_SPA_HTML = """<!doctype html><html><body>
<form id="f"><input id="t" type="text" placeholder="note"><button type="submit">Add</button></form>
<ul id="list"></ul>
<script>
 document.getElementById('f').onsubmit = function(e){
   e.preventDefault();                                   // SPA: no navigation, JS renders the item in place
   var li = document.createElement('li');
   li.textContent = document.getElementById('t').value;  // the created item paints client-side (httpx can't see)
   document.getElementById('list').appendChild(li);
 };
</script></body></html>"""


class _SpaApp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = _SPA_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")
def test_create_and_read_back_observes_the_client_rendered_value():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpaApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        out = browser.create_and_read_back(base, "HLrb99 日本語", "HLrb99")
        assert out is not None and "HLrb99" in out          # the marker round-tripped through the client render
    finally:
        srv.shutdown()


_XSS_SPA_HTML = """<!doctype html><html><body>
<form id="f"><input id="t" type="text"><button type="submit">Add</button></form>
<div id="out"></div>
<script>
 document.getElementById('f').onsubmit = function(e){
   e.preventDefault();
   var d = document.createElement('div');
   d.innerHTML = document.getElementById('t').value;   // UNESCAPED -> a stored img-onerror executes
   document.getElementById('out').appendChild(d);
 };
</script></body></html>"""


class _XssSpaApp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = _XSS_SPA_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")
def test_create_and_check_execution_fires_when_the_stored_payload_runs():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _XssSpaApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        # the payload sets window.__hl_domxss = 'hl-domxss-9a2b' when it executes
        assert browser.create_and_check_execution(base, browser._XSS_PAYLOAD, "hl-domxss-9a2b") is True
    finally:
        srv.shutdown()


@pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")
def test_create_and_check_execution_clean_when_the_render_escapes():
    # the safe SPA (textContent, not innerHTML) never executes the stored value
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpaApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert browser.create_and_check_execution(base, browser._XSS_PAYLOAD, "hl-domxss-9a2b") is False
    finally:
        srv.shutdown()
