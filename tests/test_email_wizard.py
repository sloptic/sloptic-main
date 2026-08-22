"""Lane B: the email-first signup WIZARD (step 1 = email + emailed CODE, no password; step 2 = create password).
The DOM-selection logic (find the code field, click the advance button, detect no-password step) is unit-tested
against a mock page here; the end-to-end browser drive is an integration test that runs only where a headless
browser is available (the grading box), skipped on the dev box."""
import http.server
import threading

import pytest

from sloptic import browser, pipeline
from sloptic.email_verify import EmailMessage, MockReceiver


# ---- mock-page unit tests (no browser) --------------------------------------------------------------------

class _El:
    def __init__(self, tag="input", attrs=None, text="", visible=True):
        self.tag, self.attrs, self.text, self._visible = tag, attrs or {}, text, visible
        self.filled = None
        self.clicked = False

    def is_visible(self):
        return self._visible

    def get_attribute(self, n):
        return self.attrs.get(n)

    def inner_text(self):
        return self.text

    def fill(self, v):
        self.filled = v

    def click(self, **k):
        self.clicked = True


class _Page:
    def __init__(self, inputs=None, buttons=None):
        self.inputs = inputs or []
        self.buttons = buttons or []

    def query_selector_all(self, sel):
        if "password" in sel:
            return [i for i in self.inputs if i.attrs.get("type") == "password" and i.is_visible()]
        if "button" in sel or "role=button" in sel:
            return self.buttons
        return list(self.inputs)

    def query_selector(self, sel):
        for i in self.inputs:                            # stand in for the _EMAIL_INPUT selector
            blob = (i.attrs.get("name", "") + i.attrs.get("id", "") + i.attrs.get("placeholder", "")).lower()
            if i.attrs.get("type") == "email" or "email" in blob:
                return i
        return None


def test_has_visible_password():
    assert browser._has_visible_password(_Page(inputs=[_El(attrs={"type": "password"})])) is True
    assert browser._has_visible_password(_Page(inputs=[_El(attrs={"type": "email"})])) is False


def test_find_code_field_by_hint():
    assert len(browser._find_code_field(_Page(inputs=[_El(attrs={"type": "text", "name": "otp"})]))) == 1
    assert len(browser._find_code_field(_Page(inputs=[_El(attrs={"placeholder": "6-digit code"})]))) == 1


def test_find_code_field_boxed_otp():
    boxes = [_El(attrs={"maxlength": "1"}) for _ in range(6)]
    assert len(browser._find_code_field(_Page(inputs=boxes))) == 6


def test_find_code_field_none_when_absent():
    assert browser._find_code_field(_Page(inputs=[_El(attrs={"type": "email"})])) is None


def test_click_step_button_prefers_advance_and_skips_no_click():
    cont = _El(tag="button", text="Continue")
    danger = _El(tag="button", text="Delete account")
    assert browser._click_step_button(_Page(buttons=[danger, cont]), 1) is True
    assert cont.clicked and not danger.clicked


def test_fill_code_single_and_boxed():
    single = [_El()]
    assert browser._fill_code(single, "481920") and single[0].filled == "481920"
    boxes = [_El() for _ in range(6)]
    browser._fill_code(boxes, "481920")
    assert "".join(b.filled for b in boxes) == "481920"


def test_accepts_kwarg():
    assert pipeline._accepts_kwarg(lambda base, code_getter=None: None, "code_getter")
    assert pipeline._accepts_kwarg(lambda base, **k: None, "code_getter")
    assert not pipeline._accepts_kwarg(lambda base, email=None: None, "code_getter")


def test_poll_email_code_returns_the_first_code():
    rx = MockReceiver(domain="app.test")
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=rx)
    ctx.email_address("")
    rx.inject(ctx._email_cache["tag"], EmailMessage.parse("hl@app.test", "Code", "Your verification code is 481920"))
    assert ctx._poll_email_code("") == "481920"


def test_poll_email_code_none_without_receiver():
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=None)
    assert ctx._poll_email_code("") is None


def test_browser_register_once_threads_code_getter_only_to_an_accepting_lane():
    seen = {}

    def code_lane(base_url, email=None, code_getter=None):
        seen["code_getter"] = code_getter
        return {"cookies": []}
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None,
                        email=MockReceiver(domain="app.test"), browser_register=code_lane)
    ctx._browser_register_once("", "http://app.test")
    assert callable(seen["code_getter"])                 # the real lane gets a code fetcher

    called = {}

    def two_arg(base_url, email=None):                   # a 2-arg stub must NOT receive code_getter (no crash)
        called["ok"] = True
        return {"cookies": []}
    ctx2 = pipeline._Ctx(base_url="http://app.test", client=None, profile=None,
                         email=MockReceiver(domain="app.test"), browser_register=two_arg)
    ctx2._browser_register_once("", "http://app.test")
    assert called["ok"]


# ---- end-to-end browser drive (grading box only) ----------------------------------------------------------

_WIZARD_HTML = """<!doctype html><html><body>
<div id="s1"><input id="email" type="email" placeholder="Email"><button id="c1">Continue</button></div>
<div id="s2" style="display:none"><input id="otp" name="otp" placeholder="6-digit code"><button id="c2">Verify</button></div>
<div id="s3" style="display:none"><input id="pw" type="password"><button id="c3">Create account</button></div>
<div id="done" style="display:none">welcome</div>
<script>
 c1.onclick=function(){s1.style.display='none';s2.style.display='block';};
 c2.onclick=function(){ if(otp.value==='481920'){s2.style.display='none';s3.style.display='block';} };
 c3.onclick=function(){ if(pw.value){ document.cookie='sessionid=S; path=/'; s3.style.display='none'; done.style.display='block'; } };
</script></body></html>"""


class _WizardApp(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = _WIZARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")
def test_email_first_wizard_completes_and_returns_a_session():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _WizardApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        out = browser.register_in_browser(base, email="hl-x@app.test", code_getter=lambda: "481920")
        assert isinstance(out, dict) and any(c["name"] == "sessionid" for c in out.get("cookies", []))
    finally:
        srv.shutdown()
