"""_fill_and_submit_magic: the passwordless magic-link / email-OTP request lane. It runs only after every
password-signup attempt fails, and acts ONLY on an email-first form with no password field, so it can convert a
dead-end N/A without touching the tuned password-signup path. Exercised here against a mock page (no browser)."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic import browser  # noqa: E402


class _El:
    def __init__(self, tag="input", attrs=None, visible=True, text=""):
        self.tag, self.attrs, self._visible, self.text = tag, attrs or {}, visible, text
        self.filled = None
        self.checked = False
        self.clicked = False

    def is_visible(self):
        return self._visible

    def get_attribute(self, n):
        return self.attrs.get(n)

    def fill(self, v):
        self.filled = v

    def check(self):
        self.checked = True

    def input_value(self):
        return self.filled or ""

    def inner_text(self):
        return self.text

    def click(self, timeout=None):
        self.clicked = True

    def evaluate(self, js):
        return ""                              # labels / previousElementSibling -> nothing in the mock


class _Kbd:
    def __init__(self):
        self.pressed = None

    def press(self, k):
        self.pressed = k


class _Page:
    def __init__(self, inputs, buttons):
        self.inputs, self.buttons, self.keyboard = inputs, buttons, _Kbd()

    def query_selector_all(self, sel):
        if sel == "input[type=password]":
            return [i for i in self.inputs if (i.get_attribute("type") or "").lower() == "password"]
        if sel == "input":
            return self.inputs
        if "button" in sel:                    # "button, input[type=submit], [role=button]"
            return self.buttons
        return []


CREDS = {"email": "hl-x@app.test", "username": "hlprobe", "password": "Hl!pw12345"}


def test_magic_submit_fires_on_an_email_only_form():
    email = _El(attrs={"type": "email"})
    btn = _El(tag="button", text="Send magic link")
    page = _Page([email], [btn])
    assert browser._fill_and_submit_magic(page, CREDS) is True
    assert email.filled == "hl-x@app.test" and btn.clicked        # our address submitted via the app's own button


def test_magic_submit_skips_a_form_with_a_password_field():
    email = _El(attrs={"type": "email"})
    pw = _El(attrs={"type": "password"})
    btn = _El(tag="button", text="Sign in")
    page = _Page([email, pw], [btn])
    assert browser._fill_and_submit_magic(page, CREDS) is False    # password present -> the password lane's job
    assert not btn.clicked


def test_magic_submit_skips_when_there_is_no_email_field():
    name = _El(attrs={"type": "text", "name": "username"})
    btn = _El(tag="button", text="Continue")
    page = _Page([name], [btn])
    assert browser._fill_and_submit_magic(page, CREDS) is False    # a bare username form is not email-first


def test_magic_submit_falls_back_to_enter_without_a_matching_button():
    email = _El(attrs={"type": "email"})
    page = _Page([email], [])                                      # no button to click
    assert browser._fill_and_submit_magic(page, CREDS) is True
    assert email.filled == "hl-x@app.test" and page.keyboard.pressed == "Enter"


def test_magic_submit_fills_a_required_field_so_the_submit_is_not_blocked():
    email = _El(attrs={"type": "email"})
    extra = _El(attrs={"type": "text", "required": "true"})        # an unlabeled required field
    btn = _El(tag="button", text="Email me a link")
    page = _Page([email, extra], [btn])
    assert browser._fill_and_submit_magic(page, CREDS) is True
    assert extra.filled == "hl-x@app.test" and btn.clicked        # required field filled -> native validation won't block


# ---- the auth-surface gate: skip the guessed-route fishing on a no-auth page (WAF-antagonism cut) --------------

class _GatePage:
    def __init__(self, inputs, links):
        self.inputs, self.links = inputs, links

    def query_selector(self, sel):
        if "password" in sel:
            return next((i for i in self.inputs if (i.get_attribute("type") or "") == "password"), None)
        return None

    def query_selector_all(self, sel):
        return self.links if ("a," in sel or "button" in sel) else []


def test_auth_entrypoint_true_on_a_password_field():
    p = _GatePage([_El(attrs={"type": "password"})], [])
    assert browser._page_has_auth_entrypoint(p) is True


def test_auth_entrypoint_true_on_a_login_link():
    p = _GatePage([], [_El(tag="a", text="Log in"), _El(tag="a", text="Pricing")])
    assert browser._page_has_auth_entrypoint(p) is True           # a sign-in link -> auth exists -> keep fishing


def test_auth_entrypoint_false_on_a_pure_no_auth_page():
    p = _GatePage([], [_El(tag="a", text="Features"), _El(tag="a", text="Pricing")])
    assert browser._page_has_auth_entrypoint(p) is False          # no password, no auth link -> skip the fishing
