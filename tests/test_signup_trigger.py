"""_first_signup_trigger: reach a JS-router signup CTA -- a 'Sign up' <button> whose onClick pushes the signup
route (no <a href>, so _signup_hrefs can't see it). It must pick that button, skip <a href> signups (the href
walk's job), and never a destructive/login control."""
from sloptic import browser


class _El:
    def __init__(self, text, href=None, aria="", vis=True):
        self.text, self.href, self.aria, self.vis = text, href, aria, vis

    def is_visible(self):
        return self.vis

    def get_attribute(self, n):
        return {"href": self.href, "aria-label": self.aria}.get(n)

    def inner_text(self):
        return self.text


class _Page:
    def __init__(self, els):
        self.els = els

    def query_selector_all(self, sel):
        return self.els


def test_picks_a_js_router_signup_button():
    got = browser._first_signup_trigger(_Page([_El("Log out"), _El("Sign up"), _El("Home")]))
    assert got is not None and got.inner_text() == "Sign up"


def test_skips_an_anchor_href_signup_left_to_the_href_walk():
    assert browser._first_signup_trigger(_Page([_El("Sign up", href="/signup")])) is None


def test_skips_destructive_and_finds_nothing_when_no_signup_cta():
    assert browser._first_signup_trigger(_Page([_El("Delete account"), _El("Dashboard")])) is None


def test_matches_create_account_and_get_started_via_aria():
    assert browser._first_signup_trigger(_Page([_El("", aria="Create your account")])) is not None
    assert browser._first_signup_trigger(_Page([_El("Get Started")])) is not None
    assert browser._first_signup_trigger(_Page([_El("Continue")])) is None   # too generic -> not a signup trigger
