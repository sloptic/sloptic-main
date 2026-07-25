"""Which cookie the session probes judge, and when a missing `Secure` is real.

Two precision fixes found by hand-auditing live findings:
  (1) an app can set SEVERAL session-NAMED cookies (`app_session=user@example.com` for the UI next to the
      real `session=eyJ...`); picking the wrong one reported that cookie's flags as the session's, so a
      correctly-hardened token read as unprotected. The verdict also never said WHICH cookie -> unfalsifiable.
  (2) on a host where HTTPS is browser-ENFORCED (HSTS preload / preloaded-apex platform subdomain) a cookie
      missing `Secure` cannot transit in cleartext, so charging for it contradicts the sec-headers-003
      carve-out that already forgives the missing HSTS header on those same hosts.
"""
import pathlib
import sys

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import auth  # noqa: E402
from hacklet_runner.probes import _https_browser_enforced  # noqa: E402

_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")


def _resp(*set_cookies):
    return httpx.Response(200, headers=[("set-cookie", c) for c in set_cookies],
                          request=httpx.Request("GET", "https://app.example.com/"))


def test_picks_the_token_cookie_not_a_session_named_email_cookie():
    # the real token is hardened (HttpOnly+Secure); a sibling UI cookie holds the plaintext email. The
    # LAST matching cookie is the email one — the old "last match wins" rule judged that, and reported the
    # session as having no HttpOnly while the actual session token had it.
    r = _resp(f"brain_session={_JWT}; Path=/; HttpOnly; Secure; SameSite=None",
              "brain_app_session=test%40test.com; Path=/; SameSite=Lax",
              "brain-md-auth=test%40test.com; Path=/; SameSite=Lax")
    c = auth.session_cookie(r)
    assert c["name"] == "brain_session"          # the JWT, not either email cookie
    assert c["httponly"] is True and c["secure"] is True


def test_falls_back_to_the_name_heuristic_when_no_value_is_token_shaped():
    # an opaque-but-short or non-token session value still has to be judged — never return None here,
    # or a genuinely unprotected session would go unmeasured (N/A reads as "couldn't test", not "clean").
    r = _resp("app_session=abc; Path=/")
    c = auth.session_cookie(r)
    assert c is not None and c["name"] == "app_session" and c["httponly"] is False


def test_token_shape_rejects_identifiers_and_accepts_opaque_ids():
    assert auth._token_shaped(_JWT) is True
    assert auth._token_shaped("s%3AaGVsbG8gd29ybGQgbG9uZ2lk.9xQ") is True     # long opaque id
    assert auth._token_shaped("test%40test.com") is False                     # url-encoded email
    assert auth._token_shaped("user@example.com") is False
    assert auth._token_shaped("abc") is False and auth._token_shaped("") is False


def test_camelcase_token_cookies_are_recognized_as_sessions():
    # the modern JS convention is a camelCase name with no separator, which an exact-name set plus a
    # `session`-only substring both miss. Measured cost of the miss on the OopsSec anchor (cookie: authToken):
    # no session detected -> the self-as-oracle holds no identity -> IDOR x5, session x4, CSRF, upload x2 all
    # read N/A, and the session-hygiene probes never judge the real token.
    for name in ("authToken", "accessToken", "idToken", "sessionToken", "auth_token", "jwt", "session", "sid"):
        assert auth._is_session_cookie(name) is True, name


def test_token_named_cookies_that_are_not_the_session_stay_excluded():
    # a CSRF/anti-forgery token is deliberately JS-readable, so judging it would report a false hygiene
    # failure; a refresh token is not the access session; a verification token is not a login
    for name in ("csrfToken", "XSRF-TOKEN", "__Host-csrf", "antiforgeryToken", "anti-forgery-token",
                 "refreshToken", "emailVerificationToken", "verifyToken"):
        assert auth._is_session_cookie(name) is False, name


def test_parse_set_cookies_now_carries_the_value():
    got = auth.parse_set_cookies(_resp("sid=xyz123; HttpOnly"))[0]
    assert got["name"] == "sid" and got["value"] == "xyz123" and got["httponly"] is True


class _Ctx:
    def __init__(self, base_url, hsts=None):
        self.base_url = base_url
        self._hsts = hsts

    class _C:
        def __init__(self, hsts):
            self._hsts = hsts

        def get(self, _path):
            h = {"strict-transport-security": self._hsts} if self._hsts else {}
            return httpx.Response(200, headers=h, request=httpx.Request("GET", "https://x/"))

    @property
    def client(self):
        return self._C(self._hsts)


def test_secure_flag_is_moot_where_https_is_browser_enforced():
    # a preloaded-apex platform subdomain: the browser upgrades before the request leaves (same reason
    # sec-headers-003 already forgives the missing HSTS header there)
    assert _https_browser_enforced(_Ctx("https://myapp.vercel.app")) is True
    # the app's OWN header, but only when it claims preload-list membership
    assert _https_browser_enforced(
        _Ctx("https://www.brain-md.dev", "max-age=63072000; includeSubDomains; preload")) is True
    # trust-on-first-use only (no preload) -> NOT suppressed: a first-ever http:// visit can still leak
    assert _https_browser_enforced(_Ctx("https://ex.com", "max-age=63072000; includeSubDomains")) is False
    assert _https_browser_enforced(_Ctx("https://ex.com", "max-age=0; includeSubDomains; preload")) is False
    assert _https_browser_enforced(_Ctx("https://ex.com")) is False           # no HSTS at all -> real finding
