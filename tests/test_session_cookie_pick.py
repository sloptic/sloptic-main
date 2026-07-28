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


# --------------------------------------------------------- hosted auth providers (measured, not guessed)

def test_auth0s_bare_cookie_is_recognised_as_a_session():
    """A REAL browser registration was being thrown away over a name list.

    On dawg-den.vercel.app the browser lane drove a full signup and handed back seven token-shaped cookies —
    `auth0` and `auth0_compat` (303 bytes each, the session), `did`/`did_compat`, and three `__txn_*`.
    _is_session_cookie matched NONE of them, so _register_via_browser returned None and the app reported "no
    recognizable session cookie" despite holding a live session.

    Auth0's bare `auth0` cookie is the gap. Every other hosted provider checked is already covered
    incidentally by the generic hints, which is why only this one was added.
    """
    from hacklet_runner.auth import _is_session_cookie
    assert _is_session_cookie("auth0")
    assert _is_session_cookie("auth0_compat")
    # covered incidentally — asserted so a future "tidy-up" of the hint list cannot silently drop them
    for name in ("__session",                 # Clerk
                 "appSession",                # Auth0 Next.js SDK
                 "next-auth.session-token",   # NextAuth
                 "authjs.session-token",      # Auth.js v5
                 "better-auth.session_token", # Better Auth
                 "wos-session",               # WorkOS
                 "ory_kratos_session",        # Ory
                 "sb-abcdefgh-auth-token",    # Supabase
                 "sAccessToken"):             # SuperTokens
        assert _is_session_cookie(name), name


def test_the_provider_widening_did_not_take_the_non_session_cookies_with_it():
    """Precision guard on the same live sample. `__txn_*` are Auth0's short-lived PRE-login transaction
    cookies and `did` is a device id — both token-shaped, neither a session. Judging one would report cookie
    flags for the wrong cookie, which is exactly the unfalsifiable verdict session_cookie() exists to avoid."""
    from hacklet_runner.auth import _is_session_cookie
    for name in ("__txn_f8XSvhCTI92gUF2uF6hAmwhgn87v", "did", "did_compat",
                 "csrftoken", "XSRF-TOKEN", "authenticity_token",   # deliberately JS-readable
                 "refresh_token", "email_verification_token",       # not the access session
                 "_ga", "__stripe_mid"):                            # third-party, token-shaped
        assert not _is_session_cookie(name), name


def test_the_browser_lane_names_WHICH_stage_it_failed_at():
    """Five distinct outcomes used to collapse into one bare None, and diagnosing them by inspection cost three
    refuted theories in a row. The diag out-param is what turns "187 apps, cause unknown" into a distribution."""
    from hacklet_runner.auth import _register_via_browser

    diag = {}
    assert _register_via_browser("http://x", lambda _u: None, diag) is None
    assert "no fillable signup" in diag["stage"]

    diag = {}
    assert _register_via_browser("http://x", lambda _u: (_ for _ in ()).throw(RuntimeError()), diag) is None
    assert "raised RuntimeError" in diag["stage"]

    diag = {}                                     # the Auth0 shape, before the fix: cookies but no known name
    result = {"cookies": [{"name": "__txn_abc", "value": "x" * 40}], "bearer": None, "creds": {}}
    assert _register_via_browser("http://x", lambda _u: result, diag) is None
    assert "none is a recognised session name" in diag["stage"] and "__txn_abc" in diag["stage"]

    diag = {}                                     # and after: a recognised provider cookie yields an account
    ok = {"cookies": [{"name": "auth0", "value": "y" * 40}], "bearer": None, "creds": {"username": "u"}}
    assert _register_via_browser("http://x", lambda _u: ok, diag) is not None
    assert diag == {}, "a SUCCESS must not record a failure stage"


def test_the_two_causes_that_look_identical_from_auth_are_reported_SEPARATELY():
    """The bucket that made the first session-gap run useless.

    From auth's side both look the same — register_in_browser just returned falsy — so the reason read "no
    fillable signup, OR the signup left neither a cookie nor a token" and 87% of the first 39 apps landed
    there. They are opposite findings: one is our discovery bug, the other is almost certainly e-mail
    confirmation and a CORRECT N/A. register_in_browser now records which exit it took, and auth prefers it.
    """
    from hacklet_runner import auth, browser

    browser.LAST_STAGE.clear()
    browser.LAST_STAGE["stage"] = "no fillable signup reached: no visible password field"
    diag = {}
    assert auth._register_via_browser("http://x", lambda _u: None, diag) is None
    assert "no fillable signup reached" in diag["stage"]

    browser.LAST_STAGE.clear()
    browser.LAST_STAGE["stage"] = "signup filled and submitted, but the app set no cookie and issued no token"
    diag = {}
    assert auth._register_via_browser("http://x", lambda _u: None, diag) is None
    assert "filled and submitted" in diag["stage"]
    assert "no fillable signup" not in diag["stage"], "the two causes must not collapse again"

    browser.LAST_STAGE.clear()          # no stage recorded -> the generic fallback still applies
    diag = {}
    assert auth._register_via_browser("http://x", lambda _u: None, diag) is None
    assert diag["stage"]


def test_infrastructure_and_flow_cookies_are_not_reported_as_a_missing_vendor():
    """The wording I nearly acted on. Nine apps read "cookies set but none is a recognised session name", which
    implies a vendor list to extend — and not ONE was a missing vendor. Every cookie was Google's own
    (__Host-GAPS, GAESA -> SSO), Clerk client state without __session, a NextAuth/oauth CSRF or callback-url
    from a flow that never completed, or Cloudflare/Vercel infrastructure. The honest verdict is "no app session
    exists", which is a CORRECT N/A."""
    from hacklet_runner.auth import _no_app_session_cookies

    # the real samples, from session-gap-diag2/3
    assert _no_app_session_cookies(["__Host-GAPS", "GAESA"])                     # Google SSO
    assert _no_app_session_cookies(["__client", "__client_uat_u843LpZH"])        # Clerk, no __session
    assert _no_app_session_cookies(["__Host-next-auth.csrf-token",
                                    "__Secure-next-auth.callback-url"])         # unfinished NextAuth flow
    assert _no_app_session_cookies(["__cf_bm", "__dpl"])                        # platform only
    assert _no_app_session_cookies(["__Host-oauth_csrf"])

    # but a plausible unknown vendor session MUST still be flagged as one worth adding
    assert not _no_app_session_cookies(["myapp_sess_v2"])
    assert not _no_app_session_cookies(["__cf_bm", "kinde_state_thing"])
    assert not _no_app_session_cookies([])                                      # nothing set at all


def test_a_login_only_homepage_does_not_consume_the_signup_attempt():
    """recovr-smoky.vercel.app: the homepage is a login whose only button reads "Login". A password field is
    present, so the fill loop filled it, reported success, and the walk to /signup never ran — then the Enter
    fallback submitted a LOGIN for an account that does not exist, so no registration request was ever made.
    A password field is not evidence of a signup; a login form has one too."""
    from hacklet_runner.browser import _LOGIN_ONLY, _SIGNUP_SUBMIT
    for lbl in ("Login", "log in", "Sign in", "SIGNIN"):
        assert _LOGIN_ONLY.search(lbl), lbl
    for lbl in ("Create account", "Sign up", "Register", "Get started", "Join now"):
        assert _SIGNUP_SUBMIT.search(lbl), lbl
        assert not _LOGIN_ONLY.search(lbl), lbl
