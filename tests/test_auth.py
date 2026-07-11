"""Self-as-oracle auth helpers — pure functions, no server."""
import httpx

from hacklet_runner.auth import (
    _fill,
    _password_form,
    create_form,
    is_csrf_field,
    is_password_change_form,
    parse_set_cookies,
    session_cookie,
)
from hacklet_runner.schema import Form

# DVWA's /vulnerabilities/csrf/ — the form that locked the grader out: password_new/password_conf, no identity
_DVWA_CSRF = Form(action="/vulnerabilities/csrf/", method="get", fields=["password_new", "password_conf", "Change"])


def _resp(set_cookies):
    return httpx.Response(200, headers=[("set-cookie", c) for c in set_cookies])


def test_parse_set_cookies_reads_flags():
    by = {c["name"]: c for c in parse_set_cookies(
        _resp(["session=abc; HttpOnly; SameSite=Lax", "csrftoken=xyz"])
    )}
    assert by["session"]["httponly"] and by["session"]["samesite"]
    assert not by["csrftoken"]["httponly"]


def test_session_cookie_picks_session_not_csrf():
    c = session_cookie(_resp(["csrftoken=xyz", "session=abc; HttpOnly"]))
    assert c["name"] == "session" and c["httponly"]


def test_password_form_prefers_register():
    forms = [
        Form(action="/login", method="post", fields=["username", "password"]),
        Form(action="/register", method="post", fields=["username", "email", "password"]),
    ]
    assert _password_form(forms).action == "/register"


def test_password_form_none_without_password():
    assert _password_form([Form(action="/search", method="get", fields=["q"])]) is None


def test_fill_maps_fields_by_name():
    data = _fill(Form(action="/register", method="post", fields=["username", "email", "password"]),
                 "bob", "pw")
    assert data == {"username": "bob", "email": "bob@example.com", "password": "pw"}


def test_create_form_picks_content_form():
    forms = [
        Form(action="/login", method="post", fields=["username", "password"]),
        Form(action="/register", method="post", fields=["username", "password"]),
        Form(action="/search", method="get", fields=["q"]),
        Form(action="/notes", method="post", fields=["text"]),
    ]
    assert create_form(forms).action == "/notes"


def test_create_form_none_when_only_auth_and_search():
    forms = [
        Form(action="/login", method="post", fields=["username", "password"]),
        Form(action="/search", method="get", fields=["q"]),
    ]
    assert create_form(forms) is None


def test_is_password_change_form_flags_credential_change_not_registration():
    # a password-CHANGE form (no identity / explicit new-password field) — never auto-submit it
    assert is_password_change_form(_DVWA_CSRF)
    assert is_password_change_form(Form(action="/account", method="post",
                                        fields=["current_password", "new_password", "confirm"]))
    assert is_password_change_form(Form(action="/settings", method="post", fields=["password", "password2"]))
    # a real registration / login (has an identity field) is NOT a change form
    assert not is_password_change_form(Form(action="/register", method="post",
                                            fields=["username", "email", "password", "password_confirmation"]))
    assert not is_password_change_form(Form(action="/login", method="post", fields=["username", "password"]))
    assert not is_password_change_form(Form(action="/search", method="get", fields=["q"]))  # no password at all


def test_password_form_skips_a_password_change_form():
    # register_account must not pick DVWA's csrf password-change form (filling it locks the account out)
    forms = [_DVWA_CSRF, Form(action="/login", method="post", fields=["username", "password"])]
    assert _password_form(forms).action == "/login"
    assert _password_form([_DVWA_CSRF]) is None  # only a change form -> nothing safe to submit


def test_create_form_skips_a_password_change_form():
    # the captcha-style change form is a POST with a non-password field ("Change"), but still must be skipped
    forms = [Form(action="/vulnerabilities/captcha/", method="post",
                  fields=["step", "password_new", "password_conf", "Change"]),
             Form(action="/notes", method="post", fields=["text"])]
    assert create_form(forms).action == "/notes"


def test_is_csrf_field():
    assert is_csrf_field("csrf_token") and is_csrf_field("authenticity_token") and is_csrf_field("_token")
    assert not is_csrf_field("username") and not is_csrf_field("text")


# --- login forms recovered from INFERRED fields (anonymous SPA inputs -> [email, password]) -------
from hacklet_runner.auth import login_form  # noqa: E402


def test_inferred_email_password_is_a_detectable_login_not_a_change_form():
    # phish-school's /login after field inference: [email, password]. "email" is an identity field, so this
    # is a real login credential form — NOT withheld as a password-change form, and login-detectable.
    f = Form(action="/login", method="post", fields=["email", "password"])
    assert not is_password_change_form(f)
    assert login_form([f]) is f


def test_password_only_inferred_form_is_withheld_as_change_form():
    # when ONLY the password field could be inferred (no identity field), it's indistinguishable from a
    # password-CHANGE form, so it's treated as one and withheld — the safe default (never auto-submit it).
    assert is_password_change_form(Form(action="/login", method="post", fields=["password"]))


# --- json-login discovery must not fire on a static SPA (the rate-limit false positive) -----------
from hacklet_runner.auth import find_json_login  # noqa: E402


def test_find_json_login_rejects_a_static_spa_shell():
    # a static SPA answers ANY POST with its 200 text/html index shell — that is NOT a login endpoint,
    # so we must not treat it as one (else the rate-limit probe reports a phantom no-throttle finding)
    c = httpx.Client(base_url="http://t", transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text="<html>spa</html>")))
    assert find_json_login(c) == (None, None, None)


def test_find_json_login_accepts_a_real_auth_failure():
    c = httpx.Client(base_url="http://t", transport=httpx.MockTransport(
        lambda req: httpx.Response(401, json={"error": "invalid credentials"})))
    path, _creds, r = find_json_login(c)
    assert path is not None and r.status_code == 401
