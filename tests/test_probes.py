"""Detection-primitive unit tests. Focus: precision of the content matchers — they must catch real
problems and must NOT flag benign content (a false positive wrongly penalizes).
"""
import httpx

from hacklet_runner.probes import (
    _csrf_candidates,
    response_csp_weak,
    response_has_header,
    response_is_dotenv,
    response_is_git_config,
    response_is_git_head,
    response_leaks_secret,
    response_missing_header,
)
from hacklet_runner.schema import Form, Profile


def _resp(status, headers=None):
    return httpx.Response(status, headers=headers or {}, request=httpx.Request("GET", "http://t/"))


def test_header_policy_matchers_ignore_server_errors():
    # a missing/leaked header on a 200 is a real config finding; on a 500 (env-var-dead endpoint's error
    # page) it isn't the app's policy — counting it manufactures findings from a broken endpoint
    assert response_missing_header(_resp(200, {}), "x-content-type-options") is True
    assert response_missing_header(_resp(500, {}), "x-content-type-options") is False
    assert response_missing_header(_resp(404, {}), "x-content-type-options") is True   # 4xx is still real
    assert response_has_header(_resp(200, {"x-powered-by": "Express"}), "x-powered-by") is True
    assert response_has_header(_resp(503, {"x-powered-by": "Express"}), "x-powered-by") is False


def test_csrf_candidates_exclude_password_change_forms():
    # a password-change form must never be a CSRF target — submitting it resets the grader's own session
    prof = Profile(base_url="http://x", forms=[
        Form(action="/vulnerabilities/csrf/", method="get", fields=["password_new", "password_conf", "Change"]),
        Form(action="/guestbook", method="post", fields=["name", "message"]),   # a safe state-changer
    ])
    actions = [f.action for f in _csrf_candidates(prof)]
    assert "/guestbook" in actions and "/vulnerabilities/csrf/" not in actions


class _Resp:
    def __init__(self, text: str, status: int = 200):
        self.text = text
        self.status_code = status


def test_detects_real_secrets():
    assert response_leaks_secret(_Resp("AKIAZ3PK7NBQWXYZ1234"))                 # AWS key id (non-placeholder)
    assert response_leaks_secret(_Resp('k="sk_live_abcdef0123456789ABCDEF"'))   # Stripe live secret
    assert response_leaks_secret(_Resp("ghp_" + "a" * 36))                      # GitHub PAT
    assert response_leaks_secret(_Resp("-----BEGIN PRIVATE KEY-----\nMIIE..."))  # private key block


def test_ignores_public_by_design():
    # Firebase web apiKey, Stripe publishable key, and plain JS are NOT secrets.
    assert not response_leaks_secret(_Resp('apiKey: "AIzaSyD-EXAMPLE_firebase_public_key_x12345"'))
    assert not response_leaks_secret(_Resp("pk_live_publishablekey1234567890"))
    assert not response_leaks_secret(_Resp('const config = { api: "/api" };'))


def test_weak_csp_fires_on_toothless_policies():
    csp = lambda v: _resp(200, {"content-security-policy": v})   # noqa: E731
    assert response_csp_weak(csp("default-src 'self'; script-src 'self' 'unsafe-inline'"))  # inline runs
    assert response_csp_weak(csp("script-src *"))                                            # any host
    assert response_csp_weak(csp("default-src 'unsafe-inline'"))                             # via default-src fallback
    assert response_csp_weak(csp("frame-ancestors 'none'"))                                  # no script restriction at all


def test_weak_csp_clean_on_modern_and_absent():
    csp = lambda v: _resp(200, {"content-security-policy": v})   # noqa: E731
    assert not response_csp_weak(csp("script-src 'self' 'nonce-r4nd0m' 'strict-dynamic'"))   # nonce -> inline ignored
    assert not response_csp_weak(csp("default-src 'self'; script-src 'self'"))               # locked to self
    assert not response_csp_weak(_resp(200, {}))                                             # absent -> not THIS finding


def test_detects_exposed_files():
    assert response_is_dotenv(_Resp("DATABASE_URL=postgres://x\nSECRET_KEY=abc"))
    assert response_is_dotenv(_Resp("export GITHUB_TOKEN=ghp_xyz\n"))   # export prefix + TOKEN key
    assert response_is_dotenv(_Resp("  STRIPE_KEY=sk_live_xyz\n"))      # indented + bare *_KEY
    assert response_is_git_config(_Resp("[core]\n\trepositoryformatversion = 0\n"))
    assert response_is_git_head(_Resp("ref: refs/heads/main\n"))        # symbolic ref
    assert response_is_git_head(_Resp("a" * 40 + "\n"))                 # detached HEAD (raw SHA)


def test_exposure_needs_200_and_signature():
    assert not response_is_dotenv(_Resp("DATABASE_URL=x", status=404))   # not actually served
    assert not response_is_dotenv(_Resp("<html><body>hi</body></html>"))  # 200 but not a .env
    assert not response_is_git_head(_Resp("<html>not found</html>"))     # 200, wrong content


def test_resource_shaped_tells_a_race_from_a_fixed_redirect():
    # qa-race-001 fires on duplicate ids under concurrency. A per-resource landing (/notes/1) exposes an id
    # to compare; a fixed success-page redirect (/home) exposes none, so uniform landings must NOT read as a
    # race. This is the guard that keeps a create->redirect-to-dashboard app from a phantom race finding.
    from hacklet_runner.probes import _resource_shaped
    assert _resource_shaped("/notes/1", "/notes")            # sub-path of the create endpoint + numeric id
    assert _resource_shaped("/api/notes/42", "/api/notes")
    assert _resource_shaped("/items/a1b2c3d4e5", "/create")  # trailing hex/uuid id, different base
    assert not _resource_shaped("/home", "/notes")           # fixed landing page -> no id to compare
    assert not _resource_shaped("/dashboard", "/notes")
    assert not _resource_shaped("/notes", "/notes")          # the create endpoint / list itself


def test_console_first_party_classification():
    # qa-console-001 fires only on the APP'S OWN uncaught errors. A third-party widget/analytics script
    # that throws (cross-origin, browser-sanitized to "Script error.") is benign noise a working app carries.
    from hacklet_runner.browser import _first_party_error as fp
    o = "127.0.0.1:8080"
    assert fp("x is not defined", "ReferenceError\n    at http://127.0.0.1:8080/:61:1", o)   # inline, host:PORT
    assert fp("boom", "at f (http://127.0.0.1:8080/main.js:2:9)", o)                          # same-origin script
    assert fp("boom", "ReferenceError\n    at <anonymous>:1:1", o)                            # inline, no url
    assert not fp("boom", "at g (https://cdn.analytics.com/w.js:1:2)", o)                     # third-party host
    assert not fp("Script error.", "", o)                                                    # cross-origin sanitized


def test_a11y_penalty_damps_stacked_barriers():
    from hacklet_runner.probes import _a11y_penalty
    assert _a11y_penalty({"serious": 1}) == 18                  # a lone contrast miss -> below the old flat 26
    assert _a11y_penalty({"critical": 1}) == 30                 # a screen-reader blocker -> above the old ceiling
    assert _a11y_penalty({"critical": 1, "serious": 1}) == 41   # additive but DAMPED: 30 + 18*.6 (not a raw 48)
    assert _a11y_penalty({"serious": 3}) == 35                  # worst full, rest decay: 18 + 18*.6 + 18*.36
    assert _a11y_penalty({"moderate": 1, "minor": 2}) == 14     # 10 + 4*.6 + 4*.36 -> cosmetics stay cheap
    assert _a11y_penalty({}) == 0


def test_console_scales_by_render_health():
    from hacklet_runner.probes import _console_broken_render
    assert _console_broken_render({"error_overlay": True, "content_len": 5000}) is True    # crash overlay -> full
    assert _console_broken_render({"error_overlay": False, "content_len": 8}) is True       # near-empty -> full
    assert _console_broken_render({"error_overlay": False, "content_len": 5000}) is False   # page fine -> reduced
    assert _console_broken_render({"error_overlay": False, "content_len": None}) is False   # unmeasured -> not broken


def test_error_hygiene_signatures_match_leaks_not_prose():
    from hacklet_runner.probes import _TRACE, _SQL_ERROR
    assert _TRACE.search('Traceback (most recent call last):\n  File "app.py", line 9, in f')   # Python
    assert _TRACE.search('at handler (/srv/app/server.js:12:7)')                                  # Node
    assert _TRACE.search('goroutine 17 [chan receive]:')                                          # Go panic
    assert _TRACE.search("\tfrom app.rb:23:in `block'")                                           # Ruby
    assert _SQL_ERROR.search('sqlite3.OperationalError: no such column: x')                       # leaked DB error
    assert not _TRACE.search('Our guide explains how to handle errors: retry at most once.')      # ordinary prose


def test_declared_constraint_values_and_acceptance():
    from hacklet_runner.probes import _constraint_values, _submission_accepted
    assert _constraint_values({"type": "email"}) == ("hl.probe@example.com", "hlnotanemail")   # invalid: no @
    assert _constraint_values({"type": "number", "min": "3"})[0] == "3"        # valid = the declared min
    assert not _constraint_values({"type": "number"})[1].isdigit()             # invalid = non-numeric
    assert _constraint_values({"type": "text"}) is None                        # unconstrained -> not testable

    class R:
        def __init__(self, code, loc=""):
            self.status_code, self.headers = code, {"location": loc}
    assert _submission_accepted(R(200), "/register") is True
    assert _submission_accepted(R(302, "/dashboard"), "/register") is True     # POST-redirect-GET success
    assert _submission_accepted(R(302, "/register"), "/register") is False     # redirect back to form = re-show
    assert _submission_accepted(R(400), "/register") is False                  # explicit rejection
