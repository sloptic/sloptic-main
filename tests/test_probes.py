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


def test_a11y_severity_scale_aims_at_exclusion_not_cosmetics():
    from hacklet_runner.probes import _a11y_scale
    assert _a11y_scale({"critical": 1}) == 1.0          # real exclusion -> full ceiling
    assert _a11y_scale({"serious": 2, "minor": 3}) == 1.0
    assert _a11y_scale({"moderate": 1, "minor": 4}) == 0.6
    assert _a11y_scale({"minor": 5}) == 0.3             # decorative-alt nits -> scaled down
