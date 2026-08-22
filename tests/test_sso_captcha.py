"""SSO / CAPTCHA detection (off-score surface signal): WHY a self-register can't establish a session on an app
that has auth. High-precision only -- a provider OAuth endpoint, an auth SDK, or a 'with <provider>' CTA --
never a bare provider mention."""
from sloptic.discovery import _detect_sso_captcha, discover
from sloptic.schema import Profile


def test_detects_named_providers_from_cta_endpoint_and_sdk():
    assert _detect_sso_captcha("<button>Continue with Google</button>")[0] == ["google"]
    assert _detect_sso_captcha("fetch('https://github.com/login/oauth/authorize')")[0] == ["github"]
    assert "google" in _detect_sso_captcha("new GoogleAuthProvider()")[0]
    prov = _detect_sso_captcha("Sign in with Google or Sign in with GitHub")[0]
    assert set(prov) == {"google", "github"}


def test_generic_oauth_when_provider_unclear():
    assert _detect_sso_captcha("supabase.auth.signInWithOAuth({})")[0] == ["oauth"]
    assert _detect_sso_captcha("import NextAuth from 'next-auth'")[0] == ["oauth"]


def test_no_false_positive_on_a_bare_social_link():
    # a Facebook share / Twitter icon is NOT SSO -> no provider
    assert _detect_sso_captcha('<a href="https://facebook.com/ourpage">Follow us</a>')[0] == []
    assert _detect_sso_captcha('<a href="https://twitter.com/handle">@us</a>')[0] == []


def test_detects_captcha_kinds():
    assert _detect_sso_captcha('<div class="g-recaptcha"></div>')[1] == "recaptcha"
    assert _detect_sso_captcha('<script src="https://js.hcaptcha.com/1/api.js">')[1] == "hcaptcha"
    assert _detect_sso_captcha('<div class="cf-turnstile"></div>')[1] == "turnstile"
    assert _detect_sso_captcha("<p>no bot check here</p>")[1] is None


def test_surface_metrics_carries_sso_and_captcha():
    from sloptic.discovery import surface_metrics
    prof = Profile(base_url="http://x", capabilities={"sso_providers": ["google", "github"], "captcha": "recaptcha"})
    m = surface_metrics(prof)
    assert m["sso_providers"] == ["google", "github"] and m["has_sso"] is True and m["captcha"] == "recaptcha"
    # absent -> clean empty signal, not a crash
    m2 = surface_metrics(Profile(base_url="http://x"))
    assert m2["sso_providers"] == [] and m2["has_sso"] is False and m2["captcha"] is None
