"""sec-session-006: a reusable session/access token in a URL query string (CWE-598).

The session family checks cookies and localStorage; nothing looked at the URL. The rule under test: a
session-named param, or a generic token param holding a JWT, fires; a single-use reset/verify link and a
URL-fragment token do not, because those have a legitimate form. Pure string logic, no network.
"""
import pytest

from sloptic import probes

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


def _f(text):
    return probes._url_session_token([text])


def test_access_token_jwt_in_query_fires():
    hit = _f(f"/dashboard?access_token={_JWT}")
    assert hit and hit[0] == "access_token" and hit[2] == "jwt"


def test_a_session_named_param_fires_on_an_opaque_value():
    hit = _f("/app?sessionid=8f3b2c1d9e7a4b6c0f2e")
    assert hit and hit[0] == "sessionid" and hit[2] == "opaque"


def test_a_generic_token_param_fires_only_on_a_jwt():
    assert _f(f"/x?token={_JWT}")                       # JWT -> real bearer, fires
    assert _f("/x?token=a1b2c3d4e5f6a7b8") is None      # opaque under generic 'token' -> likely a nonce, no fire


@pytest.mark.parametrize("url", [
    "/reset-password?token=a1b2c3d4e5f6a7b8c9d0",       # single-use reset link, the standard email pattern
    f"/verify?token={_JWT}",                            # email verification
    f"/confirm?access_token={_JWT}",                    # confirm flow
    "/auth?state=abc123def456&code=xyz789abcdef",       # OAuth handshake params, not a session
    f"/callback?csrf={_JWT}",                           # a CSRF token, not a session
])
def test_single_use_and_handshake_params_never_fire(url):
    assert _f(url) is None


def test_a_fragment_token_does_not_fire():
    """A token in the URL fragment is not sent to the server or the referrer -- a different, lesser thing,
    and sec-session-005's territory. Only the query string leaks the three ways this probe is about."""
    assert _f(f"/app#access_token={_JWT}") is None


def test_a_templated_token_in_a_bundle_does_not_fire():
    """`?access_token=${var}` is code building a URL, not a leaked literal. Only a concrete value is a leak."""
    assert _f("const u = base + `/cb?access_token=${session.token}`;") is None


def test_probe_reads_routes_and_masks_the_value(monkeypatch):
    class P:
        routes = [f"/dashboard?access_token={_JWT}", "/", "/about"]
    class Ctx:
        profile = P(); evidence = {}
    monkeypatch.setattr(probes, "_client_bundle", lambda ctx: "")
    ctx = Ctx()
    assert probes.session_token_in_url(ctx, None) is True
    assert ctx.evidence["param"] == "access_token"
    assert _JWT not in ctx.evidence["value"] and "..." in ctx.evidence["value"]   # masked


def test_clean_when_no_token_in_any_url(monkeypatch):
    class P:
        routes = ["/", "/about", "/pricing?ref=twitter"]
    class Ctx:
        profile = P(); evidence = {}
    monkeypatch.setattr(probes, "_client_bundle", lambda ctx: '<a href="/login">in</a>')
    assert probes.session_token_in_url(Ctx(), None) is False


def test_session_family_is_active_only():
    from sloptic import safety
    assert not safety.is_passive("sec-session-006")     # the session family is categorically active
