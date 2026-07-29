"""sec-session-005: a session token persisted in localStorage is XSS-exfiltratable (the token-auth analog of a
session cookie missing HttpOnly). Slop when the browser register found a persisted token; clean when a session
was established without one; N/A when no session could be established at all."""
import pathlib
import sys

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.auth import Account, _synthesize_response  # noqa: E402
from sloptic.probes import session_token_in_local_storage  # noqa: E402


def _acct(*, bearer=None, cookies=None, storage_exposed=False):
    client = httpx.Client(base_url="http://x")
    if bearer:
        client.headers["Authorization"] = "Bearer " + bearer
    resp = _synthesize_response("http://x", cookies or [])
    return Account(username="u", password="p", client=client, register_response=resp,
                   storage_exposed=storage_exposed)


class _Probe:
    probe = {}


def _ctx(account):
    return type("C", (), {"register": lambda self, suffix="": account, "evidence": {}, "base_url": "http://x"})()


def test_slop_when_token_persisted_in_local_storage():
    acct = _acct(bearer="eyJ.tok.sig", storage_exposed=True)   # bearer -> a session exists; persisted -> exposed
    assert session_token_in_local_storage(_ctx(acct), _Probe()) is True


def test_clean_when_session_established_but_not_persisted():
    acct = _acct(bearer="eyJ.tok.sig", storage_exposed=False)  # in-memory bearer / cookie -> not localStorage
    assert session_token_in_local_storage(_ctx(acct), _Probe()) is False


def test_na_when_no_session_established():
    acct = _acct(storage_exposed=False)                        # no bearer, no cookie -> couldn't test (not a clean)
    assert session_token_in_local_storage(_ctx(acct), _Probe()) is None


def test_na_when_registration_fails():
    assert session_token_in_local_storage(_ctx(None), _Probe()) is None


def test_the_no_cookie_reason_distinguishes_token_auth_from_no_session_at_all():
    """The v11 run caught this reason ASSERTING COVERAGE THAT DID NOT EXIST.

    187 apps reported "token auth is sec-session-005's case" and sec-session-005 ran on ZERO of them, because
    005 gates on _has_session() and that is false when there is neither a bearer nor a cookie. Two different
    worlds had been collapsed into one reassuring string:

        bearer present -> genuinely token auth, 005 does pick it up, the N/A is correct
        nothing at all -> we hold no session by any means, so "registered" is an illusion (a 2xx from an SPA
                          placeholder POST that never reached a backend). A coverage HOLE, not coverage.

    Reading the first as the second is what made the corpus's largest gap look two thirds smaller than it is.
    """
    from sloptic.probes import session_cookie_missing_flag

    class _Flag:
        probe = {"flag": "httponly"}

    # a bearer and no cookie -> the genuine sec-session-005 case
    bearer = _acct(bearer="eyJ.tok.sig")
    ctx = _ctx(bearer)
    assert session_cookie_missing_flag(ctx, _Flag()) is None
    assert "sec-session-005" in ctx.evidence["na_reason"]
    assert "bearer" in ctx.evidence["na_reason"]

    # nothing at all -> must NOT claim 005 covers it, and must name it as untested
    empty = _acct()
    ctx = _ctx(empty)
    assert session_cookie_missing_flag(ctx, _Flag()) is None
    reason = ctx.evidence["na_reason"]
    assert "sec-session-005" not in reason, "claims coverage that does not exist: %r" % reason
    assert "NO session" in reason and "NOT covered" in reason


def test_every_na_path_says_WHY_and_the_reasons_are_DISTINGUISHABLE():
    """The session cluster was the corpus's largest coverage hole and its least diagnosable one.

    Measured on v10 (865 apps, run WITH --browser-auth): of the 204 apps carrying BOTH a login and a signup,
    session reported N/A on 177 — and not one of those records held an na_reason, because every N/A path here
    returned a bare None. aggregate.py surfaces ctx.evidence["na_reason"] per kind and had nothing to surface.

    The two dominant causes demand OPPOSITE responses: "registration failed" is a hole in the auth lanes, while
    "registered fine, but this app keeps its session in localStorage" is sec-session-005 already doing its job
    correctly. A single bare None makes 177 apps indistinguishable between a bug and correct behaviour, so the
    reasons have to be different STRINGS, not merely present.
    """
    seen = {}
    for label, account in (("no_account", None),
                           ("no_session", _acct(storage_exposed=False)),
                           ("provided", _acct(bearer="eyJ.tok.sig", storage_exposed=True))):
        if label == "provided":
            account.provided = True
        ctx = _ctx(account)
        assert session_token_in_local_storage(ctx, _Probe()) is None, label
        reason = ctx.evidence.get("na_reason")
        assert reason, "%s returned N/A with no na_reason" % label
        seen[label] = reason

    assert len(set(seen.values())) == 3, "N/A reasons collapse to the same text: %r" % seen
    assert "could not establish an account" in seen["no_account"]
    assert "no session established" in seen["no_session"]
    assert "--header" in seen["provided"]
