"""sec-session-005: a session token persisted in localStorage is XSS-exfiltratable (the token-auth analog of a
session cookie missing HttpOnly). Slop when the browser register found a persisted token; clean when a session
was established without one; N/A when no session could be established at all."""
import pathlib
import sys

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.auth import Account, _synthesize_response  # noqa: E402
from hacklet_runner.probes import session_token_in_local_storage  # noqa: E402


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
