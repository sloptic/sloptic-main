"""register_account's SPA fallback: when httpx registration establishes no session, drive the injected
browser_register and build an Account from the cookie it returns — with the flags the session probes read."""
import pathlib
import socket
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.auth import _has_session, register_account, session_cookie  # noqa: E402
from hacklet_runner.schema import Form, Profile  # noqa: E402


def _dead_url():
    # a just-closed port -> httpx registration fails fast (RST), forcing the browser fallback path
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def _signup_profile():
    return Profile(base_url="http://x",
                   forms=[Form(action="/signup", method="post", fields=["email", "password"])])


def test_register_account_falls_back_to_browser_and_reads_the_cookie_flags():
    def fake_browser_register(url):
        return {"creds": {"username": "u", "password": "p"}, "cookies": [
            {"name": "sessionid", "value": "abc", "httponly": True, "secure": True, "samesite": False},
            {"name": "csrftoken", "value": "x", "httponly": False, "secure": False, "samesite": False}]}
    acct = register_account(_dead_url(), _signup_profile(), browser_register=fake_browser_register)
    assert acct is not None
    sc = session_cookie(acct.register_response)                     # probes read flags through session_cookie()
    assert sc and sc["name"] == "sessionid"
    assert sc["httponly"] is True and sc["secure"] is True and sc["samesite"] is False   # flags preserved
    assert any(c.name == "sessionid" for c in acct.client.cookies.jar)   # authed client carries the session


def test_no_browser_register_means_no_fallback():
    assert not _has_session(register_account(_dead_url(), _signup_profile()))   # httpx failed, no browser -> N/A


def test_browser_fallback_ignored_when_only_a_non_session_cookie_is_set():
    def only_csrf(url):
        return {"cookies": [{"name": "csrftoken", "value": "x",
                             "httponly": False, "secure": False, "samesite": False}]}
    acct = register_account(_dead_url(), _signup_profile(), browser_register=only_csrf)
    assert not _has_session(acct)   # cookies set but none is a SESSION cookie -> nothing to test -> N/A


def test_register_account_authenticates_by_bearer_when_the_app_sets_no_cookie():
    # the bolt/Supabase/Firebase shape: registration yields a JWT (localStorage + Authorization: Bearer), no cookie
    def token_only(url):
        return {"creds": {"username": "u", "password": "p"}, "cookies": [],
                "bearer": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "storage_exposed": True}
    acct = register_account(_dead_url(), _signup_profile(), browser_register=token_only)
    assert acct is not None and _has_session(acct)                        # a Bearer IS a session (cookieless SPA)
    assert acct.client.headers.get("Authorization", "").startswith("Bearer eyJ")  # authed client for IDOR reuse
    assert acct.storage_exposed is True                                   # persisted in localStorage -> exposure finding


def test_provided_header_session_short_circuits_registration():
    # Option B: a caller-supplied --header session is used directly (no self-registration), marked provided so
    # the cross-user IDOR/BOLA probes stay N/A (one identity can't be both A and B). No dead host is contacted.
    for hdr in ({"Authorization": "Bearer eyJ.tok.sig"}, {"Cookie": "sessionid=abc"}):
        acct = register_account("http://127.0.0.1:1", _signup_profile(), headers=hdr)
        assert acct is not None and acct.provided is True       # the contract the two-account guard reads
        sent = acct.client.headers                              # the provided header rides on every authed request
        assert any(sent.get(k) == v for k, v in hdr.items())
