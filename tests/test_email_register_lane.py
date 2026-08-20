"""The register-lane integration: an email-verification-gated signup must not just be GRADED (qa-email-001/002),
it must be COMPLETED so the authed-surface probes run as the verified user (the reason the receiver exists). The
flow runs at most once per app; ctx.register rebuilds a fresh, independently-closeable client from the captured
session on every call, and register_account tries the email lane BEFORE the (expensive) browser launch.
"""
import types

import httpx

from sloptic import auth, pipeline, probes
from sloptic.auth import Account
from sloptic.email_verify import EmailMessage, EmailVerifyResult, MockReceiver
from sloptic.schema import Form, Profile

RX = MockReceiver()


def _ctx(email=RX, headers=None):
    return types.SimpleNamespace(email=email, headers=headers, base_url="http://app.test",
                                 profile=None, _email_cache={}, evidence={})


def _acct(handler, **hdrs):
    client = httpx.Client(base_url="http://app.test", transport=httpx.MockTransport(handler),
                          follow_redirects=True, headers=hdrs)
    return Account(username="hl_e", password="pw", client=client,
                   register_response=httpx.Response(200, request=httpx.Request("POST", "http://app.test/s")))


def _reg_response(text):
    return httpx.Response(200, text=text, request=httpx.Request("POST", "http://app.test/s"))


# --- snapshot + rebuild ------------------------------------------------------------------------------------

def test_snapshot_reads_the_session_as_the_client_would_send_it():
    acct = _acct(lambda r: httpx.Response(200), Authorization="Bearer tok", Cookie="session=abc")
    snap = probes._snapshot_session(acct)
    assert snap["headers"]["Authorization"] == "Bearer tok"
    assert snap["headers"]["Cookie"] == "session=abc"


def test_snapshot_falls_back_to_the_session_cookie_in_the_jar():
    acct = _acct(lambda r: httpx.Response(200))
    acct.client.cookies.set("sessionid", "xyz")
    acct.client.cookies.set("csrftoken", "nope")   # not a session cookie -> excluded from the picked cookie
    snap = probes._snapshot_session(acct)
    assert "sessionid=xyz" in snap["headers"]["Cookie"] and "csrftoken" not in snap["headers"]["Cookie"]


def test_email_account_rebuilds_a_fresh_independently_closeable_client_each_call():
    ctx = _ctx()
    ctx._email_cache["result"] = EmailVerifyResult(attempted=True)   # the flow has run
    ctx._email_cache["account_session"] = {
        "headers": {"Authorization": "Bearer tok", "Cookie": "session=abc"}, "username": "u", "password": "p",
        "response": _reg_response("ok"), "storage_exposed": False}
    a = probes._email_account(ctx)
    b = probes._email_account(ctx)
    assert a is not None and b is not None and a.client is not b.client   # distinct clients
    assert a.client.headers["Authorization"] == "Bearer tok"
    a.client.close()                                                      # closing one must not break the other
    assert b.client.headers["Cookie"] == "session=abc"
    b.client.close()


def test_email_account_returns_none_when_no_session_was_captured():
    ctx = _ctx()
    ctx._email_cache["result"] = EmailVerifyResult(attempted=True, email_gated=True, email_arrived=False)
    assert probes._email_account(ctx) is None    # gated but no session established -> nothing to reuse


# --- the email-gated gate (don't tax a non-email app before its browser launch) -----------------------------

def test_email_account_does_not_run_the_flow_for_a_non_announcing_signup(monkeypatch):
    ran = []
    monkeypatch.setattr(probes, "_run_email_flow", lambda ctx: ran.append(1) or EmailVerifyResult(attempted=True))
    ctx = _ctx()
    acct = _acct(lambda r: httpx.Response(200))
    acct.register_response = _reg_response("<html>Welcome, you're in.</html>")   # no email-pending language
    assert probes._email_account(ctx, acct) is None
    assert ran == []                              # not email-gated -> flow never runs -> browser lane handles it


def test_email_account_runs_the_flow_for_an_announcing_signup_and_returns_the_session(monkeypatch):
    def fake_flow(ctx):
        ctx._email_cache["account_session"] = {
            "headers": {"Cookie": "s=1"}, "username": "u", "password": "p",
            "response": _reg_response("ok"), "storage_exposed": False}
        return EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True, session_after_verify=True)
    monkeypatch.setattr(probes, "_run_email_flow", fake_flow)
    ctx = _ctx()
    acct = _acct(lambda r: httpx.Response(200))
    acct.register_response = _reg_response("Check your email to confirm your account.")
    out = probes._email_account(ctx, acct)
    assert out is not None and out.client.headers["Cookie"] == "s=1"
    out.client.close()


def test_email_account_reuses_a_session_captured_by_the_qa_probes_even_if_not_announced(monkeypatch):
    # if the shared flow already ran (via a qa-email probe) and captured a session, reuse it regardless of the gate
    monkeypatch.setattr(probes, "_run_email_flow", lambda ctx: (_ for _ in ()).throw(AssertionError("should reuse")))
    ctx = _ctx()
    ctx._email_cache["result"] = EmailVerifyResult(attempted=True, session_after_verify=True)
    ctx._email_cache["account_session"] = {"headers": {"Cookie": "s=1"}, "username": "u", "password": "p",
                                           "response": _reg_response("ok"), "storage_exposed": False}
    acct = _acct(lambda r: httpx.Response(200))
    acct.register_response = _reg_response("<html>no email language</html>")
    out = probes._email_account(ctx, acct)                                 # cache present -> flow not re-run
    assert out is not None and out.client.headers["Cookie"] == "s=1"
    out.client.close()


# --- follow: verify-then-login must CARRY the session onto the client (so it is reusable) -------------------

_VERIFY_MSG = EmailMessage.parse("hl@app.test", "Verify", "http://app.test/verify?t=1")


def test_follow_verify_then_login_carries_the_session_onto_the_account_client(monkeypatch):
    monkeypatch.setattr(probes.auth, "login_with_credentials",
                        lambda b, ident, pw, prof: {"Authorization": "Bearer T"})
    acct = _acct(lambda req: httpx.Response(200))                          # link verifies but sets no cookie
    ver = probes._follow_verification(acct, _VERIFY_MSG, "http://app.test", None, "hl@app.test")
    assert ver.session is True
    assert acct.client.headers["Authorization"] == "Bearer T"             # now authenticated for authed-surface reuse


def test_follow_auto_login_promotes_the_flag_bearing_response():
    acct = _acct(lambda req: httpx.Response(200, headers={"set-cookie": "sessionid=abc; HttpOnly; Path=/"}))
    probes._follow_verification(acct, _VERIFY_MSG, "http://app.test", None, "hl@app.test")
    sc = auth.session_cookie(acct.register_response)                       # cookie-flag probes read this response
    assert sc and sc["name"] == "sessionid" and sc["httponly"] is True


# --- ctx.register wiring -----------------------------------------------------------------------------------

def test_ctx_register_wires_the_email_lane_for_single_identity_not_the_idor_pair(monkeypatch):
    seen = {}

    def fake_ra(base, profile, suffix="", browser_register=None, headers=None, email_verify=None):
        seen[suffix] = email_verify
        return None
    monkeypatch.setattr(pipeline.auth, "register_account", fake_ra)
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=RX)
    for suffix in ("", "_race", "_csrf", "_a", "_b"):
        ctx.register(suffix)
    assert seen[""] is not None and seen["_race"] is not None and seen["_csrf"] is not None
    assert seen["_a"] is None and seen["_b"] is None                       # two distinct identities can't come from one


def test_ctx_register_wires_no_email_lane_without_a_receiver(monkeypatch):
    seen = {}
    monkeypatch.setattr(pipeline.auth, "register_account",
                        lambda *a, **k: seen.setdefault("cb", k.get("email_verify")))
    pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=None).register("")
    assert seen["cb"] is None


# --- register_account: the email lane runs BEFORE the browser launch ----------------------------------------

def test_register_account_tries_the_email_lane_before_the_browser(monkeypatch):
    sessionless = _acct(lambda r: httpx.Response(200))                     # httpx register: no session
    monkeypatch.setattr(auth, "_register_httpx", lambda *a, **k: sessionless)
    prof = Profile(base_url="http://app.test", forms=[], capabilities={"signup_trigger": True})
    launched = []
    email_acct = _acct(lambda r: httpx.Response(200), Authorization="Bearer E")
    out = auth.register_account("http://app.test", prof,
                                browser_register=lambda b: launched.append(1),
                                email_verify=lambda acct: email_acct)
    assert out is email_acct                                              # the email session won
    assert launched == []                                                # ... and the browser was never launched


def test_register_account_falls_through_to_browser_when_email_lane_returns_none(monkeypatch):
    sessionless = _acct(lambda r: httpx.Response(200))
    monkeypatch.setattr(auth, "_register_httpx", lambda *a, **k: sessionless)
    prof = Profile(base_url="http://app.test",
                   forms=[Form(action="/signup", method="post", fields=["email", "password"])])
    monkeypatch.setattr(auth, "_register_json", lambda *a, **k: None)      # no JSON session either
    launched = []

    def browser(url):
        launched.append(1)
        return {"cookies": [{"name": "sessionid", "value": "b", "httponly": True, "secure": False,
                             "samesite": False}]}
    out = auth.register_account("http://app.test", prof, browser_register=browser,
                                email_verify=lambda acct: None)            # email lane declines
    assert launched == [1] and auth._has_session(out)                     # browser lane ran and won
