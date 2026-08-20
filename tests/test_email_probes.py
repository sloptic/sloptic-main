"""The two email predicates (probes.email_never_arrives / email_verification_inert) map the shared
EmailVerifyResult onto a probe verdict. The flow itself is tested in test_email_verify; here we monkeypatch it
to canned results and check the mapping + the report_only + N/A guards, so no network or registration runs."""
import types

import httpx

from sloptic import probes
from sloptic.email_verify import EmailMessage, EmailVerifyResult, MockReceiver

RX = MockReceiver()   # a non-None receiver; _run_email_flow is monkeypatched, so it is never actually used


def _ctx(email=None, headers=None):
    return types.SimpleNamespace(email=email, headers=headers, base_url="http://app.test",
                                 profile=None, _email_cache={}, evidence={})


def _canned(monkeypatch, res):
    monkeypatch.setattr(probes, "_run_email_flow", lambda ctx: res)


def test_na_without_a_receiver():
    c = _ctx(email=None)
    assert probes.email_never_arrives(c, None) is None
    assert "no email receiver" in c.evidence["na_reason"]
    assert c.evidence["report_only"] is True     # always off-score in v1


def test_na_with_a_provided_session():
    c = _ctx(email=RX, headers={"Cookie": "session=x"})
    assert probes.email_never_arrives(c, None) is None
    assert "session was supplied" in c.evidence["na_reason"]


def test_na_when_signup_is_not_email_gated(monkeypatch):
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=False, na_reason="not gated"))
    assert probes.email_never_arrives(_ctx(email=RX), None) is None
    assert probes.email_verification_inert(_ctx(email=RX), None) is None


def test_email_001_ladder_no_email_60s_locks_out_top_rung(monkeypatch):
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=False, detail="no mail"))
    c = _ctx(email=RX)
    assert probes.email_never_arrives(c, None) is True
    assert c.evidence["no_email_60s"] is True and c.evidence["report_only"] is True
    assert probes.email_verification_inert(_ctx(email=RX), None) is None   # 002 N/A: no link ever arrived


def test_email_001_ladder_late_email_sets_the_30s_escalator(monkeypatch):
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True,
                                           first_leg_empty=True, has_resend_control=True))
    c = _ctx(email=RX)
    assert probes.email_never_arrives(c, None) is True
    assert c.evidence.get("email_late_30s") is True and "no_email_60s" not in c.evidence


def test_email_001_ladder_no_resend_control_fires_even_when_email_is_prompt(monkeypatch):
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True,
                                           first_leg_empty=False, has_resend_control=False))
    c = _ctx(email=RX)
    assert probes.email_never_arrives(c, None) is True                    # base-5 fire on a working app
    assert c.evidence.get("no_resend_button") is True
    assert "email_late_30s" not in c.evidence and "no_email_60s" not in c.evidence


def test_email_001_clean_only_when_prompt_and_a_resend_control_exists(monkeypatch):
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True,
                                           first_leg_empty=False, has_resend_control=True))
    assert probes.email_never_arrives(_ctx(email=RX), None) is False


def test_email_002_fires_when_link_establishes_no_session(monkeypatch):
    msg = EmailMessage.parse("hl@app.test", "Verify", "http://app.test/v")
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True,
                                           has_resend_control=True, acted_on_verification=True,
                                           session_after_verify=False, message=msg))
    assert probes.email_verification_inert(_ctx(email=RX), None) is True
    assert probes.email_never_arrives(_ctx(email=RX), None) is False   # 001 clean: prompt email + resend control


def test_both_clean_when_the_whole_flow_works(monkeypatch):
    msg = EmailMessage.parse("hl@app.test", "Verify", "http://app.test/v")
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True,
                                           first_leg_empty=False, has_resend_control=True,
                                           acted_on_verification=True, session_after_verify=True, message=msg))
    assert probes.email_never_arrives(_ctx(email=RX), None) is False
    assert probes.email_verification_inert(_ctx(email=RX), None) is False


def _client(handler):
    return httpx.Client(base_url="http://app.test", transport=httpx.MockTransport(handler))


def _reg(body):
    return httpx.Response(200, text=body, request=httpx.Request("POST", "http://app.test/signup"))


def test_has_resend_control_detects_link_form_and_text_but_not_a_bare_page():
    assert probes._has_resend_control(_reg("<p>Didn't receive it? <a href='/resend'>Resend</a></p>")) is True
    assert probes._has_resend_control(_reg('<form action="/auth/resend"></form>')) is True
    assert probes._has_resend_control(_reg("<html>Check your email to confirm.</html>")) is False


def test_try_resend_follows_a_resend_link():
    hit = []
    body = '<html>Check your email. <a href="/verify/resend?u=1">Resend confirmation</a></html>'
    assert probes._try_resend(_client(lambda r: (hit.append(str(r.url)), httpx.Response(200))[1]),
                              _reg(body), "hl@app.test") is True
    assert any("resend" in u for u in hit)


def test_try_resend_posts_a_resend_form():
    def handler(req):
        return httpx.Response(200) if req.method == "POST" and "resend" in str(req.url) else httpx.Response(404)
    body = '<form action="/auth/resend-verification" method="post"></form>'
    assert probes._try_resend(_client(handler), _reg(body), "hl@app.test") is True


def test_try_resend_tries_json_only_when_page_mentions_resend():
    def handler(req):
        return httpx.Response(200) if req.url.path == "/api/resend" else httpx.Response(404)
    assert probes._try_resend(_client(handler), _reg("Didn't receive it? Resend."), "hl@app.test") is True


def test_try_resend_false_and_no_blind_spray_without_a_resend_control():
    posted = []
    assert probes._try_resend(_client(lambda r: (posted.append(1), httpx.Response(404))[1]),
                              _reg("<html>Welcome</html>"), "hl@app.test") is False
    assert posted == []   # no resend concept on the page -> no requests sent at all


def _acct(handler):
    from sloptic.auth import Account
    client = httpx.Client(base_url="http://app.test", transport=httpx.MockTransport(handler),
                          follow_redirects=True)
    return Account(username="hl_x", password="pw", client=client,
                   register_response=httpx.Response(200, request=httpx.Request("POST", "http://app.test/s")))


_VERIFY_MSG = EmailMessage.parse("hl@app.test", "Verify", "http://app.test/verify?t=1")


def test_follow_auto_login_via_the_link():
    # the link itself sets a session cookie -> verified + logged in, no separate login needed
    acct = _acct(lambda req: httpx.Response(200, headers={"set-cookie": "session=abc; Path=/"}))
    ver = probes._follow_verification(acct, _VERIFY_MSG, "http://app.test", None, "hl@app.test")
    assert ver.acted is True and ver.session is True


def test_follow_verify_then_login_reads_clean(monkeypatch):
    # the link verifies but does NOT log us in; a login with the creds now succeeds -> the flow WORKS (not a fire)
    monkeypatch.setattr(probes.auth, "login_with_credentials", lambda b, ident, pw, prof: {"Cookie": "s=1"})
    acct = _acct(lambda req: httpx.Response(200))
    ver = probes._follow_verification(acct, _VERIFY_MSG, "http://app.test", None, "hl@app.test")
    assert ver.acted is True and ver.session is True


def test_follow_inert_when_login_still_fails_after_verifying(monkeypatch):
    # clicked the link, still no session, and a login STILL fails -> verification is genuinely broken (fires)
    monkeypatch.setattr(probes.auth, "login_with_credentials", lambda *a: {})
    acct = _acct(lambda req: httpx.Response(200))
    ver = probes._follow_verification(acct, _VERIFY_MSG, "http://app.test", None, "hl@app.test")
    assert ver.acted is True and ver.session is False


def test_follow_code_only_email_reads_na():
    acct = _acct(lambda req: httpx.Response(200))
    msg = EmailMessage.parse("hl@app.test", "Code", "your verification code is 123456")   # no link
    assert probes._follow_verification(acct, msg, "http://app.test", None, "hl@app.test").acted is False


def test_email_002_na_on_a_code_only_email(monkeypatch):
    msg = EmailMessage.parse("hl@app.test", "Code", "your verification code is 903217")
    _canned(monkeypatch, EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True,
                                           acted_on_verification=False, message=msg,
                                           detail="no followable verification link"))
    c = _ctx(email=RX)
    assert probes.email_verification_inert(c, None) is None   # could not act -> N/A, never a fire
    assert "followable" in c.evidence["na_reason"]
