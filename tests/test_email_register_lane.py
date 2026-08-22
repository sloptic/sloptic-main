"""The register-lane integration: an email-verification-gated signup must not just be GRADED (qa-email-001/002),
it must be COMPLETED so the authed-surface probes run as the verified user (the reason the receiver exists). The
flow runs at most once per app; ctx.register rebuilds a fresh, independently-closeable client from the captured
session on every call, and register_account tries the email lane BEFORE the (expensive) browser launch.
"""
import types

import httpx

from sloptic import auth, baas, pipeline, probes
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
    monkeypatch.setattr(probes, "_run_email_flow", lambda ctx, suffix="": ran.append(1) or EmailVerifyResult(attempted=True))
    ctx = _ctx()
    acct = _acct(lambda r: httpx.Response(200))
    acct.register_response = _reg_response("<html>Welcome, you're in.</html>")   # no email-pending language
    assert probes._email_account(ctx, acct) is None
    assert ran == []                              # not email-gated -> flow never runs -> browser lane handles it


def test_email_account_runs_the_flow_for_an_announcing_signup_and_returns_the_session(monkeypatch):
    def fake_flow(ctx, suffix=""):
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
    monkeypatch.setattr(probes, "_run_email_flow", lambda ctx, suffix="": (_ for _ in ()).throw(AssertionError("should reuse")))
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

def test_ctx_register_wires_the_email_lane_for_every_identity_including_the_idor_pair(monkeypatch):
    seen = {}

    def fake_ra(base, profile, suffix="", browser_register=None, headers=None, email_verify=None):
        seen[suffix] = email_verify
        return None
    monkeypatch.setattr(pipeline.auth, "register_account", fake_ra)
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=RX)
    for suffix in ("", "_race", "_csrf", "_a", "_b"):
        ctx.register(suffix)
    # every identity now gets the email lane -- the two-account IDOR pair (_a/_b) mints its own address per suffix
    assert all(seen[s] is not None for s in ("", "_race", "_csrf", "_a", "_b"))


def test_ctx_register_mints_distinct_addresses_per_identity():
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=MockReceiver(domain="app.test"))
    a, b, default = ctx.email_address("_a"), ctx.email_address("_b"), ctx.email_address("")
    assert len({a, b, default}) == 3                       # A, B and the default are three distinct inboxes
    assert ctx.email_address("_a") == a                    # ... and stable (minted once per identity)


def test_second_identity_runs_its_own_flow_once_the_first_verified(monkeypatch):
    # "_b" (an IDOR second account) mints its own session once the default ("") has email-verified.
    ctx = _spa_ctx(None)
    ctx._email_cache["result"] = EmailVerifyResult(attempted=True, session_after_verify=True)
    ctx._email_cache["account_session"] = {"headers": {"Cookie": "s0=1"}, "username": "a", "password": "p",
                                           "response": _reg_response("ok"), "storage_exposed": False}

    def fake_flow_b(ctx, suffix=""):
        assert suffix == "_b"                              # driven for the second identity
        ctx._email_cache["account_session_b"] = {"headers": {"Cookie": "sb=1"}, "username": "b", "password": "p",
                                                 "response": _reg_response("ok"), "storage_exposed": False}
        return EmailVerifyResult(attempted=True, session_after_verify=True)
    monkeypatch.setattr(probes, "_run_email_flow", fake_flow_b)
    acct = _acct(lambda r: httpx.Response(200))
    acct.register_response = _reg_response("Check your email to confirm.")
    b = probes._email_account(ctx, acct, "_b")
    assert b is not None and b.client.headers["Cookie"] == "sb=1"           # a DISTINCT session from A's s0=1
    b.client.close()


def test_second_identity_abandoned_when_the_first_never_verified(monkeypatch):
    # the first-account gate: if "" could not email-verify (broken email), don't even try a second -> abandon IDOR.
    ctx = _spa_ctx(None)
    ctx._email_cache["result"] = EmailVerifyResult(attempted=True, email_gated=True, email_arrived=False)  # no session
    monkeypatch.setattr(probes, "_run_email_flow",
                        lambda ctx, suffix="": (_ for _ in ()).throw(AssertionError("must not run a second flow")))
    acct = _acct(lambda r: httpx.Response(200))
    acct.register_response = _reg_response("Check your email to confirm.")
    assert probes._email_account(ctx, acct, "_b") is None                   # gated on the first -> None, no wasted poll


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


def _spa_ctx(browser_register):
    return pipeline._Ctx(base_url="http://app.test", client=None,
                         profile=Profile(base_url="http://app.test", forms=[]),
                         email=MockReceiver(domain="app.test"), browser_register=browser_register)


def test_email_ctx_mints_one_shared_address():
    ctx = _spa_ctx(lambda *a, **k: None)
    t1, a1 = probes._email_ctx(ctx)
    t2, a2 = probes._email_ctx(ctx)
    assert (t1, a1) == (t2, a2) and a1 == "hl-%s@app.test" % t1     # minted once, stable


def test_snapshot_browser_session_shape():
    snap = probes._snapshot_browser_session(
        {"cookies": [{"name": "sessionid", "value": "S", "httponly": True, "secure": False, "samesite": False},
                     {"name": "other", "value": "x", "httponly": False, "secure": False, "samesite": False}],
         "bearer": "TOK", "storage_exposed": True}, "http://app.test")
    assert "sessionid=S" in snap["headers"]["Cookie"] and "other" not in snap["headers"]["Cookie"]
    assert snap["headers"]["Authorization"] == "Bearer TOK" and snap["storage_exposed"] is True


def test_spa_browser_lane_registers_with_our_address_verifies_and_snapshots(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)   # no server-rendered form (an SPA)
    got = {}

    def fake_browser_register(base_url, email=None):
        got["email"] = email                                    # the SPA must be signed up with OUR address
        return {"email_pending": True, "creds": {"email": email}, "cookies": [],
                "page_text": "Check your email to confirm your account."}   # the announce gate
    monkeypatch.setattr(probes.browser, "verify_in_browser",
                        lambda link, base="", **k: {"cookies": [{"name": "sessionid", "value": "S",
                                                                 "httponly": True, "secure": True,
                                                                 "samesite": False}], "bearer": None,
                                                    "storage_exposed": False})
    ctx = _spa_ctx(fake_browser_register)
    ctx._email_cache["tag"] = "t1"                               # control the tag so we can inject the mail
    ctx._email_cache["address"] = ctx.email.address("t1")
    ctx.email.inject("t1", EmailMessage.parse("hl-t1@app.test", "Confirm", "http://app.test/verify?token=abc"))

    res = probes._email_verify_result(ctx)                     # the shared entry the probes use (caches result)
    assert got["email"] == "hl-t1@app.test"                     # signed up with the controlled address
    assert res.email_gated and res.email_arrived and res.acted_on_verification and res.session_after_verify
    assert "account_session" in ctx._email_cache               # verified session captured for authed reuse
    acct = probes._email_account(ctx)                          # ... and rebuilt into a fresh authed client
    assert acct is not None and "sessionid=S" in acct.client.headers["Cookie"]
    acct.client.close()


def test_spa_browser_email_pending_without_announce_is_not_a_false_lockout(monkeypatch):
    # submitted, no session, but the post-submit page shows NO email language (CAPTCHA / SSO / approval) -> must
    # NOT read as email-verification-gated (no 60s poll, no qa-email-001 at 72). This is the v21-sample FP fix.
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: None)
    monkeypatch.setattr(probes, "_firebase_config", lambda ctx: None)
    ctx = _spa_ctx(lambda base_url, email=None: {"email_pending": True, "cookies": [],
                                                 "page_text": "Please complete the CAPTCHA to continue."})
    res = probes._email_verify_result(ctx)
    assert not res.email_gated             # no announcement -> N/A; email_never_arrives then can't fire (72 lockout)


def test_spa_browser_lane_immediate_session_is_not_email_gated(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)

    def fake_browser_register(base_url, email=None):            # the SPA logs us in at once -> no email step
        return {"cookies": [{"name": "sessionid", "value": "S", "httponly": True, "secure": True,
                             "samesite": False}], "bearer": None, "creds": {}}
    res = probes._run_email_flow(_spa_ctx(fake_browser_register))
    assert res.attempted and not res.email_gated               # session immediately -> not email-verification-gated


def test_spa_browser_lane_inert_link_fires_002(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)
    monkeypatch.setattr(probes.browser, "verify_in_browser", lambda link, base="", **k: None)  # link grants nothing
    ctx = _spa_ctx(lambda base_url, email=None: {"email_pending": True, "cookies": [],
                                                 "page_text": "We've sent a verification link to your inbox."})
    ctx._email_cache["tag"] = "t2"
    ctx._email_cache["address"] = ctx.email.address("t2")
    ctx.email.inject("t2", EmailMessage.parse("hl-t2@app.test", "Confirm", "http://app.test/verify?token=x"))
    res = probes._run_email_flow(ctx)
    assert res.email_arrived and res.acted_on_verification and not res.session_after_verify   # inert -> qa-email-002


# --- BaaS / Supabase lane -----------------------------------------------------------------------------------

class _BaasResp:
    def __init__(self, status, data=None, headers=None):
        self.status_code = status
        self._data = data
        self.headers = headers or {}

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


def test_baas_email_signup_pending_when_confirmation_required(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(200, {"id": "u1", "email": "x@y"}))
    out = baas.email_signup("https://ref.supabase.co", "key", "hl@anachron.dev")
    assert out["pending"] is True and out["session"] is None    # 200 + user, no token -> confirmation pending


def test_baas_email_signup_session_when_confirmation_off(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(200, {"access_token": "T", "refresh_token": "R"}))
    out = baas.email_signup("https://ref.supabase.co", "key", "hl@anachron.dev")
    assert out["session"]["access_token"] == "T" and out["pending"] is False


def test_baas_email_signup_neither_when_closed(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(422, {"msg": "signups disabled"}))
    out = baas.email_signup("https://ref.supabase.co", "key", "hl@anachron.dev")
    assert out["session"] is None and out["pending"] is False


def test_baas_verify_email_link_posts_the_token_hash(monkeypatch):
    calls = {}

    def fake_post(url, json=None, **k):
        calls["url"], calls["json"] = url, json
        return _BaasResp(200, {"access_token": "AT", "refresh_token": "RT"})
    monkeypatch.setattr(baas.httpx, "post", fake_post)
    s = baas.verify_email_link("https://ref.supabase.co", "key",
                               "https://ref.supabase.co/auth/v1/verify?token_hash=HASH&type=signup")
    assert s["access_token"] == "AT"
    assert calls["url"].endswith("/auth/v1/verify") and calls["json"]["type"] == "signup"
    assert calls["json"].get("token_hash") == "HASH"


def test_baas_verify_email_link_falls_back_to_the_redirect_fragment(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(400))   # POST verify unsupported
    monkeypatch.setattr(baas.httpx, "get",
                        lambda url, **k: _BaasResp(303, headers={"location":
                                                                 "https://app.test/#access_token=FT&refresh_token=FR"}))
    s = baas.verify_email_link("https://ref.supabase.co", "key", "https://app.test/confirm?token=X&type=signup")
    assert s["access_token"] == "FT" and s["refresh_token"] == "FR"


def test_baas_lane_pending_confirmation_verifies_and_snapshots(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)      # not a server-form app
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: ("https://ref.supabase.co", "anonkey"))
    monkeypatch.setattr(probes.baas, "email_signup",
                        lambda gw, key, email: {"session": None, "pending": True, "_email": email, "_password": "p"})
    monkeypatch.setattr(probes.baas, "verify_email_link",
                        lambda gw, key, link: {"access_token": "AT", "refresh_token": "RT"})
    ctx = _spa_ctx(None)                                          # no browser -> the BaaS lane is reached
    ctx._email_cache["tag"] = "t3"
    ctx._email_cache["address"] = ctx.email.address("t3")
    ctx.email.inject("t3", EmailMessage.parse("hl-t3@app.test", "Confirm your signup",
                                              "https://ref.supabase.co/auth/v1/verify?token_hash=H&type=signup"))
    res = probes._email_verify_result(ctx)
    assert res.email_gated and res.email_arrived and res.session_after_verify
    acct = probes._email_account(ctx)                            # authed client carries the gateway session
    assert acct.client.headers["Authorization"] == "Bearer AT" and acct.client.headers["apikey"] == "anonkey"
    assert "sb-ref-auth-token" in acct.client.headers.get("Cookie", "")
    acct.client.close()


def test_baas_lane_immediate_session_is_not_email_gated(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: ("https://ref.supabase.co", "k"))
    monkeypatch.setattr(probes.baas, "email_signup",
                        lambda gw, key, email: {"session": {"access_token": "T"}, "pending": False})
    res = probes._email_verify_result(_spa_ctx(None))
    assert res.attempted and not res.email_gated                 # confirmation off -> logged in at once


# --- Firebase lane ------------------------------------------------------------------------------------------

def test_firebase_api_key_requires_a_firebase_marker():
    key = "AIza" + "A" * 35
    assert baas.firebase_api_key('{apiKey:"%s",authDomain:"x.firebaseapp.com"}' % key) == key
    assert baas.firebase_api_key('{apiKey:"%s",mapsOnly:true}' % key) is None   # apiKey but no Firebase marker


def test_firebase_signup_returns_the_idtoken_session(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post",
                        lambda *a, **k: _BaasResp(200, {"idToken": "ID", "refreshToken": "R", "localId": "u1"}))
    s = baas.firebase_signup("AIzaKEY", "hl@anachron.dev")
    assert s["idToken"] == "ID" and s["_password"]


def test_firebase_signup_none_on_error(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(400, {"error": {"message": "EMAIL_EXISTS"}}))
    assert baas.firebase_signup("AIzaKEY", "hl@anachron.dev") is None


def test_firebase_lane_unlocks_the_authed_surface_not_email_gated(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: None)         # not Supabase
    monkeypatch.setattr(probes, "_firebase_config", lambda ctx: "AIzaKEY")
    monkeypatch.setattr(probes.baas, "firebase_signup",
                        lambda key, email: {"idToken": "IDT", "localId": "u1", "email": email, "_password": "p"})
    ctx = _spa_ctx(None)
    res = probes._email_verify_result(ctx)
    assert res.attempted and not res.email_gated                          # session at signup -> not email-gated
    acct = probes._email_account(ctx)                                     # ... but the authed surface still unlocks
    assert acct is not None and acct.client.headers["Authorization"] == "Bearer IDT"
    acct.client.close()


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


# --- eager email prime: send at grade start, poll late (the overlap-the-wait optimization) ------------------

def test_prime_email_registers_once_without_polling_and_the_flow_reuses_it(monkeypatch):
    calls = {"register": 0}

    def fake_httpx(base, profile, suffix, email=None):
        calls["register"] += 1
        acct = _acct(lambda r: httpx.Response(200))
        acct.register_response = _reg_response("Check your email to confirm your account.")
        return acct
    monkeypatch.setattr(probes.auth, "_register_httpx", fake_httpx)
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: None)
    monkeypatch.setattr(probes, "_firebase_config", lambda ctx: None)
    monkeypatch.setattr(probes.auth, "login_with_credentials", lambda *a, **k: {})
    ctx = _spa_ctx(None)
    ctx._email_cache["tag"] = "tp"
    ctx._email_cache["address"] = ctx.email.address("tp")

    probes._prime_email(ctx)                       # SEND at "grade start"
    assert calls["register"] == 1 and "_reg" in ctx._email_cache    # registered once, cached; no poll here

    ctx.email.inject("tp", EmailMessage.parse("hl-tp@app.test", "Confirm", "http://app.test/verify?t=1"))
    res = probes._email_verify_result(ctx)         # LATER poll -> must reuse the primed registration
    assert calls["register"] == 1                  # NOT re-sent
    assert res.email_gated and res.email_arrived    # the poll found the already-delivered mail


def test_prime_email_is_a_noop_without_a_receiver():
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=None, email=None)
    probes._prime_email(ctx)                        # no receiver -> no send, no raise
    assert "_reg" not in ctx._email_cache


# --- session-aware injection (3): the injection probes inject WITH the register-lane session ----------------

def test_authed_headers_merges_the_register_lane_session():
    def fake_register(suffix=""):
        c = httpx.Client(base_url="http://a", headers={"Authorization": "Bearer T"})
        return Account(username="u", password="p", client=c,
                       register_response=httpx.Response(200, request=httpx.Request("POST", "http://a/s")))
    ctx = types.SimpleNamespace(headers={"user-agent": "x"}, register=fake_register)
    h = probes._authed_headers(ctx)
    assert h["Authorization"] == "Bearer T" and h["user-agent"] == "x"   # session carried, UA preserved


def test_authed_headers_falls_back_to_anonymous_without_a_session():
    ctx = types.SimpleNamespace(headers={"user-agent": "x"}, register=lambda suffix="": None)
    assert probes._authed_headers(ctx) == {"user-agent": "x"}            # no session -> anonymous (skip handles /login)


def test_authed_headers_respects_a_provided_header_session_without_registering():
    ctx = types.SimpleNamespace(headers={"Cookie": "session=abc"},
                                register=lambda suffix="": (_ for _ in ()).throw(AssertionError("must not register")))
    assert probes._authed_headers(ctx) == {"Cookie": "session=abc"}      # --header session wins, no self-register


# --- MAGIC-LINK / passwordless lane -------------------------------------------------------------------------
# A passwordless app has no password: enter your email, it mails a login link, clicking it logs you in. Every
# other lane assumes a password signup, so we never triggered the link. These two submission paths do -- then
# the EXISTING follow (httpx auto-login / baas verify_email_link) completes it.

def test_email_only_form_detects_passwordless_rejects_password_and_newsletter():
    magic = Form(action="/auth/magic-link", method="post", fields=["email"])
    pw = Form(action="/signup", method="post", fields=["email", "password"])
    news = Form(action="/auth/subscribe", method="post", fields=["email"])   # "auth" substring but a subscribe box
    assert auth._email_only_form([pw, magic, news]) is magic
    assert auth._email_only_form([pw]) is None                # has a password -> _password_form's job, not this lane
    assert auth._email_only_form([news]) is None              # newsletter/subscribe -> excluded (never POST to it)


def test_register_passwordless_fills_the_email_and_posts_the_form(monkeypatch):
    posted = {}

    def handler(req):
        if req.method == "POST":
            posted["path"], posted["body"] = req.url.path, req.content.decode()
            return httpx.Response(200, text="Check your email for a login link.")
        return httpx.Response(200, text="<form action='/auth/magic-link'><input name='email'></form>")   # CSRF GET
    real_client = httpx.Client
    monkeypatch.setattr(auth.httpx, "Client",
                        lambda *a, **k: real_client(*a, **{**k, "transport": httpx.MockTransport(handler)}))
    prof = Profile(base_url="http://app.test",
                   forms=[Form(action="/auth/magic-link", method="post", fields=["email"])])
    acct = auth._register_passwordless("http://app.test", prof, "_m", email="hl-x@app.test")
    assert acct is not None and posted["path"] == "/auth/magic-link"
    assert "email=" in posted["body"] and "hl-x" in posted["body"]        # our address was submitted
    assert acct.password == ""                                            # passwordless: no password sent
    acct.client.close()


def test_register_passwordless_none_without_an_email_only_form():
    prof = Profile(base_url="http://app.test",
                   forms=[Form(action="/signup", method="post", fields=["email", "password"])])
    assert auth._register_passwordless("http://app.test", prof, "_m", email="hl-x@app.test") is None


def test_magic_link_httpx_lane_registers_via_email_only_form_and_the_link_logs_in(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)   # no password signup surface
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: None)
    monkeypatch.setattr(probes, "_firebase_config", lambda ctx: None)

    def magic_acct(base, profile, suffix="", email=None):
        # the passwordless form accepted our address and announced a link; GETting the emailed link auto-logs in.
        acct = _acct(lambda r: httpx.Response(200, headers={"set-cookie": "sessionid=S; HttpOnly; Path=/"}))
        acct.register_response = _reg_response("Check your email for a login link.")
        return acct
    monkeypatch.setattr(probes.auth, "_register_passwordless", magic_acct)
    ctx = _spa_ctx(None)
    ctx._email_cache["tag"] = "tm"
    ctx._email_cache["address"] = ctx.email.address("tm")
    ctx.email.inject("tm", EmailMessage.parse("hl-tm@app.test", "Your login link", "http://app.test/magic?t=1"))
    res = probes._email_verify_result(ctx)
    assert res.email_gated and res.email_arrived and res.session_after_verify   # passwordless login worked
    acct = probes._email_account(ctx)
    assert acct is not None and "sessionid=S" in acct.client.headers.get("Cookie", "")
    acct.client.close()


def test_baas_magic_link_signup_pending_on_2xx(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(202))    # OTP accepted -> link on its way
    assert baas.magic_link_signup("https://ref.supabase.co", "k", "hl@anachron.dev")["pending"] is True


def test_baas_magic_link_signup_not_pending_when_otp_disabled(monkeypatch):
    monkeypatch.setattr(baas.httpx, "post", lambda *a, **k: _BaasResp(422, {"msg": "otp disabled"}))
    assert baas.magic_link_signup("https://ref.supabase.co", "k", "hl@anachron.dev")["pending"] is False


def test_magic_link_baas_otp_lane_when_password_signup_is_closed(monkeypatch):
    monkeypatch.setattr(probes.auth, "_register_httpx", lambda *a, **k: None)
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: ("https://ref.supabase.co", "anonkey"))
    monkeypatch.setattr(probes.baas, "email_signup",
                        lambda gw, key, email: {"session": None, "pending": False})   # password signup closed
    otp = {}

    def fake_otp(gw, key, email):
        otp["email"] = email
        return {"pending": True}
    monkeypatch.setattr(probes.baas, "magic_link_signup", fake_otp)
    monkeypatch.setattr(probes.baas, "verify_email_link",
                        lambda gw, key, link: {"access_token": "AT", "refresh_token": "RT"})
    ctx = _spa_ctx(None)
    ctx._email_cache["tag"] = "to"
    ctx._email_cache["address"] = ctx.email.address("to")
    ctx.email.inject("to", EmailMessage.parse("hl-to@app.test", "Magic link",
                                              "https://ref.supabase.co/auth/v1/verify?token_hash=H&type=magiclink"))
    res = probes._email_verify_result(ctx)
    assert otp["email"] == "hl-to@app.test"                    # OTP requested with our controlled address
    assert res.email_gated and res.email_arrived and res.session_after_verify
    acct = probes._email_account(ctx)
    assert acct.client.headers["Authorization"] == "Bearer AT"
    acct.client.close()


# --- PASSWORD-RESET lane (qa-reset-001) ---------------------------------------------------------------------

def test_forgot_form_detects_email_only_reset_form_rejects_login_and_change():
    forgot = Form(action="/account/forgot-password", method="post", fields=["email"])
    login = Form(action="/login", method="post", fields=["email", "password"])   # magic/login, not reset
    change = Form(action="/reset-password", method="post", fields=["new_password", "confirm"])  # sets a pw, email-less
    assert auth._forgot_form([login, forgot, change]) is forgot
    assert auth._forgot_form([login]) is None
    assert auth._forgot_form([change]) is None                 # no email field -> not a request-a-link form


def test_trigger_reset_httpx_posts_the_owned_address(monkeypatch):
    posted = {}

    def handler(req):
        if req.method == "POST":
            posted["path"], posted["body"] = req.url.path, req.content.decode()
        return httpx.Response(200, text="If that account exists, a reset link is on its way.")
    client = httpx.Client(base_url="http://app.test", transport=httpx.MockTransport(handler), follow_redirects=True)
    form = Form(action="/account/forgot-password", method="post", fields=["email"])
    ok = auth._trigger_reset_httpx(client, "http://app.test", form, "hl-r@app.test")
    assert ok is True and posted["path"] == "/account/forgot-password" and "hl-r" in posted["body"]
    client.close()


def test_baas_recover_posts_the_email(monkeypatch):
    calls = {}

    def fake_post(url, json=None, **k):
        calls["url"], calls["json"] = url, json
        return _BaasResp(200)
    monkeypatch.setattr(baas.httpx, "post", fake_post)
    assert baas.recover("https://ref.supabase.co", "k", "hl@anachron.dev") is True
    assert calls["url"].endswith("/auth/v1/recover") and calls["json"] == {"email": "hl@anachron.dev"}


def _reset_ctx(profile):
    ctx = pipeline._Ctx(base_url="http://app.test", client=None, profile=profile,
                        email=MockReceiver(domain="app.test"))
    ctx._email_cache["tag"] = "tr"
    ctx._email_cache["address"] = ctx.email.address("tr")
    return ctx


def test_reset_httpx_form_lane_fires_when_no_reset_email_arrives(monkeypatch):
    # an established account (session) + a forgot-password form + no reset email -> locked out of recovery.
    monkeypatch.setattr(probes, "_email_register_once", lambda ctx, suffix="": None)
    prof = Profile(base_url="http://app.test",
                   forms=[Form(action="/account/forgot-password", method="post", fields=["email"])])
    ctx = _reset_ctx(prof)
    acct = _acct(lambda r: httpx.Response(200, text="reset link sent"))
    acct.client.cookies.set("sessionid", "S")                  # -> _has_session True -> the account exists
    ctx._email_cache["_live"] = {"acct": acct, "lane": "httpx"}
    fired = probes.reset_email_unreliable(ctx, None)
    assert fired is True
    assert ctx.evidence.get("no_reset_email_60s") and "report_only" not in ctx.evidence   # SCORED, not off-score
    acct.client.close()


def test_reset_lane_clean_when_email_arrives_with_a_live_link(monkeypatch):
    monkeypatch.setattr(probes, "_email_register_once", lambda ctx, suffix="": None)
    prof = Profile(base_url="http://app.test",
                   forms=[Form(action="/account/forgot-password", method="post", fields=["email"])])
    ctx = _reset_ctx(prof)
    acct = _acct(lambda r: httpx.Response(200))                 # POST reset ok; GET the link -> 200 (alive)
    acct.client.cookies.set("sessionid", "S")
    ctx._email_cache["_live"] = {"acct": acct, "lane": "httpx"}
    ctx.email.inject("tr", EmailMessage.parse("hl-tr@app.test", "Reset your password",
                                              "http://app.test/reset?token=abc"))
    assert probes.reset_email_unreliable(ctx, None) is False    # delivered + live reset page -> recovery works
    acct.client.close()


def test_reset_baas_recover_lane_fires_when_no_email(monkeypatch):
    monkeypatch.setattr(probes, "_email_register_once", lambda ctx, suffix="": None)
    monkeypatch.setattr(probes, "_baas_gateway", lambda ctx: ("https://ref.supabase.co", "anonkey"))
    recovered = {}
    monkeypatch.setattr(probes.baas, "recover",
                        lambda gw, key, email: recovered.setdefault("email", email) == email)
    ctx = _reset_ctx(Profile(base_url="http://app.test", forms=[]))
    ctx._email_cache["_live"] = {"lane": "baas"}               # a Supabase signup created the account
    assert probes.reset_email_unreliable(ctx, None) is True
    assert recovered["email"] == "hl-tr@app.test" and ctx.evidence.get("no_reset_email_60s")


def test_reset_na_without_an_established_account(monkeypatch):
    monkeypatch.setattr(probes, "_email_register_once", lambda ctx, suffix="": None)
    ctx = _reset_ctx(Profile(base_url="http://app.test",
                             forms=[Form(action="/account/forgot-password", method="post", fields=["email"])]))
    ctx._email_cache["_live"] = {"acct": None, "lane": ""}     # register lane established nothing
    assert probes.reset_email_unreliable(ctx, None) is None    # no controlled account to reset -> N/A, never a fire
