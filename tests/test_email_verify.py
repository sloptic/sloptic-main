"""email_verify.py: the receiver-agnostic email-verification flow.

The flow is callback-driven so its whole decision tree runs here with an in-memory receiver, no network and no
clock. The one false positive it exists to avoid gets its own test: a signup that simply wants a separate login
(no session, no mail) must read N/A, never a lock-out.
"""
import httpx

from sloptic.email_verify import (
    EmailMessage, EmailReceiver, EmailVerifyResult, HttpReceiver, MailHogReceiver, MockReceiver,
    RegistrationOutcome, Verification, announces_pending_email, signals_email_verification, verify_email_flow)


# ---- parsing ----------------------------------------------------------------------------------------------

def test_parse_extracts_links_from_href_and_strips_trailing_punctuation():
    body = 'Confirm here: <a href="https://app.example/verify?token=abc123">Verify</a>. ' \
           "Or visit https://app.example/welcome, thanks!"
    msg = EmailMessage.parse("me@grader.test", "Confirm", body)
    assert "https://app.example/verify?token=abc123" in msg.links
    assert "https://app.example/welcome" in msg.links       # trailing comma stripped, not part of the URL
    assert all(not link.endswith((",", ".")) for link in msg.links)


def test_parse_extracts_numeric_and_alphanumeric_codes_but_not_plain_words():
    msg = EmailMessage.parse("me@grader.test", "Your code",
                             "PLEASE VERIFY your account. Code: 481920 or use A1B2C3 to CONFIRM NOW")
    assert "481920" in msg.codes                 # 6-digit OTP
    assert "A1B2C3" in msg.codes                 # alphanumeric with a digit
    assert "VERIFY" not in msg.codes and "CONFIRM" not in msg.codes and "PLEASE" not in msg.codes


def test_parse_dedupes_and_ignores_digit_runs_inside_longer_tokens():
    msg = EmailMessage.parse("me@grader.test", "s",
                             "code 123456 code 123456 id=abc123456789def")
    assert msg.codes.count("123456") == 1                  # deduped
    assert "123456789" not in "".join(msg.codes)           # not carved out of the middle of a token


def test_announces_pending_email_matches_confirmation_language_only():
    assert announces_pending_email("Please check your email to confirm your account.")
    assert announces_pending_email("We've sent you a verification link.")
    assert announces_pending_email("A confirmation email is on its way to your inbox.")
    assert not announces_pending_email("Welcome! You are now logged in.")
    assert not announces_pending_email("Update your email address in settings.")   # 'email' alone is not enough


def test_signals_email_verification_catches_prose_and_allauth_pending_json():
    # the 'promise' signal: human announce language OR a machine flag (allauth's verify_email is_pending)
    assert signals_email_verification("Please check your email to confirm your account.")
    assert signals_email_verification('{"data":{"flows":[{"id":"verify_email","is_pending":true}]}}')
    assert not signals_email_verification('{"status":200,"data":{"user":{"id":1}},"meta":{"is_authenticated":true}}')
    assert not signals_email_verification("")


# ---- MockReceiver -----------------------------------------------------------------------------------------

def test_mock_receiver_address_is_unique_per_tag_and_poll_returns_injected():
    rx = MockReceiver(domain="d.dev")
    assert rx.address("t1") == "hl-t1@d.dev" and rx.address("t2") == "hl-t2@d.dev"
    assert rx.poll("t1", timeout=5) is None                # nothing injected yet
    rx.inject("t1", EmailMessage.parse("hl-t1@d.dev", "Confirm", "link https://d.dev/v?t=1"))
    assert rx.poll("t1", timeout=0).links == ["https://d.dev/v?t=1"]
    assert rx.poll("t2", timeout=0) is None                # a different tag stays empty


# ---- HttpReceiver / MailHogReceiver via MockTransport (no network) ----------------------------------------

def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_http_receiver_parses_messages_envelope_and_sends_bearer():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["to"] = dict(request.url.params).get("to")
        return httpx.Response(200, json={"messages": [
            {"to": "hl-t@x.dev", "subject": "Confirm", "text": "go https://x.dev/verify?c=9"}]})

    rx = HttpReceiver("x.dev", "https://inbox.local/mail", token="secret", client=_client(handler))
    msg = rx.poll("t", timeout=0)
    assert msg is not None and msg.links == ["https://x.dev/verify?c=9"]
    assert seen["auth"] == "Bearer secret"
    assert seen["to"] == "hl-t@x.dev"


def test_http_receiver_accepts_bare_list_and_items_envelope():
    for payload in ([{"to": "a", "subject": "s", "html": "https://x.dev/a"}],
                    {"items": [{"to": "a", "subject": "s", "body": "https://x.dev/a"}]}):
        rx = HttpReceiver("x.dev", "https://inbox.local/mail",
                          client=_client(lambda req, p=payload: httpx.Response(200, json=p)))
        assert rx.poll("t", timeout=0).links == ["https://x.dev/a"]


def test_http_receiver_returns_none_on_empty_and_on_error_status():
    empty = HttpReceiver("x.dev", "https://inbox.local/mail",
                         client=_client(lambda req: httpx.Response(200, json={"messages": []})))
    assert empty.poll("t", timeout=0) is None              # empty inbox, no sleep at timeout 0
    err = HttpReceiver("x.dev", "https://inbox.local/mail",
                       client=_client(lambda req: httpx.Response(503)))
    assert err.poll("t", timeout=0) is None                # provider error is "nothing yet", never a crash


def test_mailhog_receiver_parses_mailhog_search_shape():
    payload = {"items": [{"Content": {"Headers": {"Subject": ["Verify your email"]},
                                      "Body": "Click https://x.dev/confirm?tok=77 to finish"}}]}
    rx = MailHogReceiver("x.dev", "http://localhost:8025",
                         client=_client(lambda req: httpx.Response(200, json=payload)))
    msg = rx.poll("t", timeout=0)
    assert msg.subject == "Verify your email"
    assert msg.links == ["https://x.dev/confirm?tok=77"]


# ---- the flow: one helper builds the callbacks from canned outcomes --------------------------------------

def _run(reg, *, arrived=None, follow_result=None, domain="grader.test"):
    """Drive verify_email_flow with a MockReceiver. `reg` is the RegistrationOutcome; `arrived` (an
    EmailMessage or None) is what the inbox holds; `follow_result` is the Verification returned when acting."""
    rx = MockReceiver(domain=domain)
    if arrived is not None:
        rx.inject("tag", arrived)
    follow = lambda r, m: (follow_result or Verification(acted=False))
    return verify_email_flow(rx, "tag", register=lambda addr: reg, follow=follow,
                             announced_timeout=0, unannounced_timeout=0)


def test_flow_na_when_signup_cannot_be_submitted():
    res = _run(RegistrationOutcome(submitted=False))
    assert res.attempted is False and res.email_gated is False and "could not submit" in res.na_reason


def test_flow_na_when_signup_logs_straight_in_not_email_gated():
    res = _run(RegistrationOutcome(submitted=True, has_session=True))
    assert res.attempted is True and res.email_gated is False and "not email-gated" in res.na_reason


def test_flow_nonblocking_promise_delivered_is_clean_not_a_penalty():
    # session at signup + a confirmation email that ARRIVES: non-blocking verification that works. Must NOT fire
    # the gated lockout/inert-link penalties (email_gated False); a delivered mail is itself the promise.
    msg = EmailMessage.parse("hl-tag@grader.test", "Confirm your email", "https://grader.test/verify?t=1")
    res = _run(RegistrationOutcome(submitted=True, has_session=True, announces_email=False), arrived=msg)
    assert res.email_gated is False and res.session_at_signup is True
    assert res.announces_email is True and res.email_arrived is True
    assert "non-blocking" in res.na_reason


def test_flow_nonblocking_promise_broken_no_email_fires_dead_verification():
    # session at signup + the signup ANNOUNCED a confirmation email, but none arrives: not a lockout (you are in),
    # but a broken promise -> the qa-email-001 verification_dead_nonblocking rung (36). Intent-independent -- the
    # promise is the app's own announcement, its non-arrival is observable, no design judgement.
    res = _run(RegistrationOutcome(submitted=True, has_session=True, announces_email=True), arrived=None)
    assert res.email_gated is False and res.session_at_signup is True
    assert res.announces_email is True and res.email_arrived is False
    assert res.detail                                     # the "hunts a nonexistent mail" broken-promise detail is set


def test_flow_na_when_no_announcement_and_no_email_the_false_positive_guard():
    # a signup that just wants a SEPARATE login: no session, no confirm-email language, no mail. Must NOT read
    # as a lock-out. This is the single false positive the whole disambiguation exists to prevent.
    res = _run(RegistrationOutcome(submitted=True, announces_email=False), arrived=None)
    assert res.email_gated is False and res.email_arrived is False
    assert "not email-gated" in res.na_reason


def test_flow_fires_email_001_when_gated_but_no_email_arrives():
    res = _run(RegistrationOutcome(submitted=True, announces_email=True), arrived=None)
    assert res.attempted is True and res.email_gated is True and res.email_arrived is False
    assert not res.na_reason                                # gated + no email = a real lock-out, not N/A


def test_flow_gated_by_arrival_even_without_announcement():
    # an opaque SPA that shows a spinner (no confirm text) but really does send mail is still email-gated.
    msg = EmailMessage.parse("hl-tag@grader.test", "Confirm", "https://grader.test/verify?t=1")
    res = _run(RegistrationOutcome(submitted=True, announces_email=False), arrived=msg,
               follow_result=Verification(acted=True, session=True))
    assert res.email_gated is True and res.email_arrived is True and res.session_after_verify is True


def test_flow_clean_when_link_establishes_a_session():
    msg = EmailMessage.parse("hl-tag@grader.test", "Confirm", "https://grader.test/verify?t=1")
    res = _run(RegistrationOutcome(submitted=True, announces_email=True), arrived=msg,
               follow_result=Verification(acted=True, session=True))
    assert res.email_arrived is True and res.acted_on_verification is True and res.session_after_verify is True


def test_flow_fires_email_002_when_link_establishes_no_session():
    msg = EmailMessage.parse("hl-tag@grader.test", "Confirm", "https://grader.test/verify?t=1")
    res = _run(RegistrationOutcome(submitted=True, announces_email=True), arrived=msg,
               follow_result=Verification(acted=True, session=False))
    assert res.email_arrived is True and res.acted_on_verification is True and res.session_after_verify is False


def test_flow_email_002_cannot_judge_a_code_only_email():
    # code-only mail we cannot submit: acted is False, so qa-email-002 will read N/A, never a false fire.
    msg = EmailMessage.parse("hl-tag@grader.test", "Your code", "Your verification code is 903217")
    res = _run(RegistrationOutcome(submitted=True, announces_email=True), arrived=msg,
               follow_result=Verification(acted=False))
    assert res.email_arrived is True and res.acted_on_verification is False
    assert res.session_after_verify is False and "cannot judge" in res.detail


def test_resend_at_the_mark_rescues_a_slow_email():
    # nothing in the first leg -> click resend (which delivers) -> the email arrives in the second leg.
    rx = MockReceiver()

    def resend(reg):
        rx.inject("tag", EmailMessage.parse("hl-tag@grader.test", "Confirm", "https://grader.test/v"))
        return True
    res = verify_email_flow(rx, "tag", register=lambda a: RegistrationOutcome(submitted=True, announces_email=True),
                            follow=lambda r, m: Verification(acted=True, session=True), resend=resend,
                            announced_timeout=1, unannounced_timeout=0, resend_at=0)
    assert res.email_arrived is True and res.resent is True and res.session_after_verify is True


def test_email_001_fires_only_after_resend_also_fails():
    calls = []
    res = verify_email_flow(MockReceiver(),
                            "tag", register=lambda a: RegistrationOutcome(submitted=True, announces_email=True),
                            follow=lambda r, m: Verification(acted=False),
                            resend=lambda reg: (calls.append(1), True)[1],   # resend control clicked, still no mail
                            announced_timeout=1, unannounced_timeout=0, resend_at=0)
    assert res.email_arrived is False and res.resent is True and calls == [1]
    assert "even after clicking resend" in res.detail


def test_no_resend_when_signup_is_not_announced():
    # not announced -> the short unannounced poll only, resend is never attempted (we can't confirm it's gated).
    calls = []
    res = verify_email_flow(MockReceiver(),
                            "tag", register=lambda a: RegistrationOutcome(submitted=True, announces_email=False),
                            follow=lambda r, m: Verification(acted=False),
                            resend=lambda reg: (calls.append(1), True)[1],
                            announced_timeout=1, unannounced_timeout=0, resend_at=0)
    assert res.email_gated is False and calls == []


def test_receivers_are_email_receivers_and_result_is_a_dataclass():
    assert issubclass(MockReceiver, EmailReceiver) and issubclass(HttpReceiver, EmailReceiver)
    assert isinstance(_run(RegistrationOutcome(submitted=False)), EmailVerifyResult)


# ---- the reset flow (qa-reset-001) ------------------------------------------------------------------------
from sloptic.email_verify import ResetResult, reset_email_flow


def test_reset_flow_na_when_no_reset_surface():
    res = reset_email_flow(MockReceiver(), "tag", trigger=lambda addr: False, timeout=0)
    assert res.attempted is False and "no reachable password-reset surface" in res.na_reason


def test_reset_flow_only_ever_submits_the_owned_address():
    rx = MockReceiver(domain="d.dev")
    seen = {}

    def trigger(addr):
        seen["addr"] = addr
        return True
    reset_email_flow(rx, "tag", trigger=trigger, timeout=0)
    assert seen["addr"] == rx.address("tag") == "hl-tag@d.dev"   # SAFETY: the flow passes only our owned mailbox


def test_reset_flow_fires_when_no_reset_email_arrives():
    res = reset_email_flow(MockReceiver(), "tag", trigger=lambda addr: True, timeout=0)
    assert res.attempted and res.reset_available and res.email_arrived is False   # locked out of recovery
    assert "no email arrived" in res.detail


def test_reset_flow_dead_link_is_recorded():
    rx = MockReceiver()
    rx.inject("tag", EmailMessage.parse("hl-tag@grader.test", "Reset", "https://grader.test/reset?t=1"))
    res = reset_email_flow(rx, "tag", trigger=lambda addr: True, follow=lambda msg: False, timeout=0)
    assert res.email_arrived is True and res.link_alive is False and "dead" in res.detail


def test_reset_flow_clean_when_email_arrives_with_a_live_link():
    rx = MockReceiver()
    rx.inject("tag", EmailMessage.parse("hl-tag@grader.test", "Reset", "https://grader.test/reset?t=1"))
    res = reset_email_flow(rx, "tag", trigger=lambda addr: True, follow=lambda msg: True, timeout=0)
    assert res.email_arrived is True and res.link_alive is True and isinstance(res, ResetResult)
