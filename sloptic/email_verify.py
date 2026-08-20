"""Email-verification coverage: when a signup promises a confirmation email, does one actually arrive, and does
acting on it (clicking the link) actually let you in?

Two failure modes real hackathon apps ship, both of which lock a genuine user out while the signup page looks
like it worked:

  * the confirmation email NEVER arrives (SMTP misconfigured, wrong provider key, a send that fails silently in
    a serverless handler). You register, you are told to check your inbox, and nothing comes. qa-email-001.
  * the email arrives but the verification is INERT (the link 404s, the token is unrecognised, clicking it sets
    no session). You did everything asked and still cannot get in. qa-email-002.

Receiving mail from the public internet requires a public MX on port 25, which a residential or local box does
not have, so the live grader reaches a real inbox through an EmailReceiver backed by hosted infrastructure
(Cloudflare Email Routing + a Worker for grading, MailHog/Mailpit for local dev and the wedge test). The FLOW
logic here is receiver-agnostic and callback-driven: registration and link-following are injected, so the whole
decision tree is unit-tested end to end against an in-memory MockReceiver with no network and no clock.

We never solve a CAPTCHA and never drive SSO: those signups do not hand us a controllable address to register
with, so the flow simply reports it could not submit and the probes read N/A. The only address we ever use is
one WE own on a dedicated throwaway domain (never sloptic.org), so no third party's mail is ever touched.
"""
from __future__ import annotations

import abc
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

# A URL as it appears in a text or HTML body. The class stops at whitespace, quotes and closing brackets so an
# `href="https://app/verify?t=..."` yields the bare URL; trailing sentence punctuation is stripped after.
_URL_RE = re.compile(r'https?://[^\s"\'<>)\]}]+')
_URL_TRAIL = ".,;:!?)]}'\""

# A verification CODE. Numeric OTPs are 4-8 digits; alphanumeric codes (A1B2C3) must carry at least one digit,
# so a plain uppercase word in the copy ("VERIFY", "PLEASE") is not mistaken for a code. Word boundaries keep a
# code out of the middle of a longer token (an id, a hex blob).
_NUM_CODE_RE = re.compile(r"(?<![\w-])(\d{4,8})(?![\w-])")
_ALNUM_CODE_RE = re.compile(r"(?<![\w-])([A-Z0-9]{5,8})(?![\w-])")

# Phrases a signup response shows when it is WAITING ON AN EMAIL (so absence-of-session means "verify your
# email", not "now go log in"). This is the disambiguator that keeps qa-email-001 from firing on an app that
# simply has no email step and redirects you to a login page. Matched case-insensitively against the response
# body. Kept deliberately specific to a confirmation-pending state, not any mention of the word "email".
_ANNOUNCE_RE = re.compile(
    r"(?:check|confirm|verif|activat)\w*[^.]{0,40}(?:e-?mail|inbox|link)"
    r"|(?:e-?mail|inbox|link)[^.]{0,40}(?:sent|on its way|to (?:confirm|verify|activate))"
    r"|we(?:'ve| have)?\s+sent[^.]{0,30}(?:e-?mail|link|code)"
    r"|(?:confirmation|verification|activation)\s+(?:e-?mail|link|code)",
    re.IGNORECASE,
)


def _dedupe(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


@dataclass
class EmailMessage:
    """One received email, already parsed into the two things a verification flow acts on: the links to follow
    and any standalone codes to submit. `body` is the raw text/HTML kept for evidence and re-parsing."""
    to: str
    subject: str
    body: str
    links: list[str] = field(default_factory=list)
    codes: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, to: str, subject: str, body: str) -> "EmailMessage":
        text = body or ""
        links = _dedupe(m.rstrip(_URL_TRAIL) for m in _URL_RE.findall(text))
        codes = _dedupe(
            _NUM_CODE_RE.findall(text)
            + [c for c in _ALNUM_CODE_RE.findall(text) if any(ch.isdigit() for ch in c)]
        )
        return cls(to=to, subject=subject or "", body=text, links=links, codes=codes)


def announces_pending_email(response_body: str) -> bool:
    """Does a signup RESPONSE announce that a confirmation email is on the way? This is what makes 'no session
    after signup' mean 'the app is waiting on email verification' rather than 'the app wants a separate login'.
    Only when this is true (or an email actually shows up) do we treat a missing email as a lock-out."""
    return bool(_ANNOUNCE_RE.search(response_body or ""))


# --- receivers ---------------------------------------------------------------------------------------------

class EmailReceiver(abc.ABC):
    """A source of received mail addressed to us. `address(tag)` mints a unique deliverable address for one
    grade; `poll(tag, timeout)` waits up to `timeout` seconds for the first mail to it (None on timeout)."""

    @abc.abstractmethod
    def address(self, tag: str) -> str:
        ...

    @abc.abstractmethod
    def poll(self, tag: str, timeout: float) -> EmailMessage | None:
        ...


class MockReceiver(EmailReceiver):
    """In-memory receiver for tests: preload a message with `inject(tag, message)`; `poll` returns it at once and
    never sleeps, so the flow's decision tree is exercised deterministically with no clock and no network."""

    def __init__(self, domain: str = "grader.test") -> None:
        self.domain = domain
        self._inbox: dict[str, EmailMessage] = {}

    def address(self, tag: str) -> str:
        return f"hl-{tag}@{self.domain}"

    def inject(self, tag: str, message: EmailMessage) -> None:
        self._inbox[tag] = message

    def poll(self, tag: str, timeout: float) -> EmailMessage | None:
        return self._inbox.get(tag)


class HttpReceiver(EmailReceiver):
    """Live receiver over an HTTP inbox API: the Cloudflare Email Worker (its KV-backed endpoint) and any hosted
    mailbox that answers a GET with recent mail. Contract: GET `endpoint` with ?to=<address>&tag=<tag>, optional
    Bearer, returns JSON as {"messages": [...]}, {"items": [...]}, or a bare list; each item carries to/subject
    and one of text/html/body. `poll` re-fetches every `poll_interval` seconds until a message or the timeout.

    Timing lives in the receiver, never in the flow, so a MockReceiver test needs no clock and the score never
    depends on how long an email took beyond the fixed arrived-or-not verdict."""

    def __init__(self, domain: str, endpoint: str, *, token: str = "", poll_interval: float = 3.0,
                 client: httpx.Client | None = None) -> None:
        self.domain = domain
        self.endpoint = endpoint
        self.token = token
        self._poll_interval = max(0.5, poll_interval)
        self._own_client = client is None
        self._client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def address(self, tag: str) -> str:
        return f"hl-{tag}@{self.domain}"

    def close(self) -> None:
        if self._own_client:
            self._client.close()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self.token} if self.token else {}

    def _get_items(self, address: str, tag: str) -> list[dict]:
        r = self._client.get(self.endpoint, params={"to": address, "tag": tag}, headers=self._headers())
        if r.status_code != 200:
            return []
        data = r.json()
        if isinstance(data, dict):
            items = data.get("messages") or data.get("items") or []
        else:
            items = data
        return [it for it in items if isinstance(it, dict)]

    def _to_message(self, item: dict, address: str) -> EmailMessage:
        lower = {str(k).lower(): v for k, v in item.items()}
        body = lower.get("text") or lower.get("html") or lower.get("body") or ""
        return EmailMessage.parse(to=str(lower.get("to") or address),
                                  subject=str(lower.get("subject") or ""), body=str(body))

    def _fetch_latest(self, address: str, tag: str) -> EmailMessage | None:
        try:
            items = self._get_items(address, tag)
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
            return None   # transport error or non-JSON body: treat as "nothing yet", keep polling
        return self._to_message(items[0], address) if items else None

    def poll(self, tag: str, timeout: float) -> EmailMessage | None:
        address = self.address(tag)
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            msg = self._fetch_latest(address, tag)
            if msg is not None:
                return msg
            if time.monotonic() >= deadline:
                return None
            time.sleep(self._poll_interval)


class MailHogReceiver(HttpReceiver):
    """Local-dev / wedge-test receiver over MailHog (or Mailpit) v2 search API: GET /api/v2/search?kind=to&
    query=<address> -> {"items": [{"Content": {"Headers": {"Subject": [...]}, "Body": "..."}}]}, newest first.
    Only the fetch/parse differs from HttpReceiver; the poll loop is inherited."""

    def __init__(self, domain: str, base_url: str = "http://localhost:8025", *, poll_interval: float = 1.0,
                 client: httpx.Client | None = None) -> None:
        endpoint = base_url.rstrip("/") + "/api/v2/search"
        super().__init__(domain, endpoint, poll_interval=poll_interval, client=client)

    def _fetch_latest(self, address: str, tag: str) -> EmailMessage | None:
        try:
            r = self._client.get(self.endpoint, params={"kind": "to", "query": address})
            if r.status_code != 200:
                return None
            items = (r.json() or {}).get("items") or []
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
            return None
        if not items:
            return None
        content = items[0].get("Content") or {}
        headers = content.get("Headers") or {}
        subject = (headers.get("Subject") or [""])[0]
        return EmailMessage.parse(to=address, subject=str(subject), body=str(content.get("Body") or ""))


# --- the flow ----------------------------------------------------------------------------------------------

@dataclass
class RegistrationOutcome:
    """What a signup attempt with OUR controlled address established. `handle` is opaque to the flow (the real
    predicate passes the live Account so `follow` can act as the same session); the flow only reads the flags."""
    submitted: bool                 # we found a signup surface and submitted it with our address
    has_session: bool = False       # signup logged us straight in -> the app is NOT email-verification-gated
    announces_email: bool = False   # the signup response said a confirmation email is on the way
    has_resend_control: bool = False  # the confirm page offers a 'resend' option (a resilience expectation)
    handle: Any = None


@dataclass
class Verification:
    """What acting on the received email accomplished. `acted` is False when there was nothing followable (a
    code-only email we cannot submit, or no link at all) -> the flow reports it could not judge, never a fire."""
    acted: bool
    session: bool = False


@dataclass
class EmailVerifyResult:
    """The single shared observation both email probes read. Run once per app, memoized: registering and polling
    twice would double the mutation and the wait."""
    attempted: bool                     # a signup with our address was submitted
    email_gated: bool = False           # signup is waiting on email verification (announced, or an email arrived)
    email_arrived: bool = False
    first_leg_empty: bool = False       # no email by the resend_at checkpoint (even if it arrived later) -> slow send
    has_resend_control: bool = False    # the confirm page offers a 'resend' option
    resent: bool = False                # we clicked the app's own 'resend' control at the halfway mark
    acted_on_verification: bool = False  # a followable link was found and acted on
    session_after_verify: bool = False
    message: EmailMessage | None = None
    na_reason: str = ""
    detail: str = ""


def verify_email_flow(
    receiver: EmailReceiver,
    tag: str,
    register: Callable[[str], RegistrationOutcome | None],
    follow: Callable[[RegistrationOutcome, EmailMessage], Verification],
    resend: Callable[[RegistrationOutcome], bool] | None = None,
    *,
    announced_timeout: float = 60.0,
    unannounced_timeout: float = 8.0,
    resend_at: float = 30.0,
) -> EmailVerifyResult:
    """Register with a controlled address, decide whether the signup is email-gated, and if so whether the email
    arrives and its link lets us in. The decision tree, with the false positive it is built to avoid:

      * signup could not be submitted (CAPTCHA/SSO/no surface) -> N/A, we tested nothing.
      * signup logged us straight in -> N/A, the app is not email-verification-gated, nothing to verify.
      * no confirm-email language AND no email arrived -> N/A. This is the guard: a signup that just wants a
        separate login also establishes no session and receives no mail, and must NOT read as a lock-out.
      * gated (announced or an email arrived) but no email came -> email_arrived False (qa-email-001 fires).
      * email arrived: follow its link. Acted and got a session -> the flow works. Acted and got no session ->
        verification is inert (qa-email-002 fires). Nothing followable -> acted False -> qa-email-002 reads N/A.

    SECOND CHANCE for a slow announced email: poll to `resend_at`, then click the app's OWN 'resend
    confirmation' control if `resend` finds one, then poll the rest of `announced_timeout`. So qa-email-001
    fires only after BOTH the initial send and a resend fail to deliver -- a flaky first send is not a lock-out.
    """
    address = receiver.address(tag)
    reg = register(address)
    if reg is None or not reg.submitted:
        return EmailVerifyResult(attempted=False,
                                 na_reason="could not submit a signup with a controlled address "
                                           "(no reachable signup form/API, or a CAPTCHA/SSO gate)")
    if reg.has_session:
        return EmailVerifyResult(attempted=True, email_gated=False,
                                 na_reason="signup established a session immediately (not email-gated)")
    resent = first_leg_empty = False
    if reg.announces_email:
        first_leg = min(resend_at, announced_timeout)
        msg = receiver.poll(tag, first_leg)
        first_leg_empty = msg is None                           # no email by the resend checkpoint -> slow send
        if msg is None and resend is not None and announced_timeout > first_leg:
            resent = bool(resend(reg))                          # give a flaky first send a second chance
            msg = receiver.poll(tag, announced_timeout - first_leg)
    else:
        # not announced: a single short confirmatory poll; no resend (we cannot confirm it is even email-gated)
        msg = receiver.poll(tag, unannounced_timeout)
    if not reg.announces_email and msg is None:
        return EmailVerifyResult(attempted=True, email_gated=False,
                                 na_reason="signup is not email-gated (no confirmation-email language, "
                                           "no email received, no immediate session)")
    common = dict(first_leg_empty=first_leg_empty, has_resend_control=reg.has_resend_control, resent=resent)
    if msg is None:
        return EmailVerifyResult(attempted=True, email_gated=True, email_arrived=False, **common,
                                 detail=f"signup announced a confirmation email but none arrived to {address} "
                                        f"within {announced_timeout:.0f}s"
                                        + (" (even after clicking resend)" if resent else ""))
    result = EmailVerifyResult(attempted=True, email_gated=True, email_arrived=True, message=msg, **common)
    ver = follow(reg, msg)
    result.acted_on_verification = ver.acted
    result.session_after_verify = ver.session
    if not ver.acted:
        result.detail = ("the email carried no followable verification link (code-only or none); "
                         "cannot judge whether verification establishes a session")
    return result
