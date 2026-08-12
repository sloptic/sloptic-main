"""Shared httpx client factory for authenticated runs.

A `--header 'Cookie: session=...'` must not be pinned as a STATIC header: apps that rotate the session
cookie mid-session (DVWA, many PHP/Rails apps issue a fresh id via Set-Cookie) would de-authenticate a
long crawl using a fixed Cookie header. Seeding the cookie into httpx's jar instead lets the client
absorb Set-Cookie updates and stay logged in. Non-cookie auth (Authorization: Bearer) stays static.
"""
from __future__ import annotations

import contextvars
from urllib.parse import urlparse

import httpx

# --trace: when active, EVERY httpx request a probe makes is recorded (method/url/headers/body/status),
# tagged with the probe currently running, so a clean/N/A probe's payloads+endpoints are inspectable — not
# just findings. Held in a ContextVar (not a global) so it's scoped to the grade's process and leaks nothing
# between runs; None (the default) means make_client installs no hook -> zero overhead on a normal grade.
_trace_sink: contextvars.ContextVar = contextvars.ContextVar("hl_trace_sink", default=None)
_trace_counts: contextvars.ContextVar = contextvars.ContextVar("hl_trace_counts", default=None)
_trace_probe: contextvars.ContextVar = contextvars.ContextVar("hl_trace_probe", default="")
# challenge onset: the FIRST probe whose request hit a WAF/challenge status. Always-on (status+header only, no
# body read -> negligible cost), surfaced only when the grade is CONFIRMED a bot_challenge -> names the probe
# whose traffic tripped the mitigation, so the corpus can show WHICH probes to gate/reorder on WAF-fronted hosts.
_challenge_onset: contextvars.ContextVar = contextvars.ContextVar("hl_challenge_onset", default=None)
# per-probe request TALLY (always-on, cheap): surfaces which probes send abnormally many requests -- the
# cumulative-volume trigger for a WAF, and the pacing/trim candidates.
_req_counts: contextvars.ContextVar = contextvars.ContextVar("hl_req_counts", default=None)
_CHALLENGE_STATUS = frozenset({403, 429, 503})


def _watch_challenge(response) -> None:
    counts = _req_counts.get()                      # tally this request against the probe that sent it
    if counts is not None:
        p = _trace_probe.get() or "?"
        counts[p] = counts.get(p, 0) + 1
    if _challenge_onset.get() is not None:
        return
    if "cf-mitigated" in response.headers:
        _challenge_onset.set(_trace_probe.get() or "?")
    elif response.status_code in _CHALLENGE_STATUS:
        # BODY-CONFIRM it's a challenge, not a plain auth-403: a challenge/block page carries the markers, an
        # auth 403 does not. A blocked response is small + non-streaming, so reading it here is safe.
        try:
            response.read()
            if is_bot_challenge(response):
                _challenge_onset.set(_trace_probe.get() or "?")
        except Exception:
            pass


def challenge_onset() -> str | None:
    """The probe id whose request first hit a CONFIRMED WAF/challenge response this grade (None if none)."""
    return _challenge_onset.get()


def request_counts() -> dict | None:
    """{probe_id: request count} for this grade (None if not started)."""
    return _req_counts.get()
# The cap is PER PROBE, not global: a global cap lets a high-fan-out probe (cmdi/lfi/crash send 100s of
# requests) monopolize the budget and STARVE every probe later in the catalog to zero — which defeats the
# whole point (you couldn't inspect the clean probe you cared about). Per-probe keeps EVERY probe represented.
_TRACE_PER_PROBE_CAP = 40  # requests recorded per probe (a representative sample of a big fan-out's payloads)
_TRACE_CAP = 4000          # global backstop only (per-probe cap x ~80 probes) — bounds total record size
_TRACE_BODY_CAP = 2048     # truncate a large/binary body (a multipart upload) so the record stays readable


def start_trace(enabled: bool = True) -> list | None:
    """(Re)set request recording for this grade and return the sink (None when disabled). ALWAYS resets the
    ContextVars, so a trace=False run after a trace=True one in the same process records into nothing, not a
    stale sink from the prior run."""
    sink: list | None = [] if enabled else None
    _trace_sink.set(sink)
    _trace_counts.set({} if enabled else None)
    _challenge_onset.set(None)   # reset per-grade onset + request tally regardless of --trace (runs every grade)
    _req_counts.set({})
    return sink


def set_trace_probe(probe_id: str) -> None:
    """Tag subsequent recorded requests with the probe now running (the executor calls this per probe)."""
    _trace_probe.set(probe_id or "")


def _trace_response(response) -> None:
    """httpx response hook: append the request that produced `response` to the active trace sink, subject to a
    PER-PROBE cap (so a fan-out probe can't starve later probes) and a global backstop."""
    sink = _trace_sink.get()
    if sink is None or len(sink) >= _TRACE_CAP:
        return
    counts = _trace_counts.get()
    probe = _trace_probe.get()
    if counts is not None:
        if counts.get(probe, 0) >= _TRACE_PER_PROBE_CAP:   # this probe already has its sample -> keep room for others
            return
        counts[probe] = counts.get(probe, 0) + 1
    req = response.request
    try:
        body = req.content.decode("utf-8", "replace") if req.content else None
    except Exception:      # a streaming/multipart body already consumed by send -> not inline-capturable
        body = None
    if body and len(body) > _TRACE_BODY_CAP:
        body = body[:_TRACE_BODY_CAP] + "…(+%d bytes)" % (len(body) - _TRACE_BODY_CAP)
    sink.append({"probe": _trace_probe.get(), "method": req.method, "url": str(req.url),
                 "headers": dict(req.headers), "body": body, "status": response.status_code})


def parse_cookie_header(value: str) -> dict:
    """`"a=1; b=2"` -> `{"a": "1", "b": "2"}` (split on the FIRST '=' so base64 '=' padding survives)."""
    out = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def make_client(base_url: str, headers: dict | None = None, **kwargs) -> httpx.Client:
    """An httpx.Client whose Cookie header (if any) is seeded into the jar (so a rotating session is
    followed via Set-Cookie); all other headers stay static. Extra kwargs pass through to httpx.Client."""
    cookies = None
    if headers:
        static = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        cookie_vals = [v for k, v in headers.items() if k.lower() == "cookie"]
        if cookie_vals:
            cookies = parse_cookie_header(cookie_vals[0])
        headers = static or None
    # A black-box grader connects to whatever cert the target presents (self-signed / sandbox / expired
    # certs are normal for an app under test) -- cert validity is a separate concern, not a connection
    # blocker. Default to not verifying TLS; callers can still override via kwargs.
    kwargs.setdefault("verify", False)
    eh = dict(kwargs.get("event_hooks") or {})
    hooks = list(eh.get("response") or []) + [_watch_challenge]   # always: cheap status watch for challenge onset
    if _trace_sink.get() is not None:   # --trace active -> ALSO record every request this client makes (by probe)
        hooks.append(_trace_response)
    eh["response"] = hooks
    kwargs["event_hooks"] = eh
    client = httpx.Client(base_url=base_url, headers=headers, **kwargs)
    if cookies:
        # Seed under the SAME domain http.cookiejar assigns to the server's own Set-Cookie, so a rotated
        # cookie REPLACES our seed instead of coexisting (both sent -> the stale one wins -> de-auth). A
        # Domain-less Set-Cookie is stored under the request host, with ".local" appended to a dotless
        # host (cookiejar's effective-host rule) -> match that.
        host = urlparse(base_url).hostname or ""
        domain = host if "." in host else host + ".local"
        for name, value in cookies.items():
            client.cookies.set(name, value, domain=domain, path="/")
    return client


# A CDN/WAF interstitial or a sleeping-app wake page served IN PLACE OF the real app. Grading it is doubly
# wrong: its (uncompressed) HTML draws false findings, and it HIDES the real surface so every probe after it
# reads a false clean. Detection is header-first (cheap, high-confidence) then a specific-marker body scan.
_CHALLENGE_MARKERS = (
    "just a moment", "checking your browser", "cf-browser-verification", "cf_chl_opt", "__cf_chl",
    "attention required!", "enable javascript and cookies to continue", "verifying you are human",
    "ddos protection by", "vercel security checkpoint", "verifying your browser", "please wait while we verify",
    "this app has gone to sleep", "get this app back up",   # Streamlit Community Cloud sleep page
    # other WAF / bot-manager block+challenge pages -- each string appears ONLY on the interstitial, never on a
    # real app merely served THROUGH the vendor, so precision holds (a plain vendor header/cookie is NOT enough).
    "incapsula incident id",                        # Imperva / Incapsula block page
    "sucuri website firewall",                      # Sucuri WAF block page
    "our systems have detected unusual traffic",    # Google / reCAPTCHA rate-limit interstitial
    "px-captcha",                                   # PerimeterX / HUMAN challenge (the element id, not the vendor name)
    "captcha-delivery.com",                         # DataDome captcha page
    "captcha.awswaf.com",                           # AWS WAF CAPTCHA
)


def is_bot_challenge(resp) -> bool:
    """True when `resp` is a bot-challenge / WAF interstitial / sleeping-app page, not the app itself. Callers
    should treat it as UNAVAILABLE (N/A / withhold the grade), never as content. Conservative: only fires on a
    Cloudflare mitigation header or a specific known interstitial marker, so a real 403/error page is not one."""
    try:
        if "cf-mitigated" in resp.headers:
            return True
        ctype = resp.headers.get("content-type", "").lower()
        if "html" not in ctype and "text" not in ctype:
            return False   # a challenge page is HTML; skip JSON/binary/asset responses
        body = resp.text[:8192].lower()
    except (httpx.HTTPError, ValueError, UnicodeError):
        return False
    return any(m in body for m in _CHALLENGE_MARKERS)
