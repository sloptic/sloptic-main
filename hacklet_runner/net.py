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
_trace_probe: contextvars.ContextVar = contextvars.ContextVar("hl_trace_probe", default="")
_TRACE_CAP = 800        # bound the trace: a fan-out probe (SQLi/XSS) must not grow it without limit
_TRACE_BODY_CAP = 2048  # truncate a large/binary body (a multipart upload) so the record stays readable


def start_trace(enabled: bool = True) -> list | None:
    """(Re)set request recording for this grade and return the sink (None when disabled). ALWAYS resets the
    ContextVar, so a trace=False run after a trace=True one in the same process records into nothing, not a
    stale sink from the prior run."""
    sink: list | None = [] if enabled else None
    _trace_sink.set(sink)
    return sink


def set_trace_probe(probe_id: str) -> None:
    """Tag subsequent recorded requests with the probe now running (the executor calls this per probe)."""
    _trace_probe.set(probe_id or "")


def _trace_response(response) -> None:
    """httpx response hook: append the request that produced `response` to the active trace sink."""
    sink = _trace_sink.get()
    if sink is None or len(sink) >= _TRACE_CAP:
        return
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
    if _trace_sink.get() is not None:   # --trace active -> record every request this client makes (tagged by probe)
        eh = dict(kwargs.get("event_hooks") or {})
        eh["response"] = list(eh.get("response") or []) + [_trace_response]
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
