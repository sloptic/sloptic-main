"""Shared httpx client factory for authenticated runs.

A `--header 'Cookie: session=...'` must not be pinned as a STATIC header: apps that rotate the session
cookie mid-session (DVWA, many PHP/Rails apps issue a fresh id via Set-Cookie) would de-authenticate a
long crawl using a fixed Cookie header. Seeding the cookie into httpx's jar instead lets the client
absorb Set-Cookie updates and stay logged in. Non-cookie auth (Authorization: Bearer) stays static.
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx


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
