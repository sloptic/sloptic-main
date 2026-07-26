"""Managed-backend (Supabase) plumbing shared by discovery, auth and the probes.

Extracted rather than duplicated: `probes` imports `auth`, so `auth` cannot import `probes`, and both need to
resolve the app's data-plane gateway. Everything here is read-only or creates a THROWAWAY account.

Why this module exists at all: on a BaaS app the auth API is not the app's. Measured on supavulnbase,
`register_account` gets a 404 from every app-side path and the crawl silently proceeds ANONYMOUS, while
`POST <gateway>/auth/v1/signup` with the public anon key answers 200 with a session. Anonymously every route
renders the same shell (31 bytes on /app/dashboard), so the authed half of the app — its routes, its
per-route chunks, and therefore its API surface and any secret compiled into them — is invisible.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
from urllib.parse import urlparse

import httpx

# A JWT-shaped anon key, and the origins a bundle names. Hosted Supabase is `<ref>.supabase.co`; a self-hosted
# gateway is any origin the TARGET is already on (see reachable_origin — that restriction is an SSRF guard).
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{6,}")
_BUNDLE_ORIGIN = re.compile(r"""["'`](https?://[A-Za-z0-9.\-\[\]]+(?::\d{2,5})?)(?=["'`/])""")
_SCRIPT_SRC = re.compile(r"""["'](/[^"']*?_next/static/[^"']+?\.js|/[^"']*?\.js)["']""")
_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}
_CHUNK_CAP = 12


def reachable_origin(candidate: str, target: str) -> bool:
    """Is `candidate` an origin the target is already on? Same host (any port), or loopback-for-loopback.

    This is the SSRF guard. A bundle string is attacker-influenced input, so following an arbitrary URL from it
    would turn the grader into a request forwarder; on a real deployment at app.example.com a literal pointing
    at internal-db.corp or 169.254.169.254 is refused."""
    try:
        c, t = urlparse(candidate), urlparse(target)
    except ValueError:
        return False
    ch, th = (c.hostname or "").lower(), (t.hostname or "").lower()
    if not ch or not th:
        return False
    return ch == th or (ch in _LOOPBACK and th in _LOOPBACK)


def looks_postgrest(client, origin: str) -> bool:
    """Behavioural signature, so a gateway is recognised by what it DOES rather than by its hostname: PostgREST
    answers its root with JSON — an OpenAPI document or its own 'no API key' complaint — and Supabase fronts it
    with Kong."""
    try:
        r = client.get(origin.rstrip("/") + "/rest/v1/", timeout=6.0)
    except Exception:
        return False
    server = (r.headers.get("server") or "").lower()
    if "postgrest" in server or "kong" in server:
        return True
    if "json" in (r.headers.get("content-type") or "").lower():
        body = (r.text or "")[:400].lower()
        return any(t in body for t in ('"swagger"', '"paths"', "api key", "apikey", "postgrest"))
    return False


def resolve_gateway(blob: str, target: str) -> str | None:
    """The Supabase data-plane origin this app talks to: the hosted project, else a co-located self-hosted
    gateway that proves itself PostgREST."""
    hosted = re.search(r"https://([a-z0-9]{15,40})\.supabase\.co", blob or "")
    if hosted:
        return "https://" + hosted.group(1) + ".supabase.co"
    cands = [c for c in dict.fromkeys(_BUNDLE_ORIGIN.findall(blob or "")) if reachable_origin(c, target)]
    if not cands:
        return None
    with httpx.Client(timeout=6.0, follow_redirects=True, verify=False) as c:
        for cand in cands[:6]:
            if looks_postgrest(c, cand):
                return cand.rstrip("/")
    return None


def anon_key(blob: str) -> str | None:
    """The PUBLIC anon key. `role` is read from the payload so a service_role key — which would make every
    request omnipotent and every RLS check meaningless — is never mistaken for it."""
    for m in _JWT.finditer(blob or ""):
        seg = m.group(1)
        try:
            payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        except Exception:
            continue
        if isinstance(payload, dict) and str(payload.get("role", "")).lower() == "anon":
            return m.group(0)
    return None


def client_blob(base_url: str, start_path: str = "", headers=None, cap: int = _CHUNK_CAP) -> str:
    """The app's entry page plus its referenced scripts, concatenated — enough to find the gateway and key.

    The client is ORIGIN-bound with the entry path passed separately, the same split discovery uses. Binding it
    to a path-bearing base_url instead makes httpx resolve `/app` against `.../app` and fetch `/app/app`: the
    blob came back 8552 bytes of shell with no gateway and no key, where the correct split yields 727KB."""
    parts = urlparse(base_url)
    origin = "%s://%s" % (parts.scheme, parts.netloc) if parts.netloc else base_url
    entry = start_path or parts.path or "/"
    out = []
    try:
        with httpx.Client(base_url=origin, headers=headers or None, timeout=12.0,
                          follow_redirects=True, verify=False) as c:
            html = c.get(entry).text
            out.append(html)
            for src in list(dict.fromkeys(_SCRIPT_SRC.findall(html)))[:cap]:
                try:
                    out.append(c.get(src).text)
                except Exception:
                    continue
    except Exception:
        return ""
    return "\n".join(out)


def cookie_name(gateway: str) -> str:
    """`sb-<ref>-auth-token`, the cookie @supabase/ssr stores the session in. The ref is the gateway host's
    first label: `abcdefgh.supabase.co` -> abcdefgh, and a self-hosted `localhost:8055` -> localhost."""
    host = (urlparse(gateway).hostname or "").lower()
    return "sb-" + (host.split(".")[0] or "local") + "-auth-token"


def cookie_value(session: dict) -> str:
    """@supabase/ssr accepts the session JSON, and writes it `base64-` prefixed. Measured on supavulnbase:
    both forms render the authed page (10675 bytes vs 31 anonymous); a BARE access token does not."""
    keep = {k: session.get(k) for k in
            ("access_token", "refresh_token", "expires_in", "expires_at", "token_type", "user")}
    raw = json.dumps(keep, separators=(",", ":"))
    return "base64-" + base64.b64encode(raw.encode()).decode()


def signup(gateway: str, key: str, suffix: str = "") -> dict | None:
    """Register a THROWAWAY account at the gateway's GoTrue. Returns the session, or None when signup is closed
    (email confirmation required, captcha, or anonymous sign-ups disabled) -> the caller reads N/A honestly."""
    email = "hl-probe-%s%s@example.com" % (secrets.token_hex(5), suffix)
    body = {"email": email, "password": "Hl-Probe-Passw0rd!"}
    try:
        r = httpx.post(gateway.rstrip("/") + "/auth/v1/signup", json=body, timeout=12.0, verify=False,
                       headers={"apikey": key, "Content-Type": "application/json"})
    except Exception:
        return None
    if r.status_code not in (200, 201):
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("access_token"):
        return None      # confirmation-required signups answer 200 with a user and NO token -> no session
    data["_email"], data["_password"] = email, body["password"]
    return data
