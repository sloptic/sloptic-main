"""Self-as-oracle: register the runner's own account so it can test the authenticated surface.

Account creation is just an HTTP POST to a registration form — discover the form (a password field),
fill it heuristically, submit, and hold the resulting session. Reusable by the auth-mechanics probes
(cookie hygiene now; logout-invalidation, login rate-limit, two-account IDOR next).
"""
from __future__ import annotations

import contextlib
import re
import secrets
from dataclasses import dataclass, field

import httpx

from .schema import Form, Profile

_HIDDEN_INPUT = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_INPUT_ATTR = re.compile(r'\b(name|value)\s*=\s*"([^"]*)"', re.IGNORECASE)


def _csrf_token(html: str) -> str | None:
    """Parse the first hidden input whose name looks like a CSRF token and return its value, so a
    CSRF-protected form POST (Gitea, Django, Rails, ...) is accepted instead of silently rejected."""
    for tag in _HIDDEN_INPUT.findall(html):
        attrs = {k.lower(): v for k, v in _INPUT_ATTR.findall(tag)}
        if "value" in attrs and is_csrf_field(attrs.get("name", "")):
            return attrs["value"]
    return None

# Common session cookie names. Excludes CSRF tokens, which are intentionally readable by JS (not
# HttpOnly) — flagging those would be a false positive.
SESSION_COOKIE_NAMES = {
    "session", "sessionid", "session_id", "sid", "connect.sid", "phpsessid",
    "jsessionid", "_session", "auth", "auth_token", "access_token", "token", "jwt",
}

_REGISTER_HINTS = ("register", "signup", "sign-up", "sign_up", "join", "create-account")


@dataclass
class Account:
    username: str
    password: str
    client: httpx.Client          # carries the session (cookie jar and/or Authorization: Bearer) for authed probes
    register_response: httpx.Response
    storage_exposed: bool = False  # session token was persisted in localStorage (XSS-reachable) -> sec-session-005
    provided: bool = False         # a caller-supplied --header session (ONE identity), not a fresh self-registration
    backend_reads: list = field(default_factory=list)  # managed-backend (Supabase /rest/v1) reads the app's own
    #     client made during registration {url, apikey} — replayed as a second user by the managed-backend IDOR probe


# A field that names a NEW / CURRENT / OLD password — the hallmark of a password-CHANGE form (as opposed
# to a "confirm password" field, which also appears on registration). "password2"/"retype"/"confirm" are
# deliberately NOT here: they're ambiguous (registration has them too).
_PW_CHANGE_FIELD = re.compile(r"pass(?:word)?[_-]?(?:new|current|old)|(?:new|current|old)[_-]?pass(?:word)?",
                              re.IGNORECASE)
_IDENTITY_HINT = ("user", "email", "mail", "login", "phone", "handle", "account")


def is_password_change_form(form: Form) -> bool:
    """True when a form CHANGES the current session's own password rather than authenticating or
    registering with one. Submitting it (any probe, with our real cookie) resets the account's password
    and locks the grader — and the real user — out (DVWA's /vulnerabilities/csrf/ is exactly this). A
    registration needs an IDENTITY field (username/email); a password-change is new/confirm passwords
    with none, or an explicit new/current/old-password field."""
    names = [n.lower() for n in form.fields]
    if not any("pass" in n or "pwd" in n for n in names):
        return False  # no password field at all -> not a credential form
    if any(_PW_CHANGE_FIELD.search(n) for n in names):
        return True   # an explicit new/current/old-password field -> a change form
    return not any(any(h in n for h in _IDENTITY_HINT) for n in names)  # password(s) but no identity to register


def _password_form(forms: list[Form]) -> Form | None:
    pw = [f for f in forms
          if any("pass" in name.lower() for name in f.fields) and not is_password_change_form(f)]
    if not pw:
        return None
    return next((f for f in pw if any(h in f.action.lower() for h in _REGISTER_HINTS)), pw[0])


def _fill(form: Form, username: str, password: str) -> dict[str, str]:
    data = {}
    for name in form.fields:
        low = name.lower()
        # password + its confirm/retype field (password2, password_confirmation, retype, ...) so a
        # registration with a "confirm password" input isn't rejected for a mismatch.
        if "pass" in low or "pwd" in low or "retype" in low or "repeat" in low:
            data[name] = password
        elif "email" in low or "mail" in low:
            data[name] = username + "@example.com"
        else:
            data[name] = username
    return data


_CREATE_HINTS = ("note", "post", "item", "todo", "comment", "message", "create", "add", "new")
_NON_CREATE = ("login", "signin", "sign-in", "sign_in", "log_in", "log-in", "register", "signup",
               "sign-up", "sign_up", "search", "query", "logout", "auth")


def create_form(forms: list[Form]) -> Form | None:
    """A content-creation form: a POST form with a non-password field that isn't auth/search."""
    cands = [
        f for f in forms
        if (f.method or "post").lower() == "post"
        and f.fields
        and not any(h in f.action.lower() for h in _NON_CREATE)
        and not all("pass" in n.lower() for n in f.fields)
        and not is_password_change_form(f)  # never submit a credential-change form as "content"
    ]
    if not cands:
        return None
    return next((f for f in cands if any(h in f.action.lower() for h in _CREATE_HINTS)), cands[0])


_CSRF_FIELD_HINTS = ("csrf", "xsrf", "authenticity_token", "_token", "csrfmiddleware")


def is_csrf_field(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in _CSRF_FIELD_HINTS)


_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "log-in", "authenticate")


def login_form(forms: list[Form]) -> Form | None:
    """A password form for authenticating (not registering) — prefers a login-hinted action, else any
    password form that isn't the registration form."""
    pw = [f for f in forms if any("pass" in name.lower() for name in f.fields)]
    if not pw:
        return None
    hinted = next((f for f in pw if any(h in f.action.lower() for h in _LOGIN_HINTS)), None)
    if hinted is not None:
        return hinted
    non_register = [f for f in pw if not any(h in f.action.lower() for h in _REGISTER_HINTS)]
    return non_register[0] if non_register else None


def _provided_session(headers) -> bool:
    """A caller supplied a live session via --header (a Cookie or an Authorization/Bearer) — the Option-B path
    for apps we can't self-register (CAPTCHA / email-verify / SSO)."""
    return bool(headers) and any(k.lower() in ("cookie", "authorization") for k in headers)


def _account_from_headers(base_url: str, headers) -> Account:
    """Wrap a caller-supplied session (--header) as an Account: an httpx client that carries those headers on
    every request, so the authed-surface probes reach the authenticated surface as the provided identity. No
    Set-Cookie is available (a client-side Cookie header has no flags), so the cookie-flag probes read N/A."""
    client = httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True, headers=dict(headers))
    return Account(username="hl_provided", password="", client=client,
                   register_response=httpx.Response(200, request=httpx.Request("GET", base_url)), provided=True)


def _session_from_client(client: httpx.Client, response: httpx.Response) -> dict:
    """The live session established on `client` (+ its login `response`) as REPLAYABLE headers: a Cookie of
    the session cookies in the jar (fall back to all cookies), and/or a Bearer from the response body/header."""
    out: dict = {}
    session = [(c.name, c.value) for c in client.cookies.jar if _is_session_cookie(c.name)]
    jar = session or [(c.name, c.value) for c in client.cookies.jar]
    if jar:
        out["Cookie"] = "; ".join("%s=%s" % (n, v) for n, v in jar)
    token = _bearer_token(response)
    if token:
        out["Authorization"] = "Bearer " + token
    return out


def login_with_credentials(base_url: str, email: str, password: str, profile: "Profile | None" = None) -> dict:
    """Log in with CALLER-PROVIDED credentials (--login, a team's demo/test account) and return the session as
    replayable headers ({"Cookie": ...} / {"Authorization": "Bearer ..."}), or {} if none was established. The
    LOW-FRICTION handoff for gated apps (email-verify / captcha / SDK signup): the team hands us a login, we
    authenticate, and every authed-surface probe runs as that identity — bypassing ALL signup gates at once,
    which an email server (defeats only email-conf) can't. Self-contained (no discovery needed): tries JSON
    login endpoints (spec-named first) then the HTML login form (parsed from '/'), so it can authenticate the
    CRAWL too, not just the probes. `email` doubles as the username when the app keys on that."""
    login_paths = list(dict.fromkeys(_spec_auth_paths(profile, _LOGIN_KW) + list(_JSON_LOGIN_PATHS)))
    with httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True, verify=False) as c:
        for path in login_paths:                                        # 1) JSON login endpoints
            for body in ({"email": email, "password": password},
                         {"username": email, "password": password},
                         {"email": email, "username": email, "password": password}):
                try:
                    r = c.post(path, json=body)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if r.status_code in (200, 201) and _auth_shaped(r):
                    hdrs = _session_from_client(c, r)
                    if hdrs:
                        return hdrs
        forms = list(profile.forms) if profile is not None else _login_forms_at(base_url, c)
        form = login_form(forms)                                        # 2) HTML login form
        if form is not None:
            data = {n: (password if "pass" in n.lower() else email) for n in form.fields}
            try:
                r = c.request((form.method or "post").upper(), form.action, data=data)
                if r.status_code < 400:
                    hdrs = _session_from_client(c, r)
                    if hdrs:
                        return hdrs
            except (httpx.HTTPError, httpx.InvalidURL):
                pass
    return {}


def _login_forms_at(base_url: str, client: httpx.Client) -> list:
    """Fetch '/' and parse its <form>s (lazy discovery import, avoiding an import cycle) — so a provided-creds
    login can find an HTML login form with no pre-built profile."""
    try:
        from .discovery import _FORM, _parse_forms
        html = client.get("/").text
        return _parse_forms(_FORM.findall(html), base_url, "/")
    except Exception:
        return []


def register_account(base_url: str, profile: Profile, suffix: str = "", browser_register=None,
                     headers=None) -> Account | None:
    """Create a fresh account (self-as-oracle) for the authed-surface probes. httpx registration first (HTML
    form POST, else JSON-API); if that establishes NO session — the SPA case, where the form's action is a
    placeholder and the real registration is a JS fetch — and a `browser_register` callback is supplied, drive
    the BROWSER to register (its own JS makes the real request) and use the session cookie/token it establishes.
    Returns None when nothing establishes a session (email-verify / CAPTCHA / SSO / third-party auth) -> caller
    reads N/A. If the caller supplied a session via --header (Option B), that is used directly (single identity)."""
    if _provided_session(headers):
        return _account_from_headers(base_url, headers)
    acct = _register_httpx(base_url, profile, suffix)
    if not _has_session(acct) and _password_form(profile.forms) is not None:
        # the HTML-form POST established NO session — on a SPA the form is a React onSubmit with a placeholder
        # action, and the REAL registration is a JSON API (which _register_httpx only tries when there's no
        # form). Try it before spending a browser launch (the Borrow-Tracker / Next.js case).
        json_acct = _register_json(base_url, suffix, profile)
        if _has_session(json_acct):
            if acct is not None:
                acct.client.close()
            acct = json_acct
    if _has_session(acct) or browser_register is None:
        return acct
    caps = profile.capabilities
    if _password_form(profile.forms) is None and not (caps.get("login_trigger") or caps.get("signup_trigger")):
        return acct   # no auth surface at all -> don't spend a browser launch
    return _register_via_browser(base_url, browser_register) or acct


def _register_httpx(base_url: str, profile: Profile, suffix: str = "") -> Account | None:
    """Register via the discovered HTML form (POST its action) or a JSON API. Returns None on a transport error;
    an Account even when no session cookie came back (the caller checks _has_session; the probes then read N/A)."""
    form = _password_form(profile.forms)
    if form is None:
        # no HTML form -> JSON-API registration + login, preferring endpoints named in the spec
        return _register_json(base_url, suffix, profile)
    # per-call random username: a real app with a unique-username constraint rejects a FIXED name on
    # re-grade (run 2+), silently nulling the authed session and flipping the auth probes to clean.
    # The score depends on the cookie's flags, not the username value, so this stays deterministic.
    username = "hl_" + secrets.token_hex(5) + suffix
    password = "Hl-Probe-Passw0rd!"
    client = httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True)
    data = _fill(form, username, password)
    try:
        # GET the form's page first: sets the CSRF cookie and lets us read the token out of the HTML,
        # so a CSRF-protected registration (Gitea, Django, Rails, ...) is accepted instead of rejected.
        try:
            token = _csrf_token(client.get(form.action).text)
            if token:
                for name in form.fields:
                    if is_csrf_field(name):
                        data[name] = token
        except (httpx.HTTPError, httpx.InvalidURL):
            pass  # form page not GET-able (POST-only endpoint) -> proceed without a token
        resp = client.request("POST", form.action, data=data)
    except (httpx.HTTPError, httpx.InvalidURL):
        # InvalidURL is NOT a subclass of HTTPError; catching both ensures a control-char form
        # action (hostile target) closes the client here instead of leaking it and crashing run().
        client.close()
        return None
    return Account(username=username, password=password, client=client, register_response=resp)


# JSON-API auth: modern SPAs (Juice Shop, Django REST, ...) authenticate via JSON endpoints, not HTML
# forms. These let the self-as-oracle probes reach that surface — session established as a bearer token
# (set as a default Authorization header) or a session cookie, whichever the app returns.
_JSON_LOGIN_PATHS = ("/rest/user/login", "/api/login", "/api/auth/login", "/api/sessions",
                     "/login", "/api/v1/login", "/auth/login", "/api/token", "/users/login",
                     "/api/user/login", "/api/authenticate")
_JSON_REGISTER_PATHS = ("/api/users", "/api/register", "/api/auth/register", "/api/signup",
                        "/register", "/api/v1/users", "/api/accounts", "/api/user")


def _bearer_token(resp: httpx.Response) -> str | None:
    """Pull a JWT/bearer token from a JSON login response (top level or one level nested)."""
    try:
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    nodes = [data] + [data[p] for p in ("authentication", "data", "auth", "result") if isinstance(data.get(p), dict)]
    for node in nodes:
        for key in ("token", "accessToken", "access_token", "auth_token", "authToken", "jwt", "id_token"):
            v = node.get(key)
            if isinstance(v, str) and len(v) > 10:
                return v
    return None


def find_json_login(client: httpx.Client):
    """Probe common JSON login endpoints with a wrong-creds body; return (path, creds, response) for
    the first that behaves like a REAL login, else (None, None, None). Lets the rate-limit probe reach
    JSON-API apps with no HTML login form — WITHOUT firing on a static SPA, whose catch-all serves the
    index.html shell (200 text/html) for any POST, which would look like an always-succeeding 'login'
    and produce a phantom no-rate-limit finding. So we require an auth-shaped answer to wrong creds:
    an auth-failure status, or a JSON body — never a 2xx HTML shell (the SPA) or 404/405/501."""
    creds = {"email": "hacklet_probe_rl@example.com", "username": "hacklet_probe_rl",
             "password": "hl-wrong-password"}
    for path in _JSON_LOGIN_PATHS:
        try:
            r = client.post(path, json=creds)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        if r.status_code in (404, 405, 501):
            continue
        ct = r.headers.get("content-type", "").lower()
        # a genuine login rejects wrong creds (400/401/403/422) or answers in JSON; a static SPA returns
        # 200 text/html (its shell) for everything — that's not a login surface, so keep looking.
        if r.status_code in (400, 401, 403, 422) or "json" in ct:
            return path, creds, r
    return None, None, None


_REGISTER_KW = ("register", "signup", "sign-up", "sign_up", "join", "create-account")
_LOGIN_KW = ("login", "signin", "sign-in", "sign_in", "authenticate")


def _spec_auth_paths(profile, keywords) -> list[str]:
    """POST endpoints from a discovered OpenAPI spec whose path names an auth action (register/login),
    so a versioned or non-standard path (VAmPI's /users/v1/login) is tried before the generic list."""
    out = []
    for e in getattr(profile, "endpoints", None) or []:
        if e.method.lower() == "post" and any(k in e.raw_path.lower() for k in keywords):
            out.append(e.raw_path)
    return out


def _auth_shaped(r: httpx.Response) -> bool:
    """A real JSON-API register answers with JSON or an auth artifact (Set-Cookie / bearer) — NOT a static
    SPA's 200 text/html shell, whose catch-all serves index.html for ANY POST and would otherwise read as a
    successful registration on the first path tried (leaving a session-less account -> a silent N/A)."""
    ct = r.headers.get("content-type", "").lower()
    return "json" in ct or bool(r.headers.get_list("set-cookie")) or _bearer_token(r) is not None


def _register_json(base_url: str, suffix: str, profile=None) -> Account | None:
    """Self-register via a JSON API (no HTML form): try register endpoints (spec-named first), then
    log in for an authed session — a bearer token (default Authorization header) or a session cookie."""
    username = "hl_" + secrets.token_hex(5) + suffix
    password = "Hl-Probe-Passw0rd!"
    email = username + "@example.com"
    register_paths = list(dict.fromkeys(_spec_auth_paths(profile, _REGISTER_KW) + list(_JSON_REGISTER_PATHS)))
    login_paths = list(dict.fromkeys(_spec_auth_paths(profile, _LOGIN_KW) + list(_JSON_LOGIN_PATHS)))
    client = httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True)
    # a SUPERSET body: many signup APIs require a display NAME and/or a confirm field beyond email+password
    # (a bare {email,username,password} 500s a name-required API — the Borrow-Tracker / Next.js case). Extra
    # keys are ignored by lenient APIs; the confirm variant is the fallback for the ones that validate it.
    base = {"email": email, "username": username, "name": username, "password": password}
    variants = (base, {**base, "password_confirmation": password, "confirmPassword": password, "password2": password})
    reg = None
    for path in register_paths:
        for body in variants:
            try:
                r = client.post(path, json=body)
            except (httpx.HTTPError, httpx.InvalidURL):
                break   # transport error on this path -> next path
            if r.status_code in (200, 201) and _auth_shaped(r):   # skip a static-SPA 200 text/html shell
                reg = r
                break
        if reg is not None:
            break
    if reg is None:
        client.close()
        return None
    # the REGISTER itself may auto-establish the session (a Set-Cookie, or a bearer in its body) — the common
    # SPA cookie-auth shape (Next.js). Use it directly; only fall to a separate login for APIs that split the two.
    token = _bearer_token(reg)
    if token:
        client.headers["Authorization"] = "Bearer " + token
        return Account(username=username, password=password, client=client, register_response=reg)
    if session_cookie(reg) is not None or any(_is_session_cookie(c.name) for c in client.cookies.jar):
        return Account(username=username, password=password, client=client, register_response=reg)
    for path in login_paths:
        for cred in ({"email": email, "password": password}, {"username": username, "password": password}):
            try:
                r = client.post(path, json=cred)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if r.status_code == 200:
                token = _bearer_token(r)
                if token:
                    client.headers["Authorization"] = "Bearer " + token
                return Account(username=username, password=password, client=client, register_response=r)
    client.close()
    return None


def parse_set_cookies(resp: httpx.Response) -> list[dict]:
    """Each Set-Cookie header -> {name, httponly, secure, samesite}. Flags are read from the raw
    header because cookie jars drop them. samesite is True only for Lax/Strict: SameSite=None is the
    explicit cross-site OPT-OUT (no CSRF defense), so it must read as undefended."""
    out = []
    for raw in resp.headers.get_list("set-cookie"):
        first, _, rest = raw.partition(";")
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        attrs = {}
        for a in rest.split(";"):
            a = a.strip()
            if not a:
                continue
            k, _, v = a.partition("=")
            attrs[k.strip().lower()] = v.strip().lower()
        out.append({
            "name": name,
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": attrs.get("samesite") in ("lax", "strict"),
        })
    return out


_SESSION_HINTS = ("session", "sessid")


def _is_session_cookie(name: str) -> bool:
    """Recognize framework-namespaced session cookies (myapp_session, laravel_session, __Host-session,
    next-auth.session-token, ...), not just the exact known names. CSRF tokens are intentionally
    JS-readable, so they are never treated as the session cookie."""
    low = name.lower()
    if "csrf" in low or "xsrf" in low:
        return False
    return low in SESSION_COOKIE_NAMES or any(h in low for h in _SESSION_HINTS)


def _all_set_cookies(resp: httpx.Response) -> list[dict]:
    """Set-Cookie across the whole redirect chain. register_account follows redirects, and the very
    common POST /register -> 302 -> dashboard sets the session cookie on the 302 (resp.history), not
    on the final 200 response — reading only the final response would miss it entirely."""
    out: list[dict] = []
    for r in (*resp.history, resp):
        out.extend(parse_set_cookies(r))
    return out


def session_cookie(resp: httpx.Response) -> dict | None:
    # last match across the chain = the cookie's final state (a later Set-Cookie overrides earlier).
    matches = [c for c in _all_set_cookies(resp) if _is_session_cookie(c["name"])]
    return matches[-1] if matches else None


def _has_session(acct: Account | None) -> bool:
    """Did registration actually establish an authenticated session? A bearer token (Authorization header) OR a
    session COOKIE (in the register response, or the client's jar after redirects). If neither, an SPA's
    placeholder-action POST just hit the shell — nothing to test — so the caller can try the browser path."""
    if acct is None:
        return False
    if acct.client.headers.get("Authorization"):
        return True
    if session_cookie(acct.register_response) is not None:
        return True
    return any(_is_session_cookie(c.name) for c in acct.client.cookies.jar)


def _jwt_claims(token: str) -> dict | None:
    """Decode a JWT's payload (middle segment) without verifying the signature — we only read the app's OWN
    claims about the account WE just registered (its `sub` = the user id the app keys records on). No secret
    needed, no trust decision; None on any malformed token."""
    import base64
    import json
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        seg = parts[1] + "=" * (-len(parts[1]) % 4)   # pad base64url to a multiple of 4
        claims = json.loads(base64.urlsafe_b64decode(seg))
        return claims if isinstance(claims, dict) else None
    except Exception:
        return None


def session_subject(acct: Account | None) -> str | None:
    """The account's OWN user id as the app assigns it — the value its per-user records are keyed on — read
    from the session JWT's `sub` claim (the Supabase/Firebase/JWT cohort). This is what the user-record IDOR
    probe addresses A's record by. None for a cookie session with no JWT (that probe then can't address A)."""
    if acct is None:
        return None
    auth_hdr = acct.client.headers.get("Authorization", "")
    if auth_hdr[:7].lower() == "bearer ":
        claims = _jwt_claims(auth_hdr[7:])
        sub = claims.get("sub") if claims else None
        if isinstance(sub, str) and sub:
            return sub
    return None


def _synthesize_response(base_url: str, cookies: list[dict]) -> httpx.Response:
    """Re-encode browser cookies (name + httponly/secure/samesite) as Set-Cookie headers on an httpx.Response,
    so the session probes read the flags through session_cookie()/parse_set_cookies() UNCHANGED — the browser
    handed us the flags directly; this just puts them in the exact shape the probes already parse."""
    setc = []
    for c in cookies:
        parts = [f"{c['name']}={c.get('value', '')}"]
        if c.get("httponly"):
            parts.append("HttpOnly")
        if c.get("secure"):
            parts.append("Secure")
        if c.get("samesite"):
            parts.append("SameSite=Lax")   # samesite True = Lax/Strict was set (a real cross-site defense)
        setc.append(("set-cookie", "; ".join(parts)))
    return httpx.Response(200, headers=setc, request=httpx.Request("POST", base_url))


def _register_via_browser(base_url: str, browser_register) -> Account | None:
    """SPA registration through the browser: the injected browser_register(base_url) drives Playwright to fill +
    submit the signup so the app's OWN JS makes the real request, returning the session it establishes — a cookie
    AND/OR a Bearer token (the bolt/Supabase/Firebase cohort authenticates by JWT, not cookie). Build an Account
    whose httpx client carries both (cookie jar + Authorization header) for the authed IDOR / etc. probes, plus a
    synthetic register_response for the cookie-flag probes. None when the browser established NEITHER."""
    try:
        result = browser_register(base_url)
    except Exception:
        return None
    if not result:
        return None
    cookies = result.get("cookies") or []
    bearer = result.get("bearer")
    if not any(_is_session_cookie(c["name"]) for c in cookies) and not bearer:
        return None   # neither a session cookie nor a token (email-verify / CAPTCHA / SSO) -> nothing to test -> N/A
    client = httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True)
    for c in cookies:
        with contextlib.suppress(Exception):
            client.cookies.set(c["name"], c.get("value", ""))
    if bearer:
        client.headers["Authorization"] = "Bearer " + bearer   # authenticate the client the IDOR probes reuse
    creds = result.get("creds") or {}
    return Account(username=creds.get("username", "hl_browser"), password=creds.get("password", ""),
                   client=client, register_response=_synthesize_response(base_url, cookies),
                   storage_exposed=bool(result.get("storage_exposed")),
                   backend_reads=result.get("backend_reads") or [])
