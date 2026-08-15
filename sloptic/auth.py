"""Self-as-oracle: register the runner's own account so it can test the authenticated surface.

Account creation is just an HTTP POST to a registration form — discover the form (a password field),
fill it heuristically, submit, and hold the resulting session. Reusable by the auth-mechanics probes
(cookie hygiene now; logout-invalidation, login rate-limit, two-account IDOR next).
"""
from __future__ import annotations

import contextlib
import re
import secrets
import urllib.parse
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


# The browser lane's last failure stage, so a probe reading N/A can say WHICH of the five outcomes it hit
# without threading an out-param through register_account -> ctx.register -> every predicate. A grade runs in
# its own subprocess and register_account is single-threaded within it, so a module slot is safe here; the
# `diag` out-param on _register_via_browser stays the testable interface.
LAST_BROWSER_DIAG: dict = {}


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


def _register_via_baas(base_url: str, suffix: str = "", entry: str = "") -> Account | None:
    """Register at the app's own Supabase gateway and carry the session the way the app stores it.

    The client ends up holding BOTH halves, because they address different servers: the `sb-<ref>-auth-token`
    cookie is what the APP reads to render an authed page (measured: 10675 bytes vs 31 anonymous, while a bare
    access token gets the unauthenticated shell), and `Authorization: Bearer` + `apikey` are what the GATEWAY
    reads. Returns None when no gateway/key is embedded or signup is closed -> the caller reads N/A."""
    from . import baas   # local import: only the BaaS lane needs it, and this keeps auth import-light
    # The ENTRY path matters: the pipeline passes the ORIGIN, so on a sub-path app the blob would come from "/",
    # which here is a 404 page that only happens to reference the same chunks. Passing landing_path makes it
    # deliberate instead of lucky.
    blob = baas.client_blob(base_url, entry)
    if not blob:
        return None
    gateway = baas.resolve_gateway(blob, base_url)
    key = baas.anon_key(blob)
    if not gateway or not key:
        return None
    session = baas.signup(gateway, key, suffix)
    if not session:
        return None
    client = httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True)
    client.cookies.set(baas.cookie_name(gateway), baas.cookie_value(session))
    client.headers["Authorization"] = "Bearer " + session["access_token"]
    client.headers["apikey"] = key
    resp = httpx.Response(200, request=httpx.Request("POST", gateway + "/auth/v1/signup"),
                          json={"gateway": gateway})
    return Account(username=session.get("_email", "hl_baas"), password=session.get("_password", ""),
                   client=client, register_response=resp)


def _carry_secure_cookies_over_http(base_url: str, client: httpx.Client) -> None:
    """Re-send the jar's session cookies as an explicit Cookie header when the target is PLAINTEXT http.

    httpx STORES a `Secure` cookie but never transmits it over http. So an app that (correctly) marks its
    session cookie Secure authenticates us, `_has_session` sees the cookie in the jar, and then every authed
    request goes out anonymous — measured on OopsSec over http://localhost:3000, where the client got 401 on
    /api/wishlists while the identical cookie sent by hand got 200. Every probe reading the authed surface
    then reports N/A or clean, which is the worst shape of wrong: invisible.

    Retained is not sent — that distinction is the whole bug. Hoisted here from idor_horizontal /
    race_resource_ids, which each hand-rolled this same re-send: it belongs to the session, not to a probe.
    Only for http, so an https target keeps httpx's correct behaviour. sec-session-003 still reports a
    MISSING Secure flag independently, because it reads the raw Set-Cookie header, not the jar."""
    if not base_url.lower().startswith("http://") or client.headers.get("Cookie"):
        return
    jar = "; ".join("%s=%s" % (c.name, c.value) for c in client.cookies.jar if c.value is not None)
    if jar:
        client.headers["Cookie"] = jar


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
    LAST_BROWSER_DIAG.clear()
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
    if _has_session(acct):
        _carry_secure_cookies_over_http(base_url, acct.client)
        return acct
    # Two remaining lanes, and their ORDER costs a finding either way round.
    #
    # BROWSER first when a callback is available: it registers the way the app's own JS does, so it observes the
    # session cookie WITH ITS FLAGS — a cookie written by document.cookie is not HttpOnly by definition, which
    # is exactly what the cookie-hygiene probes exist to report.
    #
    # BaaS second: on a managed-backend app the auth API is not the app's at all. Measured on supavulnbase,
    # every app-side path 404s while POST <gateway>/auth/v1/signup with the public anon key answers 200 with a
    # session. That session unlocks the authed half of the app — its routes, its per-route chunks, and the
    # service_role key compiled into the dashboard chunk. But it sets the cookie OURSELVES, so no Set-Cookie is
    # ever observed and sec-session-001..004 read N/A: running it FIRST traded a real 20-point cookie finding
    # for the 35-point bundle secret rather than collecting both.
    #
    # `_crawl_auth_headers` passes no browser callback, so discovery still takes the BaaS lane it needs.
    caps = profile.capabilities
    has_auth_surface = _password_form(profile.forms) is not None or bool(
        caps.get("login_trigger") or caps.get("signup_trigger"))
    if browser_register is not None and has_auth_surface:   # the caps gate: never spend a launch on an app
        out = _register_via_browser(base_url, browser_register, LAST_BROWSER_DIAG)   # with no auth surface at all
        if _has_session(out):
            _carry_secure_cookies_over_http(base_url, out.client)
            if acct is not None:
                acct.client.close()
            return out
    baas = _register_via_baas(base_url, suffix, getattr(profile, "landing_path", "") or "")
    if baas is not None:
        if acct is not None:
            acct.client.close()
        return baas
    return acct


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
_JSON_REGISTER_PATHS = ("/api/users", "/api/register", "/api/auth/register", "/api/auth/signup",
                        "/api/signup", "/register", "/api/v1/users", "/api/accounts", "/api/user")


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


# a CREDENTIAL-rejection phrase (for an HTML login answer), deliberately NOT matching a generic server-error
# page like nginx "400 Bad Request" / "403 Forbidden" -- those are the request/server saying no, not the app
# rejecting credentials (geoiq /users/login served a bare nginx 400 and read as a login surface).
_AUTH_REJECT_PHRASE = re.compile(r"invalid|incorrect|unauthor|wrong\s+(?:password|credential|email|user)|"
                                 r"\bcredential|login\s+failed|authentication\s+failed", re.I)


def find_json_login(client: httpx.Client, root: str = ""):
    """Probe common JSON login endpoints with a wrong-creds body; return (path, creds, response) for
    the first that behaves like a REAL login, else (None, None, None). Lets the rate-limit probe reach
    JSON-API apps with no HTML login form — WITHOUT firing on a static SPA, whose catch-all serves the
    index.html shell (200 text/html) for any POST, which would look like an always-succeeding 'login'
    and produce a phantom no-rate-limit finding. So we require an auth-shaped answer to wrong creds:
    an auth-failure status, or a JSON body — never a 2xx HTML shell (the SPA) or 404/405/501.

    `root` is the APP's root path, and it matters because these candidates are GUESSED rather than
    discovered. Resolved against the origin, a sub-path deployment gets its HOST probed instead of itself:
    on GapBench every scenario lives at /site/<id>/, so before this the probe hammered the origin
    gapbench.vibe-eval.com/rest/user/login for every scenario. Anchoring under `root` keeps a sub-path app
    from inheriting a NEIGHBOUR's login — a real correctness fix, covered by the sub-path test. Empty root
    (the whole root-served corpus) is a no-op.

    WHAT THIS DOES NOT DO, corrected after live verification: it does NOT clear the GapBench control false
    positives, and the commit that introduced it (1993fa2) wrongly claimed it would. Re-graded live, the
    control ref0 STILL fires sec-ratelimit-001 — now at /site/ref0/api/login, a REAL endpoint of ref0's own
    app (a nonexistent sibling 404s) that answers wrong creds with {"error":"invalid credentials"} and never
    throttles. The FP was never about targeting the wrong host; it is that our probe treats "10 wrong logins,
    no 429" as a finding and that condition is near-universal — 626/628 corpus apps, and GapBench's own "clean"
    controls, have unthrottled logins. That is a CALIBRATION question (is missing login rate-limiting a
    distinguishing weakness or a near-constant we over-charge?), owned by the score, not something a path
    prefix fixes. The mistake here was verifying the precondition (targeting is anchored — a unit test) and
    asserting the outcome (FP eliminated) without measuring it.

    The returned path is the RESOLVED one, so a caller that keeps hammering it stays on the app."""
    creds = {"email": "hacklet_probe_rl@example.com", "username": "hacklet_probe_rl",
             "password": "hl-wrong-password"}
    root = (root or "").rstrip("/")
    for suffix in _JSON_LOGIN_PATHS:
        path = root + suffix
        try:
            r = client.post(path, json=creds)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        if r.status_code in (404, 405, 501):
            continue
        ct = r.headers.get("content-type", "").lower()
        body = ""
        try:
            body = r.text[:5000]
        except Exception:
            pass
        rejects = bool(_AUTH_REJECT_PHRASE.search(body))
        # A login SURFACE is one that REJECTS wrong creds. Three shapes are NOT that, each a v18 json-login FP:
        #   - a 2xx SUCCESS body (usaii /api/sessions -> 201 {"sessionId":...}): it ACCEPTED the garbage creds,
        #     so it is not a rejection to rate-limit. A 2xx qualifies ONLY if the body itself says it rejected
        #     them (some real logins answer 200 + {"error":"invalid credentials"}).
        #   - a redirect (3xx): a platform auth handoff, not the app rejecting creds.
        #   - a bare server-error page (nginx "400 Bad Request" text/html): the SERVER rejected the request
        #     shape, not the APP rejecting credentials (geoiq /users/login).
        if r.status_code in (400, 401, 403, 422):
            if "json" in ct or rejects:
                return path, creds, r
        elif 200 <= r.status_code < 300 and rejects:
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


# A route the crawl DID observe names the auth namespace even when it names no auth action: OopsSec's surface
# yields GET /api/auth/logout, from which /api/auth/signup follows. Inferring the sibling beats extending the
# hardcoded list forever, because it works for whatever prefix an app chose (/api/v2/auth, /backend/auth).
# Measured: registration on OopsSec failed for exactly one missing string, and every authed family went dark.
_AUTH_LEAF = ("logout", "signout", "sign-out", "session", "me", "whoami", "refresh", "token",
              "login", "signin", "sign-in", "register", "signup", "sign-up", "user")


def _sibling_auth_paths(profile, keywords) -> list[str]:
    """Candidate auth paths inferred from the namespace of an OBSERVED route/endpoint. A path whose parent is
    `auth` (or whose leaf is a known auth action) implies its siblings, so `/api/auth/logout` yields
    `/api/auth/signup` and `/api/auth/register`."""
    parents: list[str] = []
    seen_paths = [e.raw_path for e in getattr(profile, "endpoints", None) or []]
    seen_paths += list(getattr(profile, "routes", None) or [])
    for raw in seen_paths:
        path = (raw or "").split("?")[0].rstrip("/")
        segs = [s for s in path.split("/") if s]
        if len(segs) < 2:
            continue
        parent, leaf = "/" + "/".join(segs[:-1]), segs[-1].lower()
        if (segs[-2].lower() == "auth" or leaf in _AUTH_LEAF) and parent not in parents:
            parents.append(parent)
    return [p + "/" + k for p in parents for k in keywords]


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
    # order: named in a spec -> inferred from an observed auth namespace -> the generic conventions
    register_paths = list(dict.fromkeys(_spec_auth_paths(profile, _REGISTER_KW)
                                        + _sibling_auth_paths(profile, _REGISTER_KW)
                                        + list(_JSON_REGISTER_PATHS)))
    login_paths = list(dict.fromkeys(_spec_auth_paths(profile, _LOGIN_KW)
                                     + _sibling_auth_paths(profile, _LOGIN_KW)
                                     + list(_JSON_LOGIN_PATHS)))
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
    """Each Set-Cookie header -> {name, value, httponly, secure, samesite}. Flags are read from the raw
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
            "value": first.split("=", 1)[1].strip(),   # needed to tell the real session token from a
            #     session-NAMED cookie holding a plaintext identifier (see _token_shaped)
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": attrs.get("samesite") in ("lax", "strict"),
        })
    return out


# Substring hints, matched case-insensitively. `token`/`jwt` are here because the modern JS convention is a
# camelCase name with no separator — authToken, accessToken, idToken, sessionToken — which an exact-name set
# and a `session`-only substring both miss. That miss is expensive: no session detected means the self-as-
# oracle holds no identity, so every authed probe (IDOR x5, session x4, CSRF, upload x2) reads N/A, and the
# session-hygiene probes never judge the real token. Measured on the OopsSec anchor, whose cookie is authToken.
_SESSION_HINTS = ("session", "sessid", "token", "jwt")
# HOSTED AUTH PROVIDERS whose cookie name contains none of the generic hints above. Measured, not guessed: on
# dawg-den.vercel.app the browser lane registered successfully and handed back seven token-shaped cookies —
# `auth0` and `auth0_compat` (the session, 303 bytes each), `did`/`did_compat`, and three `__txn_*` — and
# _is_session_cookie rejected ALL of them, so _register_via_browser threw a real session away and the app
# reported "no recognizable session cookie".
#
# Most hosted providers are already covered incidentally and were checked before adding anything here: Clerk
# (`__session`), Auth0's Next.js SDK (`appSession`), NextAuth/Auth.js (`next-auth.session-token`,
# `authjs.session-token`), Better Auth (`better-auth.session_token`), WorkOS (`wos-session`), Ory
# (`ory_kratos_session`), Keycloak (`AUTH_SESSION_ID`) all contain "session"; Supabase (`sb-<ref>-auth-token`),
# SuperTokens (`sAccessToken`) and Cognito contain "token". Auth0's bare `auth0` cookie is the gap.
#
# Kept to what is VERIFIED against a live app rather than a list of plausible vendors: a speculative fragment
# here is a wrong-cookie verdict, and _NOT_SESSION exclusions still win. Note `__txn_*` correctly stays
# unmatched — those are Auth0's short-lived pre-login transaction cookies, not the session, and judging one
# would report flags for the wrong cookie.
_PROVIDER_SESSION = ("auth0",)
# ... but a token-NAMED cookie is not always the session. A CSRF/anti-forgery token is deliberately
# JS-readable (judging it would report a false hygiene failure), a refresh token is not the access session,
# and an email/verification token is not a login. Exclusions win over hints.
_NOT_SESSION = ("csrf", "xsrf", "antiforgery", "anti-forgery", "authenticity", "verification", "verify",
                "refresh", "code-verifier", "code_verifier", "clerk_db_jwt", "taboola")
# `authenticity` was missing and is a pre-existing FP vector this file's own precision test caught: Rails names
# its CSRF token `authenticity_token`, which contains "token" and so matched as a session. is_csrf_field already
# listed it for FORM fields (_CSRF_FIELD_HINTS) while the COOKIE check did not — the two lists had drifted. A
# CSRF cookie is deliberately JS-readable, so judging one reports a false "missing HttpOnly" on an app doing
# nothing wrong, which is precisely what these exclusions exist to prevent.
#
# The last four were the ENTIRE sec-session-001 fire set on the v18 corpus (23/23 findings, a 100%-FP probe),
# all client-readable-BY-DESIGN vendor cookies namespaced into the auth family but NOT the app's session:
#   `code-verifier`  Supabase/PKCE `sb-<ref>-auth-token-code-verifier` — the pre-login OAuth nonce (9 apps).
#                    The real session is a JWT in localStorage, which sec-session-005 already judges. The SDK
#                    MUST read the verifier from JS to complete the code exchange, so HttpOnly is impossible.
#   `clerk_db_jwt`   Clerk's dev-instance handshake cookie `__clerk_db_jwt[_suffix]` (13 apps). Clerk's real
#                    session is `__session` (HttpOnly, and still judged); the db-jwt is JS-read by the FAPI
#                    client by design. Matched here only via the "jwt" hint.
#   `taboola`        `taboola_session_id`, a third-party ad-network tracker (1 app) — session-NAMED but not an
#                    app login at all. Matched via the "session" hint.
# The verifier/db-jwt were selected because `session_cookie()` prefers a token-shaped value and their opaque
# base64url bodies pass `_token_shaped`, so nothing downstream rescued the pick. Same bar as every other entry
# here: added only after being VERIFIED on live findings, never speculatively.


def _is_session_cookie(name: str) -> bool:
    """Recognize framework-namespaced session cookies (myapp_session, laravel_session, __Host-session,
    next-auth.session-token, ...), not just the exact known names. CSRF tokens are intentionally
    JS-readable, so they are never treated as the session cookie."""
    low = name.lower()
    if any(h in low for h in _NOT_SESSION):
        return False
    return (low in SESSION_COOKIE_NAMES or any(h in low for h in _SESSION_HINTS)
            or any(h in low for h in _PROVIDER_SESSION))


def _all_set_cookies(resp: httpx.Response) -> list[dict]:
    """Set-Cookie across the whole redirect chain. register_account follows redirects, and the very
    common POST /register -> 302 -> dashboard sets the session cookie on the 302 (resp.history), not
    on the final 200 response — reading only the final response would miss it entirely."""
    out: list[dict] = []
    for r in (*resp.history, resp):
        out.extend(parse_set_cookies(r))
    return out


def _token_shaped(value: str) -> bool:
    """The cookie VALUE looks like a session token — a JWT, or a long opaque id — rather than a plaintext
    identifier. Apps commonly set several session-NAMED cookies (`app_session=user@example.com` for the UI
    alongside the real `session=eyJhbGci…`); judging the wrong one reports that cookie's flags as if they
    were the session's, so a correctly-hardened token reads as unprotected (and vice versa)."""
    v = urllib.parse.unquote(value or "").strip()
    if v.startswith("eyJ") and v.count(".") >= 2:
        return True                       # JWT
    if not v or "@" in v or " " in v:
        return False                      # an email / human-readable value is not the session token
    return len(v) >= 16                   # long opaque id


def session_cookie(resp: httpx.Response) -> dict | None:
    """THE session cookie: prefer a token-shaped value (the real session), else fall back to the name
    heuristic alone. Last match wins within each group — a later Set-Cookie overrides an earlier one."""
    matches = [c for c in _all_set_cookies(resp) if _is_session_cookie(c["name"])]
    if not matches:
        return None
    tokens = [c for c in matches if _token_shaped(c.get("value", ""))]
    return (tokens or matches)[-1]


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


# Cookies that are never an app session: platform/CDN infrastructure, and auth-FLOW state that exists before a
# login completes. Measured across the 9 apps whose reason read "cookies set but none is a recognised session
# name" — NOT ONE was a missing vendor name, which is what that wording implied and what I nearly acted on:
#   __Host-GAPS, GAESA          Google's own cookies -> the app uses Google SSO, we cannot self-register
#   __client, __client_uat*     Clerk client state WITHOUT __session -> no session was established
#   __Host-next-auth.csrf-token,
#   __Secure-next-auth.callback-url,
#   __Host-oauth_csrf           an auth flow that STARTED and never completed
#   __cf_bm, __dpl              Cloudflare bot-management and Vercel deploy id — the app set none of its own
# So the honest verdict there is "no app session exists", usually SSO-only or an abandoned flow, which is a
# CORRECT N/A. Reporting it as an unrecognised name sends the reader hunting for vendors to add.
_NEVER_SESSION = ("__cf_bm", "__dpl", "gaps", "gaesa", "_ga", "__stripe", "callback-url", "_uat",
                  "oauth_state", "__client", "amplitude", "_hj", "intercom")


def _no_app_session_cookies(names: list[str]) -> bool:
    """True when EVERY cookie is infrastructure, third-party or pre-login flow state — so the app itself never
    set a session and there is no vendor name we are failing to recognise."""
    return bool(names) and all(
        any(h in n.lower() for h in _NEVER_SESSION) or any(h in n.lower() for h in _NOT_SESSION)
        for n in names)


def _register_via_browser(base_url: str, browser_register, diag: dict | None = None) -> Account | None:
    """SPA registration through the browser: the injected browser_register(base_url) drives Playwright to fill +
    submit the signup so the app's OWN JS makes the real request, returning the session it establishes — a cookie
    AND/OR a Bearer token (the bolt/Supabase/Firebase cohort authenticates by JWT, not cookie). Build an Account
    whose httpx client carries both (cookie jar + Authorization header) for the authed IDOR / etc. probes, plus a
    synthetic register_response for the cookie-flag probes. None when the browser established NEITHER."""
    # `diag` is an out-param the caller may pass to learn WHICH stage failed. Five distinct outcomes used to
    # collapse into one bare None, and diagnosing them by inspection cost three wrong guesses in a row: a
    # concurrency theory, a hydration-race theory and a homepage-login-hijack theory, all refuted against live
    # apps. Naming the stage is what turns "187 apps, cause unknown" into a distribution we can fix in frequency
    # order. Measured causes so far, one live app each: an unrecognised provider cookie (dawg-den, Auth0), a real
    # signup that established no session (timbermarket, running-bh — most likely e-mail confirmation, which is a
    # CORRECT N/A), and no fillable password field anywhere (flashcard-royale).
    def _fail(stage: str):
        if diag is not None:
            diag["stage"] = stage
        return None

    try:
        result = browser_register(base_url)
    except Exception as exc:
        return _fail("browser register raised %s" % type(exc).__name__)
    if not result:
        # Prefer the stage register_in_browser recorded for ITSELF. From here the two causes are
        # indistinguishable — the callable just returned falsy — and merging them is what made the first
        # session-gap run put 87% of apps into one useless bucket. Fall back only if the browser module is
        # absent or older than this instrumentation.
        with contextlib.suppress(Exception):
            from . import browser as _browser
            if (_browser.LAST_STAGE or {}).get("stage"):
                return _fail(_browser.LAST_STAGE["stage"])
        return _fail("browser found no fillable signup, or the signup left neither a cookie nor a token")
    cookies = result.get("cookies") or []
    bearer = result.get("bearer")
    if not any(_is_session_cookie(c["name"]) for c in cookies) and not bearer:
        # NOT "registration failed" — the browser drove a real signup and the app set cookies; we simply do not
        # recognise any of their NAMES as a session. Distinguishing this from the no-signup case above is the
        # whole point of the split, because this one is OUR bug and that one may not be.
        names = [c["name"] for c in cookies]
        shown = ", ".join(names[:4]) or "none"
        if _no_app_session_cookies(names):
            # NOT a gap in our vendor list. Every cookie is infrastructure, third-party or an unfinished auth
            # flow, so the app set no session of its own — SSO-only or an abandoned login. A CORRECT N/A.
            return _fail("no app session exists: the %d cookie(s) present are all infrastructure, third-party "
                         "or pre-login flow state (%s), so registration never completed — SSO-only or an "
                         "abandoned auth flow" % (len(cookies), shown))
        return _fail("browser registered and set %d cookie(s) but none is a recognised session name (%s) and no "
                     "bearer was seen — candidate vendor cookie to add" % (len(cookies), shown))
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
