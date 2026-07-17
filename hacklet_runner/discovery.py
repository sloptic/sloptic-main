"""Phase 1: discovery. Build a stack-agnostic surface map by crawling the live app over HTTP.

A bounded, same-origin breadth-first crawl from the homepage: it records every reachable route and
every HTML form (action, method, field names). Stays polite and bounded — page and depth caps, same
origin only. Production adds browser-driven discovery (Playwright) for SPA routes this static crawl
can't see (client-rendered forms), plus per-endpoint baselines for oracle differentials.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from . import jsmine, openapi
from .auth import is_password_change_form, login_form
from .net import make_client
from .schema import Endpoint, Form, Profile

_LINK = re.compile(r'(?<![-\w])href=["\']([^"\']+)["\']', re.I)
_SRC = re.compile(r'(?<![-\w])src=["\']([^"\']+)["\']', re.I)  # any tag: img / iframe / script / source / ...
_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ACTION = re.compile(r'(?<![-\w])action=["\']([^"\']*)["\']', re.I)
_METHOD = re.compile(r'(?<![-\w])method=["\']([^"\']*)["\']', re.I)
_ENCTYPE = re.compile(r'(?<![-\w])enctype=["\']([^"\']*)["\']', re.I)
_FIELD = re.compile(r'<(?:input|textarea|select)\b[^>]*(?<![-\w])name=["\']([^"\']+)["\']', re.I)

# Input parsing. We walk <label> and <input>/<textarea>/<select> in document order so each control can be
# tied to its nearest preceding <label> — a name-less SPA input is often addressable only by its label.
_LABEL_OR_INPUT = re.compile(r"<label\b[^>]*>(.*?)</label>|<(input|textarea|select)\b([^>]*?)>", re.I | re.S)
_ATTR_NAME = re.compile(r'(?<![-\w])name=["\']([^"\']+)["\']', re.I)
_ATTR_ID = re.compile(r'(?<![-\w])id=["\']([^"\']+)["\']', re.I)
_ATTR_TYPE = re.compile(r'(?<![-\w])type=["\']?([a-zA-Z]+)', re.I)
_ATTR_PLACEHOLDER = re.compile(r'(?<![-\w])placeholder=["\']([^"\']+)["\']', re.I)
_ATTR_AUTOCOMPLETE = re.compile(r'(?<![-\w])autocomplete=["\']([^"\']+)["\']', re.I)
_TAG = re.compile(r"<[^>]+>")            # strip any nested tags out of a <label>'s text before slugging
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]*")
# <input type=...> values that already name the field's purpose, so a name-less one is still addressable
_SEMANTIC_TYPES = frozenset({"email", "password", "tel", "url", "search", "number"})
# input types that carry no injectable free text (a submit button, a toggle, a color swatch, ...)
_NONINJECTABLE_INPUT = frozenset({"submit", "button", "reset", "image", "hidden",
                                  "checkbox", "radio", "range", "color"})
# routes NOT worth browser-rendering for forms — static assets / JSON blobs, never an HTML page with a form
_NON_HTML_EXT = re.compile(
    r"\.(?:js|mjs|cjs|css|map|json|xml|svg|png|jpe?g|gif|webp|ico|bmp|woff2?|ttf|otf|eot|pdf|"
    r"zip|gz|mp4|webm|mp3|wav|wasm|txt|csv)$", re.I)

# Bundled third-party library paths — served BY the app but not its own surface. A 3D/mapping app
# (Potree, three.js, Cesium) serves 60+ such files, padding the surface count without being real attack
# surface, so they're excluded from surface_metrics' denominator (not from probing).
_VENDOR_PATH = re.compile(
    r"/(?:potree|node_modules|bower_components|vendor|libs?|three|cesium|draco|ammo|jquery|bootstrap|"
    r"leaflet|mapbox|openlayers|d3|chartjs|plotly|ace|monaco|pdfjs|tesseract|opencv|wasm)(?:[/.\-]|$)",
    re.I)

MAX_PAGES = 25
MAX_DEPTH = 2
_BASELINE_CAP = 60   # cap the per-endpoint health baseline requests (a huge mined API shouldn't 10x the grade)
# login / upload surfaces on a JSON API are ENDPOINTS, not <form>s — so has_login/has_upload (form-based)
# would falsely read blind on an api-only app whose login/upload endpoint we DID discover. Recognize them.
_LOGIN_EP = re.compile(r"/(?:login|log-?in|signin|sign-?in|auth|authenticate|session|token|oauth)(?:[/.\-]|$)", re.I)
_UPLOAD_EP = re.compile(r"/(?:upload|files?|media|attachments?|import|ingest|documents?)(?:[/.\-]|$)", re.I)
# Login/signup presented as a BUTTON or LINK (not an inline password form): 'Sign in', 'Continue with
# Google', 'Sign up', 'Start Free Trial'. The audit's #1 complaint was has_login=false on apps whose login
# is a CTA button, not a <form> — so has_login must also credit these triggers, not just password forms.
_LOGIN_TRIGGER = re.compile(r"\b(?:log ?in|sign ?in|log-in|sign-in)\b|continue with (?:google|github|apple|email)|\bsso\b", re.I)
_SIGNUP_TRIGGER = re.compile(r"\bsign ?up\b|\bregister\b|create (?:an |my )?(?:account|profile)|"
                             r"get started|start (?:your )?free|join (?:the )?(?:free|beta|waitlist)", re.I)
_BROWSER_ROUTE_CAP = 12  # max routes to browser-render for forms (one launch, but each goto has a cost)
# conventional auth routes a CTA login/signup navigates to via the JS router (no crawlable href) — rendered
# explicitly ONLY when a login/signup trigger was seen but no password form captured, so the auth self-oracle
# probes get a registerable form (Part 2). Skips OAuth (can't appear in self-contained apps).
_AUTH_ROUTES = ["/login", "/signin", "/sign-in", "/signup", "/sign-up", "/register", "/auth"]
# anti-bot widget tokens (Cloudflare Turnstile / reCAPTCHA / hCaptcha / ASP.NET AV) — NOT app-controlled
# fields; injecting into them produced XSS false positives (the reflection is the vendor's, not the app's).
_VENDOR_FIELD = re.compile(r"turnstile|recaptcha|h-?captcha|__requestverification|g-recaptcha", re.I)


def _auth_triggers(markup: str) -> tuple[bool, bool]:
    """Scan a page's BUTTON/LINK labels (not arbitrary text -> low FP) for a login/signup trigger. Returns
    (has_login_trigger, has_signup_trigger). Catches the button/link/CTA logins a password-form check misses."""
    text = " ".join(re.sub(r"<[^>]+>", " ", m)
                    for m in re.findall(r"<(?:button|a)\b[^>]*>(.*?)</(?:button|a)>", markup, re.S | re.I))
    return bool(_LOGIN_TRIGGER.search(text)), bool(_SIGNUP_TRIGGER.search(text))


# A logout/sign-out link must never be crawled or probed: following it destroys the runner's own
# authenticated session, silently de-authing the rest of an --header'd crawl (the classic auth-crawl
# footgun — it's why an authed DVWA crawl kept dropping to the login page mid-run).
_LOGOUT = re.compile(r"(?:^|[/_-])(?:logout|log-?out|log_?out|signout|sign-?out|sign_?out|logoff)\b", re.I)

# Un-rendered client-side template syntax leaking into markup: `${x}` (JS template literal), `{{x}}`
# (Angular/Vue/Handlebars/Jinja), or a stray backtick. A target that ships these in an href/name has a
# rendering bug — they are never real server routes or params, so probing them chases ghost endpoints.
# (`#{x}` Pug/Ruby needs no handling here: `#` is the URL-fragment delimiter, stripped before this check.)
_TEMPLATE_ARTIFACT = re.compile(r"\$\{|\{\{|\}\}|`")


def _same_origin_path(href: str, base_url: str, page_path: str) -> str | None:
    """Resolve href against the current page; return its path if same-origin (and not a logout link),
    else None."""
    href = href.split("#")[0].strip()
    if not href or href.startswith(("mailto:", "javascript:", "tel:", "data:")):
        return None
    base = urlparse(base_url)
    page_abs = urljoin(f"{base.scheme}://{base.netloc}", page_path)
    target = urlparse(urljoin(page_abs, href))
    if target.netloc != base.netloc:
        return None
    path = target.path or "/"
    if _LOGOUT.search(path):
        return None  # crawling logout would destroy the authenticated session
    if _TEMPLATE_ARTIFACT.search(path):
        return None  # an un-rendered template literal in the href -> a ghost route, not a real endpoint
    return path


def _slug(text: str | None) -> str | None:
    """First word of human text (a <label>/placeholder) as a lowercase id: 'Email address' -> 'email'."""
    if not text:
        return None
    m = _WORD.search(_TAG.sub(" ", text))
    return m.group(0).lower() if m else None


def _infer_name(attrs: str, label: str | None) -> str | None:
    """Best-effort field name for a NAME-less input from its semantic signals — a React-controlled input
    frequently ships no name and no id, only a type / autocomplete / <label> / placeholder. Ordered by
    reliability: standardized autocomplete token, then a self-naming input type (email/password/...), then
    the label, then the placeholder, and a structural id only as a last resort. None when nothing is
    addressable (a bare `type=text` with no other hint — we can't guess a server field name for it)."""
    ac = _ATTR_AUTOCOMPLETE.search(attrs)
    if ac:
        tok = ac.group(1).strip().lower()
        if tok and tok not in ("on", "off"):
            return "password" if "password" in tok else tok   # current-password / new-password -> password
    tm = _ATTR_TYPE.search(attrs)
    if tm and tm.group(1).lower() in _SEMANTIC_TYPES:
        return tm.group(1).lower()                             # type=email/password/tel/... names itself
    if _slug(label):
        return _slug(label)
    ph = _ATTR_PLACEHOLDER.search(attrs)
    if ph and _slug(ph.group(1)):
        return _slug(ph.group(1))
    idm = _ATTR_ID.search(attrs)
    return idm.group(1) if idm else None                      # a structural id (kept verbatim, not slugged)


_ATTR_REQUIRED = re.compile(r'(?<![-\w])required(?![-\w])', re.I)                 # boolean attr
_ATTR_MIN = re.compile(r'(?<![-\w])min=["\']?([^"\'\s>]+)', re.I)
_ATTR_MAX = re.compile(r'(?<![-\w])max=["\']?([^"\'\s>]+)', re.I)
# HTML5 input types the BROWSER validates -> the app's DECLARED contract. A server that accepts a value
# violating one is doing client-only validation (tested by qa-input-001 / declared_constraint_unenforced).
_CONSTRAINT_TYPES = {"email", "url", "number", "range", "date", "datetime-local", "time", "month", "week"}


def _scan_form_inputs(html: str, drop_named_noninjectable: bool = False):
    """(fields, file_fields, has_password, constraints) for the interactive controls in an HTML fragment, in
    document
    order. A NAMED control keeps its name for any type (a real <form> needs its hidden/CSRF fields to
    submit faithfully); a NAME-less control gets an inferred name (_infer_name) so React inputs with no
    name/id are still addressable. File inputs also appear in `fields` (a superset — lets the text-input
    capability see a pure-upload surface). drop_named_noninjectable drops loose submit/hidden/checkbox
    noise for formless synthesis, where a lone non-text control isn't a real input surface."""
    fields: list[str] = []
    file_fields: list[str] = []
    has_password = False
    constraints: dict = {}
    label: str | None = None
    for label_text, tag, attrs in _LABEL_OR_INPUT.findall(html):
        if not tag:                                   # a <label> — remember it for the NEXT input
            label = label_text
            continue
        this_label, label = label, None               # each label pairs with the one following input
        tm = _ATTR_TYPE.search(attrs)
        itype = tm.group(1).lower() if tm else "text"
        is_input = tag.lower() == "input"
        is_file = is_input and itype == "file"
        noninjectable = is_input and itype in _NONINJECTABLE_INPUT
        nm = _ATTR_NAME.search(attrs)
        if is_file:
            idm = _ATTR_ID.search(attrs)
            name = nm.group(1) if nm else (idm.group(1) if idm else "file")
        elif nm:
            if noninjectable and drop_named_noninjectable:
                continue
            name = nm.group(1)
        elif noninjectable:
            continue                                  # a name-less button/checkbox/hidden — nothing to inject
        else:
            name = _infer_name(attrs, this_label)
            if name is None:
                continue
        if _TEMPLATE_ARTIFACT.search(name):
            continue                                  # a `${x}`/`{{x}}` artifact leaked into the identifier
        if _VENDOR_FIELD.search(name):
            continue                                  # a captcha/anti-bot widget token — not app-controlled;
            #     injecting into it produced XSS false positives (its reflection is the vendor's, not the app's)
        if is_file and name not in file_fields:
            file_fields.append(name)
        if name not in fields:
            fields.append(name)
            has_password = has_password or itype == "password"
        cons = {}                                     # the field's DECLARED constraint (its own HTML5 contract)
        if itype in _CONSTRAINT_TYPES:
            cons["type"] = itype
        if _ATTR_REQUIRED.search(attrs):
            cons["required"] = True
        mnm, mxm = _ATTR_MIN.search(attrs), _ATTR_MAX.search(attrs)
        if mnm:
            cons["min"] = mnm.group(1)
        if mxm:
            cons["max"] = mxm.group(1)
        if cons:
            constraints.setdefault(name, cons)
    return fields, file_fields, has_password, constraints


def _parse_forms(matches, base_url: str, page_path: str) -> list[Form]:
    forms = []
    for attrs, body in matches:
        am, mm = _ACTION.search(attrs), _METHOD.search(attrs)
        # a "#..."/empty action submits back to the CURRENT page (very common: DVWA, many CMS forms) —
        # strip the fragment so it resolves to page_path instead of being dropped as un-resolvable.
        raw_action = (am.group(1).strip() if am else "").split("#")[0]
        action = _same_origin_path(raw_action, base_url, page_path) if raw_action else page_path
        if action is None:  # cross-origin action — not our target
            continue
        method = mm.group(1).lower() if mm else "get"
        em = _ENCTYPE.search(attrs)
        fields, file_fields, _, constraints = _scan_form_inputs(body)  # keeps hidden/CSRF fields for faithful submit
        forms.append(Form(
            action=action,
            method=method if method in ("get", "post") else "get",
            fields=fields,
            enctype=em.group(1).lower() if em else "",
            file_fields=file_fields,
            constraints=constraints,
        ))
    return forms


def _renderable_route(path: str) -> bool:
    """A route worth browser-rendering for forms: an HTML page, not a static asset or JSON/API blob."""
    return not _NON_HTML_EXT.search(path.split("?")[0])


def _form_key(form: Form) -> tuple:
    """Dedup identity for a discovered form (across the static crawl and every rendered route)."""
    return (form.action, form.method, tuple(form.fields))


def _formless_form(html: str, page_path: str) -> Form | None:
    """Synthesize a Form from interactive inputs NOT wrapped in a <form> — the modern-SPA pattern
    (React/Vue controlled inputs submitted via fetch(), e.g. phish-school's bare <input type=file> +
    <button> with no <form>). The <form>-anchored parser structurally cannot see these, so on such apps
    the entire login/upload/search surface is invisible and every injection/upload/auth probe reads N/A.

    Best-effort by nature: the real submit endpoint lives in JS, so the action is the page itself —
    correct for same-path server actions / Next.js API routes / PHP self-post, and a harmless no-op
    elsewhere (a wrong target just returns the SPA shell, which yields no oracle differential, so this
    can't manufacture a false positive). Field names come from _scan_form_inputs/_infer_name, which
    handle the name-less React inputs these apps use. Returns None when the page has no such inputs."""
    body = _FORM.sub(" ", html)   # drop real <form>s (handled by _parse_forms) -> only UNwrapped inputs
    fields, file_fields, has_password, _ = _scan_form_inputs(body, drop_named_noninjectable=True)
    if not fields:
        return None
    return Form(
        action=page_path,                                        # best-effort: the page's own path
        method="post" if (file_fields or has_password) else "get",  # login/upload POST; search-ish GET
        fields=fields,
        enctype="multipart/form-data" if file_fields else "",
        file_fields=file_fields,
    )


def _clean_names(v) -> list:
    """Sanitize an LLM-provided list of param / body-field names: strings only, stripped, deduped, bounded
    — the plan is untrusted input (it can carry non-strings, dupes, or a runaway list)."""
    out: list[str] = []
    for x in v if isinstance(v, list) else []:
        if isinstance(x, str) and x.strip() and x.strip() not in out:
            out.append(x.strip())
    return out[:12]


_OBS_ENDPOINT_CAP = 40
# Known THIRD-PARTY hosts an app's client talks to that are NEVER the app's own backend -> never probed.
_VENDOR_HOSTS = re.compile(
    r"google-analytics|googletagmanager|doubleclick|gstatic|fonts\.google|jsdelivr|unpkg|cdnjs|cloudflareinsights|"
    r"sentry|datadog|hotjar|clarity\.ms|mixpanel|amplitude|posthog|segment|"
    r"clerk\.|auth0|accounts\.google|identitytoolkit|oauth|"
    r"openai|anthropic|generativelanguage|api\.stripe|paypal|"
    r"mapbox|maps\.googleapis|cloudinary|algolia|imgix|res\.cloudinary|tile\.|basemaps|"   # maps/media/search vendors
    r"facebook|twitter|\bx\.com|vercel-insights|vitals\.vercel|va\.vercel|analytics", re.I)
# Managed BaaS: the app's OWN data plane, config-testable (the idor-004 / backend-exposure "test the config" lane).
_BAAS_HOSTS = re.compile(r"supabase\.co|firebaseio|firebasedatabase|firestore\.googleapis|\.appwrite|"
                         r"convex\.cloud|pocketbase|planetscale|neon\.tech|upstash|xata\.io|nhost", re.I)


def _classify_hosts(observed, base_url) -> dict:
    """Where does the app's runtime traffic actually GO? Classify each observed xhr/fetch host to see the real
    backend location (OFF-SCORE diagnostic): same-origin (probe-able now), managed BaaS (Supabase/Firebase —
    the config-testable data plane), a known third-party VENDOR (never the app's -> never probed), or OTHER
    off-origin (an unknown host = likely the app's OWN custom backend = the recall frontier). The SPA corpus
    keeps its server-side surface off-origin, so this tells us WHICH lever (better driving vs off-origin
    targeting) unlocks it."""
    app_host = urlparse(base_url).netloc
    counts = {"same_origin": 0, "managed_baas": 0, "vendor": 0, "other_off_origin": 0}
    baas, other = set(), set()
    for _method, url, _pd in observed:
        h = urlparse(url).netloc
        if not h or h == app_host:
            counts["same_origin"] += 1
        elif _BAAS_HOSTS.search(h):
            counts["managed_baas"] += 1
            baas.add(h)
        elif _VENDOR_HOSTS.search(h):
            counts["vendor"] += 1
        else:
            counts["other_off_origin"] += 1
            other.add(h)
    return {"counts": counts, "baas_hosts": sorted(baas), "other_hosts": sorted(other)[:10]}


def _endpoints_from_observed(observed, base_url) -> list:
    """Endpoints OBSERVED in the app's own same-origin xhr/fetch traffic during render+interaction — the
    ACCURATE endpoint surface (the app actually called these), which the deterministic crawl and the static
    JS mine (jsmine) both miss when the path is built dynamically. Ground truth: real method, real path, and a
    JSON POST body's keys as body_fields for the injection/crash probes to reach. No 404-verification needed
    (it was observed). origin='observed' for the off-score pointer telemetry."""
    out, seen = [], set()
    app_host = urlparse(base_url).netloc
    for method, url, post_data in observed:
        try:
            u = urlparse(url)
        except Exception:
            continue
        if u.netloc and u.netloc != app_host:
            continue                        # off-origin (BaaS/vendor/app-backend) -> not a same-origin probe target
        path, m = u.path or "/", (method or "get").lower()
        if path.startswith("/_next/") or path.startswith("/__") or "_rsc" in (u.query or ""):
            continue                        # Next.js RSC / route-prefetch / framework noise, not the app's API
        if (m, path) in seen or _same_origin_path(path, base_url, "/") is None:
            continue                        # deduped; _same_origin_path drops logout / template-artifact paths
        seen.add((m, path))
        bf = []
        if post_data:
            try:
                body = json.loads(post_data)
                if isinstance(body, dict):
                    bf = list(body.keys())[:12]
            except (ValueError, TypeError):
                pass
        out.append(Endpoint(path=path, method=m, query_params=sorted(parse_qs(u.query)),
                            body_fields=bf, raw_path=path, origin="observed"))
        if len(out) >= _OBS_ENDPOINT_CAP:
            break
    return out


def _endpoints_from_features(features) -> list:
    """Turn the deploy LLM's source-read feature inventory into Endpoints so the catalog can fire on an
    api-only app whose JSON API has NO crawlable HTML — the #1 discovery blind spot (Foodgrid: 7 endpoints
    in source, 0 found by crawling '/'). Best-effort: a hallucinated path just 404s harmlessly. The LLM
    also names each endpoint's ACTUAL query params + body fields (build #2), so injection points at the
    real source-declared input surface a crawler can't see; a search endpoint the LLM left unparametrized
    falls back to common query names, and a templated /x/{id}/ yields path_params for BOLA/traversal.
    The LLM only WIDENS which targets get probed — the deterministic probe still decides fire vs clean, so
    a hallucinated name simply no-ops (never a false finding)."""
    out = []
    for f in features or []:
        raw = (f.get("path") or "").strip()
        if not raw.startswith("/") or _TEMPLATE_ARTIFACT.search(raw):
            continue
        method = (f.get("method") or "get").lower()
        if method not in ("get", "post", "put", "patch", "delete"):
            method = "get"
        path_params = re.findall(r"\{([^}]+)\}", raw)
        concrete = re.sub(r"\{[^}]+\}", "1", raw)          # {id} -> 1 for fan-out fetches; injection uses raw
        qp = _clean_names(f.get("params"))                  # source-declared query inputs (the build #2 win)
        bf = _clean_names(f.get("body_fields"))             # source-declared request-body inputs
        if not qp and not bf and f.get("kind") == "search":
            qp = ["q", "search", "query"]                   # fallback only when the LLM named nothing
        out.append(Endpoint(path=concrete, method=method, query_params=qp, body_fields=bf,
                            path_params=path_params, raw_path=raw, kind=f.get("kind") or "", origin="llm"))
    return out


def _union(a: list, b: list) -> list:
    """Order-preserving union of two name lists (deduped)."""
    out = list(a)
    for x in b:
        if x not in out:
            out.append(x)
    return out


def _merge_inputs(into: Endpoint, extra: Endpoint) -> None:
    """Fold `extra`'s injectable input surface into `into` (the kept endpoint). Dedup keeps the first
    occurrence's origin/baseline/path, but must not DROP a later source's params — e.g. the LLM's
    source-named body fields on an endpoint the crawler independently found (the crawler found the PATH,
    the LLM the request SHAPE). origin downgrades to "crawl" if EITHER contributor was crawled, so the
    pointer telemetry only credits the LLM with endpoints it UNIQUELY found."""
    into.query_params = _union(into.query_params, extra.query_params)
    into.body_fields = _union(into.body_fields, extra.body_fields)
    into.path_params = _union(into.path_params, extra.path_params)
    if not into.kind and extra.kind:
        into.kind = extra.kind
    if extra.origin == "crawl":
        into.origin = "crawl"


def _dedup_merge_endpoints(endpoints: list) -> list:
    """Dedup by (method, raw_path), MERGING each duplicate's injectable inputs into the first occurrence
    rather than dropping it (keep-first would lose an LLM feature's source-named params on an endpoint the
    crawler ALSO found). Insertion order preserved."""
    merged: dict = {}
    for e in endpoints:
        key = (e.method, e.raw_path)
        if key in merged:
            _merge_inputs(merged[key], e)
        else:
            merged[key] = e
    return list(merged.values())


def _forms_from_perceived(perceived_forms) -> list:
    """Perceived forms (the LLM's read of the RENDERED page) -> Form objects for the login/signup/upload/
    CSRF/injection probes. Sanitized like the endpoint seed; RELATIVE same-origin actions only (never post to
    a third party). A hallucinated action just returns the app shell -> no oracle differential -> no false
    finding, same invariant as _endpoints_from_features. origin='llm' for the (off-score) pointer telemetry."""
    out = []
    for pf in perceived_forms or []:
        action = (pf.get("action") or "").strip()
        if not action.startswith("/"):                     # relative same-origin only (off_target posts never)
            continue
        fields = _clean_names(pf.get("fields"))
        file_fields = _clean_names(pf.get("file_fields"))
        if not fields and not file_fields:                 # nothing submittable/injectable -> not a probe target
            continue
        method = (pf.get("method") or ("post" if file_fields else "get")).lower()
        if method not in ("get", "post", "put", "patch", "delete"):
            method = "get"
        out.append(Form(action=action, method=method, fields=fields, file_fields=file_fields,
                        enctype="multipart/form-data" if file_fields else "", origin="perceived"))
    return out


def merge_perceived(profile: Profile, perceived: dict) -> Profile:
    """Fold an LLM perception of the RENDERED surface (perceive_surface output) into a discovered Profile —
    the forms + endpoints the crawl MISSED (client-side logins / uploads / action buttons a static crawl can't
    see). Endpoints reuse the exact source-seed rails (_endpoints_from_features -> _dedup_merge_endpoints, so a
    perceived endpoint the crawler ALSO found merges its inputs rather than duplicating); forms dedup by
    _form_key. Mutates + returns `profile`. The deterministic surface is NEVER removed — perception only
    WIDENS it, and a hallucinated target self-gates to N/A at probe time. None/empty perception is a no-op, so
    the crawl stays the FLOOR. Callers run this BEFORE _drop_phantom_surface so perceived phantoms on a
    catch-all host get suppressed too."""
    if not perceived:
        return profile
    perceived_eps = _endpoints_from_features(perceived.get("endpoints"))
    for e in perceived_eps:
        e.origin = "perceived"          # distinguish rendered-PERCEPTION from source-read #2 ("llm") for telemetry
    profile.endpoints = _dedup_merge_endpoints(profile.endpoints + perceived_eps)
    seen = {_form_key(f) for f in profile.forms}
    for f in _forms_from_perceived(perceived.get("forms")):
        if _form_key(f) not in seen:
            seen.add(_form_key(f))
            profile.forms.append(f)
    return profile


_CATCHALL_PROBE = "/__hacklet_nonexistent_probe_9z8x7q__"


def _body_sig(text: str) -> str:
    """Whitespace-normalized, bounded body — for comparing whether two responses are the same shell."""
    return re.sub(r"\s+", " ", text)[:4096]


def _drop_phantom_surface(base_url, headers, endpoints, forms):
    """Catch-all / phantom-surface suppression. A static-SPA or soft-404 host serves the SAME 200 shell for
    EVERY path, so a discovered endpoint/form whose GET echoes that shell is NOT real server-side surface —
    the injection / CSRF / rate-limit probes would fire on the shell (a submission once scored SQLi-40 on a
    literal 404 page). Detect the shell (a deterministic nonexistent path's 200 body) and drop the targets
    that echo it. PER-TARGET, not host-level: a mixed host — or the soft-404-having vulnerable reference —
    keeps every REAL endpoint (only targets that literally return the shell are dropped; routes stay, so
    headers/a11y/perf on the served shell remain real). Returns (catch_all, endpoints, forms)."""
    try:
        with make_client(base_url, headers, timeout=5.0, follow_redirects=True) as c:
            probe = c.get(_CATCHALL_PROBE)
            if probe.status_code != 200 or "html" not in probe.headers.get("content-type", "").lower():
                return False, endpoints, forms          # a real 404 for a nonexistent path -> not a catch-all
            shell = _body_sig(probe.text)

            def echoes(path):
                try:
                    r = c.get(path)
                    return r.status_code == 200 and _body_sig(r.text) == shell
                except (httpx.HTTPError, httpx.InvalidURL):
                    return False
            return (True,
                    [e for e in endpoints if not echoes(e.path)],
                    [f for f in forms if not echoes(f.action)])
    except (httpx.HTTPError, httpx.InvalidURL):
        return False, endpoints, forms


def discover(base_url: str, render=None, max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH,
             headers=None, seed_features=None, perceive=None) -> Profile:
    """`perceive(rendered_doms, observed)` (optional) — PROACTIVE discovery: an injected LLM reads the rendered
    pages and returns the probeable surface the crawl missed (perceive_surface output), merged in below via
    merge_perceived. LLM-agnostic here: the callback owns the model call; a None/failing one degrades to the
    pure deterministic crawl (the FLOOR)."""
    routes: dict[str, None] = {}      # insertion-ordered set
    forms: list[Form] = []
    seen_forms: set[tuple] = set()
    visited: set[str] = set()
    # Split a path-bearing --target into ORIGIN + entry path. The client and probes bind to the origin
    # (a path-bearing base_url breaks httpx's relative-redirect resolution -> loops, and breaks the
    # `base_url + "/probe/path"` construction probes rely on), while the crawl SEEDS at the entry path so
    # a --target pointing at a specific page (e.g. bWAPP's /sqli_1.php, whose "/" only redirects to a
    # login/portal the crawler can't navigate) gets THAT page discovered. A bare origin still starts at "/".
    _parsed = urlparse(base_url)
    start_path = _parsed.path or "/"
    base_url = f"{_parsed.scheme}://{_parsed.netloc}" if _parsed.netloc else base_url
    queue: list[tuple[str, int]] = [(start_path, 0)]
    any_response = False
    endpoints: list = []
    js_urls: list[str] = []           # same-origin .js assets to mine for an SPA's API paths
    link_params: dict[str, set] = {}  # path -> query-param NAMES seen in links (?page=, ?id=, ...)
    auth = [False, False]             # [login_trigger, signup_trigger] seen as a button/link across the surface

    with make_client(base_url, headers, timeout=5.0, follow_redirects=True) as c:
        while queue and len(visited) < max_pages:
            path, depth = queue.pop(0)
            if path in visited:
                continue
            visited.add(path)
            try:
                resp = c.get(path)
            except (httpx.HTTPError, httpx.InvalidURL):
                continue  # InvalidURL isn't an HTTPError: a hostile target served a control-char path
            any_response = True
            routes[path] = None
            if "html" not in resp.headers.get("content-type", "").lower():
                continue
            html = resp.text
            _l, _s = _auth_triggers(html)   # login/signup as a button/link (a CTA a password-form check misses)
            auth[0] |= _l
            auth[1] |= _s
            for form in _parse_forms(_FORM.findall(html), base_url, path):
                key = _form_key(form)
                if key not in seen_forms:
                    seen_forms.add(key)
                    forms.append(form)
                    routes.setdefault(form.action, None)
            for src in _SRC.findall(html):  # tag srcs (img/iframe/script/...) are scan targets, not crawled
                p = _same_origin_path(src, base_url, path)
                if p:
                    routes.setdefault(p, None)
                    if p.split("?")[0].endswith(".js"):
                        js_urls.append(p)
            if depth < max_depth:
                for href in _LINK.findall(html):
                    p = _same_origin_path(href, base_url, path)
                    if p:
                        routes.setdefault(p, None)
                        # capture query-param NAMES from the link (?page=, ?id=, ...) so a reflected /
                        # includable GET param is testable — the crawl otherwise drops the query string
                        if "?" in href:
                            for name in parse_qs(href.split("?", 1)[1].split("#")[0], keep_blank_values=True):
                                if not _TEMPLATE_ARTIFACT.search(name):  # skip a `${x}`/`{{x}}` param name
                                    link_params.setdefault(p, set()).add(name)
                        if p not in visited:
                            queue.append((p, depth + 1))

        # API surface from a served OpenAPI/Swagger spec, paths mined from an SPA's JS bundles, and the
        # deploy LLM's source-read feature inventory (the last activates the catalog on an api-only app
        # with no crawlable HTML — otherwise surface_size collapses to 1). Dedup by (method, raw_path).
        endpoints = (openapi.ingest(base_url, c) + jsmine.ingest(c, js_urls)
                     + _endpoints_from_features(seed_features))
        endpoints += [Endpoint(path=p, method="get", query_params=sorted(params), raw_path=p)
                      for p, params in link_params.items()]
        endpoints = _dedup_merge_endpoints(endpoints)   # MERGE inputs on collision (don't drop LLM params)
        # Baseline each endpoint with a well-formed (read-only GET) request: an env-var-gated endpoint
        # (dummy Supabase/API key) 500s on EVERYTHING, so a baseline 5xx marks it reached-but-DEAD. This
        # separates "healthy-observed" surface (parity's real denominator) from merely "reached", and lets
        # behavioral probes skip an endpoint that never works. GET-only stays side-effect-free (a POST-only
        # endpoint answers 405 = alive; its POST deadness is handled by the crash probe's own baseline).
        for ep in endpoints[:_BASELINE_CAP]:
            try:
                ep.baseline_status = c.get(ep.path).status_code
            except (httpx.HTTPError, httpx.InvalidURL):
                ep.baseline_status = None
        for ep in endpoints:
            routes.setdefault(ep.path, None)

    browser_ok = False
    host_tiers: dict = {}     # off-score: where the app's runtime traffic goes (same-origin / BaaS / vendor /
    if render is not None:    # other off-origin) — populated from the observed net once the browser render runs
        # Browser-render the discovered HTML routes and harvest their client-rendered forms AND formless
        # inputs. A SPA paints its login/upload/search controls on their OWN routes (often with no <form>
        # at all), so the old single-"/" render only ever saw a form-less landing page — and every
        # injection/upload/auth probe went N/A for want of a target. Two phases so nav routes that only
        # appear AFTER "/" renders still get rendered: (1) render the entry page and fold its
        # client-rendered links into the route set; (2) render the rest of the now-fuller HTML route set
        # in one reused browser session (bounded — each goto costs). render(base_url, paths, headers) ->
        # {path: DOM} is browser.render_routes; None/{} when no browser launched (browser probes read N/A).
        observed_net, observed_scripts = [], []  # xhr/fetch (the app's API surface) + runtime-loaded same-origin
        rendered = render(base_url, [start_path], headers=headers,   # .js URLs (native ESM import() chunks a static
                          net_sink=observed_net, script_sink=observed_scripts) or {}   # <script> scan can't see)
        if rendered:
            browser_ok = True  # a real render returned HTML -> the browser actually launched/works
            any_response = True
            for dom in list(rendered.values()):     # phase 1: entry-page links -> route set
                for ref in _SRC.findall(dom) + _LINK.findall(dom):
                    p = _same_origin_path(ref, base_url, start_path)
                    if p:
                        routes.setdefault(p, None)
            extra = [r for r in routes if r != start_path and _renderable_route(r)]
            extra = list(dict.fromkeys(extra))[:_BROWSER_ROUTE_CAP]
            # a login/signup CTA was seen but no password form captured -> the form is likely on a conventional
            # auth route the CTA navigates to (JS router push, no href to crawl). Render those to find it (Part 2).
            if (auth[0] or auth[1]) and not any(any("pass" in n.lower() for n in f.fields) for f in forms):
                extra += [p for p in _AUTH_ROUTES if p not in extra and p not in visited]
            if extra:                               # phase 2: render the rest of the HTML surface
                rendered.update(render(base_url, extra, headers=headers,
                                       net_sink=observed_net, script_sink=observed_scripts) or {})
            for path, dom in rendered.items():
                _l, _s = _auth_triggers(dom)   # a SPA paints 'Sign in'/'Sign up' client-side, so scan the DOM too
                auth[0] |= _l
                auth[1] |= _s
                candidates = _parse_forms(_FORM.findall(dom), base_url, path)
                formless = _formless_form(dom, path)   # SPA inputs with no <form> wrapper
                if formless is not None:
                    candidates.append(formless)
                for form in candidates:
                    key = _form_key(form)
                    if key not in seen_forms:
                        seen_forms.add(key)
                        forms.append(form)
                        routes.setdefault(form.action, None)
                for ref in _SRC.findall(dom) + _LINK.findall(dom):
                    p = _same_origin_path(ref, base_url, path)
                    if p:
                        routes.setdefault(p, None)

            for u in observed_scripts:   # runtime-loaded same-origin .js (native ESM import() chunks / modulepreload)
                p = _same_origin_path(u, base_url, start_path)   # that leave no <script src> tag -> fold into routes
                if p and p.split("?")[0].endswith(".js"):        # so the bundle probes (depscan / secret-scan /
                    routes.setdefault(p, None)                   # source-map) actually read the lazy chunk

            host_tiers = _classify_hosts(observed_net, base_url)  # off-score: WHERE the traffic goes — same-origin
                                                                  # (probe-able) / managed BaaS (config-test lane) /
                                                                  # vendor (never the app's) / other off-origin (the
                                                                  # app's OWN backend = the recall frontier for Move 2)
            # OBSERVED-request harvest: the REAL endpoints the app called as it rendered/interacted (its own
            # same-origin xhr/fetch) -> the accurate endpoint surface. Ground truth the crawl + static JS-mine
            # miss when the path is built dynamically. Observed == real (no 404-verify); a GET baseline just
            # feeds the probes' health gate. Added BEFORE perception so the LLM is told these, not re-guessing.
            obs_eps = [e for e in _endpoints_from_observed(observed_net, base_url)
                       if not any(x.method == e.method and x.path == e.path for x in endpoints)
                       and not (e.method == "get" and not e.query_params and e.path in routes)]  # nav prefetch
            if obs_eps:
                with make_client(base_url, headers, timeout=5.0, follow_redirects=True) as pc:
                    for e in obs_eps[:_BASELINE_CAP]:
                        try:
                            e.baseline_status = pc.get(e.path).status_code
                        except (httpx.HTTPError, httpx.InvalidURL):
                            e.baseline_status = None
                endpoints += obs_eps
                for e in obs_eps:
                    routes.setdefault(e.path, None)

            # PROACTIVE discovery: the injected LLM perceives the RENDERED pages and returns the probeable
            # surface the crawl MISSED (client-rendered logins / uploads / action buttons a static crawl can't
            # see). Merge BEFORE the password-change filter + phantom-suppression below, so perceived surface is
            # held / dropped by the same guards; a hallucinated target then self-gates to N/A at probe time. Any
            # failure is swallowed and a None result is a no-op -> the deterministic crawl stays the FLOOR.
            if perceive is not None:
                try:
                    observed = {"routes": list(routes)[:30], "form_actions": [f.action for f in forms][:20],
                                "endpoints": [e.raw_path or e.path for e in endpoints][:20]}
                    _prof = Profile(base_url=base_url, forms=forms, endpoints=endpoints)
                    merge_perceived(_prof, perceive(rendered, observed))
                    forms, endpoints = _prof.forms, _prof.endpoints
                    # Baseline the endpoints perception just added: the crawl's baseline loop already ran and
                    # closed its client, so a perceived endpoint would otherwise stay unjudged (no baseline) —
                    # its reachable/hallucinated telemetry AND the injection probes' health gate need it. A GET
                    # is side-effect-free; a POST-only route answers 405 (reachable), a ghost path answers 404.
                    fresh = [e for e in endpoints
                             if getattr(e, "origin", "") == "perceived" and e.baseline_status is None]
                    if fresh:
                        with make_client(base_url, headers, timeout=5.0, follow_redirects=True) as pc:
                            for e in fresh[:_BASELINE_CAP]:
                                try:
                                    e.baseline_status = pc.get(e.path).status_code
                                except (httpx.HTTPError, httpx.InvalidURL):
                                    e.baseline_status = None
                except Exception:
                    pass   # perception NEVER breaks discovery — the crawl is the floor

    # Withhold password-CHANGE forms from the whole surface (like logout links above): probes SUBMIT
    # discovered forms (and fold GET forms into query-param injection targets), so a `password_new`/
    # `password_conf` form would get posted with our own session cookie and reset — and lock out — the
    # account we're grading. DVWA's /vulnerabilities/csrf/ is exactly this. They stay in `routes` (safe
    # to have crawled); only their submittable form/param projection is dropped.
    forms = [f for f in forms if not is_password_change_form(f)]

    # drop phantom server-side surface on a catch-all / soft-404 host (endpoints/forms that just echo the
    # app shell) so injection/CSRF/rate-limit don't fire on a page that has no real backend (see the helper).
    catch_all, endpoints, forms = _drop_phantom_surface(base_url, headers, endpoints, forms)

    has_pw = any(any("pass" in name.lower() for name in form.fields) for form in forms)
    capabilities = {
        "at_least_one_http_endpoint_exists": any_response,
        # text-input surface = HTML form fields OR API query params / JSON body fields (so the
        # injection probes become applicable on a form-less JSON API discovered via its spec).
        "any_endpoint_accepts_text_input": (
            any(f.fields for f in forms)
            or any(ep.query_params or ep.body_fields for ep in endpoints)
        ),
        "any_form_has_password": has_pw,
        # gate on an ACTUAL successful render, not just --browser: if Playwright/Chrome can't launch,
        # render returns None and browser probes must read N/A, not silently 'clean' (false negative).
        "browser": browser_ok,
        # HSTS and other transport-security headers are meaningless over plain HTTP -> gate on this so
        # those probes read N/A (not a false positive) against an http:// target.
        "served_over_https": base_url.lower().startswith("https"),
        # host serves a 200 shell for every path -> phantom server-side surface was dropped (off-score signal)
        "catch_all": catch_all,
        # login/signup presented as a BUTTON/LINK (not an inline password form) -> feeds has_login/has_signup
        # so parity credits a CTA login (the audit's #1 has_login=false complaint), not only password forms
        "login_trigger": auth[0],
        "signup_trigger": auth[1],
        # any auth DOOR — an inline password form OR a login/signup CTA (button/link to a separate route). The
        # auth self-oracle (httpx form-POST, else the browser register) can ATTEMPT registration wherever one
        # exists; the predicate self-gates to N/A when it can't establish a session, so widening here never
        # false-fires — it just lets the auth-probe cluster reach the CTA-login SPAs a password-form check missed.
        "has_auth_entrypoint": has_pw or auth[0] or auth[1],
    }
    return Profile(base_url=base_url, routes=list(routes), forms=forms, capabilities=capabilities,
                   endpoints=endpoints, host_tiers=host_tiers)


def surface_metrics(profile: Profile) -> dict:
    """A quantitative + categorical fingerprint of the surface discovery actually SAW. This is the
    denominator that separates a low slop score that means 'clean' from one that means 'we were blind':
    genuine cleanliness shows HIGH observed surface + few findings, blindness shows LOW observed surface
    + few findings (and, at batch scale, CLUSTERS on a stack). The same quantity feeds surface-aware
    scoring, so it's a first-class Report field, not a script-local calc. Categorical flags (has_login/
    upload/api) enable TYPE parity — did we see the login form five login apps each expose? — not just a
    coverage percentage."""
    forms = profile.forms
    inputs = sum(len(f.fields) for f in forms)
    caps = profile.capabilities
    # count APP routes, not bundled libraries: a Potree/three.js/etc. app serves 60+ vendor files
    # (/potree/libs/...) that pad the denominator and flatter its slop-to-surface ratio. Strip them.
    app_routes = [r for r in profile.routes if not _VENDOR_PATH.search(r)]
    # HEALTHY endpoints only: an env-var-dead endpoint (baseline >=500) is reached but not testable — count
    # it as unobserved so 'reached-but-half-dead' (sapling: ~95 reached, many 500) isn't scored well-covered.
    eps = profile.endpoints
    healthy_eps = [e for e in eps if (e.baseline_status or 0) < 500]
    # login/upload can be an API ENDPOINT (feature kind auth/upload, or a login/upload-named path), a
    # password FORM, or — the case the audit kept flagging — a login/signup BUTTON/LINK with no inline form.
    # Credit all three so parity doesn't report a false has_login=false blind spot on CTA-style auth.
    has_login = login_form(forms) is not None or bool(caps.get("login_trigger")) or any(
        e.kind == "auth" or _LOGIN_EP.search(e.raw_path or e.path or "") for e in eps)
    has_signup = bool(caps.get("signup_trigger")) or any(
        e.kind in ("auth", "signup") for e in eps) or any(
        re.search(r"sign-?up|register", (f.action or ""), re.I) for f in forms)
    has_upload = any(f.file_fields for f in forms) or any(
        e.kind == "upload" or _UPLOAD_EP.search(e.raw_path or e.path or "") for e in eps)
    # LLM-POINTER precision (build #2 telemetry, OFF-SCORE): endpoints the LLM UNIQUELY seeded from source
    # (origin "llm" — survived dedup, so the crawler never found them = coverage the pointer added) and
    # whether they turned out REAL on the deployed app. reachable = the path exists (baseline not 404);
    # hallucinated = 404 (the LLM named a path that isn't there); the rest were beyond the baseline cap
    # (unjudged). This MEASURES the pointer without ever letting it score — pointer/never-judge, quantified.
    llm_eps = [e for e in eps if getattr(e, "origin", "crawl") == "llm"]
    perceived_eps = [e for e in eps if getattr(e, "origin", "crawl") == "perceived"]
    perceived_forms = [f for f in forms if getattr(f, "origin", "crawl") == "perceived"]
    pointer = {
        "endpoints_seeded": len(llm_eps),                                                 # coverage the SOURCE pointer(#2) added
        "endpoints_reachable": sum(e.baseline_status not in (None, 404) for e in llm_eps),  # path exists -> LLM right
        "endpoints_hallucinated": sum(e.baseline_status == 404 for e in llm_eps),         # 404 -> LLM named a ghost path
        "params_seeded": sum(len(e.query_params) + len(e.body_fields) for e in llm_eps),  # injection targets it added
        # rendered-PERCEPTION pointer (proactive discovery, origin "perceived") — the same honesty measure on the
        # surface an LLM read off the RENDERED page (client-side logins/uploads/actions the crawl missed). Forms
        # here already survived phantom-suppression; endpoint reachable/hallucinated via the frozen baseline above.
        "perceived_endpoints_seeded": len(perceived_eps),
        "perceived_endpoints_reachable": sum(e.baseline_status not in (None, 404) for e in perceived_eps),
        "perceived_endpoints_hallucinated": sum(e.baseline_status == 404 for e in perceived_eps),
        "perceived_endpoint_paths": [(e.raw_path or e.path) for e in perceived_eps][:8],   # which paths it added
        "perceived_ghost_paths": [(e.raw_path or e.path) for e in perceived_eps            # the 404s = what it INVENTED
                                  if e.baseline_status == 404][:8],                        # (per-app hallucination audit)
        "perceived_forms_seeded": len(perceived_forms),
        "perceived_password_forms": sum(any("pass" in n.lower() for n in f.fields) for f in perceived_forms),
        "perceived_form_actions": [f.action for f in perceived_forms][:8],
    }
    return {
        "routes": len(app_routes),
        "routes_all": len(profile.routes),           # incl. vendor assets, for reference
        "routes_list": app_routes[:12],              # the actual APP route PATHS (vendor-stripped, capped) —
                                                     # lets the coverage auditor render sub-routes, not just "/"
        "forms": len(forms),
        "inputs": inputs,
        "endpoints": len(healthy_eps),               # healthy = responds to a baseline without a 5xx
        "endpoints_reached": len(eps),               # incl. env-var-dead (reached but not testable)
        "endpoints_dead": len(eps) - len(healthy_eps),
        "has_login": has_login,                       # HTML login form, API login endpoint, OR a CTA login button
        "has_signup": has_signup,                     # signup form/endpoint OR a 'Sign up'/'Get started' CTA
        "has_upload": has_upload,                     # multipart form OR an API upload endpoint
        "has_api": bool(healthy_eps),
        "browser_rendered": bool(caps.get("browser")),
        "accepts_text_input": bool(caps.get("any_endpoint_accepts_text_input")),
        "has_password_form": bool(caps.get("any_form_has_password")),
        # composite "how much observable & HEALTHY APP surface we saw" — the parity denominator
        "surface_size": len(app_routes) + inputs + len(healthy_eps),
        "pointer": pointer,                          # LLM-pointer precision telemetry (off-score, build #2)
        "catch_all": bool(caps.get("catch_all")),    # phantom server-side surface was suppressed (soft-404/SPA)
        "host_tiers": profile.host_tiers,            # off-score: backend-tier map (where runtime traffic GOES) —
                                                     # batch-aggregates to size the SPA off-origin gap (Move 2)
    }
