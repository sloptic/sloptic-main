"""Headless-browser harness (Playwright). Renders a page so discovery sees client-rendered forms
and routes a static crawl misses (SPAs), and (later) so DOM/stored XSS and Core Web Vitals can be
measured. Optional: every entry point degrades to None when no browser is available, so the rest of
the runner is unaffected.

Browser-agnostic: drives the REAL system Chrome/Edge first (a legitimate branded-browser fingerprint),
then Chromium channels, and Playwright's bundled Chromium only as a last resort. The ORDER matters for
reach, not merely availability: bundled headless Chromium presents a HeadlessChrome UA + automation tells
that WAF/bot mitigations (Vercel's default DDoS challenge) escalate on, which reputation-flagged a grading
IP across every Vercel host; the real installed Chrome the dev box and laptop drive never tripped it.
"""
from __future__ import annotations

import contextlib
import json
import pathlib
import re
import time
import urllib.parse

# An <img onerror> payload executes when inserted into the DOM (unlike a bare <script>), so it fires
# for both reflected-that-executes and DOM-sink XSS. The marker is read back from window.
_XSS_PAYLOAD = "<img src=x onerror=\"window.__hl_domxss='hl-domxss-9a2b'\">"
_XSS_MARKER = "hl-domxss-9a2b"
# Executing payloads across reflection CONTEXTS (each sets the marker when it RUNS) — used to CONFIRM a
# server-reflected XSS candidate by real browser execution, covering the contexts the single DOM-sink
# payload can't reach (attribute-value and <script>-block breakout). A candidate that reflects the marker
# but runs NONE of these is inert (framework-escaped / JSON RSC-flight data) — present, not executable.
_XSS_EXEC_PAYLOADS = (
    _XSS_PAYLOAD,                                                          # HTML body: <img> onerror handler
    "<svg onload=\"window.__hl_domxss='%s'\">" % _XSS_MARKER,             # HTML body: <svg> onload handler
    "\"><svg onload=\"window.__hl_domxss='%s'\">" % _XSS_MARKER,         # break OUT of an attribute value
    "</script><svg onload=\"window.__hl_domxss='%s'\">" % _XSS_MARKER,    # break OUT of a <script> block
)


def browser_available() -> bool:
    """True when a browser can ACTUALLY launch here — not merely when playwright imports (the old check,
    which let a broken/missing chromium read as 'available' and silently degrade a browser run to
    static-only). Tests skip on this; the CLIs use browser_preflight() for the (ok, detail) form."""
    return browser_preflight()[0]


# Real branded Chrome/Edge FIRST, bundled Chromium LAST. Not for availability (any of these renders the
# page) but for LEGITIMACY: bundled headless Chromium transmits a HeadlessChrome UA + automation tells that
# trip WAF/bot challenges and got a grading IP reputation-flagged across every Vercel host, while the real
# installed Chrome the dev box/laptop drive never did (proven: same IP, same corpus, many runs, no flag --
# the only variable was that the Dell had bundled Chromium installed and used it first). Reproducibility (a
# pinned bundled build) is the lesser concern and the per-commit surface cache already absorbs cross-box
# render variance. Bundled Chromium stays as the final fallback so a box with no system browser still runs.
_LAUNCH_ORDER = ({"channel": "chrome"}, {"channel": "msedge"}, {"channel": "chromium"}, {})


_LAST_LAUNCH_ERROR = ""


def _launch(p):
    global _LAST_LAUNCH_ERROR
    for kwargs in _LAUNCH_ORDER:
        try:
            return p.chromium.launch(headless=True, **kwargs)
        except Exception as e:     # try the next channel; keep the last failure so the preflight can report WHY
            _LAST_LAUNCH_ERROR = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
    return None


def browser_preflight() -> tuple[bool, str]:
    """Preflight: can chromium ACTUALLY launch here? Returns (ok, detail). Lets the CLIs FAIL LOUD when
    --browser is requested but the browser is missing/broken — instead of silently grading every app
    browser-less (a swallowed launch error reads as 'no browser' -> every browser probe N/A -> a static
    grade wearing a browser-run label; the lost-overnight-run failure). Uses the same _launch path the
    probes use, so it catches exactly what they'd hit."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return False, f"playwright import failed: {type(e).__name__}: {e}"
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return False, _LAST_LAUNCH_ERROR or "chromium.launch() failed for every channel"
            ver = b.version
            b.close()
            return True, f"chromium {ver}"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"


def _apply_auth(page, url: str, headers) -> None:
    """Send caller-supplied auth on browser requests so the browser probes reach a session/SSO-gated
    authenticated surface: a Cookie header -> the browser cookie jar, everything else (e.g. a Bearer
    Authorization) -> extra HTTP headers."""
    if not headers:
        return
    extra = {k: v for k, v in headers.items() if k.lower() != "cookie"}
    if extra:
        page.set_extra_http_headers(extra)
    cookie = next((v for k, v in headers.items() if k.lower() == "cookie"), None)
    if cookie:
        host = urllib.parse.urlparse(url).hostname
        jar = []
        for part in cookie.split(";"):
            if "=" in part:
                name, _, val = part.strip().partition("=")
                jar.append({"name": name, "value": val, "domain": host, "path": "/"})
        if jar:
            page.context.add_cookies(jar)


# Modern SPAs paint the login modal / upload dialog / tabbed form only ON INTERACTION — a static render
# (even multi-route) never sees them, so the login/upload surface and the whole auth-probe cluster read
# N/A (AfroSecured's upload, most SPA logins). These reveal-INTENT triggers are clicked to surface those
# controls; _NO_CLICK is the safety denylist — we OPEN UI, never submit/pay/delete/logout, so clicking a
# live third-party demo can't act on it.
_REVEAL = re.compile(
    r"log ?in|sign ?in|sign ?up|register|create account|get started|get access|"
    r"upload|attach|evidence|screenshot|choose file|select file|browse|drop|"
    r"account|profile|menu|"
    # generic create/new/add OPENERS — 'New Board', 'Add Card', 'Create Your First X', 'Start', '+' — the
    # client-side action buttons the coverage audit kept flagging as missed (they open a create form/modal
    # whose inputs we then capture). The submit-guard below keeps this from clicking a form's SUBMIT button.
    r"\bnew\b|\badd\b|\bcreate\b|\bstart\b|\bbegin\b|\bcompose\b|\bwrite\b|\bpost\b|\+", re.I)
_NO_CLICK = re.compile(
    r"log ?out|sign ?out|delete|remove|pay\b|buy\b|checkout|subscribe|purchase|confirm|"
    r"send\b|publish|invite|download|share|tweet|facebook|instagram|external|https?://", re.I)


_MAX_REVEALED = 120   # bound the appended fragment: with a[href] in the harvest, a link-heavy nav could
#                       otherwise paste hundreds of elements onto every route's dom


def _reveal_hidden_controls(page, max_clicks: int = 6, per_wait_ms: int = 350) -> str:
    """Click reveal-intent controls (login / upload / menu triggers) to surface INTERACTION-GATED forms
    and inputs a static render misses, and return the revealed <form>/modal HTML (appended to the route's
    dom for discovery to scan). Reveal-ONLY: never clicks a submit / pay / delete / logout / external
    control (_NO_CLICK), so it opens UI without acting on the app; bounded by max_clicks + an Escape reset
    between clicks so one page can't loop or drift far from its initial state."""
    revealed, seen, clicked = [], set(), 0
    # `a[href]` is here for a reason worth spelling out: harvesting only form controls made this pass blind to
    # interaction-gated ROUTES. Measured on OopsSec, clicking the account menu reveals <a href="/wishlists">
    # and <a href="/cart"> — live 200 pages — and dropping them broke the whole chain downstream: no route
    # means no page chunk fetched, which means /api/wishlists is never mined, which means the IDOR family has
    # no target and reports clean. Route discovery gates chunk discovery gates endpoint discovery.
    _controls = "input, textarea, select, form, a[href]"
    with contextlib.suppress(Exception):   # baseline: controls already present -> append only NEWLY revealed
        for h in (page.eval_on_selector_all(_controls, "els => els.map(e => e.outerHTML)") or []):
            seen.add(h[:160])
    triggers = []
    with contextlib.suppress(Exception):
        triggers = page.query_selector_all("button, a, [role=button], [role=tab], summary, [onclick]")
    for el in triggers:
        if clicked >= max_clicks:
            break
        try:
            label = ((el.inner_text() or "") + " " + (el.get_attribute("aria-label") or "")).strip().lower()[:80]
        except Exception:
            continue
        if not label or not _REVEAL.search(label) or _NO_CLICK.search(label):
            continue
        is_submit = False   # a Create/Add/... SUBMIT button inside a <form> would POST it, not open UI —
        with contextlib.suppress(Exception):   # reveal is open-ONLY, so skip real form submitters (the broadened
            is_submit = el.evaluate(           # opener set now matches submit labels too; this keeps them safe)
                "e => e.tagName==='BUTTON' && (e.type==='submit'||e.type==='reset') && !!e.form")
        if is_submit:
            continue
        try:
            el.click(timeout=1500)
            page.wait_for_timeout(per_wait_ms)
            clicked += 1
        except Exception:
            continue
        with contextlib.suppress(Exception):   # controls that APPEARED since baseline (a revealed login/upload)
            for frag in (page.eval_on_selector_all(_controls, "els => els.map(e => e.outerHTML)") or []):
                key = frag[:160]
                if key not in seen and len(revealed) < _MAX_REVEALED:
                    seen.add(key)
                    revealed.append(frag)
        with contextlib.suppress(Exception):   # close a modal so the next trigger stays clickable
            page.keyboard.press("Escape")
            page.wait_for_timeout(120)
    return ("<!--revealed-controls-->" + "".join(revealed)) if revealed else ""


_DRIVE_ROUTES = 3   # drive actions on only the first few routes (submit+wait is costly + mutates) -> grade budget


def _drive_actions(page, max_actions: int = 5, per_wait_ms: int = 450) -> None:
    """ACT on the page — fill visible forms with benign values and submit them, and click NON-destructive
    action buttons — so the app FIRES its OWN business API calls, which the net_sink harvest turns into real
    endpoints. This surfaces the INTERACTION-GATED runtime surface (a chat submit -> /api/chat) that no static
    crawl, JS-mine, or load-render can see, and that the LLM was left guessing. The inverse of
    _reveal_hidden_controls (open-ONLY): guarded by the SAME _NO_CLICK regex (skips delete/pay/logout/send/
    publish/external), benign values, bounded. State mutation is within the envelope the probes already accept
    (they submit discovered forms). Best-effort + isolated (suppress) so one hostile control never breaks the render."""
    acted = 0
    with contextlib.suppress(Exception):                     # 1. real <form>s: fill benign values + submit
        for form in page.query_selector_all("form"):
            if acted >= max_actions:
                break
            with contextlib.suppress(Exception):
                if not form.is_visible() or _NO_CLICK.search((form.inner_text() or "")[:200]):
                    continue                                 # a delete/pay/logout form -> never submit it
                for inp in form.query_selector_all("input:not([type=hidden]):not([type=file]), textarea"):
                    with contextlib.suppress(Exception):
                        t = (inp.get_attribute("type") or "text").lower()
                        if t not in ("submit", "button", "checkbox", "radio"):
                            inp.fill("hl.probe@example.com" if t == "email" else "hlprobe")
                form.evaluate("f => (f.requestSubmit ? f.requestSubmit() : f.submit())")  # fires the onsubmit fetch
                page.wait_for_timeout(per_wait_ms)           # let the fetch land so net_sink captures it
                acted += 1
    with contextlib.suppress(Exception):                     # 2. action BUTTONS (SPA onclick->fetch, not a <form>)
        for btn in page.query_selector_all("button, [role=button]"):
            if acted >= max_actions:
                break
            with contextlib.suppress(Exception):
                lbl = ((btn.inner_text() or "") + " " + (btn.get_attribute("aria-label") or "")).strip().lower()[:80]
                if not lbl or _NO_CLICK.search(lbl) or not btn.is_visible():
                    continue
                if btn.evaluate("e => e.tagName==='BUTTON' && e.type==='submit' && !!e.form"):
                    continue                                 # a form submitter -> already handled in (1)
                btn.click(timeout=1500)
                page.wait_for_timeout(per_wait_ms)
                acted += 1


# --- websocket-rendered SPAs (Streamlit) -----------------------------------------------------------------
# Streamlit is NOT a canvas app: it's a React frontend that paints REAL DOM elements from Protocol-Buffer
# "deltas" over a websocket, but only AFTER `load` fires on the static shell, and Community Cloud parks idle
# apps behind a "get this app back up" page. So a `wait_until="load"` + 300ms capture snapshots the ~108-node
# bootstrap shell every time — which made every Streamlit app grade identically (the framework, not the
# submission). Wake a sleeping app, then wait for the real app to paint, crash, or exhaust the budget, so the
# surface probe sees the actual app — or an honest "won't come up" failure, which is exactly what a judge
# hitting a slept app sees too.
_ST_HOST = ".streamlit.app"
_ST_SLEEP = re.compile(r"gone to sleep|get this app back up", re.I)
_ST_ERROR = re.compile(r"error running app|oh no\s*[.,]|connection error", re.I)
# the app has really painted: the view container exists AND several st-widgets rendered (the shell alone has none)
_ST_READY_JS = ('() => !!document.querySelector(\'[data-testid="stAppViewContainer"]\') '
                '&& document.querySelectorAll(\'[data-testid^="st"]\').length > 5')


def _looks_streamlit(page, url: str) -> bool:
    """Cheap gate so the slow await only runs for Streamlit (host suffix, or a Streamlit root in the DOM)."""
    if _ST_HOST in (url or ""):
        return True
    try:
        return bool(page.query_selector('[data-testid="stApp"], [data-testid="stAppViewContainer"]'))
    except Exception:
        return False


def await_streamlit(page, budget_s: float = 60.0) -> str:
    """Drive a Streamlit page to a terminal state and return it:
      'rendered' — the real app painted (view container + real widgets)
      'error'    — Streamlit's "Oh no. Error running app." crash screen (a genuine functional failure)
      'stuck'    — never came up within budget_s (asleep-and-won't-wake / too slow / dead)
    Wakes a sleeping Community-Cloud app first. Bounded by budget_s so a dead app can't stall the crawl."""
    t0 = time.monotonic()
    woke = False
    while time.monotonic() - t0 < budget_s:
        try:
            txt = (page.evaluate("() => document.body ? document.body.innerText : ''") or "")[:3000]
            if _ST_ERROR.search(txt):
                return "error"
            if not woke and _ST_SLEEP.search(txt):
                for sel in ('button:has-text("get this app back up")', 'button:has-text("back up")'):
                    el = page.query_selector(sel)
                    if el:
                        el.click()
                        woke = True
                        break
            elif page.evaluate(_ST_READY_JS):
                page.wait_for_timeout(600)   # let the last deltas settle before the DOM snapshot
                return "rendered"
        except Exception:
            pass
        page.wait_for_timeout(1500)
    return "stuck"




def render_routes(base_url: str, paths, headers=None, timeout: float = 12.0,
                  total_timeout: float = 60.0, interact: bool = True,
                  interact_routes: int = 6, net_sink: list | None = None,
                  script_sink: list | None = None, meta_sink: dict | None = None) -> dict[str, str]:
    """Render each same-origin path in ONE reused browser session and return {path: rendered_DOM}.
    Paths that fail to load are omitted; {} if no browser is available. A single launch is amortized
    across all routes — a launch-per-route helper would relaunch (and re-warm) the browser each time.
    Bounded by total_timeout so a slow-loris route can't stall the whole crawl (like dom_xss_executes).
    Used by discovery to harvest the client-rendered forms/inputs a SPA paints on routes OTHER than "/"
    (login, upload, search) — the interactive surface a single "/" render misses. Pass ["/"] for just
    the entry page.

    interact_routes bounds HOW MANY routes get the (expensive) reveal-click pass: every route is still
    rendered, but only the first `interact_routes` are interacted with. Reveal-clicking EVERY route on a
    big SPA is what pushed AfroSecured past the grade budget, and the gated surface (login/upload) lives
    on the entry + top nav routes anyway — deep routes almost never gate NEW controls."""
    out: dict[str, str] = {}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return out
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return out
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)  # cookies/headers persist for the origin across gotos
                if net_sink is not None or script_sink is not None:  # harvest the app's runtime requests as it renders
                    _host = urllib.parse.urlparse(base_url).netloc
                    def _cap(req):
                        with contextlib.suppress(Exception):
                            u = req.url
                            if net_sink is not None and req.resource_type in ("xhr", "fetch") and len(net_sink) < 150:
                                net_sink.append((req.method, u, req.post_data))   # xhr/fetch = the API surface (all
                            if script_sink is not None and len(script_sink) < 60:  # origins; discovery classifies)
                                pu = urllib.parse.urlparse(u)         # a runtime-loaded same-origin .js — a native ESM
                                if pu.netloc == _host and pu.path.rsplit(".", 1)[-1].lower() == "js":  # import() chunk
                                    script_sink.append(u)             # / modulepreload leaves NO <script src> tag for
                    page.on("request", _cap)                          # the DOM scan -> discovery folds it into routes
                deadline = time.monotonic() + total_timeout
                for idx, path in enumerate(paths):
                    if time.monotonic() > deadline:
                        break
                    url = base_url.rstrip("/") + path
                    with contextlib.suppress(Exception):
                        page.goto(url, timeout=timeout * 1000, wait_until="load")
                        if idx == 0 and _looks_streamlit(page, url):
                            # websocket-rendered SPA: wake + wait for the real app. Bounded to ~35s (covers a
                            # cold-start wake; a slower app is marked 'stuck', not waited on) so a mostly-dead
                            # Streamlit corpus can't burn the run — still within the crawl deadline.
                            st_state = await_streamlit(page, budget_s=max(8.0, min(35.0, deadline - time.monotonic())))
                            if meta_sink is not None:      # rendered|error|stuck -> the record's shell_only signal
                                meta_sink["render_state"] = st_state
                        else:
                            page.wait_for_timeout(300)  # let client JS paint the route's forms/inputs
                        dom = page.content()
                        if interact and idx < interact_routes:  # bound: reveal-clicking every route on a big
                            dom += _reveal_hidden_controls(page)  # SPA is the grade-timeout — cap to the first N
                            if net_sink is not None and idx < _DRIVE_ROUTES:   # then ACT (submit/click) to fire
                                _drive_actions(page)                            # the app's business API calls
                        out[path] = dom
            finally:
                b.close()
    except Exception:
        return out
    return out


# ---- browser-driven SPA registration (auth self-oracle, client-rendered path) --------------------
_SIGNUP_SUBMIT = re.compile(r"sign ?up|register|create account|create your account|get started|join now|"
                            r"\bjoin\b|continue|submit|create", re.I)


_LOGIN_ONLY = re.compile(r"^\s*(log ?in|sign ?in|login|signin)\b", re.I)


def _looks_like_signup(page) -> bool:
    """Positive evidence that THIS form registers rather than authenticates.

    A password field is not evidence: a login form has one too. Measured on recovr-smoky.vercel.app — the
    homepage is a login whose only button reads "Login", so the fill loop filled it, reported success, and
    _reach_and_submit_signup returned before ever walking to /signup. The Enter fallback then submitted a LOGIN
    with credentials for an account that does not exist, so no registration request was ever made. That is the
    homepage-login hijack, and it is real here even though it was NOT the cause on timbermarket, where the
    homepage carries a genuine "Create account" form.

    Evidence accepted: a signup-labelled submit, or a confirm-password field (logins do not have one). A form
    whose ONLY submit says Login/Sign in is rejected outright.
    """
    with contextlib.suppress(Exception):
        labels = [((b.inner_text() or "") + " " + (b.get_attribute("value") or "")).strip()
                  for b in page.query_selector_all("button, input[type=submit], [role=button]")
                  if b.is_visible()]
        labels = [l for l in labels if l]
        if any(_SIGNUP_SUBMIT.search(l) and not _NO_CLICK.search(l) for l in labels):
            return True
        if labels and all(_LOGIN_ONLY.search(l) for l in labels):
            return False       # a login form and nothing else -> do not spend our one signup on it
        for el in page.query_selector_all("input[type=password]"):
            with contextlib.suppress(Exception):
                if el.is_visible() and re.search(r"confirm|repeat|again|retype|verify", _field_hint(el)):
                    return True       # a confirm-password field is a registration tell
    return False


def _field_hint(el) -> str:
    """Everything that might name this field, ATTRIBUTES PLUS DOM CONTEXT.

    React forms routinely render inputs with no name, id, placeholder or aria-label and put the wording in a
    sibling element, so attribute-only matching leaves them unidentified. Measured on timbermarket.lol: the
    signup's two visible inputs carried NO name/placeholder/aria-label/id at all, with "Username" and
    "Password" sitting in the previousElementSibling. The text field was therefore never filled, it was
    `required`, HTML5 validation silently refused the submit, and no registration request ever left the page —
    which is 26.7% of the measured v11 session gap and was indistinguishable from "the app withheld a session"
    until the request-observed split existed.
    """
    parts = [el.get_attribute(a) or "" for a in ("name", "placeholder", "aria-label", "id", "autocomplete")]
    with contextlib.suppress(Exception):
        parts.append(el.evaluate("""e => {
            const lab  = [...(e.labels || [])].map(l => l.textContent || '').join(' ');
            const prev = e.previousElementSibling ? (e.previousElementSibling.textContent || '') : '';
            return (lab + ' ' + prev).slice(0, 120);
        }"""))
    return " ".join(parts).lower()


def _fill_and_submit_signup(page, creds) -> bool:
    """Fill the visible signup inputs (email / username / password + confirm, tick any terms box) and submit,
    so the app's OWN JS runs the real registration. True iff a password field was found and a submit issued.
    Best-effort field matching by type/name/placeholder/id; targets a SIGNUP (a password field must be present)."""
    filled_pw = False
    with contextlib.suppress(Exception):
        for el in page.query_selector_all("input"):
            with contextlib.suppress(Exception):
                if not el.is_visible():
                    continue
                typ = (el.get_attribute("type") or "text").lower()
                hint = _field_hint(el)
                if typ == "password" or "pass" in hint or "pwd" in hint:
                    el.fill(creds["password"]); filled_pw = True
                elif typ == "email" or "email" in hint or "mail" in hint:
                    el.fill(creds["email"])
                elif typ == "checkbox":
                    el.check()                                       # terms / agree
                elif typ in ("text", "") and any(h in hint for h in ("user", "name", "handle", "login")):
                    el.fill(creds["username"])
    if not filled_pw:
        return False   # no fillable password field -> not a signup form we can register through
    # LAST RESORT, and the reason the fix above is not sufficient on its own: a visible REQUIRED input left
    # empty makes the form unsubmittable no matter how good the labels are, and the failure is SILENT (a native
    # validation bubble, not DOM text, so nothing to scrape). Better to fill it with something and let the app
    # reject the value — a rejection is observable, a blocked submit is not.
    with contextlib.suppress(Exception):
        for el in page.query_selector_all("input"):
            with contextlib.suppress(Exception):
                if not el.is_visible() or el.get_attribute("required") is None:
                    continue
                typ = (el.get_attribute("type") or "text").lower()
                if typ in ("checkbox", "radio", "hidden", "submit", "button", "file"):
                    continue
                if (el.input_value() or "").strip():
                    continue                                  # already filled by the typed pass above
                hint = _field_hint(el)
                el.fill(creds["email"] if typ == "email" or "mail" in hint else creds["username"])
    with contextlib.suppress(Exception):                             # prefer a signup-labeled submit button
        for btn in page.query_selector_all("button, input[type=submit], [role=button]"):
            lbl = ((btn.inner_text() or "") + " " + (btn.get_attribute("value") or "") + " "
                   + (btn.get_attribute("aria-label") or "")).strip().lower()[:60]
            if _SIGNUP_SUBMIT.search(lbl) and not _NO_CLICK.search(lbl) and btn.is_visible():
                btn.click(timeout=2500)
                return True
    with contextlib.suppress(Exception):
        page.keyboard.press("Enter")                                 # fallback: submit the focused field's form
        return True
    return False


# Conventional signup routes a 'Get Started' / 'Sign up' CTA navigates to via the JS router (QuizForge's
# /register et al.) — an <a> LINK the button-only reveal can't open. Tried in order when the homepage has no
# fillable signup, so a separate-route signup (the common SPA shape) is still reached.
# The LAST failure stage of register_in_browser, read by auth._register_via_browser so an N/A reason can name
# WHICH exit was taken. This lives here rather than as an out-param because the callable is INJECTED into auth
# as `browser_register(base_url)` — a one-arg contract several call sites rely on — and widening that signature
# to carry diagnostics would be the tail wagging the dog.
#
# Why it matters, measured: the first 39 apps of the session-gap run put 87% into a single bucket that reads
# "no fillable signup, OR the signup left neither a cookie nor a token". Those are OPPOSITE findings — the
# first is our discovery bug and the second is almost certainly e-mail confirmation, which is a CORRECT N/A —
# and merging them makes a four-hour run unable to answer the question it was launched for.
LAST_STAGE: dict = {}


_SIGNUP_ROUTES = ("/register", "/signup", "/sign-up", "/join", "/auth/register", "/auth/signup",
                  "/create-account", "/get-started")


# sign[ _-]?up, not "sign ?up|sign-up": the underscore form is Devise's canonical Rails route
# (/users/sign_up) and this file's own precision test caught it missing.
_SIGNUP_LINK = re.compile(r"sign[ _-]?up|regist|create[ _-]?account|get[ _-]?started|\bjoin\b", re.I)


def _signup_hrefs(page, base_url: str) -> list[str]:
    """Signup destinations the APP ITSELF advertises, resolved and same-origin only.

    Measured on the 38 apps that reported "no fillable signup reached": 17 exposed a signup href in the DOM and
    13 of those pointed somewhere _SIGNUP_ROUTES does not walk. The app tells us where its signup is and we
    were guessing eight conventional paths instead. The misses were `/auth/sign-up` (a variant we lack),
    `/auth?mode=register` (a QUERY parameter), `#signup` and `#/signup` (hash routing),
    `/auth/login?screen_hint=signup` (the Auth0 pattern) and `signup.html` (relative). Following the href
    subsumes every one of those without enumerating any of them.

    SAME-ORIGIN ONLY, deliberately. An off-origin "Sign up" is a third party's registration (a hosted IdP, a
    marketing site) — not this app's surface, and following it would both mis-attribute the finding and point
    a credential-submitting robot at somebody who never asked for it. Same narrowing rule the bundle-origin
    SSRF guard uses.
    """
    from urllib.parse import urljoin, urlparse
    origin = urlparse(base_url)
    out: list[str] = []
    with contextlib.suppress(Exception):
        raw = page.eval_on_selector_all("a[href]", """els => els
            .filter(e => e.offsetParent !== null)
            .map(e => [(e.innerText || '').trim(), e.getAttribute('href') || ''])""")
        for text, href in raw:
            if not href or href.lower().startswith(("mailto:", "tel:", "javascript:")):
                continue
            if not (_SIGNUP_LINK.search(text) or _SIGNUP_LINK.search(href)):
                continue
            full = urljoin(page.url or base_url, href)
            u = urlparse(full)
            if u.scheme not in ("http", "https") or u.netloc != origin.netloc:
                continue                      # off-origin -> someone else's signup, not this app's
            if full not in out:
                out.append(full)
    return out[:6]


def _reach_and_submit_signup(page, base_url, creds, timeout) -> bool:
    """Get to a fillable signup and submit it. The homepage (reveal an inline modal) first; if the signup lives
    on its OWN route — a 'Get Started' <a> link the reveal can't open — walk conventional signup paths and try
    each. True once a signup form was filled + submitted (the app's own JS then makes the real request)."""
    with contextlib.suppress(Exception):
        page.goto(base_url.rstrip("/") + "/", timeout=timeout * 1000, wait_until="load")
        page.wait_for_timeout(300)
        _reveal_hidden_controls(page)
        # The homepage is the one place we have no route-name evidence, so require the form to LOOK like a
        # signup. Without this an app whose landing page is a login gets its login submitted and the walk to
        # /signup never happens.
        if _looks_like_signup(page) and _fill_and_submit_signup(page, creds):
            return True
    # THE APP'S OWN LINKS BEFORE OUR GUESSES. A hash-only href (#signup, #/signup) is client-side routing that
    # a goto may not re-trigger from the same document, so click those instead; anything with a path or query
    # is navigable.
    for href in _signup_hrefs(page, base_url):
        with contextlib.suppress(Exception):
            if "#" in href and href.split("#", 1)[0].rstrip("/") in (page.url or "").rstrip("/"):
                frag = "#" + href.split("#", 1)[1]
                page.click("a[href$='%s']" % frag.replace("'", ""), timeout=2500)
            else:
                page.goto(href, timeout=timeout * 1000, wait_until="load")
            page.wait_for_timeout(400)
            _reveal_hidden_controls(page)
            if _fill_and_submit_signup(page, creds):
                return True
    for route in _SIGNUP_ROUTES:
        with contextlib.suppress(Exception):
            page.goto(base_url.rstrip("/") + route, timeout=timeout * 1000, wait_until="load")
            page.wait_for_timeout(400)
            _reveal_hidden_controls(page)
            if _fill_and_submit_signup(page, creds):
                return True
    return False


# --- LANE B: email-first signup WIZARD (step 1 = email + emailed CODE, no password; step 2 = create password) --
# The shape register_in_browser's password-keyed path can't submit (its step 1 has no password field, e.g.
# insightaco). Driven IN ONE SESSION so the emailed code stays valid: fill email -> trigger + wait for the code
# field -> fetch the code from OUR inbox via a callback -> submit it -> fill a step-2 password if present. Every
# step is best-effort + safe-degrading (any failure -> return False, the caller then reports the normal N/A).
_EMAIL_INPUT = "input[type=email], input[name*=email i], input[id*=email i], input[placeholder*=email i]"
_CODE_INPUT_HINT = re.compile(r"code|otp|verif|pin|token", re.I)
_STEP_SUBMIT = re.compile(r"continue|next|verif|get.?code|send.?code|confirm|submit|sign.?up|create.?account", re.I)


def _has_visible_password(page) -> bool:
    with contextlib.suppress(Exception):
        return any(p.is_visible() for p in page.query_selector_all("input[type=password]"))
    return False


def _click_step_button(page, timeout) -> bool:
    """Click the step's advance button (Continue/Next/Verify/Submit), never a _NO_CLICK control (pay/delete/...)."""
    with contextlib.suppress(Exception):
        for b in page.query_selector_all("button, input[type=submit], [role=button]"):
            if not b.is_visible():
                continue
            label = ((b.inner_text() or "") + " " + (b.get_attribute("value") or "")).strip()
            if label and _STEP_SUBMIT.search(label) and not _NO_CLICK.search(label):
                b.click(timeout=timeout * 1000)
                return True
    return False


def _find_code_field(page):
    """The verification-CODE input(s): a single input hinting code/otp/verif/pin, else a row of single-char
    maxlength=1 boxes (a boxed OTP widget). None when no code field is present yet."""
    with contextlib.suppress(Exception):
        for inp in page.query_selector_all("input"):
            if not inp.is_visible():
                continue
            hint = " ".join(filter(None, [inp.get_attribute("name"), inp.get_attribute("id"),
                                          inp.get_attribute("placeholder"), inp.get_attribute("aria-label"),
                                          inp.get_attribute("autocomplete")]))
            if hint and _CODE_INPUT_HINT.search(hint):
                return [inp]
        boxes = [i for i in page.query_selector_all("input")
                 if i.is_visible() and i.get_attribute("maxlength") == "1"]
        if 3 <= len(boxes) <= 8:
            return boxes
    return None


def _fill_code(fields, code) -> bool:
    with contextlib.suppress(Exception):
        if len(fields) == 1:
            fields[0].fill(str(code))
        else:                                            # a boxed OTP widget: one char per box
            for f, ch in zip(fields, str(code)):
                f.fill(ch)
        return True
    return False


def _reach_email_first_step(page, base_url, timeout) -> bool:
    """Park on a signup route that shows an EMAIL field with NO visible password -- the email-first step."""
    for route in [""] + list(_SIGNUP_ROUTES):
        with contextlib.suppress(Exception):
            page.goto(base_url.rstrip("/") + (route or "/"), timeout=timeout * 1000, wait_until="load")
            page.wait_for_timeout(300)
            _reveal_hidden_controls(page)
            if page.query_selector(_EMAIL_INPUT) and not _has_visible_password(page):
                return True
    return False


def _drive_email_first(page, base_url, email, code_getter, creds, timeout) -> bool:
    """Drive the email-first wizard on an OPEN page. True once it has advanced through the code step (the caller
    then captures whatever session the app established); False on any dead end. `code_getter()` fetches the code
    from our inbox IN-SESSION (so re-triggering doesn't matter -- the code we submit is the one just sent)."""
    if not _reach_email_first_step(page, base_url, timeout):
        return False
    email_el = page.query_selector(_EMAIL_INPUT)
    if email_el is None:
        return False
    with contextlib.suppress(Exception):
        email_el.fill(email)
    _click_step_button(page, timeout)                    # trigger the code send / advance to the code step
    fields = None
    for _ in range(20):                                  # wait up to ~6s for the code field to appear
        fields = _find_code_field(page)
        if fields:
            break
        with contextlib.suppress(Exception):
            page.wait_for_timeout(300)
    if not fields:
        return False
    code = None
    with contextlib.suppress(Exception):
        code = code_getter()                             # polls OUR inbox (up to ~60s) for the just-sent code
    if not code:
        return False
    fields = _find_code_field(page) or fields            # re-locate: filling email may have re-rendered the DOM
    if not _fill_code(fields, code):
        return False
    _click_step_button(page, timeout)                    # submit the code
    with contextlib.suppress(Exception):
        page.wait_for_timeout(500)
    _fill_and_submit_signup(page, creds)                 # step 2: create a password if the wizard now asks for one
    return True


# A session token PERSISTED in localStorage (Supabase 'sb-<ref>-auth-token', Firebase authUser, or a bare JWT)
# is reachable by ANY XSS on the origin — unlike an HttpOnly cookie — so its presence is the token-auth analog
# of a session cookie missing HttpOnly (sec-session-005). The same token doubles as the Bearer for our authed
# client when the app sets no cookie (the bolt/Supabase cohort's whole session model).
_STORAGE_TOKEN_JS = r"""() => {
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i), v = localStorage.getItem(k) || "";
    let tok = null;
    let s = v;
    if (s.slice(0, 7) === "base64-") { try { s = atob(s.slice(7)); } catch (e) {} }  // @supabase/ssr wrapping
    if (s.slice(0, 3) === "eyJ") tok = s;                          // a raw JWT stored directly
    else if (s.indexOf("access_token") >= 0 || s.indexOf("accessToken") >= 0 || s.indexOf("idToken") >= 0) {
      try { const j = JSON.parse(s);
        tok = j.access_token || j.accessToken || j.token || j.idToken
           || (j.currentSession && j.currentSession.access_token)
           || (j.stsTokenManager && j.stsTokenManager.accessToken) || null;
      } catch (e) {}
    }
    if (tok && String(tok).length > 20) return { token: String(tok), key: k };
  }
  return {};
}"""


def _extract_storage_token(page) -> dict:
    """A persisted session token out of localStorage -> {token, key} or {} (the exposure finding + the Bearer)."""
    with contextlib.suppress(Exception):
        return page.evaluate(_STORAGE_TOKEN_JS) or {}
    return {}


# --- browser-driven DATA-PLANE READ-BACK (the SPA write round-trip httpx can't observe) --------------------
# On an SPA the form action is a placeholder (the real submit is a JS fetch), the created item paints on a
# CLIENT-SIDE route, and the create is often auth-gated -- so an httpx POST hits the shell and never sees the
# value come back. Drive the create IN THE BROWSER (carrying any session), let the app's own JS make the real
# call, then RE-RENDER and read the value back from the rendered DOM. One primitive the stateful cluster shares
# (qa-input-002 encoding, qa-integrity persistence, stored-xss, IDOR). Best-effort + safe-degrading (flaky).
def _fill_content_form(page, value: str, timeout: float) -> bool:
    """Fill a CREATE/content form's text field with `value` (other fields benign) and submit via the app's OWN JS
    (requestSubmit fires the onsubmit fetch). A content form = a VISIBLE form with a text input/textarea, NO
    password field (that's login/signup), not a _NO_CLICK (delete/pay/logout) form. True once one is submitted."""
    with contextlib.suppress(Exception):
        for form in page.query_selector_all("form"):
            with contextlib.suppress(Exception):
                if not form.is_visible() or _NO_CLICK.search((form.inner_text() or "")[:200]):
                    continue
                if form.query_selector("input[type=password]"):
                    continue                                     # a credential form, not content
                target = None
                for inp in form.query_selector_all(
                        "input:not([type=hidden]):not([type=file]):not([type=password]), textarea"):
                    t = (inp.get_attribute("type") or "text").lower()
                    if t in ("submit", "button", "checkbox", "radio"):
                        continue
                    is_textish = t in ("text", "search", "") or bool(inp.evaluate("e => e.tagName === 'TEXTAREA'"))
                    if target is None and is_textish:
                        inp.fill(value)                          # the observable field -> our marker+value
                        target = inp
                    else:
                        inp.fill("hl.probe@example.com" if t == "email" else "hlprobe")
                if target is None:
                    continue
                form.evaluate("f => (f.requestSubmit ? f.requestSubmit() : f.submit())")
                page.wait_for_timeout(int(timeout * 40))
                return True
    return False


def _dom_text(page) -> str:
    with contextlib.suppress(Exception):
        return page.inner_text("body") or ""
    return ""


def _drive_create_and_observe(base_url, submit_value, headers, timeout, observe):
    """Core browser write round trip: fill a content form with `submit_value` (carrying `headers` -- the
    register-lane session, so auth-gated creates work), submit via the app's OWN JS, RE-RENDER (in place, then one
    reload), and return the first truthy `observe(page)`. `observe` reads whatever facet the caller needs -- the
    rendered DOM text (encoding/integrity), or window.__hl_domxss (stored-xss execution). None if nothing observed.
    Best-effort + safe-degrading (browser-flaky by nature)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                with contextlib.suppress(Exception):
                    page.goto(base_url.rstrip("/") + "/", timeout=timeout * 1000, wait_until="load")
                    page.wait_for_timeout(300)
                    _reveal_hidden_controls(page)               # open a create modal/form if it's behind a CTA
                if not _fill_content_form(page, submit_value, timeout):
                    return None
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=6000)
                page.wait_for_timeout(500)
                for attempt in (0, 1):                           # the item may paint in place, or need a reload
                    result = observe(page)
                    if result:
                        return result
                    with contextlib.suppress(Exception):
                        page.reload(timeout=timeout * 1000, wait_until="load")
                        page.wait_for_timeout(600)
                return None
            finally:
                b.close()
    except Exception:
        return None


def create_and_read_back(base_url: str, submit_value: str, locate: str, headers=None, timeout: float = 12.0):
    """Drive an SPA write round trip and READ THE VALUE BACK: fill a create form's text field with `submit_value`,
    submit via the app's JS, re-render, and return the rendered DOM TEXT once `locate` (a unique marker in
    submit_value) round-trips -- else None. The client-side-route read-back httpx can't do. Consumers check that
    text (qa-input-002 -> corruption, qa-integrity -> presence)."""
    def observe(page):
        text = _dom_text(page)
        return text if locate in text else None
    return _drive_create_and_observe(base_url, submit_value, headers, timeout, observe)


def create_and_check_execution(base_url: str, payload: str, marker: str, headers=None, timeout: float = 12.0) -> bool:
    """Drive a STORED-XSS check through the browser create: submit `payload` (a script that sets
    window.__hl_domxss = marker) into a content form, re-render, and return True iff it EXECUTED -- the stored
    value ran unescaped in the DOM. Reaches auth-gated / SPA creates the httpx stored_xss_api can't POST to."""
    def observe(page):
        with contextlib.suppress(Exception):
            return marker if page.evaluate("() => window.__hl_domxss") == marker else None
        return None
    return bool(_drive_create_and_observe(base_url, payload, headers, timeout, observe))


def register_in_browser(base_url: str, headers=None, timeout: float = 12.0, total_timeout: float = 45.0,
                        email: str | None = None, code_getter=None):
    """SPA self-registration THROUGH the browser (the auth self-oracle's client-rendered path): open the signup
    form, fill throwaway creds, submit so the app's OWN JS makes the real registration request, and return the
    session cookie the server sets IN THE BROWSER — the thing an httpx form-POST can't get on an SPA (the form's
    action is a placeholder; the real POST lives in the JS). On the bolt/Supabase/Firebase cohort the session is
    NOT a cookie but a JWT (localStorage + Authorization: Bearer), so this ALSO returns that token. Returns
    {creds, cookies:[{name,value,httponly,secure,samesite}], request:{url,method,body}|None, bearer:str|None,
    storage_exposed:bool} or None (no browser / no fillable signup / NEITHER a cookie nor a token — email-verify /
    CAPTCHA / SSO). Best-effort + side-effecting: creates ONE throwaway account, like the httpx register; targets a
    SIGNUP form only (a password field), never login/pay/delete (the reveal + _NO_CLICK guards). Caller (auth)
    decides which cookie/token is the session and whether registration succeeded.

    `email`, when set, fills the signup's email field with a controlled address WE own (the email-verification
    flow), so an email-GATED SPA mails the confirmation to us. In that mode the submitted-but-no-session outcome
    is NOT a bare None: it returns {email_pending: True, creds, cookies, request} so the email flow can poll the
    inbox and complete the verification link in the browser (verify_in_browser). Callers that pass no email keep
    the exact old contract (None on no session).

    `code_getter`, when set (with `email`), enables the LANE-B email-first WIZARD fallback: if no password-signup
    form is reachable but an email-first step is (email + emailed CODE, password on a later step), drive it in one
    session, calling code_getter() to fetch the code from our inbox mid-flow. None-safe: absent -> old behavior."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    import secrets
    uname = "hl_" + secrets.token_hex(5)
    creds = {"email": email or (uname + "@example.com"), "username": uname, "password": "Hl-Probe-Passw0rd!"}
    captured, seen_bearer, reads, out = {}, {}, [], None
    LAST_STAGE.clear()
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)

                def _on_request(req):   # the REAL registration request + a Bearer the app's JS attaches post-auth
                    with contextlib.suppress(Exception):
                        if req.method in ("POST", "PUT") and creds["password"] in (req.post_data or ""):
                            captured.update(url=req.url, method=req.method, body=req.post_data)
                        authz = req.headers.get("authorization", "")
                        if authz[:7].lower() == "bearer " and len(authz) > 27:
                            seen_bearer["token"] = authz[7:]   # the token the app sends to its own authed API
                        # a Supabase PostgREST DATA read the app's OWN client makes (has the app's public apikey):
                        # recorded so the managed-backend IDOR probe can replay THIS read as a second user. Only
                        # the app's own endpoints/project/key — never anything the app doesn't itself request.
                        apikey = req.headers.get("apikey")
                        if req.method == "GET" and apikey and "/rest/v1/" in req.url and len(reads) < 10:
                            if not any(r["url"] == req.url for r in reads):
                                reads.append({"url": req.url, "apikey": apikey})
                page.on("request", _on_request)

                if not _reach_and_submit_signup(page, base_url, creds, timeout):
                    # LANE B fallback: no password-signup form, but maybe an EMAIL-FIRST wizard (email + emailed
                    # code, password on a later step). Only when we have an inbox (email) AND a code fetcher.
                    if not (email is not None and code_getter is not None
                            and _drive_email_first(page, base_url, email, code_getter, creds, timeout)):
                        LAST_STAGE["stage"] = ("no fillable signup reached: no visible password field on the "
                                               "homepage (after revealing hidden controls) or at any of %d "
                                               "conventional signup routes" % len(_SIGNUP_ROUTES))
                        return None
                with contextlib.suppress(Exception):                 # let the registration fetch + Set-Cookie/token land
                    page.wait_for_load_state("networkidle", timeout=8000)
                page.wait_for_timeout(500)
                cookies = []
                with contextlib.suppress(Exception):
                    cookies = page.context.cookies()
                jar = [{"name": c["name"], "value": c.get("value", ""),
                        "httponly": bool(c.get("httpOnly")), "secure": bool(c.get("secure")),
                        "samesite": (c.get("sameSite") or "").lower() in ("lax", "strict")}
                       for c in cookies]
                stored = _extract_storage_token(page)                # a session JWT persisted in localStorage
                # the session for our authed client: a persisted localStorage token, else a Bearer the app sent
                bearer = stored.get("token") or seen_bearer.get("token")
                if not jar and not bearer:
                    # THE SIGNUP WAS FILLED AND SUBMITTED and the app still granted nothing. Distinct from the
                    # exit above and usually NOT our bug: e-mail confirmation, CAPTCHA, admin approval or an
                    # SSO-only backend all land here, and every one of them is a correct N/A.
                    LAST_STAGE["stage"] = ("signup filled and submitted, but the app set no cookie and issued "
                                           "no token%s (e-mail confirmation / CAPTCHA / approval / SSO-only)"
                                           % (" — a registration request WAS observed" if captured else
                                              " and no registration request was even observed"))
                    if email is not None:
                        # EMAIL-FLOW mode: the signup submitted with OUR address but granted no session -> maybe
                        # e-mail confirmation, maybe CAPTCHA / SSO / admin-approval. Hand back the SUBMITTED state
                        # (not None) plus the post-submit page TEXT, so the email flow can confirm the page really
                        # announces e-mail before it treats this as email-gated (and only then poll the inbox).
                        # Callers in the non-email auth self-oracle path (email is None) still get the old None.
                        page_text = ""
                        with contextlib.suppress(Exception):
                            page_text = (page.inner_text("body") or "")[:5000]
                        return {"email_pending": True, "creds": creds, "cookies": jar, "page_text": page_text,
                                "request": captured or None, "backend_reads": reads}
                    return None
                out = {"creds": creds, "cookies": jar, "request": captured or None,
                       "bearer": bearer, "storage_exposed": bool(stored.get("token")),
                       "backend_reads": reads}
            finally:
                b.close()
    except Exception as exc:
        LAST_STAGE["stage"] = "browser registration raised %s" % type(exc).__name__
        return None
    return out


def verify_in_browser(link: str, base_url: str = "", headers=None, timeout: float = 12.0):
    """Complete a SPA e-mail verification: open the emailed confirmation LINK in a fresh browser so the app's OWN
    JS reads the token out of the URL and establishes the session — an httpx GET can't run that JS, so a
    client-rendered verify page would otherwise never log us in. Same capture path as register_in_browser:
    returns {cookies:[{name,value,httponly,secure,samesite}], bearer:str|None, storage_exposed:bool,
    backend_reads:[...]} when the link grants a session, else None (no browser / inert or dead link). Stateless by
    design — the token is IN the link, so a fresh context (no prior signup session) completes it just fine."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    seen_bearer: dict = {}
    reads: list = []
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                _apply_auth(page, base_url or link, headers)

                def _on_request(req):
                    with contextlib.suppress(Exception):
                        authz = req.headers.get("authorization", "")
                        if authz[:7].lower() == "bearer " and len(authz) > 27:
                            seen_bearer["token"] = authz[7:]
                        apikey = req.headers.get("apikey")
                        if req.method == "GET" and apikey and "/rest/v1/" in req.url and len(reads) < 10:
                            if not any(r["url"] == req.url for r in reads):
                                reads.append({"url": req.url, "apikey": apikey})
                page.on("request", _on_request)
                with contextlib.suppress(Exception):
                    page.goto(link, timeout=int(timeout * 1000), wait_until="commit")
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=8000)
                page.wait_for_timeout(500)
                cookies = []
                with contextlib.suppress(Exception):
                    cookies = page.context.cookies()
                jar = [{"name": c["name"], "value": c.get("value", ""),
                        "httponly": bool(c.get("httpOnly")), "secure": bool(c.get("secure")),
                        "samesite": (c.get("sameSite") or "").lower() in ("lax", "strict")}
                       for c in cookies]
                stored = _extract_storage_token(page)
                bearer = stored.get("token") or seen_bearer.get("token")
                if not jar and not bearer:
                    return None   # the link established no session -> inert verification (qa-email-002's concern)
                return {"cookies": jar, "bearer": bearer,
                        "storage_exposed": bool(stored.get("token")), "backend_reads": reads}
            finally:
                b.close()
    except Exception:
        return None


# ---- stale UI after a save (qa-staleui-001) ------------------------------------------------------
# The "it said nothing happened, but a refresh shows it saved" bug: the write IS durable but the SPA never
# refetched/optimistically-rendered, so the user thinks their save was lost. Provable black-box because the
# RELOAD is the ground truth — post-reload presence proves the write persisted; pre-reload absence proves the
# UI didn't reflect it. Read via inner_text (NOT content()): an input still holding the marker isn't DISPLAYED,
# so it can't masquerade as a reflected item.
_CREATE_ROUTES = ["/", "/dashboard", "/app", "/home", "/items", "/new", "/create", "/notes", "/tasks", "/posts", "/todos"]
_CREATE_SUBMIT = re.compile(r"\b(add|create|save|post|submit|new|send|share)\b", re.I)


def _fill_create_form(page, marker) -> bool:
    """Fill ONE visible text input/textarea with `marker` and submit a create — NOT a login/signup (skips
    password/email/file) and NOT a destructive action (_NO_CLICK). True iff a field was filled and submitted."""
    filled = False
    with contextlib.suppress(Exception):
        for el in page.query_selector_all("textarea, input"):
            with contextlib.suppress(Exception):
                if not el.is_visible():
                    continue
                typ = (el.get_attribute("type") or "text").lower()
                if typ not in ("text", "search", "url", ""):      # skip password/email/file/checkbox/number/etc.
                    continue
                hint = ((el.get_attribute("name") or "") + (el.get_attribute("placeholder") or "")
                        + (el.get_attribute("aria-label") or "")).lower()
                if any(h in hint for h in ("search", "email", "pass", "user", "login", "query")):
                    continue                                       # a search box / auth field, not a create field
                el.fill(marker)
                filled = True
                break
    if not filled:
        return False
    with contextlib.suppress(Exception):
        for btn in page.query_selector_all("button, input[type=submit], [role=button]"):
            lbl = ((btn.inner_text() or "") + " " + (btn.get_attribute("value") or "")).strip().lower()[:60]
            if _CREATE_SUBMIT.search(lbl) and not _NO_CLICK.search(lbl) and btn.is_visible():
                btn.click(timeout=2500)
                return True
    with contextlib.suppress(Exception):
        page.keyboard.press("Enter")                              # fallback: submit the focused field's form
        return True
    return False


def check_create_reflection(base_url, marker, headers=None, timeout: float = 12.0):
    """Submit a create form (a text field filled with `marker`), then check whether the app reflects the new
    item in the DOM WITHOUT a reload. Returns 'stale' (absent live, present after reload -> the bug),
    'reflected' (present live -> clean), 'not_saved' (absent both -> not durable — data-integrity's finding),
    or 'inconclusive' (no create form reachable / no browser). `headers` authenticate the usually-gated page."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "inconclusive"
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return "inconclusive"
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                landed = None
                for route in _CREATE_ROUTES:                       # find a page that has a create form
                    with contextlib.suppress(Exception):
                        page.goto(base_url.rstrip("/") + route, timeout=timeout * 1000, wait_until="load")
                        if _fill_create_form(page, marker):
                            landed = base_url.rstrip("/") + route
                            break
                if landed is None:
                    return "inconclusive"
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=6000)   # let the app refetch/re-render
                    page.wait_for_timeout(800)                              # brief settle for a client re-render
                live = ""
                with contextlib.suppress(Exception):
                    live = page.inner_text("body")     # displayed text only -> a marker lingering in an input
                    #                                    field is NOT counted as reflected
                if marker in live:
                    return "reflected"
                with contextlib.suppress(Exception):      # not shown live -> RELOAD and see if it actually saved
                    page.goto(landed, timeout=timeout * 1000, wait_until="load")
                    page.wait_for_load_state("networkidle", timeout=6000)
                after = ""
                with contextlib.suppress(Exception):
                    after = page.inner_text("body")
                return "stale" if marker in after else "not_saved"
            finally:
                with contextlib.suppress(Exception):
                    b.close()
    except Exception:
        return "inconclusive"


# ---- dead / inert controls (qa-deadctrl-001) -----------------------------------------------------
# The AI-shell tell: a control that RENDERS but is wired to nothing — no handler, or one that no-ops. The
# interactive analogue of a broken link. Detected by OBSERVED BEHAVIOR, not static handler presence (event
# delegation binds one listener at the document root, so "no handler on the node" != dead in React/Vue —
# most of the corpus). Click a reveal-SAFE control and watch EVERY channel; a control that moves none is
# inert. Bias is deliberately toward FALSE NEGATIVES (any observed motion clears a control), so a fired
# finding is high-confidence and we never penalize a working app whose effect we merely failed to see.
# Safety: only visible, non-disabled controls that are NOT form submitters and NOT real links (that's the
# broken-link probe), and whose label is not on the _NO_CLICK denylist (never pay/delete/logout/checkout).
_INERT_TAG_JS = r"""() => {
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const ok = el => {
    if (!vis(el) || el.disabled) return false;
    // an already-active tab / pressed toggle / selected segment correctly no-ops when re-clicked -> excluding
    // it is not a dead control (a confirmed FP class); aria-disabled is the ARIA disabled the .disabled DOM
    // property misses on role=button divs and styled toggles.
    const aria = k => (el.getAttribute(k) || '').toLowerCase();
    if (aria('aria-disabled') === 'true' || aria('aria-selected') === 'true' || aria('aria-pressed') === 'true') return false;
    const t = el.tagName;
    // a <button> defaults to type=submit even with no attribute, so gate on "submits a REAL form" (el.form),
    // not the type alone — else every plain button (type=submit, but no form) would be wrongly excluded.
    if (t === 'BUTTON') return !((el.type === 'submit' || el.type === 'reset') && el.form);
    if (t === 'A') { const h = (el.getAttribute('href') || '').trim();        // a real link is the link probe's job;
      return h === '' || h === '#' || h.toLowerCase().startsWith('javascript:'); }  // an <a> acting as a button IS ours
    return (el.getAttribute('role') || '').toLowerCase() === 'button';        // role=button div/span
  };
  const els = [...document.querySelectorAll('button, a, [role=button]')].filter(ok);
  els.forEach((el, i) => el.setAttribute('data-hl-btn', String(i)));
  return els.map(el => (el.innerText || el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 60));
}"""
# Re-installed on EVERY navigation (add_init_script): counts DOM mutations + app-initiated fetch/XHR. The
# Playwright-side page.on hooks below add ALL network (img/beacon), dialogs, and uncaught errors as channels.
_INERT_WATCH_JS = r"""(() => {
  window.__hlw = {muts: 0, reqs: 0, clip: 0, scroll: 0};
  // this init script runs BEFORE <html> is parsed, so documentElement can be null here -> defer the
  // observer to DOMContentLoaded (else observe(null) throws and NO DOM mutation is ever recorded).
  const arm = () => { try { new MutationObserver(m => { window.__hlw.muts += m.length; })
      .observe(document.documentElement, {subtree: true, childList: true, attributes: true, characterData: true}); } catch (e) {} };
  if (document.documentElement) arm(); else document.addEventListener('DOMContentLoaded', arm);
  const wrap = (o, k) => { const f = o[k]; if (f) o[k] = function () { window.__hlw.reqs++; return f.apply(this, arguments); }; };
  wrap(window, 'fetch');
  if (window.XMLHttpRequest) wrap(XMLHttpRequest.prototype, 'open');
  // off-channel effects a WORKING control commonly has (the two biggest dead-control FP classes): smooth-scroll
  // nav and copy-to-clipboard. Watched here so they CLEAR a control instead of reading as "dead". Scroll uses
  // capture so a scrollable-container scroll counts too; Playwright's own click-time scroll is excluded by
  // scrolling the control into view BEFORE the per-click counter reset (see inert_controls).
  window.addEventListener('scroll', () => { window.__hlw.scroll++; }, true);
  try { const c = navigator.clipboard, w = c && c.writeText;
        if (w) c.writeText = function () { window.__hlw.clip++; return w.apply(this, arguments); }; } catch (e) {}
  const ec = document.execCommand;
  if (ec) document.execCommand = function (cmd) { if (/copy|cut/i.test(cmd || '')) window.__hlw.clip++;
        return ec.apply(this, arguments); };
})()"""


def _quiet_close(popup):
    with contextlib.suppress(Exception):
        popup.close()


def inert_controls(url: str, headers=None, timeout: float = 12.0, max_controls: int = 10,
                   per_wait_ms: int = 400, total_timeout: float = 40.0) -> list | None:
    """Click each reveal-safe control on the page and return the labels of the ones that produced NO
    observable effect on ANY watched channel — inert ("dead") controls. None if no browser or the render
    fails; [] if every control did something. Channels: DOM mutation / network / navigation / dialog /
    uncaught error / scroll (smooth-scroll nav) / clipboard (copy) / popup (window.open) / file-chooser
    (upload) / download (a file link). Observed behavior, so event-delegated handlers (invisible to a static check) still clear a
    control; a control whose only effect is slower than per_wait_ms reads as live-or-skipped, never dead —
    the miss-don't-invent bias that keeps this safe to score. Already-active tabs/toggles (aria-selected/
    pressed) are not clicked (re-clicking them is a correct no-op, not a dead control)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                net, dialogs, errs = {"n": 0}, {"n": 0}, {"n": 0}
                popups, choosers, downloads = {"n": 0}, {"n": 0}, {"n": 0}
                page.on("request", lambda r: net.__setitem__("n", net["n"] + 1))         # ALL network (img/beacon too)
                page.on("dialog", lambda d: (dialogs.__setitem__("n", dialogs["n"] + 1), d.dismiss()))
                page.on("pageerror", lambda e: errs.__setitem__("n", errs["n"] + 1))
                # window.open (wallet-connect, OAuth, "open in new tab") and the native file picker (a <button>
                # that triggers a hidden <input type=file> — the standard upload pattern) are real effects off
                # the DOM/network channels; watch them so those controls clear instead of reading as dead.
                page.on("popup", lambda p: (popups.__setitem__("n", popups["n"] + 1), _quiet_close(p)))
                page.on("filechooser", lambda fc: choosers.__setitem__("n", choosers["n"] + 1))
                # a <a href="report.csv"> / <a download> triggers a file download, not a nav/DOM change -- a real
                # effect off the other channels, so watch it or those controls read as dead (killthebill's
                # 'Sample 1/2' CSV links were the qa-deadctrl-001 FP class).
                page.on("download", lambda d: downloads.__setitem__("n", downloads["n"] + 1))
                page.add_init_script(script=_INERT_WATCH_JS)   # re-installs the watcher on every navigation
                _apply_auth(page, url, headers)
                page.goto(url, timeout=timeout * 1000, wait_until="load")
                page.wait_for_timeout(300)
                labels = page.evaluate(_INERT_TAG_JS) or []
                dead, deadline = [], time.monotonic() + total_timeout
                for i, label in enumerate(labels):
                    if i >= max_controls or time.monotonic() > deadline:
                        break
                    if _NO_CLICK.search(label or ""):
                        continue   # never click a destructive-labeled control (pay/delete/logout/checkout/...)
                    with contextlib.suppress(Exception):
                        loc = page.locator(f'[data-hl-btn="{i}"]')
                        # Playwright auto-scrolls a control into view to click it; do that scroll BEFORE the
                        # counter reset so it isn't miscounted as the app's own scroll — then the only scroll we
                        # read is the effect of the click (e.g. a smooth-scroll nav anchor).
                        with contextlib.suppress(Exception):
                            loc.scroll_into_view_if_needed(timeout=1000)
                        page.evaluate("() => { if (window.__hlw) { window.__hlw.muts = 0; window.__hlw.reqs = 0;"
                                      " window.__hlw.clip = 0; window.__hlw.scroll = 0; } }")
                        n0, d0, e0, p0, f0, dl0, url0 = (net["n"], dialogs["n"], errs["n"], popups["n"],
                                                         choosers["n"], downloads["n"], page.url)
                        loc.click(timeout=1500)
                        page.wait_for_timeout(per_wait_ms)
                        w = page.evaluate("() => window.__hlw || {muts: 0, reqs: 0, clip: 0, scroll: 0}")
                        navigated = page.url != url0
                        moved = ((w.get("muts") or 0) or (w.get("reqs") or 0) or (w.get("clip") or 0)
                                 or (w.get("scroll") or 0) or (net["n"] - n0) or (dialogs["n"] - d0)
                                 or (errs["n"] - e0) or (popups["n"] - p0) or (choosers["n"] - f0)
                                 or (downloads["n"] - dl0) or navigated)
                        if not moved:
                            dead.append(label or "(unlabeled)")
                        if navigated:   # a live control that navigated away -> restore + re-tag to continue
                            page.goto(url, timeout=timeout * 1000, wait_until="load")
                            page.wait_for_timeout(200)
                            page.evaluate(_INERT_TAG_JS)
                return dead
            finally:
                b.close()
    except Exception:
        return None




# Accessibility is graded with axe-core (Deque), the gold-standard WCAG engine, injected into the render.
# axe splits results into `violations` (algorithmically DETERMINABLE — a rule definitively failed) and
# `incomplete` (needs a human to decide). We take `violations` only, filtered to the WCAG 2 A/AA
# conformance target (excludes best-practice opinions + aspirational AAA) — so the ingested corpus lands
# squarely on our objective/intent-independent axis, and `incomplete` is left to the human judge.
# WCAG 2.0/2.1 A/AA — the established conformance target (ADA / Section 508 / EN 301 549), the SCORED set.
_AXE_WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
# v2.0 FAMILY 2: the candidate expansion (WCAG 2.2 AA + axe best-practice: target-size, landmarks, heading
# order, skip links, ...). Run alongside the scored set but captured OFF-SCORE (see a11y_violations_present),
# so the next corpus re-grade can measure each rule's DECORRELATION from the existing a11y carrier before any
# of it is promoted to the score. This is the "gauge its precision on real apps first" the old comment asked
# for. target-size is enabled explicitly (axe ships it disabled by default).
_AXE_ADVISORY_TAGS = ["wcag22aa", "best-practice"]
_AXE_JS_CACHE: str | None = None


def _axe_js() -> str:
    global _AXE_JS_CACHE
    if _AXE_JS_CACHE is None:
        _AXE_JS_CACHE = (pathlib.Path(__file__).resolve().parent / "vendor" / "axe.min.js").read_text("utf-8")
    return _AXE_JS_CACHE


# Contrast is the ONE accessibility check that needs the CASCADE: the effective text and background
# colors come from stylesheets + inheritance, which only a rendered DOM resolves (getComputedStyle) --
# the static probe can only see inline styles. We compute the WCAG contrast ratio and count text that
# fails the universal 3:1 FLOOR (fails even for large text, so it's unarguable regardless of font size),
# matching the static inline-contrast threshold. Background is the first opaque ancestor (default white).
_CONTRAST_JS = r"""() => {
  const lum = c => { const f = x => { x/=255; return x<=0.03928 ? x/12.92 : Math.pow((x+0.055)/1.055,2.4); };
    return 0.2126*f(c[0]) + 0.7152*f(c[1]) + 0.0722*f(c[2]); };
  const parse = s => { const m = (s||'').match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/);
    return m ? [+m[1],+m[2],+m[3], m[4]===undefined?1:+m[4]] : null; };
  const bg = el => { while (el) { const c = parse(getComputedStyle(el).backgroundColor);
    if (c && c[3] !== 0) return c; el = el.parentElement; } return [255,255,255]; };
  let v = 0;
  document.querySelectorAll('body *').forEach(el => {
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own) return;                                    // only elements with their OWN visible text
    const st = getComputedStyle(el);
    if (st.visibility === 'hidden' || st.display === 'none' || +st.opacity === 0) return;
    const fg = parse(st.color); if (!fg || fg[3] === 0) return;
    const ratio = (Math.max(lum(fg), lum(bg(el))) + 0.05) / (Math.min(lum(fg), lum(bg(el))) + 0.05);
    if (ratio < 3.0) v++;
  });
  return v;
}"""


def _eval_page(url, headers, timeout, js_list):
    """Render url once and return the summed result of each JS expression, or None if no browser/render."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                _apply_auth(page, url, headers)
                page.goto(url, timeout=timeout * 1000, wait_until="load")
                page.wait_for_timeout(300)
                return sum(page.evaluate(js) for js in js_list)
            finally:
                b.close()
    except Exception:
        return None


def _contrast_data(violation) -> list:
    """The measured contrast ratio and the ratio WCAG REQUIRED, per failing node.

    Both are needed, not just the ratio: WCAG asks 4.5:1 of body text but only 3:1 of large text, so the
    honest severity measure is the SHORTFALL (ratio / required). A 2.5:1 heading is a 0.83 shortfall while
    2.5:1 body text is 0.56 — the same ratio, genuinely different harm, because larger glyphs stay legible
    at lower contrast (which is exactly why WCAG relaxes the bar for them).

    axe files the measurement under whichever check matched, so all three groups are searched. Nodes whose
    background axe could not resolve carry no contrastRatio and are skipped rather than guessed at."""
    out = []
    for node in violation.get("nodes") or []:
        for group in ("any", "all", "none"):
            for chk in node.get(group) or []:
                data = chk.get("data") or {}
                ratio = data.get("contrastRatio")
                if not isinstance(ratio, (int, float)):
                    continue
                req = data.get("expectedContrastRatio")   # "4.5:1"
                if isinstance(req, str):
                    try:
                        req = float(req.split(":")[0])
                    except ValueError:
                        req = None
                out.append({"ratio": round(float(ratio), 2),
                            "required": float(req) if isinstance(req, (int, float)) else None})
    return out


def a11y_violations(url: str, headers=None, timeout: float = 12.0) -> list | None:
    """Render url, inject axe-core, and return its violations as [{id, impact, tags}] — the WCAG 2 A/AA SCORED
    ruleset (~100 rules incl. contrast, ARIA, structure) PLUS the Family-2 advisory candidates (WCAG 2.2 AA +
    axe best-practice). `tags` lets the caller partition scored-vs-advisory. None if no browser / render fails."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page(bypass_csp=True)   # inject our audit tool even when the target sets a CSP
                _apply_auth(page, url, headers)
                page.goto(url, timeout=timeout * 1000, wait_until="load")
                try:                                              # let the SPA finish its post-load render +
                    page.wait_for_load_state("networkidle", timeout=8000)   # data fetch BEFORE axe scans, else
                except Exception:                                 # it scans a half-rendered DOM and under-counts
                    page.wait_for_timeout(300)                    # violations (and the count flaps between runs)
                page.add_script_tag(content=_axe_js())            # defines window.axe
                results = page.evaluate(
                    "() => axe.run(document, {runOnly: {type: 'tag', values: %s}, "
                    "rules: {'target-size': {enabled: true}}})" % json.dumps(_AXE_WCAG_TAGS + _AXE_ADVISORY_TAGS))
                out = []
                for v in results.get("violations", []):
                    rec = {"id": v["id"], "impact": v.get("impact"), "tags": v.get("tags") or []}
                    if v["id"] == "color-contrast":
                        # axe fixes this rule's impact at "serious" regardless of HOW unreadable the text is,
                        # so 4.4:1 (a hair under AA) and 1.1:1 (effectively invisible) arrive identical. Keep
                        # the measured ratios so severity can be graded downstream instead of flattened.
                        rec["contrast"] = _contrast_data(v)
                    out.append(rec)
                return out
            finally:
                b.close()
    except Exception:
        return None


def contrast_violations(url: str, headers=None, timeout: float = 12.0) -> int | None:
    """Render url and count text whose computed contrast is below the 3:1 floor (needs the cascade -> a
    real browser). Isolated from the presence checks for direct testing. None if no browser/render."""
    return _eval_page(url, headers, timeout, [_CONTRAST_JS])


def _first_party_error(msg: str, stack: str, origin: str) -> bool:
    """A pageerror is the APP's OWN when it isn't the cross-origin-sanitized "Script error." and its stack
    points at the app's origin or an inline script (no cross-origin URL). A third-party widget/analytics
    script that throws on another origin is browser-sanitized to a bare "Script error." with no usable
    stack, or its stack names only a foreign host -> benign noise a working app commonly carries."""
    if msg.strip().rstrip(".").lower() == "script error":
        return False
    # keep the ':' so a host:port survives; urlparse takes netloc up to the first '/', so a trailing
    # ':line:col' from the stack frame lands in the path and doesn't corrupt the host:port comparison.
    urls = re.findall(r"https?://[^\s)]+", stack)
    if not urls:
        return True   # inline / same-document script, no cross-origin frame -> the app's own code
    return any(urllib.parse.urlparse(u).netloc == origin for u in urls)


# render-health, evaluated in the SAME render that captures the errors: visible body text length + whether a
# framework crash overlay/message is on the page. Lets the probe SCALE — an uncaught error that left the page
# rendered and overlay-free is a real defect but not a functional break; one showing a crash screen is full.
_RENDER_HEALTH_JS = r"""() => {
  const body = document.body;
  const text = (body && body.innerText || '').trim();
  const html = body ? body.innerHTML : '';
  const overlay = /Application error: a client-side exception|Unhandled Runtime Error|react-error-overlay|vite-error-overlay|nextjs__container_errors/i.test(html);
  return { content_len: text.length, error_overlay: overlay };
}"""


# v2.0 Family 3 -- widen console capture beyond uncaught throws. A CSP that blocks the app's OWN resource and a
# React hydration mismatch are real functional breakages a browser reports as console.error (NOT pageerror), so
# the old pageerror-only hook dropped them (qa-console-001 fired only ~39x on the corpus). Curated to two
# high-precision classes, NOT all console.error, so library log-spam / benign warnings never register.
_CSP_VIOLATION = re.compile(r"Content Security Policy|Refused to (?:load|execute|apply|connect|frame)", re.I)
_HYDRATION_ERROR = re.compile(
    r"Hydration failed|Text content does not match|error while hydrating|did not match\. Server|"
    r"Minified React error #(?:418|423|425)", re.I)   # React hydration error codes


def _console_failure(text: str, origin: str) -> str | None:
    """Classify a console.error the pageerror hook misses. A hydration / React error is the app's OWN -> 'first'.
    A CSP violation is 'first' ONLY when it blocks a SAME-ORIGIN resource (the app's own CSP against its own
    code); a third-party-only block is the CSP working as intended -> 'third'; an unattributable inline block
    (no URL -- could be an injected third-party inline the CSP correctly stopped) -> None. Anything else -> None
    (log spam, a 404'd beacon, a benign lib warning), so this never widens into noise."""
    if _HYDRATION_ERROR.search(text):
        return "first"
    if _CSP_VIOLATION.search(text):
        urls = re.findall(r"https?://[^\s'\"]+", text)
        if any(urllib.parse.urlparse(u).netloc == origin for u in urls):
            return "first"                        # a same-origin resource the app's own CSP blocked -> breakage
        return "third" if urls else None          # third-party block = CSP working; inline = unattributable -> drop
    return None


def _tally_console(pageerrors: list, console_errors_text: list, origin: str) -> dict:
    """Fold pageerror throws + curated console.error failures into first/third/total counts. Factored out (pure)
    for testing. `sources` records how many first-party came from each channel, so a widened fire is auditable."""
    pe_fp = sum(1 for msg, stack in pageerrors if _first_party_error(msg, stack, origin))
    classes = [_console_failure(t, origin) for t in console_errors_text]
    c_fp = sum(1 for c in classes if c == "first")
    c_tp = sum(1 for c in classes if c == "third")
    return {"first_party": pe_fp + c_fp, "third_party": (len(pageerrors) - pe_fp) + c_tp,
            "total": len(pageerrors) + c_fp + c_tp, "sources": {"pageerror": pe_fp, "console": c_fp}}


def console_errors(url: str, headers=None, timeout: float = 12.0) -> dict | None:
    """Render url and capture the app's OWN load-time JavaScript failures: uncaught throws (pageerror) PLUS the
    curated console.error classes a throw hook misses -- a self-blocking CSP and a React hydration mismatch
    (v2.0 Family 3). Split FIRST-PARTY (real breakage) vs THIRD-PARTY (a cross-origin widget the app renders
    without -> benign). Returns {first_party, third_party, total, sources, content_len, error_overlay} or None
    if no browser / render fails. Still ignores console.log spam, a 404'd beacon, and missing source maps."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    origin = urllib.parse.urlparse(url).netloc
    try:
        errs, console = [], []
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                page.on("pageerror", lambda e: errs.append((str(getattr(e, "message", "") or e),
                                                            str(getattr(e, "stack", "") or ""))))
                page.on("console", lambda m: console.append(m.text) if m.type == "error" else None)
                _apply_auth(page, url, headers)
                page.goto(url, timeout=timeout * 1000, wait_until="load")
                page.wait_for_timeout(500)  # let late/async errors surface
                try:                        # render-health so the probe can SCALE the penalty by impact
                    health = page.evaluate(_RENDER_HEALTH_JS)
                except Exception:
                    health = {}
            finally:
                b.close()
        res = _tally_console(errs, console, origin)
        res["content_len"] = health.get("content_len")
        res["error_overlay"] = bool(health.get("error_overlay"))
        return res
    except Exception:
        return None


# v2.0 FAMILY 4 -- page-quality metrics from one render: (1) is the LCP element an <img>, and its loading attr
# (loading=lazy on the LCP image DELAYS first paint -- a modern anti-pattern the observer catches), and (2) the
# total DOM node count (an excessive DOM slows layout/style/interaction -- Lighthouse dom-size). The LCP
# observer is injected BEFORE load so it captures the real paint.
_METRICS_JS = """(() => {
  window.__hlm = {lcp_is_img: false, lcp_loading: ''};
  const obs = (t, cb) => { try { new PerformanceObserver(cb).observe({type: t, buffered: true}); } catch (e) {} };
  obs('largest-contentful-paint', l => {
    const es = l.getEntries(); if (!es.length) return;
    const el = es[es.length - 1].element;
    window.__hlm.lcp_is_img = !!(el && el.tagName === 'IMG');
    window.__hlm.lcp_loading = (el && el.getAttribute && (el.getAttribute('loading') || '').toLowerCase()) || '';
  });
})()"""




# Core Web Vitals — LCP (largest content paint), CLS (layout shift), total blocking time (main-thread
# jank) — measured by a PerformanceObserver injected BEFORE load, over N renders throttled to a mid-tier
# device (4x CPU + Slow-4G, Lighthouse's lab profile), so a bad number means bad on a REAL device, not
# flattered by a fast sandbox. The predicate scores off the player-favorable edge (best-of-N), so
# measurement variance can only ever help a player -- the app must be poor even on its best run to fire.
_VITALS_JS = """(() => {
  window.__hlv = {lcp: 0, cls: 0, tbt: 0};
  const obs = (t, cb) => { try { new PerformanceObserver(cb).observe({type: t, buffered: true}); } catch (e) {} };
  obs('largest-contentful-paint', l => { const es = l.getEntries(); if (es.length) window.__hlv.lcp = es[es.length - 1].startTime; });
  obs('layout-shift', l => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__hlv.cls += e.value; });
  obs('longtask', l => { for (const e of l.getEntries()) if (e.duration > 50) window.__hlv.tbt += (e.duration - 50); });
})()"""

# Lighthouse's standard mobile lab throttle -> the published CWV device profile (distinct from perf.py's
# transfer profile, which grades server-side load time). ~Slow 4G: 150ms RTT, 1.6Mbps down, 750Kbps up.
_CWV_THROTTLE = {"offline": False, "latency": 150, "downloadThroughput": 200_000, "uploadThroughput": 93_750}




def dom_xss_executes(base_url: str, paths, params=("q",), max_attempts: int = 24,
                     total_timeout: float = 45.0, headers=None, payloads=None) -> bool:
    """Inject an executing payload into candidate query params of each path, render, and return True
    if it ran (the payload's JS set a window global) — i.e. XSS that *executes* in the DOM, which a
    source-only reflection check misses (reflected-that-executes and DOM-sink XSS). False if no
    browser or nothing executed. `payloads` overrides the default single DOM-sink payload with a
    broader per-context set (_XSS_EXEC_PAYLOADS) to CONFIRM a server-reflected candidate by real
    execution across attribute/script contexts; each goto is a fresh document, so the marker resets."""
    payloads = payloads or (_XSS_PAYLOAD,)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return False
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                attempts = 0
                deadline = time.monotonic() + total_timeout  # overall wall-clock cap: a slow-loris
                for path in paths:                            # target that stalls each goto can't tie
                    for param in params:                      # up the probe (24 x 8s would be ~3 min)
                        for payload in payloads:
                            if attempts >= max_attempts or time.monotonic() > deadline:
                                return False
                            attempts += 1
                            url = f"{base_url.rstrip('/')}{path}?{param}={urllib.parse.quote(payload)}"
                            with contextlib.suppress(Exception):
                                page.goto(url, timeout=8000, wait_until="load")
                                page.wait_for_timeout(150)
                                if page.evaluate("() => window.__hl_domxss") == _XSS_MARKER:
                                    return True  # fresh document each goto, so a hit is this page's
                return False
            finally:
                b.close()
    except Exception:
        return False


def _view_fp(page) -> frozenset:
    """A coarse fingerprint of the currently-DISPLAYED view: the set of 4+ char word tokens in the body text.
    Lets back-nav tell whether BACK restored the prior view's CONTENT, not just its URL — the common SPA bug
    is the URL popping back while the app, lacking a popstate handler, keeps showing the new view."""
    with contextlib.suppress(Exception):
        return frozenset(re.findall(r"[a-z0-9]{4,}", (page.inner_text("body") or "").lower()))
    return frozenset()


def back_button_broken(base_url: str, headers=None, timeout: float = 12.0):
    """Navigate IN-APP from the entry view to another route (click a same-origin router link — NOT a fresh
    goto, which the browser's own history would always restore), fire the browser BACK button, and check the
    app returns — by URL AND displayed content. Returns (verdict, detail): verdict is 'broken' (BACK did not
    restore the entry view — the SPA router hijacked history / has no popstate handler), 'ok', or
    'inconclusive' (no in-app navigation / no browser); detail carries the nav link + entry/after-click/
    after-back URLs + the restore signals, so a fired result is AUDITABLE, not an opaque boolean."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "inconclusive", {}
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return "inconclusive", {}
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                detail = {}
                page.goto(base_url.rstrip("/") + "/", timeout=timeout * 1000, wait_until="load")
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=5000)  # let the SPA finish painting BEFORE we
                page.wait_for_timeout(300)                                  # fingerprint -> a reproducible entry view
                url_a, fa = page.url.rstrip("/"), _view_fp(page)
                detail["entry_url"] = url_a
                if len(fa) < 3:
                    return "inconclusive", detail    # entry rendered ~nothing (partial/blank) -> can't judge restoration
                host = urllib.parse.urlparse(base_url).netloc
                link, href_used = None, None
                with contextlib.suppress(Exception):
                    for a in page.query_selector_all("a[href]"):
                        href = (a.get_attribute("href") or "").strip()
                        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                            continue
                        resolved = urllib.parse.urljoin(page.url, href)
                        pu = urllib.parse.urlparse(resolved)
                        if pu.netloc and pu.netloc != host:
                            continue                                    # external link
                        if resolved.rstrip("/") == url_a or _NO_CLICK.search((a.inner_text() or "")[:60].lower()):
                            continue                                    # same page, or logout/destructive
                        if a.is_visible():
                            link, href_used = a, (pu.path or href)
                            break
                if link is None:
                    return "inconclusive", detail                       # no in-app route link to exercise
                detail["nav_link"] = href_used
                with contextlib.suppress(Exception):
                    link.click(timeout=3000)
                    page.wait_for_load_state("networkidle", timeout=5000)
                    page.wait_for_timeout(300)
                url_b, fb = page.url.rstrip("/"), _view_fp(page)
                detail["after_click_url"] = url_b
                a_only, b_only = fa - fb, fb - fa
                if url_b == url_a and not b_only:
                    return "inconclusive", detail                       # the click didn't change the view
                with contextlib.suppress(Exception):
                    page.go_back(timeout=5000)
                    page.wait_for_load_state("networkidle", timeout=5000)   # settle the restored view before comparing
                    page.wait_for_timeout(300)
                url_c, fc = page.url.rstrip("/"), _view_fp(page)
                # AUTH-GATED back: the app sent Back to a real login FORM (a visible password field) or to an auth
                # URL -> the gate intercepted, so we never observe whether Back restores the prior view -> N/A, not
                # a 'dead back button'. NB: key on the password FIELD, not "log in" TEXT -- nearly every landing
                # page has a "Log in" nav button (toyota's marketing page, findmyseat), and matching that text
                # over-suppressed normal pages. The replaceState-skip (Back -> about:blank) and view-stuck-on-B
                # defects have no password field and no auth URL, so they still fire below.
                on_login_form = False
                with contextlib.suppress(Exception):
                    on_login_form = bool(page.evaluate("() => !!document.querySelector('input[type=password]')"))
                if on_login_form or _AUTH_URL.search(url_c):
                    detail["auth_gated_on_back"] = True
                    return "inconclusive", detail
                content_restored = len(fc & a_only) >= len(fc & b_only)
                detail.update(after_back_url=url_c, url_restored=(url_c == url_a), content_restored=content_restored)
                # restored = the entry URL is back AND A's distinctive content returned (not still showing B's)
                return ("ok" if (url_c == url_a and content_restored) else "broken"), detail
            finally:
                b.close()
    except Exception:
        return "inconclusive", {}


def _fp_sim(a: frozenset, b: frozenset) -> float:
    u = a | b
    return len(a & b) / len(u) if u else 0.0


# A route that renders a LOGIN/auth screen is auth-GATED (working correctly), not a broken deep link -- and when
# the app gates everything, the nonexistent-route fallback renders that same login screen, so a gated route
# matches it and reads as "broken". The blank-shell case (route+fallback both render the empty shell, no login)
# is the REAL broken deep link. This separates them: 9 of 16 sampled v18 fires were auth-gated, 7 genuinely broken.
_LOGIN_SCREEN_JS = """() => {
  const t = (document.body ? document.body.innerText : '').toLowerCase();
  return !!document.querySelector('input[type=password]')
      || /\\b(sign in|log in|login|signin|sign up|forgot password|continue with)\\b/.test(t);
}"""

# a URL that IS an auth route -- back-navigating to it means the app gated the Back nav (qa-backnav-001), which
# we cannot score as a "dead back button": we never got to observe whether Back restores the prior view.
_AUTH_URL = re.compile(r"/(?:login|log-?in|signin|sign-?in|sign_in|auth|register|signup|sign-?up)\b", re.I)


def deep_link_broken(base_url: str, routes, headers=None, timeout: float = 12.0, max_routes: int = 8):
    """FRESH-navigate (goto, not in-app) to a guaranteed-nonexistent route to capture the app's FALLBACK render
    (home / 404 / blank), then fresh-navigate to each discovered route; return ('broken', route) for the first
    that renders ~identically to the fallback (>= 0.92 word-set similarity -> no route-specific content, so a
    shared/bookmarked link is dead) AND is not merely an auth gate, else ('ok', None) or ('inconclusive', None).
    Tests the bookmarked-link path a catch-all host's 200 shell hides from an HTTP-only check."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return ("inconclusive", None)
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return ("inconclusive", None)
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                base = base_url.rstrip("/")
                fp_bogus = frozenset()
                with contextlib.suppress(Exception):
                    page.goto(base + "/hl-nonexistent-9z1x-deeplink", timeout=timeout * 1000, wait_until="load")
                    page.wait_for_timeout(400)
                    fp_bogus = _view_fp(page)
                if len(fp_bogus) < 3:
                    return ("inconclusive", None)          # fallback renders nothing -> can't compare reliably
                tested = 0
                for route in list(routes)[:max_routes]:
                    fp_r = frozenset()
                    with contextlib.suppress(Exception):
                        page.goto(base + route, timeout=timeout * 1000, wait_until="load")
                        page.wait_for_timeout(400)
                        fp_r = _view_fp(page)
                    if len(fp_r) < 3:
                        continue                            # this route rendered blank (slow load?) -> skip, conservative
                    tested += 1
                    if _fp_sim(fp_r, fp_bogus) >= 0.92:     # renders the same as a nonexistent route
                        is_login = False
                        with contextlib.suppress(Exception):
                            is_login = bool(page.evaluate(_LOGIN_SCREEN_JS))
                        if is_login:
                            continue                         # a login/auth screen -> auth-gated, not a dead deep link
                        return ("broken", route)
                return (("ok" if tested else "inconclusive"), None)
            finally:
                b.close()
    except Exception:
        return ("inconclusive", None)


_ERROR_WORDS = re.compile(r"\b(error|failed|failure|invalid|try again|went wrong|unable|couldn'?t|"
                          r"rejected|not saved|problem|oops|something went)\b", re.I)
_ANALYTICS_PATH = re.compile(r"analytic|telemetr|/track|/beacon|/collect|/metric|/event\b|sentry|"
                             r"segment|mixpanel|posthog|/pixel|/log\b", re.I)
_ERROR_DOM_JS = """() => {
  const sel = '[class*="error" i],[class*="danger" i],[class*="invalid" i],[role="alert"],'
            + '[aria-invalid="true"],[class*="toast" i],[class*="notif" i],[class*="alert" i]';
  for (const el of document.querySelectorAll(sel)) {
    if (el.offsetParent !== null && (el.innerText || '').trim().length > 0) return true;   // a VISIBLE error UI
  }
  return false;
}"""


def silent_failure_on_action(base_url: str, headers=None, timeout: float = 12.0) -> str:
    """Fill a create/save form, FORCE its submit request to fail (fulfill the same-origin POST/PUT/PATCH with
    500), and check the app shows a failure indication. Returns 'silent' (the action's request failed but NO
    error appeared in the DOM — the app silently lost the data or faked success), 'handled' (any error
    indication appeared), or 'inconclusive' (no form / the submit fired no mutating request / no browser). The
    forced failure makes the OUTCOME definitively failed (no silent-retry-succeeds to confuse it); analytics/
    telemetry beacons are excluded, so only the runner-initiated ACTION is tested."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "inconclusive"
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return "inconclusive"
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                host = urllib.parse.urlparse(base_url).netloc
                fired = {"n": 0}

                def _route(route):
                    with contextlib.suppress(Exception):
                        req = route.request
                        pu = urllib.parse.urlparse(req.url)
                        if req.method in ("POST", "PUT", "PATCH") and (not pu.netloc or pu.netloc == host) \
                                and not _ANALYTICS_PATH.search(pu.path):
                            fired["n"] += 1                       # the runner-initiated mutating action -> fail it
                            return route.fulfill(status=500, content_type="application/json", body='{"error":"hl-forced"}')
                    with contextlib.suppress(Exception):
                        return route.continue_()

                page.route("**/*", _route)                        # set BEFORE goto: page-load GETs pass through
                with contextlib.suppress(Exception):
                    page.goto(base_url.rstrip("/") + "/", timeout=timeout * 1000, wait_until="load")
                if not _fill_create_form(page, "hlnoerr"):
                    return "inconclusive"                         # no create form to submit
                page.wait_for_timeout(1600)                       # settle: propagate the failure + render any error
                if fired["n"] == 0:
                    return "inconclusive"                         # the submit fired no mutating request -> nothing failed
                shown = False
                with contextlib.suppress(Exception):
                    shown = bool(_ERROR_WORDS.search(page.inner_text("body") or "")) or bool(page.evaluate(_ERROR_DOM_JS))
                return "handled" if shown else "silent"
            finally:
                b.close()
    except Exception:
        return "inconclusive"


def stored_xss_executes(base_url: str, paths, headers=None, total_timeout: float = 45.0, max_pages: int = 20) -> bool:
    """Render each path PLAIN — NO injection, because an XSS payload was already STORED server-side via an API
    write — and return True if it EXECUTES: the app reflected the stored value unescaped into the DOM and it
    ran (window.__hl_domxss == the marker). The stored-XSS counterpart to dom_xss_executes (which injects into
    a query param). False if no browser or nothing executed; `headers` authenticate the (usually gated) feed
    so the stored item is actually on the page. Each goto is a fresh document, so a hit is that page's own."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return False
            try:
                page = b.new_page()
                _apply_auth(page, base_url, headers)
                deadline = time.monotonic() + total_timeout
                for path in list(paths)[:max_pages]:
                    if time.monotonic() > deadline:
                        break
                    with contextlib.suppress(Exception):
                        page.goto(base_url.rstrip("/") + path, timeout=8000, wait_until="load")
                        page.wait_for_timeout(200)   # let a client-rendered feed paint the stored value
                        if page.evaluate("() => window.__hl_domxss") == _XSS_MARKER:
                            return True
                return False
            finally:
                b.close()
    except Exception:
        return False
