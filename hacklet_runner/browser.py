"""Headless-browser harness (Playwright). Renders a page so discovery sees client-rendered forms
and routes a static crawl misses (SPAs), and (later) so DOM/stored XSS and Core Web Vitals can be
measured. Optional: every entry point degrades to None when no browser is available, so the rest of
the runner is unaffected.

Browser-agnostic: tries Playwright's pinned bundled Chromium first (reproducible), then any system
browser (chromium / chrome / msedge channels), so it works wherever one is available.
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


def browser_available() -> bool:
    """True when a browser can ACTUALLY launch here — not merely when playwright imports (the old check,
    which let a broken/missing chromium read as 'available' and silently degrade a browser run to
    static-only). Tests skip on this; the CLIs use browser_preflight() for the (ok, detail) form."""
    return browser_preflight()[0]


# Pinned bundled Chromium first (reproducible), then any system browser. Bundled Chromium for
# Ubuntu 26.04 needs Playwright >= 1.61 (microsoft/playwright#40117); until that releases (latest is
# 1.60) the bundled launch fails here and a system Chrome/Edge channel is used instead.
_LAUNCH_ORDER = ({}, {"channel": "chromium"}, {"channel": "chrome"}, {"channel": "msedge"})


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


def _reveal_hidden_controls(page, max_clicks: int = 6, per_wait_ms: int = 350) -> str:
    """Click reveal-intent controls (login / upload / menu triggers) to surface INTERACTION-GATED forms
    and inputs a static render misses, and return the revealed <form>/modal HTML (appended to the route's
    dom for discovery to scan). Reveal-ONLY: never clicks a submit / pay / delete / logout / external
    control (_NO_CLICK), so it opens UI without acting on the app; bounded by max_clicks + an Escape reset
    between clicks so one page can't loop or drift far from its initial state."""
    revealed, seen, clicked = [], set(), 0
    _controls = "input, textarea, select, form"
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
                if key not in seen:
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


def render_routes(base_url: str, paths, headers=None, timeout: float = 12.0,
                  total_timeout: float = 60.0, interact: bool = True,
                  interact_routes: int = 6, net_sink: list | None = None) -> dict[str, str]:
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
                if net_sink is not None:              # harvest the app's OWN same-origin xhr/fetch calls as it
                    _host = urllib.parse.urlparse(base_url).netloc       # renders -> the REAL endpoint surface,
                    def _cap(req):                                       # vs the LLM guessing invisible API paths
                        with contextlib.suppress(Exception):
                            if (req.resource_type in ("xhr", "fetch")
                                    and urllib.parse.urlparse(req.url).netloc == _host and len(net_sink) < 100):
                                net_sink.append((req.method, req.url, req.post_data))
                    page.on("request", _cap)
                deadline = time.monotonic() + total_timeout
                for idx, path in enumerate(paths):
                    if time.monotonic() > deadline:
                        break
                    url = base_url.rstrip("/") + path
                    with contextlib.suppress(Exception):
                        page.goto(url, timeout=timeout * 1000, wait_until="load")
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
                hint = ((el.get_attribute("name") or "") + " " + (el.get_attribute("placeholder") or "") + " "
                        + (el.get_attribute("aria-label") or "") + " " + (el.get_attribute("id") or "")).lower()
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
_SIGNUP_ROUTES = ("/register", "/signup", "/sign-up", "/join", "/auth/register", "/auth/signup",
                  "/create-account", "/get-started")


def _reach_and_submit_signup(page, base_url, creds, timeout) -> bool:
    """Get to a fillable signup and submit it. The homepage (reveal an inline modal) first; if the signup lives
    on its OWN route — a 'Get Started' <a> link the reveal can't open — walk conventional signup paths and try
    each. True once a signup form was filled + submitted (the app's own JS then makes the real request)."""
    with contextlib.suppress(Exception):
        page.goto(base_url.rstrip("/") + "/", timeout=timeout * 1000, wait_until="load")
        page.wait_for_timeout(300)
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


def register_in_browser(base_url: str, headers=None, timeout: float = 12.0, total_timeout: float = 45.0):
    """SPA self-registration THROUGH the browser (the auth self-oracle's client-rendered path): open the signup
    form, fill throwaway creds, submit so the app's OWN JS makes the real registration request, and return the
    session cookie the server sets IN THE BROWSER — the thing an httpx form-POST can't get on an SPA (the form's
    action is a placeholder; the real POST lives in the JS). On the bolt/Supabase/Firebase cohort the session is
    NOT a cookie but a JWT (localStorage + Authorization: Bearer), so this ALSO returns that token. Returns
    {creds, cookies:[{name,value,httponly,secure,samesite}], request:{url,method,body}|None, bearer:str|None,
    storage_exposed:bool} or None (no browser / no fillable signup / NEITHER a cookie nor a token — email-verify /
    CAPTCHA / SSO). Best-effort + side-effecting: creates ONE throwaway account, like the httpx register; targets a
    SIGNUP form only (a password field), never login/pay/delete (the reveal + _NO_CLICK guards). Caller (auth)
    decides which cookie/token is the session and whether registration succeeded."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    import secrets
    uname = "hl_" + secrets.token_hex(5)
    creds = {"email": uname + "@example.com", "username": uname, "password": "Hl-Probe-Passw0rd!"}
    captured, seen_bearer, reads, out = {}, {}, [], None
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
                    return None   # no cookie AND no token -> registration didn't take (email-verify/CAPTCHA) -> N/A
                out = {"creds": creds, "cookies": jar, "request": captured or None,
                       "bearer": bearer, "storage_exposed": bool(stored.get("token")),
                       "backend_reads": reads}
            finally:
                b.close()
    except Exception:
        return None
    return out


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
  window.__hlw = {muts: 0, reqs: 0};
  // this init script runs BEFORE <html> is parsed, so documentElement can be null here -> defer the
  // observer to DOMContentLoaded (else observe(null) throws and NO DOM mutation is ever recorded).
  const arm = () => { try { new MutationObserver(m => { window.__hlw.muts += m.length; })
      .observe(document.documentElement, {subtree: true, childList: true, attributes: true, characterData: true}); } catch (e) {} };
  if (document.documentElement) arm(); else document.addEventListener('DOMContentLoaded', arm);
  const wrap = (o, k) => { const f = o[k]; if (f) o[k] = function () { window.__hlw.reqs++; return f.apply(this, arguments); }; };
  wrap(window, 'fetch');
  if (window.XMLHttpRequest) wrap(XMLHttpRequest.prototype, 'open');
})()"""


def inert_controls(url: str, headers=None, timeout: float = 12.0, max_controls: int = 10,
                   per_wait_ms: int = 400, total_timeout: float = 40.0) -> list | None:
    """Click each reveal-safe control on the page and return the labels of the ones that produced NO
    observable effect on ANY channel (DOM mutation / network / navigation / dialog / uncaught error) —
    inert ("dead") controls. None if no browser or the render fails; [] if every control did something.
    Observed behavior, so event-delegated handlers (invisible to a static check) still clear a control;
    a control whose only effect is slower than per_wait_ms, or off-channel (clipboard/print), reads as
    live-or-skipped, never dead — the miss-don't-invent bias that keeps this safe to score."""
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
                page.on("request", lambda r: net.__setitem__("n", net["n"] + 1))         # ALL network (img/beacon too)
                page.on("dialog", lambda d: (dialogs.__setitem__("n", dialogs["n"] + 1), d.dismiss()))
                page.on("pageerror", lambda e: errs.__setitem__("n", errs["n"] + 1))
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
                        page.evaluate("() => { if (window.__hlw) { window.__hlw.muts = 0; window.__hlw.reqs = 0; } }")
                        n0, d0, e0, url0 = net["n"], dialogs["n"], errs["n"], page.url
                        page.click(f'[data-hl-btn="{i}"]', timeout=1500)
                        page.wait_for_timeout(per_wait_ms)
                        w = page.evaluate("() => window.__hlw || {muts: 0, reqs: 0}")
                        navigated = page.url != url0
                        moved = ((w.get("muts") or 0) or (w.get("reqs") or 0) or (net["n"] - n0)
                                 or (dialogs["n"] - d0) or (errs["n"] - e0) or navigated)
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


def first_contentful_paint(url: str, headers=None, timeout: float = 12.0) -> float | None:
    """Render url and return First Contentful Paint in milliseconds (the user-facing 'time to see
    something' metric). None if no browser, render fails, or nothing ever paints."""
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
                page.wait_for_timeout(2500)  # allow delayed/contentful paint to occur
                return page.evaluate(
                    "() => { const e = performance.getEntriesByName('first-contentful-paint')[0];"
                    " return e ? e.startTime : null; }"
                )
            finally:
                b.close()
    except Exception:
        return None


# Accessibility is graded with axe-core (Deque), the gold-standard WCAG engine, injected into the render.
# axe splits results into `violations` (algorithmically DETERMINABLE — a rule definitively failed) and
# `incomplete` (needs a human to decide). We take `violations` only, filtered to the WCAG 2 A/AA
# conformance target (excludes best-practice opinions + aspirational AAA) — so the ingested corpus lands
# squarely on our objective/intent-independent axis, and `incomplete` is left to the human judge.
# WCAG 2.0/2.1 A/AA — the established conformance target (ADA / Section 508 / EN 301 549). We omit the
# newer WCAG 2.2 rules (e.g. target-size), which fire on default-sized controls across most well-built
# desktop pages and would false-positive; 2.2 can be revisited once we can gauge its precision on real apps.
_AXE_WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
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


def a11y_violations(url: str, headers=None, timeout: float = 12.0) -> list | None:
    """Render url, inject axe-core, and return its WCAG 2 A/AA violations as [{id, impact}] — the
    gold-standard deterministic a11y ruleset (~100 rules incl. contrast, ARIA, structure). None if no
    browser or the render fails."""
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
                    "() => axe.run(document, {runOnly: {type: 'tag', values: %s}})" % json.dumps(_AXE_WCAG_TAGS))
                return [{"id": v["id"], "impact": v.get("impact")} for v in results.get("violations", [])]
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


def console_errors(url: str, headers=None, timeout: float = 12.0) -> dict | None:
    """Render url and capture uncaught JavaScript errors thrown on load (pageerror), split into FIRST-PARTY
    (the app's own code threw -> a real breakage) and THIRD-PARTY (a widget/analytics script on another
    origin threw, or the browser sanitized a cross-origin error -> benign noise). Returns
    {"first_party", "third_party", "total"} or None if no browser / the render fails. Only pageerror is
    captured, so console.log spam, a 404'd analytics fetch, and a missing source map never register."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    origin = urllib.parse.urlparse(url).netloc
    try:
        errs = []
        with sync_playwright() as pw:
            b = _launch(pw)
            if b is None:
                return None
            try:
                page = b.new_page()
                page.on("pageerror", lambda e: errs.append((str(getattr(e, "message", "") or e),
                                                            str(getattr(e, "stack", "") or ""))))
                _apply_auth(page, url, headers)
                page.goto(url, timeout=timeout * 1000, wait_until="load")
                page.wait_for_timeout(500)  # let late/async errors surface
                try:                        # render-health so the probe can SCALE the penalty by impact
                    health = page.evaluate(_RENDER_HEALTH_JS)
                except Exception:
                    health = {}
            finally:
                b.close()
        fp = sum(1 for msg, stack in errs if _first_party_error(msg, stack, origin))
        return {"first_party": fp, "third_party": len(errs) - fp, "total": len(errs),
                "content_len": health.get("content_len"), "error_overlay": bool(health.get("error_overlay"))}
    except Exception:
        return None


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


def web_vitals(url: str, headers=None, timeout: float = 25.0, samples: int = 3) -> list | None:
    """Sample Core Web Vitals over N throttled renders; return [{lcp_ms, cls, tbt_ms}] per run (the caller
    scores off the player-favorable edge). None if no browser or the render fails."""
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
                out = []
                for _ in range(samples):
                    page = b.new_page()
                    try:
                        cdp = page.context.new_cdp_session(page)
                        cdp.send("Network.enable")
                        cdp.send("Network.emulateNetworkConditions", _CWV_THROTTLE)
                        cdp.send("Emulation.setCPUThrottlingRate", {"rate": 4})
                        page.add_init_script(script=_VITALS_JS)   # observers up before any page script
                        _apply_auth(page, url, headers)
                        page.goto(url, timeout=timeout * 1000, wait_until="load")
                        page.wait_for_timeout(2000)   # let LCP finalize + late layout shifts settle (throttled)
                        v = page.evaluate("() => window.__hlv")
                        out.append({"lcp_ms": round(v["lcp"]), "cls": round(v["cls"], 3), "tbt_ms": round(v["tbt"])})
                    finally:
                        page.close()
                return out
            finally:
                b.close()
    except Exception:
        return None


def dom_xss_executes(base_url: str, paths, params=("q",), max_attempts: int = 24,
                     total_timeout: float = 45.0, headers=None) -> bool:
    """Inject an executing payload into candidate query params of each path, render, and return True
    if it ran (the payload's JS set a window global) — i.e. XSS that *executes* in the DOM, which a
    source-only reflection check misses (reflected-that-executes and DOM-sink XSS). False if no
    browser or nothing executed."""
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
                        if attempts >= max_attempts or time.monotonic() > deadline:
                            return False
                        attempts += 1
                        url = f"{base_url.rstrip('/')}{path}?{param}={urllib.parse.quote(_XSS_PAYLOAD)}"
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
