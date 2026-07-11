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
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


# Pinned bundled Chromium first (reproducible), then any system browser. Bundled Chromium for
# Ubuntu 26.04 needs Playwright >= 1.61 (microsoft/playwright#40117); until that releases (latest is
# 1.60) the bundled launch fails here and a system Chrome/Edge channel is used instead.
_LAUNCH_ORDER = ({}, {"channel": "chromium"}, {"channel": "chrome"}, {"channel": "msedge"})


def _launch(p):
    for kwargs in _LAUNCH_ORDER:
        with contextlib.suppress(Exception):
            return p.chromium.launch(headless=True, **kwargs)
    return None


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
    r"add (a |an )?(file|photo|image|evidence|attachment|document|screenshot|picture)|"
    r"account|profile|menu|new (post|note|item|entry|report|upload)", re.I)
_NO_CLICK = re.compile(
    r"log ?out|sign ?out|delete|remove|pay\b|buy\b|checkout|subscribe|purchase|confirm|"
    r"download|share|tweet|facebook|instagram|external|https?://", re.I)


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


def render_routes(base_url: str, paths, headers=None, timeout: float = 12.0,
                  total_timeout: float = 60.0, interact: bool = True) -> dict[str, str]:
    """Render each same-origin path in ONE reused browser session and return {path: rendered_DOM}.
    Paths that fail to load are omitted; {} if no browser is available. A single launch is amortized
    across all routes — a launch-per-route helper would relaunch (and re-warm) the browser each time.
    Bounded by total_timeout so a slow-loris route can't stall the whole crawl (like dom_xss_executes).
    Used by discovery to harvest the client-rendered forms/inputs a SPA paints on routes OTHER than "/"
    (login, upload, search) — the interactive surface a single "/" render misses. Pass ["/"] for just
    the entry page."""
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
                deadline = time.monotonic() + total_timeout
                for path in paths:
                    if time.monotonic() > deadline:
                        break
                    url = base_url.rstrip("/") + path
                    with contextlib.suppress(Exception):
                        page.goto(url, timeout=timeout * 1000, wait_until="load")
                        page.wait_for_timeout(300)  # let client JS paint the route's forms/inputs
                        dom = page.content()
                        if interact:                # + surface interaction-gated login/upload controls
                            dom += _reveal_hidden_controls(page)
                        out[path] = dom
            finally:
                b.close()
    except Exception:
        return out
    return out


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
                page.wait_for_timeout(300)
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


def console_errors(url: str, headers=None, timeout: float = 12.0) -> int | None:
    """Render url and count uncaught JavaScript errors thrown on load (pageerror) — a page that throws
    as it renders is broken regardless of intent. None if no browser or the render fails."""
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
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                _apply_auth(page, url, headers)
                page.goto(url, timeout=timeout * 1000, wait_until="load")
                page.wait_for_timeout(500)  # let late/async errors surface
                return len(errors)
            finally:
                b.close()
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
