"""Team-facing durability REPORT CARD: turn a grade record into per-finding feedback so a team that fails
the fuzzer knows exactly where and how to improve. Every finding renders four fields:

    1. EXPECTED     — what a durable app should have done
    2. ACTUAL       — what we actually observed (from the finding evidence)
    3. INDICATES    — what the failure is symptomatic of (the risk/weakness class)
    4. REMEDIATION  — how to fix it

Two DISCLOSURE tiers, driven by the probe's `pool` (schema.Probe.pool = public | hidden):
  - PUBLIC findings get the full four-field breakdown — teams learn and fix REAL durability, so teaching to
    these tests IS the goal (a real 429, real headers, real escaping = a genuinely more durable app).
  - HIDDEN findings (HackLet League's anti-gaming set) are WITHHELD from the team card as an opaque count and
    revealed only in the organizer view (`organizer=True`). Teams can't teach-to-the-test on checks they
    can't see, so a team that only surface-patched the public checks still fails the hidden variants and its
    score reflects real durability, not gaming. Both tiers count toward the score identically — only the
    DISCLOSURE differs, never the math.

The authored copy below covers every probe that fires in practice; an unauthored probe degrades gracefully
to its catalog `reason` plus a generic remediation pointer (never blank, never crashes)."""
from __future__ import annotations

import html
import pathlib

from .catalog import load_catalog

# (expected, indicates, remediation) keyed by probe_id. Kept terse + concrete — this is copy a team reads
# while fixing, not spec prose.
_CONTENT: dict[str, tuple[str, str, str]] = {
    # ---- security: headers -------------------------------------------------------------------------
    "sec-headers-001": ("Responses carry `X-Content-Type-Options: nosniff`.",
                        "Without it a browser may MIME-sniff a response and execute it as the wrong type — an XSS/content-confusion vector.",
                        "Send `X-Content-Type-Options: nosniff` on every response (one line in your server/CDN config)."),
    "sec-headers-002": ("A `Content-Security-Policy` restricts where scripts, styles, and frames may load from.",
                        "No CSP means zero defense-in-depth: if any XSS slips through, nothing contains it.",
                        "Add a CSP. Start strict — `default-src 'self'` — then loosen per real need; prefer nonces over `'unsafe-inline'`."),
    "sec-headers-003": ("HTTPS responses send `Strict-Transport-Security` (HSTS).",
                        "Without HSTS a network attacker can downgrade the connection to HTTP and strip TLS (SSL-strip MITM).",
                        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS."),
    "sec-headers-004": ("A clickjacking defense is present (`X-Frame-Options` or CSP `frame-ancestors`).",
                        "The page can be embedded in a hostile `<iframe>` and used to trick users into clicking through your UI (clickjacking).",
                        "Send `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`), relaxing only for frames you actually need."),
    "sec-headers-005": ("A `Referrer-Policy` limits what URL data leaks to third parties.",
                        "Full URLs — which can carry tokens, ids, or private paths — leak to external sites via the `Referer` header.",
                        "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."),
    "sec-headers-006": ("The stack/version is not advertised in response headers.",
                        "`X-Powered-By` (or `Server` version) tells an attacker your exact framework and version, narrowing their exploit search.",
                        "Strip it — e.g. Express `app.disable('x-powered-by')`, or remove it at the proxy."),
    # ---- security: real vulns ----------------------------------------------------------------------
    "sec-ratelimit-001": ("Repeated failed logins get throttled (HTTP 429/423) after a few attempts.",
                          "No brute-force protection on auth — an attacker can credential-stuff or password-spray unlimited guesses.",
                          "Rate-limit auth endpoints (e.g. `express-rate-limit`); lock or slow down after N failures per IP + account."),
    "sec-csrf-001": ("State-changing requests require a CSRF token or a `SameSite` cookie.",
                     "Cross-site request forgery: a malicious page can make the victim's browser perform authenticated actions.",
                     "Set session cookies `SameSite=Lax` (or Strict) and require a CSRF token on every mutating request."),
    "sec-cors-001": ("CORS does not reflect an arbitrary `Origin` while allowing credentials.",
                     "Any website can read your authenticated API responses on a victim's behalf — an account-takeover class bug.",
                     "Allow-list specific origins; never combine a reflected `Origin` with `Access-Control-Allow-Credentials: true`."),
    "sec-xss-001": ("User input is escaped/encoded before it reaches the HTML.",
                    "Reflected XSS — attacker-controlled markup executes as script in the victim's session.",
                    "Rely on framework auto-escaping, encode output by context, and add a CSP as a backstop."),
    "sec-sqli-004": ("Query parameters are parameterized, not concatenated into SQL.",
                     "SQL injection — an attacker can read/modify/destroy the database or bypass auth.",
                     "Use parameterized queries or an ORM; never string-build SQL from user input."),
    "sec-lfi-001": ("Filename/path parameters cannot escape the intended directory.",
                    "Path traversal / local file inclusion — arbitrary server files (secrets, source, `/etc/passwd`) become readable.",
                    "Canonicalize and validate paths against an allow-list; never pass user input straight to a filesystem read."),
    "sec-exposure-001": ("Dotfiles like `.env` are not served.",
                         "A secrets file is publicly downloadable — API keys, DB credentials, and tokens are exposed.",
                         "Block dotfiles at the server/CDN and keep `.env` out of the deployed artifact. Rotate any exposed secret now."),
    "sec-exposure-002": ("The `.git` directory is not served.",
                         "`.git/config` is public — your full source repository (history, secrets in old commits) is reconstructable.",
                         "Don't deploy `.git`; block it at the web server."),
    "sec-exposure-003": ("The `.git` directory is not served.",
                         "`.git/HEAD` is public — your full source repository is downloadable and reconstructable.",
                         "Don't deploy `.git`; block it at the web server."),
    "sec-exposure-006": ("Production JS bundles do not ship their source maps.",
                         "A served `.map` lets anyone reconstruct your original source — logic, comments, and sometimes embedded secrets.",
                         "Disable source-map emission in the production build, or restrict `.map` access to internal tooling."),
    "sec-secrets-001": ("No private keys or cloud/API tokens appear in client-delivered content.",
                        "A live secret is public — it can be used to run up your bill, read your data, or impersonate your service.",
                        "Move the secret server-side behind a proxy, rotate it immediately, and load it from an env var."),
    "sec-secrets-002": ("No hardcoded server secret (Stripe `sk_`, OpenAI, AWS secret, GitHub PAT, private key) ships in the bundle.",
                        "A server-side secret is embedded in client code — anyone viewing source has full use of it.",
                        "Never put server secrets in the client; call the third party from your backend. Rotate the leaked key now."),
    "sec-hosthdr-001": ("The `Host` / `X-Forwarded-Host` header is not reflected into URLs or redirects.",
                        "Host-header injection — attacker-controlled hosts poison generated links (password-reset hijack, cache poisoning).",
                        "Validate `Host` against an allow-list of known domains; build absolute URLs from config, not the request header."),
    "sec-dos-001": ("Compressed request bodies are size-capped before decompression.",
                    "Zip-bomb DoS — a tiny gzip body inflates to gigabytes and exhausts server memory.",
                    "Cap the decompressed size and set a request-body limit; reject oversized payloads early."),
    "sec-backend-001": ("The managed backend (Supabase/Firebase) enforces row-level security.",
                        "The database is world-readable/writable through the public anon key — anyone can read or modify all rows.",
                        "Enable RLS / security rules and scope the anon key; never rely on client-side checks for authorization."),
    "sec-session-002": ("The session cookie sets a `SameSite` attribute.",
                        "Without `SameSite` the session cookie rides along on cross-site requests — a CSRF exposure.",
                        "Set `SameSite=Lax` (or Strict) plus `Secure` and `HttpOnly` on the session cookie."),
    "sec-session-005": ("The session token lives in an `HttpOnly` cookie, not `localStorage`.",
                        "A token in `localStorage` is readable by any XSS on the origin — one injection steals every session.",
                        "Store the session in an `HttpOnly`, `Secure` cookie so page scripts (and injected ones) can't read it."),
    # ---- qa ----------------------------------------------------------------------------------------
    "qa-a11y-001": ("The page has no critical accessibility violations (alt text, form labels, `lang`, control names).",
                    "Broken for screen-reader/keyboard users — and a reliable proxy for a rushed, unfinished UI.",
                    "Add `alt` on images, labels on inputs, a `lang` on `<html>`, and accessible names on controls; verify with axe DevTools."),
    "qa-a11y-002": ("The page passes the baseline accessibility hard-checks (`lang`, alt, form-control names, page title).",
                    "A fundamental accessibility element is missing — the page is unusable for assistive tech.",
                    "Add the missing `lang`/title/label/alt; these are one-line fixes with outsized impact."),
    "qa-seo-001": ("Best-practice meta tags are present (at least `viewport` and `description`).",
                   "Missing `viewport` breaks mobile layout; missing `description` hurts discoverability — signs of an unfinished page.",
                   "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">` and a `<meta name=\"description\">`."),
    "qa-console-001": ("The page loads with no uncaught JavaScript errors.",
                       "An error is being thrown on load — likely breaking functionality or leaving the UI half-initialized.",
                       "Open the devtools console, reproduce the error, and fix the throwing code path."),
    "qa-crash-010": ("Malformed input is rejected with a graceful 4xx.",
                     "An unhandled exception returns a 5xx — a reliability failure that can also leak stack traces.",
                     "Validate input at the boundary and catch errors; return `400` on bad input, never let it become a `500`."),
    "qa-deadctrl-001": ("Clickable controls actually do something when clicked.",
                        "Buttons/links wired to nothing — a happy-path demo with non-functional UI (the classic AI-generated tell).",
                        "Wire each control to its handler, or remove controls that aren't implemented yet."),
    "qa-http-001": ("A request for a nonexistent asset returns `404`.",
                    "A soft-404 (2xx for missing paths) pollutes caches and crawlers and masks real broken links.",
                    "Return a genuine `404` status for unknown routes/assets instead of falling through to `200`."),
    "qa-http-002": ("HTML responses declare their charset.",
                    "The browser must guess the encoding — causing mojibake and, via UTF-7 tricks, a legacy XSS vector.",
                    "Send `Content-Type: text/html; charset=utf-8`."),
    "qa-links-001": ("Internal links resolve to real pages.",
                     "An internal link leads to a 4xx dead end — broken navigation the user will hit.",
                     "Fix the target or remove the broken link."),
    # ---- performance -------------------------------------------------------------------------------
    "perf-cwv-001": ("First Contentful Paint is within the Core Web Vitals threshold.",
                     "The page paints slowly — users perceive it as sluggish and are more likely to bounce.",
                     "Reduce render-blocking JS/CSS, inline critical CSS, and defer non-essential scripts."),
    "perf-cwv-002": ("Core Web Vitals (LCP, layout stability) pass on the best of several throttled samples.",
                     "Poor real-world loading experience — slow largest paint or janky layout shifts.",
                     "Optimize and size images, reserve space for late content to stop layout shift, and code-split heavy bundles."),
    "perf-loadtime-001": ("The homepage loads under the ~5s user-abandonment ceiling.",
                          "Load time is past the point where a large share of users give up and leave.",
                          "Shrink the payload, lazy-load below-the-fold content, and serve static assets from a CDN."),
    "perf-compress-001": ("Sizeable text assets are served compressed (gzip/brotli).",
                          "Uncompressed text wastes bandwidth and slows every load, especially on mobile.",
                          "Enable gzip/brotli in your server or host settings (usually a one-line toggle)."),
    "perf-weight-001": ("Total page transfer weight is within the performance budget.",
                        "A heavy page is slow on mobile and constrained networks.",
                        "Compress images, tree-shake and minify bundles, and drop unused dependencies."),
    "perf-weight-002": ("Total page transfer weight is within the performance budget.",
                        "A heavy page is slow on mobile and constrained networks.",
                        "Compress images, tree-shake and minify bundles, and drop unused dependencies."),
    "perf-requests-001": ("The homepage renders without an excessive request count.",
                          "Too many requests create a loading waterfall that delays first render.",
                          "Bundle assets, inline what's critical, and lazy-load the rest."),
    "perf-cache-001": ("Static assets are cacheable (validators / sane `Cache-Control`).",
                       "Nothing is cached, so returning visitors re-download every asset each time.",
                       "Set `Cache-Control` with a validator (ETag/Last-Modified) on static assets; fingerprint filenames for long TTLs."),
    "perf-ttfb-001": ("Time-to-first-byte is under ~1s.",
                      "The server is slow to respond — often a cold start or an unoptimized request handler.",
                      "Keep the instance warm, cache expensive work, and profile the slow handler."),
    "perf-load-001": ("Endpoints stay up under a short concurrent burst.",
                      "An endpoint 5xx'd under concurrent load — it won't survive even a small crowd of real users.",
                      "Handle concurrency safely (connection pooling, limits, backpressure); don't crash under parallel requests."),
}

# Generic remediation when a probe has no authored entry (keeps the card complete + non-crashing).
_GENERIC = ("A durability check for this issue passed on well-built apps.",
            "",  # filled from the finding's own `reason`
            "Review the observed evidence below and address the underlying issue.")

_AXIS_TITLE = {"security": "Security", "qa": "Quality & Correctness", "performance": "Performance"}


def _pool_map(catalog_root: str | pathlib.Path) -> dict[str, str]:
    """probe_id -> pool ('public' | 'hidden'), from the catalog. Missing -> 'public' (fail-open to disclosure
    would over-share, so callers that can't load the catalog should treat everything as public deliberately)."""
    try:
        return {p.id: getattr(p, "pool", "public") for p in load_catalog(catalog_root)}
    except Exception:
        return {}


def _actual(finding: dict) -> str:
    """A plain-language 'what we saw' line from the finding evidence + where it fired."""
    ev = finding.get("evidence") or {}
    parts = [f"{k} = {v}" for k, v in ev.items() if k not in ("engine",) and not isinstance(v, (dict, list))]
    detail = "; ".join(parts) if parts else finding.get("reason", "")
    targets = finding.get("targets") or ([finding["target"]] if finding.get("target") else [])
    where = f"  (seen on: {', '.join(str(t) for t in targets[:5])})" if targets else ""
    return detail + where


def _entry(finding: dict) -> dict:
    """A single public finding rendered as the four fields (+ penalty/title)."""
    pid = finding.get("probe_id", "")
    expected, indicates, remediation = _CONTENT.get(pid, _GENERIC)
    if not indicates:                       # generic fallback: use the catalog reason as the 'indicates' line
        indicates = finding.get("reason", "an issue a durable app avoids")
    return {
        "probe_id": pid,
        "title": finding.get("reason", pid),
        "penalty": finding.get("penalty", 0),
        "expected": expected,
        "actual": _actual(finding),
        "indicates": indicates,
        "remediation": remediation,
    }


def build_card(record: dict, catalog_root: str | pathlib.Path | None = None, organizer: bool = False) -> dict:
    """Turn one grade record into a structured report card. `catalog_root` supplies the pool map for the
    public/hidden split; without it every finding is treated as public. `organizer=True` reveals hidden
    findings in full (for the running org), else they're an opaque count."""
    pool = _pool_map(catalog_root) if catalog_root else {}
    findings = record.get("findings") or []
    url = record.get("url") or record.get("repo") or record.get("project") or "(unknown)"

    # non-functional apps are DNF-classed, not scored — the card says so instead of inventing findings.
    if record.get("functional") is False:
        return {"url": url, "project": record.get("project"), "dnf": True,
                "page_state": (record.get("coverage_audit") or {}).get("page_state"),
                "slop_score": None, "sections": [], "hidden": {"count": 0, "penalty": 0},
                "passed": [], "cov": record.get("coverage") or {}}

    public, hidden = [], []
    for f in findings:
        (hidden if pool.get(f.get("probe_id"), "public") == "hidden" else public).append(f)

    # group public findings by axis (bundle), heaviest axis first
    by_axis: dict[str, list] = {}
    for f in public:
        by_axis.setdefault(f.get("bundle", "other"), []).append(f)
    sections = []
    for axis in sorted(by_axis, key=lambda a: -sum(x.get("penalty", 0) for x in by_axis[a])):
        entries = sorted((_entry(f) for f in by_axis[axis]), key=lambda e: -e["penalty"])
        sections.append({"axis": axis, "title": _AXIS_TITLE.get(axis, axis.title()),
                         "penalty": sum(e["penalty"] for e in entries), "entries": entries})

    cov = record.get("coverage") or {}
    fired_cats = {f.get("category") for f in findings}
    passed_cats = sorted(c for c in (cov.get("ran_kinds") or []) if c not in fired_cats)

    hidden_block = {"count": len(hidden), "penalty": sum(f.get("penalty", 0) for f in hidden)}
    if organizer:                            # organizer view: hidden findings rendered in full, like public
        hidden_block["entries"] = sorted((_entry(f) for f in hidden), key=lambda e: -e["penalty"])

    return {"url": url, "project": record.get("project"), "dnf": False,
            "slop_score": record.get("slop_score"), "axis_slop": record.get("axis_slop") or {},
            "sections": sections, "hidden": hidden_block, "passed": passed_cats, "cov": cov,
            "winner": record.get("winner")}


# ---- renderers -------------------------------------------------------------------------------------

def to_markdown(card: dict) -> str:
    """Portable markdown rendering of a report card."""
    L = []
    name = card.get("project") or card["url"]
    L.append(f"# Durability Report Card — {name}")
    L.append(f"`{card['url']}`\n")
    if card.get("dnf"):
        L.append(f"**Not scored — graded non-functional (`{card.get('page_state')}`).** "
                 "The app didn't present a working surface to test. Get it serving a functional page, then re-grade.")
        return "\n".join(L)

    L.append(f"**Slop score: {card['slop_score']}**  (lower is better — deduction-only)")
    if card.get("axis_slop"):
        L.append("  ·  " + "  ·  ".join(f"{k}: {v}" for k, v in card["axis_slop"].items()))
    cov = card.get("cov") or {}
    if cov:
        n_fail = sum(len(s["entries"]) for s in card["sections"]) + card["hidden"]["count"]
        L.append(f"\n_{cov.get('probes_applicable', '?')} durability checks applied · "
                 f"{n_fail} flagged · {max(cov.get('probes_applicable', 0) - n_fail, 0)} passed._")

    for sec in card["sections"]:
        L.append(f"\n## {sec['title']}  (−{sec['penalty']})")
        for e in sec["entries"]:
            L.append(f"\n### {e['title']}  (−{e['penalty']})")
            L.append(f"- **Expected:** {e['expected']}")
            L.append(f"- **Actual:** {e['actual']}")
            L.append(f"- **Indicates:** {e['indicates']}")
            L.append(f"- **Fix:** {e['remediation']}")

    h = card["hidden"]
    if h.get("entries") is not None:         # organizer view
        L.append(f"\n## Hidden resilience checks (organizer view)  (−{h['penalty']})")
        for e in h["entries"]:
            L.append(f"\n### {e['title']}  (−{e['penalty']})")
            L.append(f"- **Expected:** {e['expected']}")
            L.append(f"- **Actual:** {e['actual']}")
            L.append(f"- **Indicates:** {e['indicates']}")
            L.append(f"- **Fix:** {e['remediation']}")
    elif h["count"]:
        L.append(f"\n## Hidden resilience checks")
        L.append(f"_{h['count']} additional check(s) flagged (−{h['penalty']} total). Details are withheld to "
                 "keep the credential ungameable — you can't teach-to-the-test on checks you can't see. "
                 "Building genuinely durably is the only way to pass them._")

    if card.get("passed"):
        L.append("\n## Passed")
        L.append("Clean on: " + ", ".join(card["passed"]) + ".")
    return "\n".join(L)


def to_html(card: dict) -> str:
    """Self-contained HTML body (no <html>/<head>) for publishing as an Artifact — theme-aware, printable."""
    e = html.escape
    name = card.get("project") or card["url"]
    css = """
    <style>
    :root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--line:#e3e6ea;--accent:#c0392b;--good:#1e8e4e}
    @media (prefers-color-scheme:dark){:root{--bg:#15181c;--fg:#e8eaed;--muted:#9aa0a6;--card:#1e2228;--line:#2c313a;--accent:#ff6b5e;--good:#3ecf7b}}
    :root[data-theme=dark]{--bg:#15181c;--fg:#e8eaed;--muted:#9aa0a6;--card:#1e2228;--line:#2c313a;--accent:#ff6b5e;--good:#3ecf7b}
    :root[data-theme=light]{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--line:#e3e6ea;--accent:#c0392b;--good:#1e8e4e}
    *{box-sizing:border-box}body{margin:0}
    .rc{max-width:820px;margin:0 auto;padding:32px 20px;color:var(--fg);background:var(--bg);
        font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
    .rc h1{font-size:26px;margin:0 0 4px}.rc .url{color:var(--muted);font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
    .score{font-size:40px;font-weight:700;margin:18px 0 2px}.axes{color:var(--muted);font-size:14px}
    .cov{color:var(--muted);font-size:13px;margin:10px 0 8px}
    .rc h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:30px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
    .f{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:14px 16px;margin:10px 0}
    .f .t{font-weight:650;font-size:15px;display:flex;justify-content:space-between;gap:12px}
    .f .pen{color:var(--accent);font-variant-numeric:tabular-nums;font-weight:700;white-space:nowrap}
    .f dl{margin:10px 0 0;display:grid;grid-template-columns:88px 1fr;gap:4px 12px;font-size:14px}
    .f dt{color:var(--muted);font-weight:600}.f dd{margin:0}
    .f dd code,.actual code{font-family:ui-monospace,monospace;font-size:12.5px}
    .actual{font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-word}
    .passed{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--good);border-radius:8px;padding:12px 16px;font-size:14px}
    .hidden{background:var(--card);border:1px dashed var(--line);border-radius:8px;padding:14px 16px;font-size:14px;color:var(--muted)}
    .dnf{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;font-size:15px}
    </style>"""
    out = [css, '<div class="rc">', f"<h1>Durability Report Card</h1>",
           f'<div class="url">{e(card["url"])}</div>']
    if card.get("dnf"):
        out.append(f'<div class="dnf"><b>Not scored — graded non-functional '
                   f'({e(str(card.get("page_state")))}).</b> The app didn\'t present a working surface to test. '
                   "Get it serving a functional page, then re-grade.</div></div>")
        return "".join(out)

    out.append(f'<div class="score">{e(str(card["slop_score"]))}<span style="font-size:15px;color:var(--muted);font-weight:400"> slop · lower is better</span></div>')
    if card.get("axis_slop"):
        out.append('<div class="axes">' + " &nbsp;·&nbsp; ".join(f"{e(k)}: {e(str(v))}" for k, v in card["axis_slop"].items()) + "</div>")
    cov = card.get("cov") or {}
    if cov:
        n_fail = sum(len(s["entries"]) for s in card["sections"]) + card["hidden"]["count"]
        out.append(f'<div class="cov">{e(str(cov.get("probes_applicable","?")))} durability checks applied · '
                   f'{n_fail} flagged · {max(cov.get("probes_applicable",0)-n_fail,0)} passed</div>')

    def block(entry):
        return (f'<div class="f"><div class="t"><span>{e(entry["title"])}</span>'
                f'<span class="pen">−{e(str(entry["penalty"]))}</span></div><dl>'
                f'<dt>Expected</dt><dd>{e(entry["expected"])}</dd>'
                f'<dt>Actual</dt><dd class="actual">{e(entry["actual"])}</dd>'
                f'<dt>Indicates</dt><dd>{e(entry["indicates"])}</dd>'
                f'<dt>Fix</dt><dd>{e(entry["remediation"])}</dd></dl></div>')

    for sec in card["sections"]:
        out.append(f'<h2>{e(sec["title"])} · −{e(str(sec["penalty"]))}</h2>')
        out += [block(x) for x in sec["entries"]]

    h = card["hidden"]
    if h.get("entries") is not None:
        out.append(f'<h2>Hidden resilience checks (organizer) · −{e(str(h["penalty"]))}</h2>')
        out += [block(x) for x in h["entries"]]
    elif h["count"]:
        out.append('<h2>Hidden resilience checks</h2>')
        out.append(f'<div class="hidden">{e(str(h["count"]))} additional check(s) flagged '
                   f'(−{e(str(h["penalty"]))} total). Details are withheld to keep the credential ungameable — '
                   "you can't teach-to-the-test on checks you can't see. Building genuinely durably is the only "
                   "way to pass them.</div>")

    if card.get("passed"):
        out.append('<h2>Passed</h2>')
        out.append('<div class="passed">Clean on: ' + ", ".join(e(c) for c in card["passed"]) + ".</div>")
    out.append("</div>")
    return "".join(out)
