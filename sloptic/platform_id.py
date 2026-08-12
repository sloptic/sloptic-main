"""Off-score platform + AI-builder identifier (a DIAGNOSTIC, never scored).

Two independent axes read from black-box signals, kept separate on purpose:

  * host_platform - WHERE the app is served (vercel / netlify / railway / render / fly / cloudflare-pages /
    firebase / github-pages / heroku / replit / ...). Response headers first (they survive a custom domain),
    origin domain suffix as fallback/confirmation.
  * builder - WHAT generated it (lovable / bolt / replit). Read from the served MARKUP, never the host: an
    AI builder can deploy to any platform, so a Lovable app on a custom Vercel domain is still `builder=lovable,
    host_platform=vercel`. This is the thesis-relevant axis (AI-built vs hand-built) -> correlate slop against it.
  * edge - a CDN FRONTING the origin (cloudflare / fastly / cloudfront). Reported separately because it MASKS
    the origin platform: `edge=cloudflare, host_platform=unknown` is honest, `host_platform=cloudflare` is not.

Precision-first: only NAME a platform/builder on an unambiguous signal; otherwise leave it 'unknown'/None. A
custom domain with no leaking header and no known suffix is genuinely unattributable, and we say so.
"""
import urllib.parse

import httpx

# suffix -> platform name. Each label under these is its own site (a.vercel.app != b.vercel.app). Longest
# suffix wins (up.railway.app before railway.app is unnecessary since both map to railway, but firebaseapp
# vs web.app both -> firebase). Kept in sync with discovery._MULTI_SUFFIX (the scope/attribution copy).
_SUFFIX_PLATFORM = {
    "vercel.app": "vercel", "netlify.app": "netlify", "railway.app": "railway", "up.railway.app": "railway",
    "onrender.com": "render", "render.com": "render", "fly.dev": "fly", "pages.dev": "cloudflare-pages",
    "workers.dev": "cloudflare-workers", "web.app": "firebase", "firebaseapp.com": "firebase",
    "github.io": "github-pages", "herokuapp.com": "heroku", "run.app": "google-cloud-run", "deno.dev": "deno",
    "replit.app": "replit", "repl.co": "replit", "surge.sh": "surge", "glitch.me": "glitch",
    "koyeb.app": "koyeb", "adaptable.app": "adaptable", "streamlit.app": "streamlit", "cyclic.app": "cyclic",
    "lovable.app": "lovable", "lovableproject.com": "lovable", "bolt.host": "bolt",
}
# suffixes that are ALSO an AI builder's own hosting (host and builder are the same origin)
_BUILDER_SUFFIX = {"lovable.app": "lovable", "lovableproject.com": "lovable", "bolt.host": "bolt"}


def _host_of(base_url: str) -> str:
    try:
        return (urllib.parse.urlsplit(base_url).hostname or "").lower()
    except ValueError:
        return ""


def _platform_by_suffix(host: str) -> str | None:
    # longest matching suffix wins so 'up.railway.app' / 'firebaseapp.com' resolve before shorter neighbours
    for suf in sorted(_SUFFIX_PLATFORM, key=len, reverse=True):
        if host == suf or host.endswith("." + suf):
            return _SUFFIX_PLATFORM[suf]
    return None


def _builder_by_suffix(host: str) -> str | None:
    for suf, name in _BUILDER_SUFFIX.items():
        if host == suf or host.endswith("." + suf):
            return name
    return None


def classify(base_url: str, headers: dict | None, html: str | None) -> dict:
    """Return {host_platform, edge, builder, host, https, signals}. Pure function over the origin URL, its
    response headers, and its served HTML -> unit-testable without a live server."""
    host = _host_of(base_url)
    hl = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    server, via = hl.get("server", ""), hl.get("via", "")
    signals: list[str] = []

    # --- edge / CDN fronting the origin (masks the origin platform) ---
    edge = None
    if "cf-ray" in hl or "cloudflare" in server:
        edge = "cloudflare"
    elif "x-amz-cf-id" in hl or "cloudfront" in via:
        edge = "cloudfront"
    elif "fastly" in hl.get("x-served-by", "") or "fastly" in via or "varnish" in via:
        edge = "fastly"
    if edge:
        signals.append("edge:" + edge)

    # --- host platform: headers first (survive a custom domain), then origin suffix ---
    hp = None
    if "x-vercel-id" in hl or "x-vercel-cache" in hl or "vercel" in server:
        hp = "vercel"
    elif "x-nf-request-id" in hl or "netlify" in server:
        hp = "netlify"
    elif "x-render-origin-server" in hl:
        hp = "render"
    elif "fly-request-id" in hl or server.startswith("fly"):
        hp = "fly"
    elif "github.com" in server:
        hp = "github-pages"
    elif "vegur" in via or server == "cowboy":
        hp = "heroku"
    elif server.startswith("deno"):
        hp = "deno"
    elif "google frontend" in server:
        hp = "google-cloud-run"
    elif "surgecdn" in server:
        hp = "surge"
    if hp:
        signals.append("header:" + hp)

    suf_plat = _platform_by_suffix(host)
    if suf_plat:
        signals.append("suffix:" + suf_plat)
        if not hp:
            hp = suf_plat            # no leaking header (custom domain masked, or a plain static host) -> suffix

    # --- builder (from served markup; a builder can sit on any host) ---
    builder = _builder_by_suffix(host)
    low = (html or "")[:200_000].lower()
    if not builder:
        if "gpteng.co" in low or "gptengineer" in low or 'name="lovable"' in low:
            builder = "lovable"
        elif "bolt.new" in low or "stackblitz" in low:
            builder = "bolt"
        elif "replit" in low and "replit.com" in low:
            builder = "replit"
    if builder:
        signals.append("builder:" + builder)

    return {
        "host_platform": hp or "unknown",
        "edge": edge,
        "builder": builder,
        "host": host or None,
        "https": (base_url or "").startswith("https://"),
        "signals": signals,
    }


# Hosts that provide DDoS mitigation / rate-limiting / auto-scaling AT THE EDGE, which the app INHERITS. On
# these, "does the app rate-limit / survive a burst" measures the VENDOR, not the team (and sending the burst
# also trips their WAF), so the hosting-layer probes (sec-ratelimit-001 / perf-load-001) go N/A. A self-hosted
# PaaS that runs the team's container (railway / render / fly / heroku / replit) is NOT here: there the app
# owns its own rate-limiting + capacity, so those probes stay live.
_EDGE_MANAGED_HOSTS = frozenset({"vercel", "netlify", "cloudflare-pages", "cloudflare-workers", "firebase",
                                 "github-pages", "amplify"})
_EDGE_CDNS = frozenset({"cloudflare", "fastly", "cloudfront"})


def edge_managed(plat: dict) -> bool:
    """True when the host provides edge DDoS/rate-limiting/scaling the app inherits (a managed-edge platform, or
    ANY origin fronted by a WAF CDN). Used to gate the hosting-layer probes off -- test the config, not the vendor."""
    return plat.get("host_platform") in _EDGE_MANAGED_HOSTS or plat.get("edge") in _EDGE_CDNS


def classify_live(client, origin: str) -> dict:
    """Fetch the origin once and classify. Never raises (a dead/blocked origin -> URL-only classification)."""
    headers, html = {}, ""
    try:
        r = client.get(origin)
        headers, html = dict(r.headers), r.text
    except (httpx.HTTPError, httpx.InvalidURL):
        pass
    return classify(origin, headers, html)
