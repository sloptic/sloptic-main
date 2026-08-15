"""PageSpeed Insights (PSI) client — runs Lighthouse on Google's infra against a PUBLIC url and returns the
parsed result (audits + category score + lab metrics). The perf axis sources its signals from here instead of
the hand-rolled probes: Lighthouse applies a standardized CPU/network throttle (comparable across apps, no
grader-side concurrency confound) and its audits (font-display / uses-text-compression / uses-long-cache-ttl /
dom-size / server-response-time / the CWV metrics) are battle-tested where ours were 60-90% FP.

Free: https://www.googleapis.com/pagespeedonline/v5/runPagespeed — 25k req/day, 240/min WITH a key
(PSI_API_KEY / GOOGLE_API_KEY env); works keyless at a lower rate for smoke tests. PSI needs a PUBLIC url
(Google's servers fetch it), so this is the live-url / sloptic.org path; self-contained local grading will
shell the `lighthouse` Node CLI instead (a later runner, same audit shape).
"""
import json
import os
import statistics
import subprocess
import tempfile

import httpx

PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

# PIN the local Lighthouse version: audit ids are version-specific (13.x moved most "opportunity" audits to
# "-insight" ids; the classic `font-display`/`dom-size`/`uses-*` are gone), so tracking "latest" would silently
# break the mapping + shift the frozen curve. NB: the PSI path CANNOT pin — Google runs whatever version it
# runs — so for a reproducible score the local pinned runner is actually MORE deterministic than PSI.
LIGHTHOUSE_VERSION = "13.4.1"

# Median-of-N over the timing metrics: the config audits are single-run byte-stable, but FCP/CLS/speed-index
# swing run-to-run (measured: SI 4x, CLS band-flips), so the score is a MEDIAN of this many runs. Settable;
# 3 tames a single pathological run (median ignores the outlier), the corpus freeze can raise it.
DEFAULT_RUNS = 3

# Audit ids the perf axis maps onto — VERIFIED against a live 13.4.1 response (do not trust from memory; they
# rename). score: 1=pass, <1=needs-improvement, 0=fail; scoreDisplayMode: metricSavings | informative | numeric.
INSIGHT_AUDITS = (            # opportunity insights -> fire on score < 1
    "font-display-insight",       # perf-font-001
    "cache-insight",              # perf-cache-001 (efficient cache policy)
    "render-blocking-insight",    # (new; render-blocking resources)
    "image-delivery-insight",     # perf-lcp / oversized images
    "lcp-discovery-insight",      # perf-lcp-001 (LCP image lazy/late)
    "document-latency-insight",   # perf-compress-ish (text compression folded here in 13.x)
    "modern-http-insight",
    "unminified-javascript", "unminified-css",   # perf-minify-001 (kept classic ids)
)
NUMERIC_AUDITS = (            # informative -> WE threshold the numericValue
    "dom-size-insight",           # perf-dom-001   (num = node count)
    "network-requests",           # perf-requests-001 (count the details)
    "total-byte-weight",          # perf-weight-001/002 (num = bytes)
    "server-response-time",       # perf-ttfb-* (num = ms)
)
METRIC_AUDITS = (            # use the SCORE band, NOT raw ms (LCP varied 4.3s<->8.7s run-to-run)
    "first-contentful-paint", "largest-contentful-paint", "total-blocking-time",
    "cumulative-layout-shift", "speed-index", "interactive",
)


class PSIError(RuntimeError):
    """PSI could not grade the url (unreachable, quota, or a Lighthouse run error). Message carries the cause."""


def fetch_psi(url: str, *, api_key: str | None = None, strategy: str = "mobile", timeout: float = 90.0) -> dict:
    """Call PSI for `url` and return the raw response dict. Raises PSIError on an API/Lighthouse error.
    `strategy` is 'mobile' (PSI default, heavier throttle) or 'desktop'."""
    params = {"url": url, "category": "performance", "strategy": strategy}
    key = api_key or os.environ.get("PSI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if key:
        params["key"] = key
    try:
        r = httpx.get(PSI_ENDPOINT, params=params, timeout=timeout)
    except httpx.HTTPError as e:
        raise PSIError(f"request failed: {e}") from e
    if r.status_code != 200:
        # PSI returns a JSON {error:{code,message}} on failure (bad url, quota, 5xx from the target)
        try:
            msg = r.json().get("error", {}).get("message", r.text[:200])
        except ValueError:
            msg = r.text[:200]
        raise PSIError(f"HTTP {r.status_code}: {msg}")
    data = r.json()
    if "lighthouseResult" not in data:
        raise PSIError(f"no lighthouseResult: {str(data.get('error') or data)[:200]}")
    return data


def run_local(url: str, *, chrome_path: str = "/usr/bin/google-chrome", timeout: float = 120.0) -> dict:
    """Shell the `lighthouse` Node CLI (via npx) against `url` — the self-contained / no-PSI-key path (also
    reaches a localhost/private deploy PSI can't). Returns the raw Lighthouse report ({audits, categories,...}),
    the same shape PSI nests under `lighthouseResult`; the accessors below read either."""
    # Write to a temp FILE, not stdout: on npx's first run its resolution noise interleaves with the report on
    # stdout and truncates the JSON. --output-path=<file> keeps the (500KB+) report clean.
    fd, out_path = tempfile.mkstemp(suffix=".lh.json")
    os.close(fd)
    cmd = ["npx", "--yes", f"lighthouse@{LIGHTHOUSE_VERSION}", url, "--only-categories=performance",
           "--output=json", f"--output-path={out_path}", "--quiet",
           "--chrome-flags=--headless=new --no-sandbox --disable-gpu"]
    if chrome_path:
        cmd.append(f"--chrome-path={chrome_path}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        try:
            with open(out_path) as f:
                data = f.read()
        except OSError:
            data = ""
        if not data.strip():
            raise PSIError(f"local lighthouse rc={p.returncode}: {p.stderr[-300:]}")
        return json.loads(data)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise PSIError(f"local lighthouse failed: {e}") from e
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _lhr(psi: dict) -> dict:
    """The Lighthouse result object: PSI wraps it under `lighthouseResult`; the local CLI returns it top-level."""
    return psi.get("lighthouseResult") or psi


def audits(psi: dict) -> dict:
    """lighthouse audits -> {audit_id: {score, scoreDisplayMode, displayValue, numericValue, ...}}."""
    return _lhr(psi).get("audits") or {}


def perf_score(psi: dict) -> float | None:
    """The overall performance category score in [0,1] (None if absent). Lighthouse's OWN weighted headline
    (LCP/TBT/CLS/FCP/speed-index blended with its calibrated weights) — the perf axis scores off THIS, inverted
    to slop, rather than re-summing the per-audit breakdown (which double-counted metrics Lighthouse already weighed)."""
    cats = _lhr(psi).get("categories") or {}
    return (cats.get("performance") or {}).get("score")


# The metrics behind the headline, surfaced for OFF-SCORE reporting: a slow app still sees WHICH metric to fix,
# but is charged once on the weighted overall score, not once per metric.
BREAKDOWN_AUDITS = ("first-contentful-paint", "largest-contentful-paint", "total-blocking-time",
                    "cumulative-layout-shift", "speed-index", "server-response-time")


def metric_breakdown(psi: dict) -> dict:
    """{audit_id: displayValue} for the key metrics behind the overall score (Lighthouse's formatted strings,
    e.g. '4.3 s' / '0.21'). Diagnostic detail only — the score comes from perf_score, not from these."""
    au = audits(psi)
    out: dict[str, str] = {}
    for aid in BREAKDOWN_AUDITS:
        dv = (au.get(aid) or {}).get("displayValue")
        if dv:
            out[aid] = dv
    return out


def metric_ms(psi: dict, audit_id: str) -> float | None:
    """A metric audit's numericValue (ms for timings, unitless for CLS)."""
    a = audits(psi).get(audit_id) or {}
    return a.get("numericValue")


def chrome_version(chrome_path: str = "/usr/bin/google-chrome") -> str | None:
    """The Chrome the trace ran on — the SECOND version variable (Lighthouse pinned isn't enough: a Chrome
    auto-update shifts the metrics). Stamped into the grade so a bump is detectable -> a re-freeze signal."""
    try:
        out = subprocess.run([chrome_path, "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def versions(chrome_path: str = "/usr/bin/google-chrome") -> dict:
    """The exact toolchain a perf grade was produced with. A change here means the frozen curve should re-run."""
    return {"lighthouse": LIGHTHOUSE_VERSION, "chrome": chrome_version(chrome_path)}


def measure(url: str, *, runs: int = DEFAULT_RUNS, runner=None, **kw) -> dict:
    """Run Lighthouse `runs` times and return ONE consolidated report whose every audit carries the MEDIAN
    score + numericValue across the runs. The config audits (font/dom/weight/minify) are already stable so the
    median is a no-op there; it's the timing metrics (FCP/CLS/speed-index) and the savings-based audits
    (cache-insight) that this stabilizes. `runner` defaults to run_local (the pinned, deterministic path);
    pass fetch_psi for the live path. Raises PSIError only if EVERY run fails. Shaped like a PSI response so the
    accessors read it, plus `runs` = how many actually succeeded."""
    run = runner or run_local
    reports = []
    for _ in range(max(1, runs)):
        try:
            reports.append(run(url, **kw))
        except PSIError:
            pass
    if not reports:
        raise PSIError(f"all {runs} lighthouse runs failed for {url}")
    all_audits = [audits(r) for r in reports]
    merged: dict = {}
    for aid in set().union(*(set(a) for a in all_audits)):
        entries = [a[aid] for a in all_audits if aid in a]
        out = dict(entries[-1])                                   # keep title/details/displayMode from a real run
        nums = [e["numericValue"] for e in entries if e.get("numericValue") is not None]
        scores = [e["score"] for e in entries if e.get("score") is not None]
        if nums:
            out["numericValue"] = statistics.median(nums)
        if scores:
            out["score"] = statistics.median(scores)
        merged[aid] = out
    cat_scores = [s for r in reports if (s := perf_score(r)) is not None]
    lhr = dict(_lhr(reports[0]))
    lhr["audits"] = merged
    lhr["categories"] = {"performance": {"score": statistics.median(cat_scores) if cat_scores else None}}
    return {"lighthouseResult": lhr, "runs": len(reports), "versions": versions()}
