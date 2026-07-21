"""Three-way reference calibration = the runner's regression suite.

The catalog must read slop_detected on the vulnerable app, clean on the hardened app (same
surface), and not_applicable on the minimal app where the surface is absent. This batch also
exercises both aggregation dampers end-to-end: a SQLi variant group (fires once) and a
crash-resistance category (diminishing returns).
"""
import pathlib

from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import SubprocessDeployer
from hacklet_runner.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
REFS = ROOT / "references"

ALL_PROBES = [
    "sec-sqli-001", "sec-sqli-002", "sec-sqli-003",  # variant group
    "sec-xss-001", "sec-secrets-001",
    "sec-deps-001",  # supply-chain: ships jQuery 1.12.4 (known XSS CVE) in the client bundle
    "sec-session-001", "sec-session-002", "sec-session-003",  # cookie hygiene: HttpOnly / SameSite / Secure
    "sec-csrf-001", "sec-cors-001", "sec-ratelimit-001", "sec-redirect-001", "sec-hosthdr-001",
    "sec-split-001",  # HTTP response splitting (CRLF into a reflected header)
    "sec-dos-001",  # decompression-bomb: decompresses gzip request bodies with no size cap
    "sec-headers-001", "sec-headers-002", "sec-headers-004", "sec-headers-005", "sec-headers-006",  # header depth (003=HSTS https-only); 006=X-Powered-By
    "qa-errhyg-001", "perf-ttfb-001",
    "sec-debug-001",  # framework debug mode on in prod (Werkzeug debugger page at /crash)
    "sec-exposure-001", "sec-exposure-002", "sec-exposure-003", "sec-exposure-004",  # .env + .git + .aws/credentials
    "sec-idor-001",  # horizontal IDOR (self-as-oracle, two accounts)
    "qa-crash-010",  # crash-resistance: malformed input (values / JSON / decode-crashing path) -> 5xx
    "qa-input-001",  # declared-constraint: /register accepts type=email="hlnotanemail" (client-only validation)
    "qa-race-001",  # race condition: concurrent creates collide on the same id
    "perf-load-001",  # load resilience: 5xx under a concurrent burst
    "perf-compress-001",  # no gzip on a sizeable text response
    "perf-cache-001",  # static asset served with no cache validators -> refetched every load
    "qa-http-001",  # soft-404: a nonexistent static asset returns 2xx instead of 404
    "qa-a11y-002",  # static WCAG hard-fails: missing lang / alt / label / title / contrast floor
    "qa-links-001",  # broken navigation: an internal <a href> lands on a 4xx dead end
    "qa-seo-001",  # missing best-practice meta (viewport / description)
    "qa-http-002",  # HTTP conformance: an HTML response with no declared charset
]
SURFACE_PROBES = ["sec-sqli-001", "sec-sqli-002", "sec-sqli-003", "sec-xss-001"]


def _run(app: str):
    return run(SubprocessDeployer(str(REFS / app / "app.py")), load_catalog(CATALOG))


def test_vulnerable_app_accrues_slop():
    report = _run("vulnerable")
    o = report.by_id
    for probe in ALL_PROBES:
        assert o[probe] == "slop_detected", f"{probe} should fire on the vulnerable app"
    # sec-headers-001 fans across every discovered route (9). /crash returns 500, and header POLICY isn't
    # assessed on a server error (an env-var-dead endpoint's 500 page isn't the app's config) -> clean
    # there, slop on the 8 healthy routes. Score unchanged: the damper collapses the fan-out regardless.
    header_hits = [x for x in report.outcomes if x.probe_id == "sec-headers-001"]
    assert len(header_hits) == 9 and sum(x.outcome == "slop_detected" for x in header_hits) == 8
    assert all(x.outcome == "clean" for x in header_hits if (x.evidence.get("status") or 0) >= 500)
    # header-depth probes check the homepage once (global headers); HSTS is https-only -> N/A over http:
    assert o["sec-headers-002"] == "slop_detected"   # missing Content-Security-Policy
    # every declarative fire carries a replayable `repro` (the request that matched) -> Burp-reproducible
    hdr = next(x for x in report.outcomes if x.probe_id == "sec-headers-002" and x.outcome == "slop_detected")
    assert hdr.evidence.get("repro", {}).get("method") == "GET" and hdr.evidence["repro"]["url"].endswith("/")
    assert o["sec-headers-004"] == "slop_detected"   # no X-Frame-Options and no CSP frame-ancestors
    assert o["sec-headers-005"] == "slop_detected"   # missing Referrer-Policy
    assert o["sec-headers-003"] == "not_applicable"  # HSTS meaningless over plain http
    # sec-xss-001 is a comprehensive reflected+stored XSS predicate -> ONE finding (fires on /search's
    # unescaped reflection), not a per-form declarative fan-out:
    xss_hits = [x for x in report.outcomes if x.probe_id == "sec-xss-001"]
    assert len(xss_hits) == 1 and xss_hits[0].outcome == "slop_detected"
    # sec-secrets-001 finds the leaked AWS key in /config.js (variant-grouped -> one penalty):
    assert any(x.outcome == "slop_detected" and x.target == "/config.js"
               for x in report.outcomes if x.probe_id == "sec-secrets-001")
    # sec-session-001/002 (self-as-oracle): the session cookie lacks HttpOnly and SameSite:
    assert o["sec-session-001"] == "slop_detected" and o["sec-session-002"] == "slop_detected"
    # sec-csrf-001 (self-as-oracle): a cross-site POST is accepted with no token and no SameSite:
    assert o["sec-csrf-001"] == "slop_detected"
    # sec-cors-001: the app reflects an arbitrary Origin with credentials -> credentialed cross-origin reads:
    assert o["sec-cors-001"] == "slop_detected"
    # sec-session-003: the session cookie lacks Secure -> can transit in cleartext:
    assert o["sec-session-003"] == "slop_detected"
    # sec-ratelimit-001: N wrong-password logins, none throttled -> no brute-force protection:
    assert o["sec-ratelimit-001"] == "slop_detected"
    # sec-idor-001 (self-as-oracle, 2 accounts): B can read A's note -> broken access control:
    assert o["sec-idor-001"] == "slop_detected"
    # sec-domxss-001 is browser-only -> N/A in this (no-browser) run; the browser run is in test_browser:
    assert o["sec-domxss-001"] == "not_applicable"
    # qa-race-001 (self-as-oracle): N concurrent creates collide on one id -> non-atomic allocation:
    assert o["qa-race-001"] == "slop_detected"
    # perf-load-001: /report 5xx's under a concurrent burst (unsynchronized shared state):
    assert o["perf-load-001"] == "slop_detected"
    # perf-compress-001: the homepage HTML is served uncompressed (no Content-Encoding):
    assert o["perf-compress-001"] == "slop_detected"
    # qa-crash-010: malformed input (nasty field values / JSON / decode-crashing path) -> unhandled 5xx:
    assert o["qa-crash-010"] == "slop_detected"
    # perf-cache-001: /config.js (a static asset) ships no Cache-Control / ETag -> refetched every load:
    assert o["perf-cache-001"] == "slop_detected"
    # qa-http-001: a nonexistent /<rand>.js falls through to a 200 index shell (soft-404), not a 404:
    assert o["qa-http-001"] == "slop_detected"
    # qa-a11y-002 (no browser): <html> has no lang, inputs are placeholder-only (no accessible name),
    # and there's no <title> -> objective WCAG hard-fails:
    assert o["qa-a11y-002"] == "slop_detected"
    # qa-links-001: the homepage's <a href="/login"> dead-ends on a 404 (login is POST-only) -> broken nav:
    assert o["qa-links-001"] == "slop_detected"
    # sec-mixed-001 is https-gated: over the plain-http reference there's nothing to be "mixed" -> N/A
    # (fire/clean is CI-locked against a self-signed HTTPS server in test_mixed_content):
    assert o["sec-mixed-001"] == "not_applicable"
    # qa-seo-001: the vulnerable homepage has no <meta name=viewport> or description -> missing meta:
    assert o["qa-seo-001"] == "slop_detected"
    # qa-http-002: the vulnerable app serves text/html with no charset -> browser must guess encoding:
    assert o["qa-http-002"] == "slop_detected"
    # evidence rides on outcomes (clean ones too): the load-time probe records the measured number, and
    # api_sqli records the techniques it tried even when the app is clean -> for the display layer.
    ltime = next(x for x in report.outcomes if x.probe_id == "perf-loadtime-001")
    assert "load_time_s" in ltime.evidence and ltime.evidence["ceiling_s"] == 5.0
    sqli = next(x for x in report.outcomes if x.probe_id == "sec-sqli-004")
    assert set(sqli.evidence.get("techniques_tried", [])) == {"error", "boolean"}  # scored; time=advisory, union=cut
    # perf-cwv-001 (FCP) / perf-cwv-002 (full Core Web Vitals) are browser-only -> N/A here; browser run in test_browser:
    assert o["perf-cwv-001"] == "not_applicable"
    assert o["perf-cwv-002"] == "not_applicable"
    # qa-console-001 / qa-a11y-001 are browser-only too -> N/A here (fired in test_browser):
    assert o["qa-console-001"] == "not_applicable"
    assert o["qa-a11y-001"] == "not_applicable"
    # qa-deadctrl-001 (dead controls) is browser-gated too -> N/A here; fire/clean locked in test_browser:
    assert o["qa-deadctrl-001"] == "not_applicable"
    from hacklet_runner.probes import PREDICATES
    assert "dead_controls_present" in PREDICATES   # its predicate is registered (offline registration lock)
    # sec-exposure-* find the served .env and .git files (.git config+HEAD share a variant group):
    exposure_hits = {x.target for x in report.outcomes
                     if x.probe_id.startswith("sec-exposure") and x.outcome == "slop_detected"}
    assert exposure_hits == {"/.env", "/.git/config", "/.git/HEAD", "/.aws/credentials"}
    # sec-redirect-001: a user-controlled param redirects to an arbitrary external host:
    assert o["sec-redirect-001"] == "slop_detected"
    # sec-hosthdr-001: /account builds its redirect Location from the client's Host header:
    assert o["sec-hosthdr-001"] == "slop_detected"
    # sec-split-001: /redirect reflects an unsanitized param (with CRLF) into the Location header:
    assert o["sec-split-001"] == "slop_detected"
    # sec-dos-001: /ingest decompresses a gzip request body with no size cap -> zip-bomb exhaustible:
    assert o["sec-dos-001"] == "slop_detected"
    # Total decomposes by axis (the subtotals sum to slop_score). Penalties are risk-priced
    # (frequency x severity, see the catalog): security holds its catastrophic per-instance ceiling (40),
    # while qa/perf are priced up for their every-user frequency. On this deliberately security-riddled
    # reference, security still dominates; a realistic janky app (references/qa-janky) leans qa/perf.
    assert report.axis_slop == {"security": 435, "qa": 167, "performance": 68}
    assert report.slop_score == 670   # security 439->435: header re-price (sec-headers-002 12->8). qa 183->167:
                                      # crash re-price (qa-crash-010 32->16) — a 500-not-400 on malformed input
                                      # is ungraceful error handling (a QA-hygiene tier), not a server crash
    assert sum(report.axis_slop.values()) == report.slop_score


def test_every_declarative_probe_wires_its_matchers():
    # A declarative probe (no predicate) MUST carry a non-empty TOP-LEVEL slop_if, or the matcher never
    # runs and the probe is silently dead. sec-csp-001 shipped dead for weeks because its slop_if was
    # nested under `probe:` (so schema.Probe.slop_if was []) and only the matcher was unit-tested, never
    # the wiring. This catches the whole class.
    dead = [p.id for p in load_catalog(CATALOG) if "predicate" not in p.probe and not p.slop_if]
    assert not dead, f"declarative probes with no top-level slop_if (matcher never runs): {dead}"


def test_hardened_app_is_clean():
    report = _run("hardened")
    o = report.by_id
    for probe in ALL_PROBES:
        assert o[probe] == "clean", f"{probe} should be clean on the hardened app"
    assert o["sec-headers-003"] == "not_applicable"  # HSTS https-only -> N/A over the http reference
    assert report.slop_score == 0


def test_minimal_app_resolves_surface_probes_na():
    report = _run("minimal")
    o = report.by_id
    for probe in SURFACE_PROBES:  # no form/text input -> input-dependent probes don't apply
        assert o[probe] == "not_applicable"
    assert o["sec-headers-001"] == "clean"  # universal probe applies; minimal sets the header
    assert o["sec-headers-002"] == "clean" and o["sec-headers-004"] == "clean" \
        and o["sec-headers-005"] == "clean"  # minimal sets CSP / X-Frame-Options / Referrer-Policy
    assert o["sec-headers-003"] == "not_applicable"  # HSTS https-only
    assert o["sec-session-001"] == "not_applicable"  # no password form -> can't self-register
    assert o["sec-session-002"] == "not_applicable"
    assert o["sec-session-003"] == "not_applicable"
    assert o["sec-csrf-001"] == "not_applicable"
    assert o["sec-ratelimit-001"] == "not_applicable"  # no password form -> no login to brute-force
    assert o["sec-cors-001"] == "clean"  # applies (any endpoint) but minimal doesn't reflect Origin
    assert o["perf-compress-001"] == "clean"  # tiny homepage -> too small to need compression
    assert o["qa-crash-010"] == "clean"       # robust: malformed input -> graceful 4xx / 404
    assert o["perf-cache-001"] == "not_applicable"  # homepage references no static asset to cache
    assert o["qa-http-001"] == "clean"        # correct: a missing asset 404s (universally testable)
    assert o["qa-a11y-002"] == "clean"        # accessible HTML: lang + title set, no img/unlabeled control
    assert o["qa-links-001"] == "not_applicable"  # no <a href> links on the homepage -> nothing to follow
    assert o["qa-seo-001"] == "clean"         # minimal sets viewport + description meta
    assert o["qa-http-002"] == "clean"        # minimal serves text/html; charset=utf-8
    assert o["sec-redirect-001"] == "clean"   # no redirect endpoint reflects an external host
    assert o["sec-hosthdr-001"] == "clean"    # no endpoint reflects the Host header
    assert o["sec-split-001"] == "not_applicable"  # no form/param surface to inject CRLF into
    assert o["sec-dos-001"] == "not_applicable"    # no endpoint decompresses a request body
    assert o["sec-backend-001"] == "not_applicable"  # no Supabase/Firebase config embedded in the client
    assert o["sec-exposure-004"] == "clean"   # no /.aws/credentials served
    assert o["sec-headers-006"] == "clean"    # no X-Powered-By header
    assert o["sec-debug-001"] == "clean"      # no debug UI: /crash absent, no live Werkzeug debugger
    assert o["sec-idor-001"] == "not_applicable"      # same gate
    assert o["sec-domxss-001"] == "not_applicable"    # browser-gated
    assert o["qa-race-001"] == "not_applicable"       # no password form -> can't self-register
    assert o["perf-cwv-001"] == "not_applicable"      # browser-gated
    assert o["perf-cwv-002"] == "not_applicable"      # browser-gated
    assert o["qa-console-001"] == "not_applicable"    # browser-gated
    assert o["qa-a11y-001"] == "not_applicable"       # browser-gated
    assert o["qa-deadctrl-001"] == "not_applicable"   # browser-gated
    assert report.slop_score == 0


def test_cached_profile_freezes_surface_and_reproduces_score(monkeypatch):
    # build 1b (per-commit surface cache): the FIRST grade mints + hands back the discovered surface; a
    # re-grade REUSES it verbatim, skipping the crawl entirely, and reproduces the EXACT score. The
    # deployment's port differs between runs, so this also exercises the base_url re-bind (paths are relative).
    catalog = load_catalog(CATALOG)
    minted = []
    r1 = run(SubprocessDeployer(str(REFS / "vulnerable" / "app.py")), catalog, on_profile=minted.append)
    assert len(minted) == 1 and r1.slop_score == 670          # cache MISS -> discovered once + handed back

    import hacklet_runner.pipeline as pipeline_mod            # PROVE the crawl is skipped on a cache HIT:
    monkeypatch.setattr(pipeline_mod, "discover",             # discover() must never be called with a cached profile
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("discover ran on a cache hit")))
    seen = []
    r2 = run(SubprocessDeployer(str(REFS / "vulnerable" / "app.py")), catalog,
             cached_profile=minted[0], on_profile=seen.append)
    assert r2.slop_score == 670 and seen == []                # HIT -> same score, no re-crawl, no re-mint
    assert r2.axis_slop == r1.axis_slop                       # identical per-axis decomposition too


def test_recon_mode_deploys_and_classifies_but_skips_the_gauntlet():
    # --recon: deploy -> discover(render + classify) -> STOP. A fast SAMPLE to size the SPA off-origin gap
    # (host_tiers) without paying for the ~66-probe gauntlet. slop is 0 (no probes ran; the record is marked
    # recon), but the surface fingerprint — incl. the backend-tier map — still rides out to the record.
    catalog = load_catalog(CATALOG)
    r = run(SubprocessDeployer(str(REFS / "vulnerable" / "app.py")), catalog, recon=True)
    assert r.slop_score == 0 and r.outcomes == []      # the probe gauntlet was skipped
    assert "host_tiers" in r.surface                    # but the surface fingerprint (backend-tier map) survives


def test_progress_callback_fires_per_probe():
    events = []
    run(SubprocessDeployer(str(REFS / "minimal" / "app.py")), load_catalog(CATALOG),
        on_progress=lambda done, total, probe, outcomes: events.append((probe.id, outcomes is None)))
    n = len(load_catalog(CATALOG))
    starts = sum(1 for _, is_start in events if is_start)   # outcomes is None -> a start event
    dones = sum(1 for _, is_start in events if not is_start)
    assert starts == n and dones == n  # one start + one done per probe, none skipped


def test_a_predicate_can_override_its_penalty_absolutely(monkeypatch):
    # a11y computes a per-rule severity SUM that can EXCEED the nominal ceiling (barriers stack); the
    # predicate sets evidence["penalty_override"] and the framework uses it as the absolute fire penalty,
    # bounded to [1, _PENALTY_CAP]. Locks that hook (which subsumes the old down-only scale).
    import httpx
    from hacklet_runner.pipeline import _run_probe, _Ctx, _PENALTY_CAP
    from hacklet_runner.schema import Probe, Profile
    from hacklet_runner.probes import PREDICATES
    prof = Profile(base_url="http://x")
    client = httpx.Client(base_url="http://x")

    def run_one(override):
        def pred(ctx, probe):
            if override is not None:
                ctx.evidence["penalty_override"] = override
            return True
        monkeypatch.setitem(PREDICATES, "_hl_override_test", pred)
        p = Probe(id="t", bundle="qa", category="c", penalty=26, probe={"predicate": "_hl_override_test"})
        return _run_probe(p, _Ctx("http://x", client, prof, None), client, prof)[0].penalty

    try:
        assert run_one(None) == 26            # no override -> the nominal catalog penalty
        assert run_one(18) == 18              # below nominal -> down (a lone serious barrier)
        assert run_one(48) == 48              # ABOVE nominal -> up (barriers sum past the ceiling — the point)
        assert run_one(0) == 1                # bounded to >= 1
        assert run_one(9999) == _PENALTY_CAP  # runaway-guarded
    finally:
        client.close()
