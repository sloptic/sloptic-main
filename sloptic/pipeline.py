"""The five-phase run: deploy -> discover -> applicability -> execute -> aggregate (+report).

Declarative probes target either a literal path or a discovered-surface selector (`routes`), and the
executor fans the probe across each concrete target — one outcome per (probe x target). The
diminishing-returns-within-category damper (aggregate.compute_slop_score) handles the multiplicity,
so multiple vulnerable endpoints cost more than one but less than linearly.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace

import httpx

from . import auth, platform_id, safety, secretscan
from .aggregate import compute_axis_slop, compute_slop_score, coverage_metrics
from .deploy import Deployer
from .discovery import discover, surface_metrics
from .net import challenge_onset, is_bot_challenge, make_client, request_counts, set_trace_probe, start_trace

# A late-challenge grade is kept only if at least this fraction of the catalog ran BEFORE the WAF tripped (so
# most outcomes saw the real app). Below it, too much of the grade is contaminated -> withhold like an entry challenge.
_MIN_VALID_FRACTION = 0.6
from .probes import MATCHERS, PREDICATES, _repro_from_resp, describe
from .schema import Form, Outcome, Probe, Profile, Report


def _source_secret_outcome(source_dir) -> Outcome:
    """Fold a static secret scan of the submission SOURCE into the report (the one high-value class a
    black-box HTTP grader can't see: a server-side hardcoded secret that never reaches a client). One
    aggregate finding however many secrets — like the HTTP secrets probe. Only called when source is
    available; a bare --target URL has none, so this simply doesn't run."""
    findings = secretscan.scan_secrets(source_dir)
    evidence = {"secrets_found": len(findings),
                "findings": [{"file": f.file, "line": f.line, "kind": f.kind, "snippet": f.snippet}
                             for f in findings[:25]]}
    if findings:
        kinds = sorted({f.kind for f in findings})
        return Outcome(probe_id="sec-secret-src-001", bundle="security", category="hardcoded-secrets",
                       outcome="slop_detected", penalty=35, variant_group_id="hardcoded-secrets",
                       reason=f"{len(findings)} hardcoded secret(s) in source ({', '.join(kinds[:4])})",
                       evidence=evidence)
    return Outcome(probe_id="sec-secret-src-001", bundle="security", category="hardcoded-secrets",
                   outcome="clean", penalty=0, variant_group_id="hardcoded-secrets", evidence=evidence)


@dataclass
class _Ctx:
    base_url: str
    client: httpx.Client
    profile: Profile
    headers: dict | None = None
    browser_register: object = None   # optional callback: browser-driven SPA registration for the auth self-oracle
    evidence: dict = field(default_factory=dict)  # a predicate may record measured values here; the
    #     executor snapshots it onto the outcome and resets it before the next probe (probes run serially)
    _browser_cache: dict = field(default_factory=dict)  # per-suffix browser-registration RESULT (see register)

    def register(self, suffix: str = ""):
        """Self-register (self-as-oracle) for the authed-surface probes, with the browser fallback threaded in:
        a client-rendered SPA (form action = placeholder, real POST = a JS fetch) still yields a session token.
        A caller-supplied --header session (Option B) is used directly instead of self-registering.

        The BROWSER registration (20-40s: launch + fill + submit) is MEMOIZED per suffix: the ~8 authed-surface
        probes that each register the SAME identity would otherwise each launch a fresh browser (and wedge-risk
        at concurrency). The first probe for an identity pays it; the rest reuse the captured
        cookies/bearer/backend_reads. A fresh httpx client is still built PER CALL, so per-probe close semantics
        are unchanged (no shared-lifecycle risk); distinct suffixes (idor's "_a"/"_b") stay distinct identities."""
        cached = real = self.browser_register
        if real is not None:
            store = self._browser_cache

            def cached(base_url, _s=suffix, _real=real):
                if _s not in store:
                    store[_s] = _real(base_url)   # ONE browser registration per identity, reused across probes
                return store[_s]
        return auth.register_account(self.base_url, self.profile, suffix=suffix,
                                     browser_register=cached, headers=self.headers)


def _applicable(probe: Probe, profile: Profile) -> bool:
    return all(profile.capabilities.get(req, False) for req in probe.applicability.requires)


def _fetch_path(probe: Probe, client: httpx.Client, path: str) -> httpx.Response:
    p = probe.probe
    method = p.get("method", "GET").upper()
    kwargs = {"params": p.get("query"), "headers": p.get("headers")}
    if "body" in p:
        kwargs["content"] = p["body"]   # raw request body (e.g. a malformed-JSON crash probe)
    else:
        kwargs["data"] = p.get("data")  # form-encoded
    return client.request(method, path, **kwargs)


def _fetch_form(probe: Probe, client: httpx.Client, form: Form) -> httpx.Response:
    # Fill every field with the probe's payload, then submit the form the way it declares.
    payload = {field: probe.probe.get("fill", "") for field in form.fields}
    if (form.method or "get").upper() == "GET":
        return client.request("GET", form.action, params=payload)
    return client.request(form.method.upper(), form.action, data=payload)


def _expand(probe: Probe, profile: Profile):
    """Concrete (label, fetch) targets for a declarative probe: a selector fans across discovered
    surface; a literal path is a single target."""
    target = probe.probe.get("target", "/")
    # Discovered surface already carries full paths, so the fan-out sentinels need no rebasing.
    if target == "routes":
        return [(r, lambda c, r=r: _fetch_path(probe, c, r)) for r in profile.routes]
    if target == "forms":
        return [(f.action, lambda c, f=f: _fetch_form(probe, c, f)) for f in profile.forms]
    # A LITERAL target is relative to the APP's root, which for a sub-path deployment is its landing path,
    # not the origin. The client is origin-bound by design, so a declared `/.env` or `/.git/config` would
    # otherwise probe the HOST: measured on GapBench, /.git/config 404s at the apex while the scenario serves
    # it at /site/git-exposed/.git/config, so every path-guessing exposure probe silently tested nothing and
    # reported clean. Same for any app at user.github.io/project/. No-op when landing_path is "/".
    landing = (profile.landing_path or "/").rstrip("/")
    if target == "/":
        target = landing or "/"
    elif landing:
        target = landing + (target if target.startswith("/") else "/" + target)
    return [(target, lambda c: _fetch_path(probe, c, target))]


def _matches(probe: Probe, resp: httpx.Response) -> bool:
    for cond in probe.slop_if:  # ALL conditions must match -> slop present
        if isinstance(cond, str):
            if not MATCHERS[cond](resp):
                return False
        elif isinstance(cond, dict):
            ((name, arg),) = cond.items()
            if not MATCHERS[name](resp, arg):
                return False
    return bool(probe.slop_if)


_RATE_LIMIT_BACKOFF_S = 0.75   # one beat before the single retry on a 429
_PENALTY_CAP = 250   # runaway guard on penalty_override — above any real per-rule a11y sum (axe dedups to
                     # ~100 rules max), so it only ever catches a bug, never clips a legitimate multi-barrier fire


def _run_probe(probe: Probe, ctx: _Ctx, client: httpx.Client, profile: Profile) -> list[Outcome]:
    """Resolve one probe to its outcome(s): applicability gate, then an oracle predicate or a
    declarative fan-out across discovered targets. One Outcome per (probe x target)."""
    client.cookies.clear()  # each probe starts from a clean session (no cross-probe leak)
    target = probe.probe.get("target", "")
    if not _applicable(probe, profile):
        # name the exact surface precondition(s) the app lacked. Most probes gate HERE, and without a reason
        # they reported N/A blank -> the "(no reason recorded)" that dominated the coverage audit. Now the
        # fresh run can size WHY each family didn't apply (missing endpoint / form / password field / ...).
        unmet = [r for r in probe.applicability.requires if not profile.capabilities.get(r, False)]
        ev = {"na_reason": "requires unmet: " + ", ".join(unmet)} if unmet else {}
        return [_outcome(probe, "not_applicable", 0, target, evidence=ev)]
    if "predicate" in probe.probe:
        # RESOLVED OUTSIDE THE GUARD BELOW, deliberately. A name the registry doesn't know is OUR bug — a
        # catalog/probes mismatch — not something the target did, and it must not be laundered into an N/A
        # that reads as "this app had no surface". qa-devbuild-001 shipped unregistered and graded a live
        # Vite dev server clean: the KeyError landed in the except, so the probe reported not_applicable with
        # no reason while its unit tests (which import the function directly) all passed. test_catalog_integrity
        # now fails at CI time instead; this line makes it loud at run time if it ever gets that far.
        fn = PREDICATES[probe.probe["predicate"]]
        ctx.evidence = {}   # fresh per probe; the predicate may fill it with what it measured/attempted
        try:
            slop = fn(ctx, probe)
        except Exception:
            # a predicate drives an UNTRUSTED target; a hostile/edge-case response must degrade this
            # one probe to N/A, never crash the whole grade (run must not DNF). Calibration is the
            # backstop: a predicate that ALWAYS raises fails the suite.
            return [_outcome(probe, "not_applicable", 0, target,
                             evidence={"na_reason": "predicate raised on the target response"})]
        ev = dict(ctx.evidence)   # snapshot regardless of verdict — clean/n/a stats are the point here
        if slop is None:
            # the predicate couldn't establish the conditions to test (e.g. self-registration failed
            # on a CSRF/JSON-API app) -> N/A, NOT a false "clean". A false clean is a missed finding.
            return [_outcome(probe, "not_applicable", 0, target, evidence=ev)]
        pen = probe.penalty
        override = ev.get("penalty_override")   # a predicate MAY set an ABSOLUTE penalty that can EXCEED the
        if slop and isinstance(override, (int, float)) and override >= 0:   # nominal ceiling (the a11y per-rule
            pen = max(1, min(round(override), _PENALTY_CAP))                # severity sum); runaway-guarded
        return [_outcome(probe, "slop_detected" if slop else "clean", pen if slop else 0,
                         target, reason=describe(probe) if slop else "", evidence=ev)]
    na_if_absent = probe.probe.get("na_if_absent", False)
    produced: list[Outcome] = []
    for label, fetch in _expand(probe, profile):
        # A 429 is the HOST telling us to go away; its body says nothing about the app. Scanning it and finding
        # no secret counted as a CLEAN observation, so a rate-limited bundle fetch silently turned a real finding
        # into a pass. Measured: sec-secrets-001 and -002 both vanished on two corpus apps that still ship an
        # openai-key today — the probes reproduce on current code, so the miss was the fetch, not the detector.
        # ONE retry, because a limiter needs a beat and a second request is far cheaper than a lost finding.
        # 5xx is deliberately NOT in here: qa-crash-010 matches a 5xx as evidence the app crashed, and skipping
        # those would trade this false-clean for a false-clean somewhere else.
        resp = None
        for attempt in (0, 1):
            try:
                resp = fetch(client)
            except (httpx.HTTPError, httpx.InvalidURL):
                resp = None
            if resp is not None and resp.status_code != 429:
                break
            if attempt == 0:
                time.sleep(_RATE_LIMIT_BACKOFF_S)
        if resp is None:
            continue  # unreachable / malformed-URL (control-char path) target -> next
        if resp.status_code == 429:
            continue  # still throttled: not readable, so it must not count as evidence of cleanliness
        client.cookies.clear()  # form-fan submissions stay independent (no session leak)
        # endpoint-specific probe: 404/405/501 means the target endpoint/method isn't served here,
        # so it's N/A — not a clean pass (a fake "handled gracefully").
        if na_if_absent and resp.status_code in (404, 405, 501):
            continue
        slop = _matches(probe, resp)
        ev = {"status": resp.status_code, "elapsed_ms": round(resp.elapsed.total_seconds() * 1000)}
        if slop:
            ev["repro"] = _repro_from_resp(resp)   # the request that matched -> replayable in Burp (all
            #     declarative probes at once: missing-header / .env-exposure / soft-404 / content-type ...)
        produced.append(_outcome(
            probe, "slop_detected" if slop else "clean", probe.penalty if slop else 0, label,
            reason=describe(probe) if slop else "", evidence=ev,
        ))
    if not produced:  # no targets, every fetch failed, or endpoint absent -> inconclusive
        return [_outcome(probe, "not_applicable", 0, target)]
    return produced


def _blocked(probes: list[Probe]) -> tuple[list[str], list[str]]:
    """Probes a challenge prevented from running -> (their ids, the bundles/axes left INCOMPLETE). The axes are
    what a consumer needs: a bundle with any blocked probe cannot be presented or ranked as clean."""
    return [p.id for p in probes], sorted({p.bundle for p in probes})


def run(deployer: Deployer, catalog: list[Probe], render=None, headers=None, on_progress=None,
        source_dir=None, seed_features=None, cached_profile=None, on_profile=None, perceive=None,
        browser_register=None, recon: bool = False, auth_crawl: bool = False, trace: bool = False,
        login_creds=None) -> Report:
    """on_progress(done, total, probe, outcomes): called twice per probe — before it runs with
    outcomes=None (so a caller can show what's currently testing), and after with its outcomes.

    cached_profile: a FROZEN discovered surface (the per-commit cache, build 1b) reused VERBATIM instead
    of crawling — only its base_url is re-bound to this deployment. on_profile(profile): called once with
    a freshly-discovered surface (cache MISS) so the caller can persist it. Mutually exclusive: a HIT
    skips discovery entirely (no crawl, no browser, no on_profile); a MISS discovers then hands it back."""
    try:
        handle = deployer.deploy()  # inside try so teardown runs even if deploy/health fails
        # --login: authenticate with team-provided demo/test creds BEFORE the crawl, so BOTH discovery and the
        # probes run as that identity (bypasses email-verify/captcha/SDK signup gates a self-register can't).
        # Merged into `headers` -> exactly the --header path; a Cookie session also auto-suppresses auth_crawl.
        if login_creds and not auth._provided_session(headers):
            login_headers = auth.login_with_credentials(handle.base_url, login_creds[0], login_creds[1])
            if login_headers:
                headers = {**(headers or {}), **login_headers}
                auth_crawl = False   # we hold a real session -> no throwaway self-register for the crawl
        if cached_profile is not None:
            # FROZEN surface: reuse the cached crawl, re-pointing only the origin at THIS deployment's
            # ephemeral URL (routes/forms/endpoints are relative paths; base_url is the sole absolute).
            # Skips the crawl + interaction clicking entirely -> their timing non-determinism leaves the score.
            profile = replace(cached_profile, base_url=handle.base_url)
        else:
            profile = discover(handle.base_url, render=render, headers=headers, seed_features=seed_features,
                               perceive=perceive, auth_crawl=auth_crawl)
            if on_profile is not None:
                on_profile(profile)   # cache MISS -> hand the freshly-minted canonical surface to the caller
        if recon:   # deploy -> discover(render + classify) -> STOP, skipping the probe gauntlet. Recon only needs
            # the surface fingerprint (host_tiers backend-tier map) to SIZE the off-origin gap; no probes -> slop 0
            # (the record is marked recon so it's never read as a clean grade). A fraction of a full grade's cost.
            return Report(slop_score=0, outcomes=[], surface=surface_metrics(profile))
        outcomes: list[Outcome] = []
        total = len(catalog)
        # bind the client + probes to the ORIGIN (a --target may carry an entry path; discover() crawls
        # from it, but probes construct base_url + "/probe/path" and need the bare origin). profile.base_url
        # is already normalized to the origin by discover().
        origin = profile.base_url or handle.base_url
        trace_sink = start_trace(trace)   # always reset (clears any stale sink); None when trace off. BEFORE
        #                                   make_client so the shared declarative client is hooked too.
        with make_client(origin, headers, timeout=15.0, follow_redirects=True) as client:
            ctx = _Ctx(origin, client, profile, headers, browser_register=browser_register)
            # ENTRY GATE: if the target answers with a bot-challenge / WAF interstitial / sleeping-app page,
            # grading it draws false findings from its HTML AND hides the real surface (false cleans). Withhold
            # the grade instead of scoring the interstitial. The record is flagged bot_challenge -> excluded
            # from the score distribution, never read as a clean grade.
            try:
                if is_bot_challenge(client.get(origin)):   # challenged from the FIRST fetch -> ungradeable, withhold
                    bp, ia = _blocked(catalog)              # nothing ran -> the whole battery is blocked
                    return Report(slop_score=0, outcomes=[], surface=surface_metrics(profile),
                                  platform=platform_id.classify_live(client, origin),
                                  bot_challenge=True, challenge_stage="entry",
                                  blocked_probes=bp, incomplete_axes=ia, trace=trace_sink or [])
            except Exception:   # best-effort side check: a failed probe fetch must never gate the grade
                pass
            # Run low-volume probes FIRST, the high-volume injection/stress tail LAST: on an adaptive-WAF host a
            # challenge then trips late (during the tail), so the recovery keeps the already-collected outcomes
            # (it scores only PRE-onset). Stable sort -> catalog order preserved within each tier; a completed
            # grade's score is order-independent, so this never perturbs a clean grade.
            catalog = sorted(catalog, key=lambda p: safety.order_weight(p.id))
            cat_index = {p.id: i for i, p in enumerate(catalog)}
            for i, probe in enumerate(catalog):
                set_trace_probe(probe.id)                      # tag every request (for --trace AND the always-on
                #                                                challenge-onset watch); cheap ContextVar set
                if on_progress:
                    on_progress(i, total, probe, None)              # starting probe i (0-indexed)
                try:
                    probe_outcomes = _run_probe(probe, ctx, client, profile)
                except Exception:   # a single probe must NEVER DNF the whole grade: run() accumulates outcomes
                    # and only commits them at the end, so one uncaught edge case (e.g. a multipart repro's
                    # RequestNotRead — a StreamError, not an httpx.HTTPError, so the declarative fetch guard
                    # misses it) would abort the loop and discard EVERY finding (179/1043 apps DNF'd this way).
                    # Degrade the one probe to N/A; the suite is the backstop for a probe that ALWAYS raises.
                    probe_outcomes = [_outcome(probe, "not_applicable", 0, probe.probe.get("target", ""))]
                outcomes.extend(probe_outcomes)
                if on_progress:
                    on_progress(i + 1, total, probe, probe_outcomes)  # done: i+1 probes completed
                if challenge_onset():   # a CONFIRMED challenge tripped during/before this probe -> STOP: every
                    break               # request past here hits the interstitial, not the app (and stops hammering)
            # OFF-SCORE diagnostic: identify the hosting platform + AI builder from one origin fetch (headers +
            # served HTML). Inside the client block so it reuses the session; never raises -> never DNFs a grade.
            plat = platform_id.classify_live(client, origin)
            onset_probe = challenge_onset()   # a probe id if the WAF tripped MID-grade, else None
            if not onset_probe:               # no mid-grade trip -> a challenge may still appear only at the END
                try:
                    end_challenged = is_bot_challenge(client.get(origin))
                except Exception:
                    end_challenged = False
            else:
                end_challenged = False
            req_counts = request_counts() or {}
        if source_dir:   # static source scan (submission zip / --source DIR); absent for a bare --target
            outcomes.append(_source_secret_outcome(source_dir))
        # RECOVERY: a probe's outcome is trustworthy only if it ran BEFORE the confirmed challenge onset. Keep
        # the PRE-ONSET outcomes; drop the rest (they ran against the interstitial). Withhold if too few probes
        # saw the real app (an early trip). An END-only challenge (no mid-grade onset) means every probe ran on
        # the app -> keep them all. The v17 sample proved such kept grades match clean ones.
        stage, bot_challenge = "", False
        blocked_probes, incomplete_axes = [], []
        if onset_probe:
            bot_challenge = True
            onset_idx = cat_index.get(onset_probe, total)
            if onset_idx < _MIN_VALID_FRACTION * total:   # too little clean data -> ungradeable, like an entry challenge
                bp, ia = _blocked(catalog)                # nothing usable ran -> the whole battery is blocked
                return Report(slop_score=0, outcomes=[], surface=surface_metrics(profile), platform=plat,
                              bot_challenge=True, challenge_stage="entry", challenge_onset=onset_probe,
                              request_counts=req_counts, blocked_probes=bp, incomplete_axes=ia,
                              trace=trace_sink or [])
            outcomes = [o for o in outcomes if cat_index.get(o.probe_id, total) < onset_idx]
            blocked_probes, incomplete_axes = _blocked(catalog[onset_idx:])   # the tail a challenge cut off
            stage = "late"
        elif end_challenged:
            bot_challenge, stage = True, "late"
        return Report(slop_score=compute_slop_score(outcomes), outcomes=outcomes,
                      axis_slop=compute_axis_slop(outcomes), surface=surface_metrics(profile),
                      coverage=coverage_metrics(outcomes), platform=plat, bot_challenge=bot_challenge,
                      challenge_stage=stage, challenge_onset=onset_probe or "", request_counts=req_counts,
                      blocked_probes=blocked_probes, incomplete_axes=incomplete_axes, trace=trace_sink or [])
    finally:
        deployer.teardown()


def _outcome(probe: Probe, outcome: str, penalty: int, target: str = "", reason: str = "",
             evidence: dict | None = None) -> Outcome:
    return Outcome(
        probe_id=probe.id,
        bundle=probe.bundle,
        category=probe.category,
        outcome=outcome,
        penalty=penalty,
        variant_group_id=probe.variant_group_id,
        target=target,
        reason=reason,
        evidence=evidence or {},
    )
