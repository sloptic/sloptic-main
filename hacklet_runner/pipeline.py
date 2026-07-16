"""The five-phase run: deploy -> discover -> applicability -> execute -> aggregate (+report).

Declarative probes target either a literal path or a discovered-surface selector (`routes`), and the
executor fans the probe across each concrete target — one outcome per (probe x target). The
diminishing-returns-within-category damper (aggregate.compute_slop_score) handles the multiplicity,
so multiple vulnerable endpoints cost more than one but less than linearly.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

import httpx

from . import auth, secretscan
from .aggregate import compute_axis_slop, compute_slop_score, coverage_metrics
from .deploy import Deployer
from .discovery import discover, surface_metrics
from .net import make_client
from .probes import MATCHERS, PREDICATES, describe
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
    if target == "routes":
        return [(r, lambda c, r=r: _fetch_path(probe, c, r)) for r in profile.routes]
    if target == "forms":
        return [(f.action, lambda c, f=f: _fetch_form(probe, c, f)) for f in profile.forms]
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


_PENALTY_CAP = 250   # runaway guard on penalty_override — above any real per-rule a11y sum (axe dedups to
                     # ~100 rules max), so it only ever catches a bug, never clips a legitimate multi-barrier fire


def _run_probe(probe: Probe, ctx: _Ctx, client: httpx.Client, profile: Profile) -> list[Outcome]:
    """Resolve one probe to its outcome(s): applicability gate, then an oracle predicate or a
    declarative fan-out across discovered targets. One Outcome per (probe x target)."""
    client.cookies.clear()  # each probe starts from a clean session (no cross-probe leak)
    target = probe.probe.get("target", "")
    if not _applicable(probe, profile):
        return [_outcome(probe, "not_applicable", 0, target)]
    if "predicate" in probe.probe:
        ctx.evidence = {}   # fresh per probe; the predicate may fill it with what it measured/attempted
        try:
            slop = PREDICATES[probe.probe["predicate"]](ctx, probe)
        except Exception:
            # a predicate drives an UNTRUSTED target; a hostile/edge-case response must degrade this
            # one probe to N/A, never crash the whole grade (run must not DNF). Calibration is the
            # backstop: a predicate that ALWAYS raises fails the suite.
            return [_outcome(probe, "not_applicable", 0, target)]
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
        try:
            resp = fetch(client)
        except (httpx.HTTPError, httpx.InvalidURL):
            continue  # unreachable / malformed-URL (control-char path) target -> next
        client.cookies.clear()  # form-fan submissions stay independent (no session leak)
        # endpoint-specific probe: 404/405/501 means the target endpoint/method isn't served here,
        # so it's N/A — not a clean pass (a fake "handled gracefully").
        if na_if_absent and resp.status_code in (404, 405, 501):
            continue
        slop = _matches(probe, resp)
        produced.append(_outcome(
            probe, "slop_detected" if slop else "clean", probe.penalty if slop else 0, label,
            reason=describe(probe) if slop else "",
            evidence={"status": resp.status_code, "elapsed_ms": round(resp.elapsed.total_seconds() * 1000)},
        ))
    if not produced:  # no targets, every fetch failed, or endpoint absent -> inconclusive
        return [_outcome(probe, "not_applicable", 0, target)]
    return produced


def run(deployer: Deployer, catalog: list[Probe], render=None, headers=None, on_progress=None,
        source_dir=None, seed_features=None, cached_profile=None, on_profile=None, perceive=None,
        browser_register=None) -> Report:
    """on_progress(done, total, probe, outcomes): called twice per probe — before it runs with
    outcomes=None (so a caller can show what's currently testing), and after with its outcomes.

    cached_profile: a FROZEN discovered surface (the per-commit cache, build 1b) reused VERBATIM instead
    of crawling — only its base_url is re-bound to this deployment. on_profile(profile): called once with
    a freshly-discovered surface (cache MISS) so the caller can persist it. Mutually exclusive: a HIT
    skips discovery entirely (no crawl, no browser, no on_profile); a MISS discovers then hands it back."""
    try:
        handle = deployer.deploy()  # inside try so teardown runs even if deploy/health fails
        if cached_profile is not None:
            # FROZEN surface: reuse the cached crawl, re-pointing only the origin at THIS deployment's
            # ephemeral URL (routes/forms/endpoints are relative paths; base_url is the sole absolute).
            # Skips the crawl + interaction clicking entirely -> their timing non-determinism leaves the score.
            profile = replace(cached_profile, base_url=handle.base_url)
        else:
            profile = discover(handle.base_url, render=render, headers=headers, seed_features=seed_features,
                               perceive=perceive)
            if on_profile is not None:
                on_profile(profile)   # cache MISS -> hand the freshly-minted canonical surface to the caller
        outcomes: list[Outcome] = []
        total = len(catalog)
        # bind the client + probes to the ORIGIN (a --target may carry an entry path; discover() crawls
        # from it, but probes construct base_url + "/probe/path" and need the bare origin). profile.base_url
        # is already normalized to the origin by discover().
        origin = profile.base_url or handle.base_url
        with make_client(origin, headers, timeout=15.0, follow_redirects=True) as client:
            ctx = _Ctx(origin, client, profile, headers, browser_register=browser_register)
            for i, probe in enumerate(catalog):
                if on_progress:
                    on_progress(i, total, probe, None)              # starting probe i (0-indexed)
                probe_outcomes = _run_probe(probe, ctx, client, profile)
                outcomes.extend(probe_outcomes)
                if on_progress:
                    on_progress(i + 1, total, probe, probe_outcomes)  # done: i+1 probes completed
        if source_dir:   # static source scan (submission zip / --source DIR); absent for a bare --target
            outcomes.append(_source_secret_outcome(source_dir))
        return Report(slop_score=compute_slop_score(outcomes), outcomes=outcomes,
                      axis_slop=compute_axis_slop(outcomes), surface=surface_metrics(profile),
                      coverage=coverage_metrics(outcomes))
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
