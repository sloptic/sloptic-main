#!/usr/bin/env python3
"""Aggregate deploy_and_grade results into statistics — every number auditable back to the specific
app / probe / evidence that produced it (not a black-box figure).

Input is the JSONL that `deploy_and_grade.py --record FILE` appends (one line per app).

    uv run python scripts/stats.py results.jsonl
    uv run python scripts/stats.py results.jsonl --audit sec-sqli-004   # every app + evidence for one probe
    uv run python scripts/stats.py results.jsonl --json                 # machine-readable summary

Reports: (a) deploy-success rate (hackathon reproducibility), (b) slop-score distribution + histogram
+ category concentration + most-frequent findings, (c) per-probe fire-frequency, (d) winners vs
non-winners, (e) anomalies flagged for hand-verification (the surprising 0s and the surprising
outliers — where fuzzer bugs and genuinely interesting apps both hide).
"""
import argparse
import json
import pathlib
import statistics
import sys
from collections import Counter, defaultdict

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from hacklet_runner.aggregate import CATEGORY_DECAY, _damped_total  # noqa: E402
from hacklet_runner.catalog import load_catalog  # noqa: E402
from hacklet_runner.schema import Outcome  # noqa: E402


def load(path):
    """Records, deduped by repo (latest ts wins) so re-runs don't double-count. The dedup key is the
    record's "repo" field = its TARGET (a github URL for repo grades, a live URL for url grades), so a
    submission graded BOTH ways keeps both rows (distinct targets) — they're separate lenses."""
    recs = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue   # tolerate a concurrent-append-corrupted line instead of crashing the whole report
        key = r.get("repo")
        if key not in recs or r.get("ts", 0) >= recs[key].get("ts", 0):
            recs[key] = r
    return list(recs.values())


def _source(r):
    """The grade's lens: 'repo' (our controlled Docker deploy) vs 'url' (their live deployment). Explicit
    on new records; inferred from the legacy url_ingest flag on older ones; defaults to 'repo'."""
    return r.get("source") or ("url" if r.get("url_ingest") else "repo")


def cat_subtotals(rec):
    """Per-category DAMPED subtotal for one app, rebuilt from its findings — faithful to the live scorer
    (variant-group collapse + within-category decay)."""
    by_cat = defaultdict(list)
    for f in rec.get("findings", []):
        # findings are deduped-with-count (one row per probe+reason); expand so the fan-out fired
        # instances are all present for the variant-group / decay dampers to reproduce the live score.
        for _ in range(f.get("count", 1)):
            by_cat[(f["bundle"], f["category"])].append(
                Outcome(f["probe_id"], f["bundle"], f["category"], "slop_detected", f["penalty"],
                        variant_group_id=f.get("group")))
    return {k: _damped_total(v, CATEGORY_DECAY) for k, v in by_cat.items()}


def _stat_line(xs):
    if not xs:
        return "n=0"
    xs = sorted(xs)
    q = statistics.quantiles(xs, n=4) if len(xs) >= 2 else [xs[0], xs[0], xs[0]]
    sd = statistics.pstdev(xs) if len(xs) >= 2 else 0.0
    return (f"n={len(xs)}  avg={statistics.mean(xs):.1f}  median={statistics.median(xs):.1f}  "
            f"stdev={sd:.1f}  min={xs[0]:g}  max={xs[-1]:g}  (q1={q[0]:.0f} q3={q[2]:.0f})")


def _histogram(scores, bins=10, width=44):
    if not scores:
        return ["  (no scores)"]
    lo, hi = min(scores), max(scores)
    if hi == lo:
        return [f"  {lo:g} │ {'█' * min(len(scores), width)} {len(scores)}"]
    step = (hi - lo) / bins
    counts = [0] * bins
    for s in scores:
        counts[min(bins - 1, int((s - lo) / step))] += 1
    peak = max(counts) or 1
    out = []
    for i, c in enumerate(counts):
        edge = lo + i * step
        bar = "█" * round(c / peak * width)
        out.append(f"  {edge:6.0f}–{edge + step:<6.0f} │ {bar} {c}")
    return out


def _curl(repro):
    """Render a repro record as a copy-pasteable curl command (Burp Repeater: 'Paste from curl'). Every
    single-quoted field is shell-escaped so a payload's own quote can't break the command."""
    esc = lambda s: str(s).replace("'", "'\\''")   # noqa: E731
    parts = ["curl -sS -i -X %s '%s'" % (repro.get("method", "GET"), esc(repro.get("url", "")))]
    for k, v in (repro.get("headers") or {}).items():
        parts.append("-H '%s: %s'" % (k, esc(v)))
    if repro.get("body"):
        parts.append("--data '%s'" % esc(repro["body"]))
    return " ".join(parts)


def audit(recs, probe_id):
    """Every app where PROBE fired, with target + the REPRO request (paste into Burp) + evidence — makes a
    fire-frequency number auditable AND every finding reproducible."""
    print(f"\n=== audit: {probe_id} ===")
    hits = 0
    for r in recs:
        for f in r.get("findings", []):
            if f["probe_id"] == probe_id:
                hits += 1
                ev = {k: v for k, v in (f.get("evidence") or {}).items()}
                repro = ev.pop("repro", None)   # pulled out so it renders as a curl, not raw JSON
                print(f"  {r['repo']}")
                print(f"      target={f.get('target') or '—'}  penalty={f['penalty']}  reason={f['reason'][:70]}")
                if repro:
                    print(f"      $ {_curl(repro)}")
                    resp = [f"{k}={repro[k]}" for k in ("status", "ms") if k in repro]
                    if repro.get("matched"):
                        resp.append(f"matched={repro['matched']!r}")
                    if resp:
                        print(f"        -> {' · '.join(resp)}")
                if ev:   # measurements (cwv/dos timings, a11y rules, ...) — the observational-probe "repro"
                    print(f"      evidence={json.dumps(ev)[:400]}")
    print(f"\n  {probe_id} fired in {hits} app(s)."
          f"{'' if any(True for r in recs for f in r.get('findings', []) if f['probe_id'] == probe_id and (f.get('evidence') or {}).get('repro')) else '  (no repro records — re-grade to capture replayable requests)'}")


def main():
    ap = argparse.ArgumentParser(description="Aggregate deploy_and_grade results into auditable statistics.")
    ap.add_argument("results", help="the JSONL from deploy_and_grade --record")
    ap.add_argument("--audit", metavar="PROBE", help="list every app + evidence where PROBE fired, then exit")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable summary instead of the report")
    ap.add_argument("--sigma", type=float, default=2.0, help="high-outlier threshold in stdevs (default 2)")
    args = ap.parse_args()

    recs = load(args.results)
    if not recs:
        sys.exit("no records")
    if args.audit:
        audit(recs, args.audit)
        return

    # cohorts: REPO apps are cloned + deploy-tested from source (the reproducibility metric applies to
    # them). URL-INGEST apps were already live and graded raw over HTTP(S) — NOT deployed by us, and graded
    # with a different applicable-probe set (the HTTPS-only probes apply). Keep them distinct so neither the
    # deploy-rate nor the score cohorts get silently conflated.
    url_apps = [r for r in recs if _source(r) == "url"]
    repo_recs = [r for r in recs if _source(r) == "repo"]
    deployed = [r for r in repo_recs if r.get("deployed")]      # deploy-success is a REPO-only concept
    # non-functional = the audit judged it broken/not-an-app/placeholder -> DNF-CLASS: ranks below every
    # working submission, so it's EXCLUDED from the score distribution (never rescued to a low slop score).
    nonfunctional = [r for r in recs if r.get("functional") is False]
    disputed = [r for r in recs if r.get("disputed_broken") and r.get("functional") is not False]  # veto: scored, flagged
    graded = [r for r in recs if r.get("deployed") and "slop_score" in r and r.get("functional") is not False
              and not r.get("recon")]   # recon records carry host_tiers only (no probes) -> not a real grade
    ungraded = [r for r in deployed if "slop_score" not in r]   # repo app came up but grading aborted
    scores = [r["slop_score"] for r in graded]
    # (g) pairing: a submission graded BOTH ways — keyed by project, the delta is the reproducibility signal
    by_project = defaultdict(dict)
    for r in recs:
        if r.get("project"):
            by_project[r["project"]][_source(r)] = r
    paired = {p: d for p, d in by_project.items() if "repo" in d and "url" in d}
    timed = [r for r in recs if r.get("timings")]               # per-phase wall-clock, as measurement
    _PHASES = [("clone_s", "clone"), ("plan_s", "plan(LLM)"), ("deploy_s", "deploy"),
               ("grade_s", "grade"), ("audit_s", "audit(LLM)"), ("total_s", "total")]

    def _phase(key):
        return [r["timings"][key] for r in timed if r["timings"].get(key)]

    # ---- (a) deploy-success rate (the hackathon-reproducibility finding) ----
    skipped = [r for r in repo_recs if r.get("skipped")]   # not a web app -> OUT OF SCOPE, not a failure
    fails = [r for r in repo_recs if not r.get("deployed") and not r.get("skipped")]
    err_kinds = Counter((r.get("deploy_error") or "unknown")[:60] for r in fails)
    timeouts = Counter(r["timeout"] for r in recs if r.get("timeout"))   # 'took forever' — a signal itself

    # ---- per-app category subtotals (rebuilt, faithful) ----
    per_app_cats = {r["repo"]: cat_subtotals(r) for r in graded}
    cat_total = defaultdict(float)       # category -> damped slop summed across apps
    for cats in per_app_cats.values():
        for (bundle, cat), v in cats.items():
            cat_total[f"{bundle}/{cat}"] += v
    all_slop = sum(cat_total.values()) or 1.0

    # ---- (c) per-probe fire frequency (app-level) + most-frequent findings ----
    probe_apps = defaultdict(set)        # probe_id -> {repos}
    probe_meta = {}                      # probe_id -> (bundle, category)
    for r in graded:
        for f in r.get("findings", []):
            probe_apps[f["probe_id"]].add(r["repo"])
            probe_meta[f["probe_id"]] = (f["bundle"], f["category"])
    freq = sorted(((pid, len(apps)) for pid, apps in probe_apps.items()), key=lambda x: -x[1])

    # ---- (d) winners vs non-winners ----
    def split(pred):
        return [r for r in recs if r.get("winner") is True and pred(r)], \
               [r for r in recs if r.get("winner") is False and pred(r)]
    win_all, non_all = split(lambda r: True)
    # SAME population as (b) graded — exclude non-functional/DNF (they carry a slop_score but are banished from
    # the distribution) and recon records, so the winner comparison isn't contaminated by broken high-slop apps.
    win_scores = [r["slop_score"] for r in win_all
                  if r.get("deployed") and "slop_score" in r and r.get("functional") is not False and not r.get("recon")]
    non_scores = [r["slop_score"] for r in non_all
                  if r.get("deployed") and "slop_score" in r and r.get("functional") is not False and not r.get("recon")]

    # ---- (e) anomalies ----
    mean = statistics.mean(scores) if scores else 0
    sd = statistics.pstdev(scores) if len(scores) >= 2 else 0
    hi_cut = mean + args.sigma * sd
    zeros = [r for r in graded if r["slop_score"] == 0]
    thin = [r for r in graded if r["slop_score"] > 0 and len(r.get("findings", [])) < 2]
    highs = [r for r in graded if sd > 0 and r["slop_score"] > hi_cut]

    # ---- LLM-pointer precision (build #2, OFF-SCORE): of the endpoints the LLM UNIQUELY seeded from source
    # (the crawler missed them), how many were REAL vs hallucinated 404s. Measures the pointer, never scores it.
    def _ptr(r):
        s = r.get("observed_surface")
        return s.get("pointer") if isinstance(s, dict) and isinstance(s.get("pointer"), dict) else None
    ptr_active = [p for r in recs for p in [_ptr(r)] if p and p.get("endpoints_seeded")]
    ptr_seeded = sum(p["endpoints_seeded"] for p in ptr_active)
    ptr_reach = sum(p.get("endpoints_reachable", 0) for p in ptr_active)
    ptr_halluc = sum(p.get("endpoints_hallucinated", 0) for p in ptr_active)
    ptr_params = sum(p.get("params_seeded", 0) for p in ptr_active)
    ptr_judged = ptr_reach + ptr_halluc
    ptr_prec = round(ptr_reach / ptr_judged * 100, 1) if ptr_judged else None

    # rendered-PERCEPTION pointer (proactive discovery, --proactive) — the same honesty measure on surface an
    # LLM read off the RENDERED page (client-side logins/uploads/actions). Kept SEPARATE from the source pointer
    # above so a --proactive A/B is legible. Forms are counted (they survived phantom-suppression to be probed);
    # endpoint reachable/hallucinated via the frozen baseline. Off-score: measures perception, never scores it.
    pcv_active = [p for r in recs for p in [_ptr(r)]
                  if p and (p.get("perceived_endpoints_seeded") or p.get("perceived_forms_seeded"))]
    pcv_eps = sum(p.get("perceived_endpoints_seeded", 0) for p in pcv_active)
    pcv_reach = sum(p.get("perceived_endpoints_reachable", 0) for p in pcv_active)
    pcv_halluc = sum(p.get("perceived_endpoints_hallucinated", 0) for p in pcv_active)
    pcv_forms = sum(p.get("perceived_forms_seeded", 0) for p in pcv_active)
    pcv_judged = pcv_reach + pcv_halluc
    pcv_prec = round(pcv_reach / pcv_judged * 100, 1) if pcv_judged else None

    # BACKEND-TIER distribution (OFF-SCORE): WHOSE is each host the app's traffic hits (classify-hosts). Sizes the
    # Move-2 gap = how many apps have an ATTRIBUTED own off-origin backend (same domain / self-host PaaS) we could
    # safely probe. Tiers OVERLAP (an app can have a same-origin API + a BaaS + a custom backend) -> each count is
    # "how many apps have ANY host of this tier". opaque = unattributable off-origin (not probed; flagged instead).
    def _tiers(r):
        s = r.get("observed_surface")
        t = s.get("host_tiers") if isinstance(s, dict) else None
        return t if isinstance(t, dict) and isinstance(t.get("counts"), dict) else None
    tiered = [t for r in recs for t in [_tiers(r)] if t and sum(t["counts"].values())]
    n_tier = len(tiered)
    tier_same = sum(1 for t in tiered if t["counts"].get("same_origin"))
    tier_own = sum(1 for t in tiered if t["counts"].get("own_backend"))     # ATTRIBUTED own backend = Move-2 target
    tier_baas = sum(1 for t in tiered if t["counts"].get("managed_baas"))
    tier_vendor = sum(1 for t in tiered if t["counts"].get("vendor"))       # consumed third-party, not graded
    tier_opaque = sum(1 for t in tiered if t["counts"].get("opaque"))       # unattributable -> flagged, not probed
    own_hosts = Counter(h for t in tiered for h in (t.get("own_hosts") or []))
    opaque_hosts = Counter(h for t in tiered for h in (t.get("opaque_hosts") or []))

    models = Counter(r.get("model") for r in recs if r.get("model"))   # LLM(s) used (a file may mix runs)

    if args.json:
        print(json.dumps({
            "n_records": len(recs), "n_repo": len(repo_recs), "n_url": len(url_apps),
            "n_nonfunctional": len(nonfunctional),
            "n_disputed": len(disputed),
            "n_paired": len(paired), "n_deployed": len(deployed), "n_graded": len(graded),
            "deploy_rate": round(len(deployed) / ((len(repo_recs) - len(skipped)) or 1), 3),   # repo web apps
            "scores": {"avg": round(statistics.mean(scores), 1) if scores else None,
                       "median": round(statistics.median(scores), 1) if scores else None,
                       "stdev": round(sd, 1), "min": min(scores) if scores else None,
                       "max": max(scores) if scores else None},
            "category_concentration": {k: round(v, 1) for k, v in sorted(cat_total.items(), key=lambda x: -x[1])},
            "probe_fire_frequency": {pid: n for pid, n in freq},
            "winners": {"n": len(win_scores), "avg": round(statistics.mean(win_scores), 1) if win_scores else None},
            "non_winners": {"n": len(non_scores), "avg": round(statistics.mean(non_scores), 1) if non_scores else None},
            "anomalies": {"zeros": [r["repo"] for r in zeros], "thin": [r["repo"] for r in thin],
                          "high_outliers": [(r["repo"], r["slop_score"]) for r in highs]},
            "timing_s": {label: {"avg": round(statistics.mean(xs), 1), "median": round(statistics.median(xs), 1),
                                 "max": max(xs)} for key, label in _PHASES for xs in [_phase(key)] if xs},
            "pointer": {"apps": len(ptr_active), "endpoints_seeded": ptr_seeded, "reachable": ptr_reach,
                        "hallucinated": ptr_halluc, "params_seeded": ptr_params, "precision_pct": ptr_prec},
            "perception": {"apps": len(pcv_active), "endpoints_seeded": pcv_eps, "reachable": pcv_reach,
                           "hallucinated": pcv_halluc, "forms_seeded": pcv_forms, "precision_pct": pcv_prec},
            "backend_tiers": {"apps": n_tier, "has_same_origin": tier_same, "has_own_backend": tier_own,
                              "has_managed_baas": tier_baas, "has_vendor": tier_vendor, "has_opaque": tier_opaque,
                              "top_own_hosts": own_hosts.most_common(8), "top_opaque_hosts": opaque_hosts.most_common(8)},
            "models": dict(models.most_common()),
        }, indent=2))
        return

    print(f"\n═══ deploy_and_grade stats — {len(recs)} apps ═══")
    if models:
        print("    model(s): " + ", ".join(f"{m} ({n})" for m, n in models.most_common()))

    # (a)
    print(f"\n(a) DEPLOY-SUCCESS RATE (hackathon reproducibility — REPO apps only)")
    n_try = len(repo_recs) - len(skipped)   # over REPO web apps we tried to deploy (not skips, not live URLs)
    print(f"    {len(deployed)}/{n_try} deployed  ({len(deployed)/(n_try or 1)*100:.0f}%)   "
          f"— {n_try - len(deployed)} failed to come up"
          + (f"   ({len(skipped)} skipped as non-web, excluded)" if skipped else ""))
    for kind, n in err_kinds.most_common(6):
        print(f"      {n:>3}× {kind}")
    if ungraded:   # deployed but no score (grade timeout / abort) — else these vanish from every view
        print(f"    {len(ungraded)} deployed but NOT graded:")
        for kind, n in Counter((r.get("deploy_error") or "unknown")[:60] for r in ungraded).most_common(4):
            print(f"      {n:>3}× {kind}")
    if skipped:    # not web apps -> correctly NOT deployed/graded (out of scope, not a reproducibility fail)
        print(f"    {len(skipped)} SKIPPED (not a web app — out of scope, not a failure):")
        for kind, n in Counter(r.get("app_kind") or "?" for r in skipped).most_common():
            print(f"      {n:>3}× {kind}")
    if timeouts:   # the 'took forever' signal — bloated build / broken grade / wedge
        print(f"    TOOK FOREVER (timeouts — a deployability/quality signal): "
              + ", ".join(f"{n}× {k}" for k, n in timeouts.most_common()))
    if url_apps:   # graded directly from a live URL — never deploy-tested, so OUTSIDE the rate above
        u_scored = [r for r in url_apps if "slop_score" in r and r.get("functional") is not False]
        u_broken = [r for r in url_apps if r.get("functional") is False]
        u_dead = len(url_apps) - len(u_scored) - len(u_broken)
        print(f"    LIVE-URL COHORT: {len(url_apps)} app(s) graded directly (not deploy-tested) — "
              f"{len(u_scored)} scored, {len(u_broken)} non-functional (DNF-class), {u_dead} unreachable/ungraded")
    if nonfunctional:   # visible, not silently dropped: broken/not-an-app apps rank DNF, out of the distribution
        print(f"    NON-FUNCTIONAL (audit): {len(nonfunctional)} app(s) broken/not-an-app/placeholder — ranked "
              f"DNF-class, EXCLUDED from the score distribution below (not rescued to a low slop score)")
    if disputed:   # veto: LLM called it broken but discovery kept real surface + no deterministic signal agreed
        print(f"    DISPUTED-BROKEN (veto): {len(disputed)} app(s) the audit called broken but that KEPT real "
              f"surface — SCORED (not DNF'd on the LLM alone), FLAGGED for human review")

    # (b)
    print(f"\n(b) SLOP-SCORE DISTRIBUTION  (all graded apps)")
    print(f"    {_stat_line(scores)}")
    if url_apps:   # don't conflate cohorts — live apps grade over HTTPS with a different applicable-probe set
        print(f"      ├─ repo-deployed  {_stat_line([r['slop_score'] for r in graded if _source(r) == 'repo'])}")
        print(f"      └─ live-URL       {_stat_line([r['slop_score'] for r in graded if _source(r) == 'url'])}")
    for line in _histogram(scores):
        print(line)
    print(f"\n    slop concentration by category (damped, summed across apps):")
    for cat, v in sorted(cat_total.items(), key=lambda x: -x[1])[:12]:
        print(f"      {cat:34} {v:7.1f}   {v/all_slop*100:4.1f}%")
    print(f"\n    most-frequent findings across apps:")
    for pid, n in freq[:10]:
        b, c = probe_meta[pid]
        print(f"      {pid:20} {n:>3}/{len(graded)} apps   {b}/{c}")

    # (c)
    print(f"\n(c) PER-PROBE FIRE-FREQUENCY  (# of the {len(graded)} graded apps each probe fired on)")
    for pid, n in freq:
        b, c = probe_meta[pid]
        bar = "█" * round(n / (freq[0][1] or 1) * 30)
        print(f"      {pid:20} {n:>3} │ {bar}")

    # (c2) NEVER APPLIED — probes that were N/A on EVERY graded app: the intersection of the n/a sets.
    # They never reached a target — either the surface they need is absent from every app, or the probe is
    # mis-gated / broken. This is DISTINCT from a probe that applied and found nothing (working, just rare);
    # that split is shown for contrast. Exact per-probe when records carry coverage.applied; else the
    # coarser kind-level intersection (older records predate the per-probe field).
    try:
        cat = {p.id: p.bundle for p in load_catalog(str(_ROOT / "catalog"))}
    except Exception as e:                     # never let a catalog hiccup break the whole report
        cat = {}
        print(f"\n(c2) NEVER APPLIED — (catalog load failed: {e})")
    cov = [r for r in graded if r.get("coverage")]
    per_probe = [r for r in cov if r["coverage"].get("applied") is not None]
    if cat and per_probe:                      # exact: probes n/a everywhere = catalog − union(applied)
        applied = set().union(*(set(r["coverage"]["applied"]) for r in per_probe))
        never = sorted(pid for pid in cat if pid not in applied)
        ran_clean = sum(1 for pid in applied if pid in cat and pid not in probe_apps)
        print(f"\n(c2) NEVER APPLIED across all {len(per_probe)} graded apps  "
              f"({len(never)}/{len(cat)} probes never reached a target):")
        if never:
            grp = defaultdict(list)
            for pid in never:
                grp[cat[pid]].append(pid)
            for b in sorted(grp):
                print(f"      [{b}]  " + ", ".join(sorted(grp[b])))
            print(f"      ↳ surface absent everywhere, OR the probe is mis-gated/broken — audit any that SHOULD apply")
        else:
            print("      (every probe applied to at least one app)")
        print(f"      (for contrast: {ran_clean} probes DID apply somewhere but never fired — working, just rare)")
    elif cov:                                  # legacy records: only kind-level n/a survives
        na = [set(r["coverage"].get("na_kinds", [])) for r in cov]
        ran = [set(r["coverage"].get("ran_kinds", [])) for r in cov]
        na_all = sorted(set.intersection(*na) - set().union(*ran)) if na else []
        print(f"\n(c2) NEVER APPLIED across all {len(cov)} graded apps  (KIND-level — these records predate "
              f"per-probe coverage; re-grade for probe granularity):")
        print("      " + (", ".join(na_all) if na_all else "(every kind applied on ≥1 app)"))

    # (d)
    print(f"\n(d) WINNERS vs NON-WINNERS")
    if not win_all and not non_all:
        print("    (no winner labels in the records — pass winner status via deploy_and_grade --meta)")
    else:
        print(f"    winners      deploy {sum(r.get('deployed', False) for r in win_all)}/{len(win_all)}   "
              f"slop {_stat_line(win_scores)}")
        print(f"    non-winners  deploy {sum(r.get('deployed', False) for r in non_all)}/{len(non_all)}   "
              f"slop {_stat_line(non_scores)}")

    # (e)
    print(f"\n(e) ANOMALIES — hand-verify (fuzzer bugs & interesting apps hide here)")
    print(f"    surprising 0s  (deployed but scored 0 — did the fuzzer see a real surface?):")
    for r in zeros or [None]:
        print("      " + (f"{r['repo']}   0 findings" if r else "(none)"))
    print(f"    thin  (deployed, scored >0 but <2 findings — possible discovery blind spot):")
    for r in thin or [None]:
        print("      " + (f"{r['repo']}   score {r['slop_score']}, {len(r['findings'])} finding(s)" if r else "(none)"))
    print(f"    high outliers  (> mean+{args.sigma:g}σ = {hi_cut:.0f} — terrible app OR over-firing bug):")
    for r in sorted(highs, key=lambda r: -r["slop_score"]) or [None]:
        if r:
            top = sorted(cat_subtotals(r).items(), key=lambda x: -x[1])[:3]
            print(f"      {r['repo']}   {r['slop_score']}   top: " + ", ".join(f"{k[1]} {v:.0f}" for k, v in top))
        else:
            print("      (none)")
    print(f"\n    → audit any probe: scripts/stats.py {args.results} --audit <probe-id>\n")

    # (f) TIMING — measurement, not just gates: where the wall-clock goes, and the slowest apps
    if timed:
        print(f"(f) TIMING  (wall-clock seconds per phase, across {len(timed)} apps)")
        for key, label in _PHASES:
            xs = _phase(key)
            if xs:
                print(f"    {label:10} {_stat_line(xs)}")
        slow = sorted((r for r in timed if r["timings"].get("total_s")),
                      key=lambda r: -r["timings"]["total_s"])[:5]
        if slow:
            print("    slowest (total):")
            for r in slow:
                t = r["timings"]
                print(f"      {r['repo'][:48]:48} {t['total_s']:>5.0f}s   "
                      f"(deploy {t.get('deploy_s', 0):.0f} · grade {t.get('grade_s', 0):.0f})")
        print()

    # (g) PAIRED — same submission graded BOTH ways (repo deploy vs live URL). The DELTA is the signal:
    # repo-failed-but-URL-works = pure reproducibility failure; URL much cleaner = their infra hardens or
    # the repo is missing config; similar = genuinely clean AND reproducible. Never a blended average.
    if paired:
        repro_fail = [(p, d) for p, d in paired.items()
                      if "slop_score" not in d["repo"] and "slop_score" in d["url"]]
        both = [(p, d["repo"]["slop_score"], d["url"]["slop_score"]) for p, d in paired.items()
                if "slop_score" in d["repo"] and "slop_score" in d["url"]]
        print(f"(g) PAIRED repo-vs-URL  ({len(paired)} submissions graded both ways — the delta is signal)")
        print(f"    {len(both)} scored on both · {len(repro_fail)} repo-FAILED-but-URL-works "
              f"(pure reproducibility failures)")
        for p, rs, us in sorted(both, key=lambda x: -(x[1] - x[2]))[:12]:
            tag = ("URL cleaner — their infra hardens / repo missing config" if rs - us >= 20 else
                   "repo cleaner — live infra adds slop (their headers/CDN)" if us - rs >= 20 else
                   "similar — clean AND reproducible")
            print(f"      {p.rsplit('/', 1)[-1][:30]:30} repo {rs:>4} · url {us:>4} · Δ{rs - us:>+5}  {tag}")
        for p, d in repro_fail[:6]:
            print(f"      {p.rsplit('/', 1)[-1][:30]:30} repo FAILED · url {d['url']['slop_score']:>4}  "
                  f"→ live only (not reproducible from source)")
        print()

    # (h) COVERAGE AUDIT (LLM) — surface the fuzzer's discovery MISSED, per the LLM critic, aggregated into
    # a fixable backlog (the AfroSecured-style incidents), plus page-state classification (placeholder/broken).
    audited = [r for r in recs if r.get("coverage_audit")]
    if audited:
        misses = [(r["repo"], m) for r in audited for m in (r["coverage_audit"].get("missed") or [])]
        states = Counter((r["coverage_audit"].get("page_state") or "?") for r in audited)
        print(f"(h) COVERAGE AUDIT (LLM) — {len(audited)} apps audited · page states {dict(states)}")
        if misses:
            gap_apps = len({repo for repo, _ in misses})
            print(f"    DISCOVERY GAPS — surface the fuzzer missed: {len(misses)} across {gap_apps} apps  "
                  f"(by kind: {dict(Counter(m.get('kind') for _, m in misses))})")
            for repo, m in misses[:15]:
                print(f"      {repo.rsplit('/', 1)[-1][:26]:26} {(m.get('kind') or '?'):8} "
                      f"{(m.get('label') or '')[:28]:28} — {(m.get('why') or '')[:50]}")
            print(f"    → fix these in discovery, then re-grade; audit any probe: --audit <probe-id>")
        else:
            print("    DISCOVERY GAPS: none flagged — discovery covered the audited pages")
        print()

    # (i) LLM-POINTER PRECISION (build #2, off-score) — of the endpoints the LLM UNIQUELY seeded from source
    # (the crawler missed them), how many were REAL on the deployed app vs hallucinated 404s. Measures the
    # pointer's accuracy without EVER letting it touch the score — the pointer/never-judge separation, quantified.
    if ptr_active:
        print(f"(i) LLM-POINTER PRECISION (build #2, off-score) — {len(ptr_active)} apps where the LLM seeded "
              f"endpoints the crawler missed")
        print(f"    {ptr_seeded} endpoints seeded · {ptr_reach} reachable · {ptr_halluc} hallucinated (404) · "
              f"{ptr_params} injection params added")
        if ptr_judged:
            print(f"    precision {ptr_prec:.0f}%  (reachable / {ptr_judged} judged)   "
                  f"— high = the pointer names real paths; low = it invents ghost endpoints")
        worst = sorted((r for r in recs if (_ptr(r) or {}).get("endpoints_hallucinated")),
                       key=lambda r: -_ptr(r)["endpoints_hallucinated"])[:6]
        if worst:
            print("    most hallucinated paths (pointer misfires — inspect the plan):")
            for r in worst:
                pp = _ptr(r)
                print(f"      {r['repo'].rsplit('/', 1)[-1][:30]:30} {pp['endpoints_hallucinated']} ghost "
                      f"/ {pp['endpoints_seeded']} seeded")
        print()

    # (i2) PERCEPTION POINTER (proactive discovery, off-score) — of the surface an LLM perceived off the
    # RENDERED page (the client-side logins/uploads/actions the crawl missed), how much turned out REAL. The
    # recall counterpart to (h) DISCOVERY GAPS: (h) says what's still missed, this says how good the fix is.
    if pcv_active:
        pcv_pw = sum(p.get("perceived_password_forms", 0) for p in pcv_active)   # perceived forms w/ a password field
        pcv_unjudged = pcv_eps - pcv_judged                                      # seeded but no baseline (not 200/404)
        print(f"(i2) PERCEPTION POINTER (proactive discovery, off-score) — {len(pcv_active)} apps where the LLM "
              f"perceived surface the crawl missed")
        pw = f" ({pcv_pw} w/ a password field -> auth self-oracle surface)" if pcv_pw else ""
        print(f"    {pcv_forms} forms{pw} + {pcv_eps} endpoints perceived (survived suppression) · "
              f"{pcv_reach} reachable · {pcv_halluc} hallucinated (404)"
              + (f" · {pcv_unjudged} unjudged (no baseline)" if pcv_unjudged else ""))
        if pcv_judged:
            print(f"    endpoint precision {pcv_prec:.0f}%  (reachable / {pcv_judged} judged) — how much of the "
                  f"perceived ENDPOINT surface was real (forms show up as woken probes / a fuller has_login)")
        rows = [r for r in recs if (_ptr(r) or {}).get("perceived_forms_seeded")
                or (_ptr(r) or {}).get("perceived_endpoints_seeded")]
        if rows:
            print(f"    per app — what perception ADDED (cross-check against (h) DISCOVERY GAPS above):")
            for r in rows[:15]:
                p = _ptr(r)
                bits = []
                if p.get("perceived_form_actions"):
                    bits.append(f"forms {p['perceived_form_actions']}")
                if p.get("perceived_endpoint_paths"):
                    bits.append(f"endpoints {p['perceived_endpoint_paths']}")
                label = (r.get("repo") or "").rstrip("/").rsplit("/", 1)[-1][:28] or "?"   # trailing '/' -> host, not ''
                print(f"      {label:28} {' · '.join(bits)}")
            if len(rows) > 15:
                print(f"      ... and {len(rows) - 15} more (jq the per-app records for the rest)")
        ghosts = [(r.get("repo", ""), p) for r in recs for p in ((_ptr(r) or {}).get("perceived_ghost_paths") or [])]
        if ghosts:
            print(f"    ghost paths perception INVENTED (404 — eyeball these when endpoint precision dips):")
            for repo, path in ghosts[:8]:
                print(f"      {repo.rsplit('/', 1)[-1][:30]:30} {path}")
        print()

    # (i3) BACKEND-TIER DISTRIBUTION (off-score) — WHERE each app's runtime traffic goes (classify-hosts). Sizes
    # the SPA off-origin gap: same-origin = probe-able now, managed BaaS = config-test lane, OWN off-origin = the
    # Move-2 recall frontier we can't yet reach. Tiers OVERLAP (an app can span all three).
    if n_tier:
        print(f"(i3) BACKEND-TIER DISTRIBUTION (off-score) — {n_tier} apps with observed runtime traffic")
        print(f"    same-origin (probe-able now):        {tier_same:>4} ({tier_same/n_tier*100:.0f}%)")
        print(f"    OWN off-origin backend (attributed): {tier_own:>4} ({tier_own/n_tier*100:.0f}%)   <- Move-2 target (same domain / self-host PaaS)")
        print(f"    managed BaaS (config-test lane):     {tier_baas:>4} ({tier_baas/n_tier*100:.0f}%)")
        print(f"    vendor (consumed, not graded):       {tier_vendor:>4} ({tier_vendor/n_tier*100:.0f}%)")
        print(f"    opaque off-origin (unattributable):  {tier_opaque:>4} ({tier_opaque/n_tier*100:.0f}%)   <- not probed (safety); no clean-bill credit")
        if own_hosts:
            print("    top own-backend hosts: " + ", ".join(f"{h}({c})" for h, c in own_hosts.most_common(6)))
        if opaque_hosts:
            print("    top opaque hosts:      " + ", ".join(f"{h}({c})" for h, c in opaque_hosts.most_common(6)))
        print()


if __name__ == "__main__":
    main()
