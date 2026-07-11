#!/usr/bin/env python3
"""Aggregate deploy_and_grade results into statistics — every number auditable back to the specific
app / probe / evidence that produced it (not a black-box figure).

Input is the JSONL that `deploy_and_grade.py --record FILE` appends (one line per app).

    uv run python scripts/stats.py results.jsonl
    uv run python scripts/stats.py results.jsonl --audit sec-sqli-004   # every app + evidence for one probe
    uv run python scripts/stats.py results.jsonl --json                 # machine-readable summary

Reports: (a) slop-score distribution + histogram + category concentration + most-frequent findings,
(b) per-probe fire-frequency, (c) winners vs non-winners, (d) deploy-success rate (hackathon
reproducibility), (e) anomalies flagged for hand-verification (the surprising 0s and the surprising
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
        r = json.loads(line)
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


def audit(recs, probe_id):
    """Every app where PROBE fired, with target + evidence — makes a fire-frequency number auditable."""
    print(f"\n=== audit: {probe_id} ===")
    hits = 0
    for r in recs:
        for f in r.get("findings", []):
            if f["probe_id"] == probe_id:
                hits += 1
                ev = {k: v for k, v in (f.get("evidence") or {}).items()}
                print(f"  {r['repo']}")
                print(f"      target={f.get('target') or '—'}  penalty={f['penalty']}  reason={f['reason'][:70]}")
                if ev:
                    print(f"      evidence={json.dumps(ev)[:200]}")
    print(f"\n  {probe_id} fired in {hits} app(s).")


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
    graded = [r for r in recs if r.get("deployed") and "slop_score" in r]   # all graded (both cohorts)
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
               ("grade_s", "grade"), ("total_s", "total")]

    def _phase(key):
        return [r["timings"][key] for r in timed if r["timings"].get(key)]

    # ---- (d) deploy-success rate (the hackathon-reproducibility finding) ----
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

    # ---- (b) per-probe fire frequency (app-level) + most-frequent findings ----
    probe_apps = defaultdict(set)        # probe_id -> {repos}
    probe_meta = {}                      # probe_id -> (bundle, category)
    for r in graded:
        for f in r.get("findings", []):
            probe_apps[f["probe_id"]].add(r["repo"])
            probe_meta[f["probe_id"]] = (f["bundle"], f["category"])
    freq = sorted(((pid, len(apps)) for pid, apps in probe_apps.items()), key=lambda x: -x[1])

    # ---- (c) winners vs non-winners ----
    def split(pred):
        return [r for r in recs if r.get("winner") is True and pred(r)], \
               [r for r in recs if r.get("winner") is False and pred(r)]
    win_all, non_all = split(lambda r: True)
    win_scores = [r["slop_score"] for r in win_all if r.get("deployed") and "slop_score" in r]
    non_scores = [r["slop_score"] for r in non_all if r.get("deployed") and "slop_score" in r]

    # ---- (e) anomalies ----
    mean = statistics.mean(scores) if scores else 0
    sd = statistics.pstdev(scores) if len(scores) >= 2 else 0
    hi_cut = mean + args.sigma * sd
    zeros = [r for r in graded if r["slop_score"] == 0]
    thin = [r for r in graded if r["slop_score"] > 0 and len(r.get("findings", [])) < 2]
    highs = [r for r in graded if sd > 0 and r["slop_score"] > hi_cut]

    if args.json:
        print(json.dumps({
            "n_records": len(recs), "n_repo": len(repo_recs), "n_url": len(url_apps),
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
        }, indent=2))
        return

    print(f"\n═══ deploy_and_grade stats — {len(recs)} apps ═══")

    # (d)
    print(f"\n(d) DEPLOY-SUCCESS RATE (hackathon reproducibility — REPO apps only)")
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
        u_scored = [r for r in url_apps if "slop_score" in r]
        print(f"    LIVE-URL COHORT: {len(url_apps)} app(s) graded directly (not deploy-tested) — "
              f"{len(u_scored)} scored, {len(url_apps) - len(u_scored)} unreachable/ungraded")

    # (a)
    print(f"\n(a) SLOP-SCORE DISTRIBUTION  (all graded apps)")
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

    # (b)
    print(f"\n(b) PER-PROBE FIRE-FREQUENCY  (# of the {len(graded)} graded apps each probe fired on)")
    for pid, n in freq:
        b, c = probe_meta[pid]
        bar = "█" * round(n / (freq[0][1] or 1) * 30)
        print(f"      {pid:20} {n:>3} │ {bar}")

    # (b2) NEVER APPLIED — probes that were N/A on EVERY graded app: the intersection of the n/a sets.
    # They never reached a target — either the surface they need is absent from every app, or the probe is
    # mis-gated / broken. This is DISTINCT from a probe that applied and found nothing (working, just rare);
    # that split is shown for contrast. Exact per-probe when records carry coverage.applied; else the
    # coarser kind-level intersection (older records predate the per-probe field).
    try:
        cat = {p.id: p.bundle for p in load_catalog(str(_ROOT / "catalog"))}
    except Exception as e:                     # never let a catalog hiccup break the whole report
        cat = {}
        print(f"\n(b2) NEVER APPLIED — (catalog load failed: {e})")
    cov = [r for r in graded if r.get("coverage")]
    per_probe = [r for r in cov if r["coverage"].get("applied") is not None]
    if cat and per_probe:                      # exact: probes n/a everywhere = catalog − union(applied)
        applied = set().union(*(set(r["coverage"]["applied"]) for r in per_probe))
        never = sorted(pid for pid in cat if pid not in applied)
        ran_clean = sum(1 for pid in applied if pid in cat and pid not in probe_apps)
        print(f"\n(b2) NEVER APPLIED across all {len(per_probe)} graded apps  "
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
        print(f"\n(b2) NEVER APPLIED across all {len(cov)} graded apps  (KIND-level — these records predate "
              f"per-probe coverage; re-grade for probe granularity):")
        print("      " + (", ".join(na_all) if na_all else "(every kind applied on ≥1 app)"))

    # (c)
    print(f"\n(c) WINNERS vs NON-WINNERS")
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


if __name__ == "__main__":
    main()
