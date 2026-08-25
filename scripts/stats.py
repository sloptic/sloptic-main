#!/usr/bin/env python3
"""Analyze deploy_and_grade results, every number auditable back to the specific app / probe / evidence that
produced it (not a black-box figure). One tool, three complementary lenses on one results JSONL:

  * default          RECALL, where does slop concentrate + the yield / auth / axis / severity picture.
  * --parity         VISIBILITY, did we SEE the app's surface? observed vs expected per stack -> blind spots.
                     (a low slop is only meaningful if discovery saw the surface; blindness clusters by stack.)
  * --precision      the FALSE POSITIVE audit, are the fires REAL? + a worksheet you audit by hand, with a Wilson CI.

Input is the JSONL that `deploy_and_grade.py --record FILE` appends (one line per app).

    uv run python scripts/stats.py results.jsonl                        # the recall report (default)
    uv run python scripts/stats.py results.jsonl --audit sec-sqli-004   # every app + evidence for one probe
    uv run python scripts/stats.py results.jsonl --json                 # machine readable summary
    uv run python scripts/stats.py results.jsonl --parity [--by X] [--csv F]   # cross stack visibility
    uv run python scripts/stats.py results.jsonl --precision [--show N]         # false positive audit
    uv run python scripts/stats.py results.jsonl --precision --sample 30 > w.tsv  # a worksheet you audit by hand
    uv run python scripts/stats.py w.tsv --tally                        # -> FP rate + 95% Wilson CI
    uv run python scripts/stats.py cur.jsonl --diff prev.jsonl          # run to run regression (what moved)

The default report also carries a probe COST vs VALUE join (request volume vs fire rate, the trim / pacing
candidates); the precision audit ends with a SCORE TRUST join (parity x precision: blind / inflated apps).

The default report prints numbered sections [1..N] in order; each self suppresses when its data is absent, so the
numbering stays contiguous. Sections: yield and attrition (the DNF rate), per hackathon breakdown, auth
surface (login / signup / SSO reach), slop distribution + histogram + modalities, slop by axis (security /
qa / performance), Lighthouse performance, per probe fire frequency, never applied, winners vs non winners,
anomalies for hand verification, timing, paired repo vs URL, coverage audit, the off score pointer /
platform / backend tier / bot challenge / request volume / email diagnostics.
"""
import argparse
import csv
import json
import pathlib
import random
import statistics
import sys
from collections import Counter, defaultdict

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from sloptic.aggregate import CATEGORY_DECAY, _damped_total  # noqa: E402
from sloptic.catalog import load_catalog  # noqa: E402
from sloptic.eligibility import is_shell_only, is_ungradeable_challenge, is_wrong_owner  # noqa: E402
from sloptic.schema import Outcome  # noqa: E402

# probes that cannot fire without a SESSION / ACCOUNT (behind login): the authed surface cluster. Used to
# cross tab the AUTH SURFACE reach against real coverage, did establishing a session actually surface a defect.
_AUTHED_PROBES = frozenset({
    "qa-reset-001", "qa-email-001", "qa-email-002", "qa-integrity-001", "qa-integrity-002",
    "sec-idor-002", "sec-idor-003", "sec-idor-004", "sec-idor-005",
    "sec-backend-002", "sec-backend-003", "sec-xss-002", "qa-input-002",
})


def _severity_tier(penalty):
    """A finding's severity tier, derived from its risk priced penalty (no explicit severity field in the record):
    critical >= 30, serious 16..29, moderate 8..15, minor 1..7."""
    return ("critical" if penalty >= 30 else "serious" if penalty >= 16
            else "moderate" if penalty >= 8 else "minor")


def load(path):
    """Records, deduped by repo (latest ts wins) so reruns don't get counted twice. The dedup key is the
    record's "repo" field = its TARGET (a github URL for repo grades, a live URL for url grades), so a
    submission graded BOTH ways keeps both rows (the targets are distinct), they're separate lenses."""
    recs = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue   # tolerate a line that a concurrent append corrupted, instead of crashing the whole report
        key = r.get("repo")
        if key not in recs or r.get("ts", 0) >= recs[key].get("ts", 0):
            recs[key] = r
    return list(recs.values())


def _source(r):
    """The grade's lens: 'repo' (our controlled Docker deploy) vs 'url' (their live deployment). Explicit
    on new records; inferred from the legacy url_ingest flag on older ones; defaults to 'repo'."""
    return r.get("source") or ("url" if r.get("url_ingest") else "repo")


def _scored(f):
    """A finding that CONTRIBUTES to the score. report_only / off score diagnostics (the Lighthouse probes that
    run once per audit) must stay out of the concentration + fire frequency views or they read as if they scored.
    Key on the explicit `report_only` flag FIRST (correct on corpora collected before the leak was fixed, where
    these leaked at penalty 1, not 0), then fall back to penalty>0 for any other fire that costs nothing."""
    if (f.get("evidence") or {}).get("report_only"):
        return False
    return f.get("penalty", 0) > 0


def cat_subtotals(rec):
    """The damped subtotal per category for one app, rebuilt from its SCORED findings to match the live scorer
    (collapsing variant groups, then decaying within each category). Off score diagnostics (penalty 0) are excluded."""
    by_cat = defaultdict(list)
    for f in rec.get("findings", []):
        if not _scored(f):   # off score diagnostics add 0 to the damper anyway; drop them so a category that is
            continue         # ALL diagnostics (the report_only Lighthouse audits) doesn't show up as a row worth zero
        # findings arrive deduplicated with a count attached (one row per probe+reason); expand each row back out
        # so every fired instance is present, letting the variant group / decay dampers reproduce the live score.
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


def _modalities(scores, top=8):
    """The score distribution's MODES -- the exact values >1 app share, and how many -- plus the de-clump metric.
    After the float/spectrum scoring (continuous-measurement probes emit fractional penalties), a healthy grade
    is mostly UNIQUE with only a few structural clumps: 0 (fully clean) and small integers where only binary
    probes fired. A big NON-zero, non-integer clump means the continuous probes failed to de-clump those apps
    -> the thing the float work targets. Lets you SEE the spread at a glance rather than eyeball the histogram."""
    if not scores:
        return ["  (no scores)"]
    c = Counter(round(s, 1) for s in scores)
    n, uniq = len(scores), len(c)
    top_modes = c.most_common(top)
    clumps = [(v, k) for v, k in top_modes if k > 1]                       # (value, count) with a real tie
    out = [f"  spread: {uniq}/{n} distinct ({100 * uniq / n:.0f}% unique)  |  "
           f"{n - uniq} app(s) tied  |  biggest clump {top_modes[0][1]}×{top_modes[0][0]:g}"]
    out.append("  top modes: " + ("  ".join(f"{k}×{v:g}" for v, k in clumps) if clumps
                                   else "none, every score is distinct"))
    return out


def _curl(repro):
    """Render a repro record as a curl command you can paste straight into Burp Repeater ('Paste from curl'). Every
    single-quoted field is escaped for the shell so a payload's own quote can't break the command."""
    esc = lambda s: str(s).replace("'", "'\\''")   # noqa: E731
    parts = ["curl -sS -i -X %s '%s'" % (repro.get("method", "GET"), esc(repro.get("url", "")))]
    for k, v in (repro.get("headers") or {}).items():
        parts.append("-H '%s: %s'" % (k, esc(v)))
    if repro.get("body"):
        parts.append("--data '%s'" % esc(repro["body"]))
    return " ".join(parts)


def audit(recs, probe_id):
    """Every app where PROBE fired, with target + the REPRO request (paste into Burp) + evidence, makes a
    fire frequency number auditable AND every finding reproducible."""
    print(f"\n=== audit: {probe_id} ===")
    hits = 0
    for r in recs:
        for f in r.get("findings", []):
            if f["probe_id"] == probe_id:
                hits += 1
                ev = {k: v for k, v in (f.get("evidence") or {}).items()}
                repro = ev.pop("repro", None)   # pulled out so it renders as a curl, not raw JSON
                print(f"  {r['repo']}")
                print(f"      target={f.get('target') or '-'}  penalty={f['penalty']}  reason={f['reason'][:70]}")
                if repro:
                    print(f"      $ {_curl(repro)}")
                    resp = [f"{k}={repro[k]}" for k in ("status", "ms") if k in repro]
                    if repro.get("matched"):
                        resp.append(f"matched={repro['matched']!r}")
                    if resp:
                        print(f"        -> {' | '.join(resp)}")
                if ev:   # measurements (cwv/dos timings, a11y rules, ...): for an observational probe, evidence stands in as the "repro"
                    print(f"      evidence={json.dumps(ev)[:400]}")
    # --trace runs carry a per probe request log (fired OR clean OR n/a); show what this probe actually SENT
    # for each finding, as a curl command you can paste straight in, plus its status.
    traced = [(r, t) for r in recs for t in (r.get("trace") or []) if t.get("probe") == probe_id]
    if traced:
        # per probe cap (net._TRACE_PER_PROBE_CAP): a big fan out is sampled, not shown in full, say so
        capped = " (capped sample, a big fan out sends more)" if len(traced) >= 40 else ""
        print(f"\n  --- request trace: {len(traced)} request(s) {probe_id} recorded{capped} (--trace runs) ---")
        for r, t in traced:
            print(f"      $ {_curl(t)}   -> {t.get('status')}")
    print(f"\n  {probe_id} fired in {hits} app(s)."
          f"{'' if any(True for r in recs for f in r.get('findings', []) if f['probe_id'] == probe_id and (f.get('evidence') or {}).get('repro')) else '  (no repro records, regrade to capture replayable requests)'}")


def _is_graded(r):
    """A real grade that belongs in the distribution: came up, scored, not DNF/recon, and not withheld at an ENTRY
    challenge (which scores 0). The (b) distribution, (c) fire frequency, (d) winner split and (e) anomalies all
    share this ONE predicate so they can't drift; (d) once omitted the entry challenge clause and reported
    min=0 while (b) reported min=8, because the 6 apps withheld at entry (5 scoring 0) leaked into (d) alone.
    The entry challenge rule lives in sloptic.eligibility, shared with the curve (benchmark.py), and so does the
    rule for apps that are just an empty shell (a Streamlit app that's just a canvas shell and returns early with
    a 0 is excluded here too, so it doesn't show as a spurious '0' in the descriptive distribution; a RENDERED
    Streamlit is a real grade and stays)."""
    return (r.get("deployed") and "slop_score" in r and r.get("functional") is not False
            and not r.get("recon")   # recon records carry host_tiers only (no probes) -> not a real grade
            and not is_ungradeable_challenge(r) and not is_shell_only(r)
            and not is_wrong_owner(r))   # S3/Jira/no-code/editor: graded the third party, not the submission


def _slop_stats(xs):
    """min / median / mean / max / (population) stdev of a score list -- None where the sample is too small to
    define one (stdev needs >=2). pstdev matches section (b)'s overall spread."""
    return {"min": min(xs) if xs else None,
            "median": round(statistics.median(xs), 1) if xs else None,
            "mean": round(statistics.mean(xs), 1) if xs else None,
            "max": max(xs) if xs else None,
            "stdev": round(statistics.pstdev(xs), 1) if len(xs) >= 2 else None}


def lighthouse_scores(recs):
    """The Lighthouse performance score (0-100) across records that carry it -> {'performance': {n, min, q1,
    median, q3, max (the 5-number summary), mean, stdev}} (values None when none do). This is the score the perf
    axis already grades on, surfaced for the report. (Accessibility is NOT here on purpose: a11y is scored by the
    qa-a11y axe probes, not Lighthouse.) Records from before the switch to Lighthouse have no score, so the caller skips at n=0."""
    xs = []
    for r in recs:
        lh = (r.get("observed_surface") or {}).get("lighthouse")
        if isinstance(lh, dict) and lh.get("performance") is not None:
            xs.append(lh["performance"])
    q = statistics.quantiles(xs, n=4) if len(xs) >= 2 else None   # [Q1, Q2, Q3]; needs >=2 points
    green = sum(1 for x in xs if x >= 90)   # >=90 is Lighthouse's green line = the 90-N floor => ZERO perf slop
    return {"performance": {"n": len(xs),
                            "min": min(xs) if xs else None,
                            "q1": round(q[0]) if q else None,
                            "median": round(statistics.median(xs)) if xs else None,
                            "q3": round(q[2]) if q else None,
                            "max": max(xs) if xs else None,
                            "mean": round(statistics.mean(xs), 1) if xs else None,
                            "stdev": round(statistics.pstdev(xs), 1) if len(xs) >= 2 else None,
                            "green_n": green,
                            "pct_green": round(100 * green / len(xs), 1) if xs else None}}


def by_hackathon(recs):
    """Roll the Devpost hackathon slug on each record up into stats grouped by hackathon: submissions, deploy%
    (REPO apps only -- URL apps aren't deploy tested), graded count, slop median/mean/stdev, winner count, and the
    winners' own median/mean. Sorted by submission count. The slug is already on every record (run_batch threads it
    via --meta); this is the breakdown over it. Winner stats are over the GRADED winners (a DNF winner has no
    score), while `winners` is however many of the whole cohort are flagged as winners."""
    agg = defaultdict(lambda: {"subs": 0, "repo": 0, "deployed": 0, "graded": [], "winners": 0, "win_scores": []})
    for r in recs:
        d = agg[r.get("hackathon") or "(unlabeled)"]
        d["subs"] += 1
        if _source(r) == "repo":
            d["repo"] += 1
            d["deployed"] += 1 if r.get("deployed") else 0
        won = r.get("winner") is True
        if won:
            d["winners"] += 1
        if _is_graded(r):
            d["graded"].append(r["slop_score"])
            if won:
                d["win_scores"].append(r["slop_score"])
    rows = []
    for h, d in agg.items():
        s, w = _slop_stats(d["graded"]), _slop_stats(d["win_scores"])
        rows.append({"hackathon": h, "subs": d["subs"], "graded": len(d["graded"]),
                     "deploy_pct": round(100 * d["deployed"] / d["repo"]) if d["repo"] else None,
                     "min_slop": s["min"], "median_slop": s["median"], "mean_slop": s["mean"],
                     "max_slop": s["max"], "stdev_slop": s["stdev"],
                     "winners": d["winners"], "winner_graded": len(d["win_scores"]),
                     "winner_min": w["min"], "winner_median": w["median"], "winner_mean": w["mean"],
                     "winner_max": w["max"], "winner_stdev": w["stdev"]})
    rows.sort(key=lambda x: -x["subs"])
    return rows


def _dnf_reason(r):
    """Why a record we ATTEMPTED did not produce a graded score. One bucket, most specific first, so the (a)
    attrition breakdown sums to the DNF total without double counting."""
    if r.get("dead_url"):
        return "dead URL (link rot / 4xx / 5xx)"
    if is_ungradeable_challenge(r):
        return "entry challenge (WAF withheld the grade)"
    if r.get("functional") is False:
        return "non functional (broken / not an app / placeholder)"
    if _source(r) == "repo" and not r.get("deployed"):
        return "deploy failed (did not come up)"
    if "slop_score" not in r:
        return "ungraded (grade aborted / timed out)"
    return "other"


def auth_surface(graded):
    """The login / signup / SSO shape across graded apps + the reach it implies. self_registerable (a password
    signup we can drive) is the slice the authed / email / browser data plane probes reach; sso_only + captcha is
    the hard blocked slice they abstain on. Reads surface_metrics off each record's observed_surface; empty when
    no record carries the fields (older corpora), so the caller self suppresses the section."""
    surfaced = [r for r in graded if isinstance(r.get("observed_surface"), dict)
                and r["observed_surface"].get("has_login") is not None]

    def sf(key):
        return sum(1 for r in surfaced if r["observed_surface"].get(key))

    def bucket(s):
        # ONE auth type per app, keyed on what we can DRIVE, so the buckets are mutually exclusive and sum to n
        # (the old flat has_signup / self_registerable / sso_only counts OVERLAP -> can't reconcile, and the
        # password+SSO app is invisible: counted in self_registerable, excluded from sso_only). has_password_form
        # says we can drive the signup; has_signup can be True with no form we can drive (SDK, SSO signup, wizard).
        pw, sso = s.get("has_password_form"), s.get("has_sso")
        if pw and sso:        return "password_and_sso"        # self serve password AND SSO offered (BOTH)
        if pw:                return "password_only"           # self serve password, no SSO
        if sso:               return "sso_only"                # SSO present, no drivable password form
        if s.get("has_signup"): return "signup_undrivable"     # signup detected but no form we can drive, no SSO
        if s.get("has_login"):  return "login_only"            # a login wall, no self serve way in
        return "no_auth"                                       # no login / signup / sso at all
    partition = Counter(bucket(r["observed_surface"]) for r in surfaced)   # sums to len(surfaced) by construction
    return {"n": len(surfaced), "has_login": sf("has_login"), "has_signup": sf("has_signup"),
            "self_registerable": sf("has_password_form"), "has_sso": sf("has_sso"), "sso_only": sf("sso_only"),
            "no_auth": sum(1 for r in surfaced if not r["observed_surface"].get("has_login")
                           and not r["observed_surface"].get("has_signup")
                           and not r["observed_surface"].get("has_sso")),
            "partition": partition,
            "sso_providers": Counter(p for r in surfaced for p in (r["observed_surface"].get("sso_providers") or [])),
            "captcha": Counter(r["observed_surface"].get("captcha") for r in surfaced
                               if r["observed_surface"].get("captcha"))}



# ==========================================================================================================
# PARITY (cross stack visibility): observed vs expected surface per stack -> blind spots.
# ==========================================================================================================
# categorical surfaces with an observed<->expected pair, so parity = "did we see what the source implies?"
_TYPES = ("login", "signup", "upload", "api")   # signup added after discovery emitted has_signup (SSO work)


def _row(rec: dict) -> dict:
    """Flatten one record to a parity row per app (stack + observed + expected + slop + ratio)."""
    sp = rec.get("stack_profile") or {}
    obs = rec.get("observed_surface") or {}
    exp = rec.get("expected_surface") or {}
    cov = rec.get("coverage") or {}
    tm = rec.get("timings") or {}
    slop = rec.get("slop_score")
    size = obs.get("surface_size")
    return {
        "repo": rec.get("repo"),
        "deployed": bool(rec.get("deployed")),
        "app_kind": rec.get("app_kind") or "?",
        # web_gradeable defaults True when unknown (old records) so they still count toward parity
        "web_gradeable": rec.get("web_gradeable") is not False,
        "n_features": len(rec.get("features") or []),
        "framework": sp.get("framework") or "?",
        "routing": sp.get("routing") or "?",
        "api_style": sp.get("api_style") or "?",
        "stack": rec.get("stack") or "?",
        "obs_routes": obs.get("routes"), "obs_forms": obs.get("forms"),
        "obs_inputs": obs.get("inputs"), "obs_endpoints": obs.get("endpoints"),
        # endpoints reached vs healthy: many reached but few healthy means the env vars behind them are dead (dummy keys)
        "obs_endpoints_reached": obs.get("endpoints_reached"), "obs_endpoints_dead": obs.get("endpoints_dead"),
        "obs_surface_size": size,
        "obs_login": obs.get("has_login"), "obs_signup": obs.get("has_signup"),
        "obs_upload": obs.get("has_upload"), "obs_api": obs.get("has_api"),
        "exp_login": exp.get("login"), "exp_signup": exp.get("signup"), "exp_upload": exp.get("upload"),
        "exp_search": exp.get("search"), "exp_api": exp.get("api"), "exp_views": exp.get("views"),
        "slop_score": slop, "findings": len(rec.get("findings", [])),
        # how much of the battery APPLIED: coverage as the fuzzer sees it. Low pct or many n/a kinds means we
        # tested little here (blind, or a genuinely tiny app); a low slop score then means little.
        "pct_applicable": cov.get("pct_applicable"),
        "probes_applicable": cov.get("probes_applicable"),
        "na_kinds": len(cov.get("na_kinds") or []),
        # wall clock per phase (measurement): which stacks are expensive to deploy vs grade
        "deploy_s": tm.get("deploy_s"), "grade_s": tm.get("grade_s"), "total_s": tm.get("total_s"),
        # slop normalized by how much we SAW: high surface + low ratio = clean; low surface = suspect
        "slop_per_surface": round(slop / size, 2) if (slop is not None and size) else None,
    }


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.mean(xs), 1) if xs else None


def _dist(xs) -> dict | None:
    """avg/median/stdev/min/max + quartiles over the values that aren't None (None if empty)."""
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    q = statistics.quantiles(xs, n=4) if len(xs) > 1 else [xs[0], xs[0], xs[0]]
    return {"n": len(xs), "avg": round(statistics.mean(xs), 1), "median": round(statistics.median(xs), 1),
            "stdev": round(statistics.stdev(xs), 1) if len(xs) > 1 else 0.0,
            "min": round(min(xs), 1), "max": round(max(xs), 1),
            "q1": round(q[0], 1), "q3": round(q[2], 1)}


def group_parity(rows: list, key: str) -> dict:
    """Per stack aggregates + TYPE parity. Parity for a surface type = of the DEPLOYED apps whose source
    says they HAVE it (expected), on how many did discovery actually OBSERVE it, i.e. the recall of that
    surface type for this stack. Low + clustered = a blind spot."""
    groups = defaultdict(list)
    for r in rows:
        groups[r[key]].append(r)
    out = {}
    for g, rs in groups.items():
        dep = [r for r in rs if r["deployed"] and r["obs_surface_size"] is not None]
        parity = {}
        for t in _TYPES:
            expected = [r for r in dep if r.get(f"exp_{t}")]                 # source says the surface exists
            observed = [r for r in expected if r.get(f"obs_{t}")]            # ...and discovery saw it
            parity[t] = (len(observed), len(expected))                       # (saw, what we should have seen)
        out[g] = {
            "n": len(rs), "deployed": sum(r["deployed"] for r in rs),
            "surface_avg": _avg([r["obs_surface_size"] for r in dep]),
            "coverage_avg": _avg([r["pct_applicable"] for r in dep]),   # avg % of battery that applied
            "findings_avg": _avg([r["findings"] for r in dep]),
            "slop_avg": _avg([r["slop_score"] for r in dep]),
            "slop_per_surface_avg": _avg([r["slop_per_surface"] for r in dep]),
            "parity": parity,
        }
    return out


def blind_spots(rows: list, key: str) -> list:
    """Ranked (stack, type, missed, observed, expected), missed = expected−observed = the number of apps
    where the source says a surface exists but we didn't see it. This IS prevalence × brokenness (how many
    apps of the stack have it × the fraction we miss), so the ranking tells you what to fix first."""
    gp = group_parity(rows, key)
    spots = []
    for g, agg in gp.items():
        for t, (obs, exp) in agg["parity"].items():
            if exp and obs < exp:
                spots.append({"stack": g, "type": t, "missed": exp - obs, "observed": obs, "expected": exp})
    return sorted(spots, key=lambda s: (-s["missed"], -s["expected"]))


_CSV_COLS = ["repo", "app_kind", "web_gradeable", "deployed", "framework", "routing", "api_style", "stack",
             "n_features", "obs_routes", "obs_forms", "obs_inputs", "obs_endpoints",
             "obs_endpoints_reached", "obs_endpoints_dead", "obs_surface_size",
             "obs_login", "obs_signup", "obs_upload", "obs_api", "exp_login", "exp_signup", "exp_upload", "exp_search",
             "exp_api", "exp_views", "pct_applicable", "na_kinds", "deploy_s", "grade_s", "total_s",
             "slop_score", "findings", "slop_per_surface"]


def parity_report(recs, args):
    rows = [_row(r) for r in recs]
    if not rows:
        sys.exit("no records")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_COLS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {len(rows)} rows -> {args.csv}")
        return

    # parity/blind spots are only meaningful for apps the black-box HTTP grader can actually assess,
    # a mobile/CLI/notebook scoring low isn't a blind spot, it's out of scope. Split them out.
    web = [r for r in rows if r["web_gradeable"]]
    nonweb = [r for r in rows if not r["web_gradeable"]]
    gp = group_parity(web, args.by)
    spots = blind_spots(web, args.by)

    # ASSESSABILITY: parity CONTRASTS stacks against the expected surface the source implies. The URL ingest
    # path grades a bare URL with no source, so it emits no expected_surface and one flat stack -> there is
    # nothing to contrast. Report that honestly instead of a silent one-row "clean" (an unassessable file is
    # NOT a clean bill). The false negative comparison between SPA and server-rendered stacks is the columns
    # grouped by routing below; it needs >1 routing class AND expected labels, i.e. deploy_and_grade records, to appear.
    has_expected = any(r[f"exp_{t}"] is not None for r in web for t in _TYPES)
    single_stack = len(gp) <= 1
    assessable = has_expected and not single_stack

    if args.json:
        kinds = Counter(r["app_kind"] for r in rows)
        print(json.dumps({"n_apps": len(rows), "web_gradeable": len(web),
                          "app_kinds": dict(kinds), "group_by": args.by,
                          "assessable": assessable, "has_expected_labels": has_expected,
                          "single_stack": single_stack,
                          "groups": gp, "blind_spots": spots}, indent=2))
        return

    print(f"\n═══ cross stack parity, {len(rows)} apps ({len(web)} web gradeable), grouped by {args.by} ═══")

    if not assessable:
        print("\n⚠ CANNOT ASSESS CROSS STACK PARITY on this results file (this is not a clean bill):")
        if single_stack:
            only = repr(next(iter(gp))) if gp else "?"
            print(f"    all {len(web)} web gradeable apps are a SINGLE stack ({only}), parity contrasts stacks,")
            print("    so there is nothing to contrast. The false negative comparison between SPA and")
            print(f"    server-rendered stacks is the columns grouped by {args.by} below and needs >1 class to appear.")
        if not has_expected:
            print("    NO expected surface is present for the source to imply (the URL ingest path grades a bare")
            print("    URL with no source, so it emits none); parity between observed and expected, and blind")
            print("    spots, are undefined without them.")
        print("    → run deploy_and_grade again with --submission <source> to produce assessable records.")

    # APP KIND distribution, how much of the field is even a web app? (out of scope isn't a blind spot)
    print("\nAPP KIND DISTRIBUTION  (only web apps are gradeable; the rest are out of scope, not blind spots)")
    for kind, n in Counter(r["app_kind"] for r in rows).most_common():
        tag = "" if kind in ("web-app", "web-api", "static-site", "?") else "   ← not web gradeable"
        print(f"  {kind:14} {n:>3}{tag}")
    if nonweb:
        print(f"  → {len(nonweb)}/{len(rows)} ({len(nonweb)/len(rows)*100:.0f}%) are NOT web apps, "
              f"excluded from the parity below")

    # stack DISTRIBUTION (which stacks dominate, the head to cover first)
    print("\nSTACK DISTRIBUTION  (cover the head)")
    for g, agg in sorted(gp.items(), key=lambda kv: -kv[1]["n"]):
        print(f"  {g:16} {agg['n']:>3} apps  ({agg['deployed']} deployed)")

    # per stack observed surface + test COVERAGE + TYPE parity. cov% = avg share of the battery that
    # applied; a low cov% (lots of n/a) means a low slop score is uninformative, not necessarily clean.
    print(f"\nOBSERVED SURFACE & TYPE PARITY  (per {args.by}; parity = saw / the source says it exists)")
    print(f"  {'stack':16} {'dep':>4} {'surf':>5} {'cov%':>5} {'find':>5} {'slop':>5}   "
          + "  ".join(f"{t:>9}" for t in _TYPES))
    for g, agg in sorted(gp.items(), key=lambda kv: -kv[1]["n"]):
        par = "  ".join(
            (f"{o}/{e}".rjust(9) if e else "   -".rjust(9)) for o, e in
            (agg["parity"][t] for t in _TYPES))
        print(f"  {g:16} {agg['deployed']:>4} {str(agg['surface_avg']):>5} "
              f"{str(agg['coverage_avg']):>5} {str(agg['findings_avg']):>5} "
              f"{str(agg['slop_avg']):>5}   {par}")

    # COVERAGE % BAR per stack, the cov% column above drawn as a bar so a blind / barely tested stack pops out
    # (a short bar = we applied little of the battery there, so its low slop means little). Scaled to 100% = full.
    cov_rows = [(g, agg["coverage_avg"], agg["n"]) for g, agg in gp.items() if agg["coverage_avg"] is not None]
    if cov_rows:
        print(f"\nCOVERAGE % BY {args.by.upper()}  (probe battery applied; short bar = blind / tiny stack)")
        for g, cov, n in sorted(cov_rows, key=lambda x: -x[1]):
            print(f"  {g:16} {cov:5.1f}% │ {'█' * round(cov / 100 * 40)} (n{n})")

    # TEST COVERAGE PER APP, the cross app spread of how much of the battery APPLIED. The per stack cov%
    # above is only an average; this is the full distribution. A wide stdev = coverage swings hard app to app
    # (some apps barely tested), which bounds how comparable their slop scores are, a low slop on a
    # low coverage app means little. Over web gradeable apps.
    cov_pct = _dist([r["pct_applicable"] for r in web])
    cov_cnt = _dist([r["probes_applicable"] for r in web])
    print("\nTEST COVERAGE PER APP  (share of the probe battery that APPLIED, bounds slop comparability)")
    if cov_pct:
        print(f"  pct applicable   n={cov_pct['n']}  avg={cov_pct['avg']}%  median={cov_pct['median']}%  "
              f"stdev={cov_pct['stdev']}  min={cov_pct['min']}%  max={cov_pct['max']}%  "
              f"(q1={cov_pct['q1']}% q3={cov_pct['q3']}%)")
    if cov_cnt:
        print(f"  probes applied   n={cov_cnt['n']}  avg={cov_cnt['avg']}  median={cov_cnt['median']}  "
              f"stdev={cov_cnt['stdev']}  min={cov_cnt['min']:.0f}  max={cov_cnt['max']:.0f}  "
              f"(q1={cov_cnt['q1']} q3={cov_cnt['q3']})")
    if cov_pct:   # the app level cov% spread as a histogram, a left heavy shape = many barely tested apps
        print("  distribution (pct applicable across apps):")
        for line in _histogram([r["pct_applicable"] for r in web if r["pct_applicable"] is not None]):
            print(line)
    if not cov_pct:
        print("  (no coverage data on these records)")

    # blind spot ranking (prevalence × brokenness = # apps where we missed a surface the source implies)
    print("\nBLIND SPOTS  (fix order, apps where the source says a surface exists but we didn't see it)")
    if not has_expected:
        print("  CANNOT ASSESS: no expected surface here for the source to imply (the URL ingest path emits")
        print("  none). This is an unassessable condition, NOT a clean bill; blind spots are undefined without")
        print("  ground truth. Run deploy_and_grade again with --submission <source> to assess.")
    elif not spots:
        print("  (none, observed surface matches expected across every assessed stack)")
    for s in spots[:12]:
        print(f"  {s['stack']:16} {s['type']:8} missed {s['missed']}/{s['expected']} apps "
              f"(saw {s['observed']})")
    print(f"\n  → per app ledger: scripts/stats.py {args.results} --parity --csv rows.csv\n")


# ==========================================================================================================
# PRECISION (false positive audit): phantom / vendor / signal fires, + a hand audit worksheet.
# ==========================================================================================================
def _unvalidated_probes(recs, min_penalty: int = 25) -> list:
    """Catalog probes that fired 0x across `recs`, 0 fires is ABSENCE OF EVIDENCE, not precision (the corpus
    is auth-dark for the authed surface probes, so they never get to fire). Returns (id, penalty), high first,
    so the report NEVER lets a probe with a high penalty that never fired read as 'precise / 0 FP'."""
    fired = {f["probe_id"] for r in recs for f in (r.get("findings") or [])}
    try:
        catalog = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
    except Exception:
        return []
    return sorted([(p.id, p.penalty) for p in catalog if p.id not in fired and p.penalty >= min_penalty],
                  key=lambda x: -x[1])

# Probes that require a REAL server side endpoint or state change, hallucinated on a catch-all/broken shell.
_PHANTOM_SENSITIVE = ("sec-sqli", "sec-csrf", "sec-cmdi", "sec-ssti", "sec-lfi", "sec-hosthdr",
                      "sec-split", "sec-ratelimit", "sec-idor", "sec-redirect", "sec-dos", "sec-xss",
                      "sec-ssrf", "qa-crash", "qa-race")
# These probes now route through the endpoint level LIVENESS GATE (_endpoint_is_live in probes.py): they
# only fire on an endpoint proven distinct from a nonexistent sibling under its own prefix. So a SURVIVING
# fire is on a REAL server endpoint, and the host level catch-all flag no longer implies a phantom: a modern
# app routinely pairs a catch-all SPA FRONTEND with a real API BACKEND (roadio's /api/locations/search, a real
# SQLi, was firing correctly but got falsely flagged here just because the frontend is a catch-all). We
# TRUST the gate for these and never call their fires catch-all phantoms.
_GATE_VETTED = ("sec-sqli-004", "sec-ratelimit-001", "sec-csrf-001", "qa-crash-010", "sec-dos-001",
                "sec-hosthdr-001")
# EFFECT CONFIRMED probes (added after the browser data plane + integrity/IDOR lanes shipped; precision predates
# them): they fire ONLY on an OBSERVED effect a catch-all shell cannot fake, stored XSS that EXECUTES in the DOM,
# a create that READS BACK, a cross user READ of a real owned object, an international round trip. A catch-all
# serves the same inert shell to everyone, so these gate themselves there, and a SURVIVING fire is real, never a phantom.
# Without this they matched _PHANTOM_SENSITIVE ("sec-xss" / "sec-idor") and were falsely flagged on a catch-all.
_EFFECT_CONFIRMED = ("sec-xss-002", "sec-idor-002", "sec-idor-003", "sec-idor-004", "sec-idor-005",
                     "qa-integrity-001", "qa-integrity-002", "qa-input-002", "qa-race-002")
# Everything else (headers/a11y/seo/perf/compression/dead controls/...) measures the ACTUAL served
# response and stays real even on a catch-all, a missing CSP header is missing regardless.
_NON_WORKING = {"broken", "not-an-app", "placeholder"}   # page states where the WHOLE surface is untrustworthy
# Third-party fields that reflect by design (anti-bot tokens), an XSS "reflection" here is the vendor's, not the app's.
_VENDOR_FIELDS = ("cf-turnstile-response", "g-recaptcha-response", "h-captcha-response", "__requestverificationtoken")
# Fires whose SIGNAL is timing (perf) or an error caused by load (crash / sqli-error), trustworthy only when the
# app was graded in ISOLATION at stable latency. Under a concurrent batch a saturated grader inflates timing and
# a shared backend leaks 500s, so precision.py CANNOT vouch for these from the record alone: it reports them
# UNCONFIRMED (neither clean nor FP) -> fire them again in isolation to resolve. This exists so the audit can't
# lie about 0 FP again: it never counts a fire that's sensitive to concurrency as verified clean. (sqli-004's
# TIME technique is now hardened with a dose-response check and stays stable under load, but its error technique
# and crash can still ride a 500 caused by load.)
_SIGNAL_SENSITIVE = {"perf-lighthouse-001",   # scored off the Lighthouse headline, which shifts with grader side load
                     "perf-cwv-001", "perf-cwv-002", "perf-loadtime-001", "perf-ttfb-001",
                     "perf-load-001",   # a 12-connection concurrent BURST -> under a --concurrency batch the
                                        # grader's own ~96 simultaneous conns can DROP (counted as failure);
                                        # only trustworthy graded in ISOLATION. Was missing -> false "verified".
                     "qa-crash-010", "sec-sqli-004"}


def _phantom_sensitive(pid):
    return pid.startswith(_PHANTOM_SENSITIVE)


def _audited(pid):
    """True iff precision.py has an ACTUAL rule that inspects this probe (phantom/catch-all, signal
    instability, or the exposure/secret guard). When False, a `_suspect()==None` verdict means NO OPINION
   , the finding is UNAUDITED, not verified. The unaudited surface (a11y / headers / seo / perf-requests /
    web-vitals-count / …) is the MAJORITY of the score and exactly where scope & attribution FPs hide (the
    asi1 perf-requests fire is here: real signal, correct probe, live endpoint, wrong owner, every rule
    the audit owns says 'real'). Only auditing by hand (--sample) can vouch for it. See [[fuzz-runner]]."""
    return _phantom_sensitive(pid) or pid in _SIGNAL_SENSITIVE or pid.startswith("sec-secret")


def _damped_by_probe(findings, decay=CATEGORY_DECAY):
    """Per probe DAMPED penalty for one app, what each fire actually COSTS in the score, not the raw
    `penalty x count` this tool used to report. Mirrors aggregate._damped_total: a variant group counts once
    (its highest penalty member), then per category diminishing returns (sorted desc, penalty * decay**i).
    Raw sums badly overstate a fan out probe: sec-headers-001 fires per ROUTE, so its raw mass looked like
    ~25k on the corpus while its damped cost collapses to near zero behind the higher penalty header fires."""
    items = []                                    # expand a fan out finding back into its per target outcomes
    for f in findings:
        pid, grp = f.get("probe_id", ""), f.get("group")
        cat, pen = (f.get("category") or ""), f.get("penalty", 0)
        items.extend([(pid, cat, grp, pen)] * max(1, f.get("count", 1)))
    groups, singles = {}, []
    for it in items:
        if it[2]:                                 # variant group -> only its highest penalty member counts
            cur = groups.get(it[2])
            if cur is None or it[3] > cur[3]:
                groups[it[2]] = it
        else:
            singles.append(it)
    by_cat = defaultdict(list)
    for it in (*singles, *groups.values()):
        by_cat[it[1]].append(it)
    out = defaultdict(float)
    for cat_items in by_cat.values():
        for i, it in enumerate(sorted(cat_items, key=lambda x: -x[3])):
            out[it[0]] += it[3] * (decay ** i)    # the worst counts full; each additional decays
    return out


def _page_state(r):
    return (r.get("coverage_audit") or {}).get("page_state")


def _soft404(r):
    return any(f.get("probe_id") == "qa-http-001" for f in r.get("findings", []))


def _suspect(f, catch_all):
    """Classify finding f on a scored app as one of:
      - ("fp", reason)        a likely FALSE POSITIVE (counts toward the precision gap)
      - ("advisory", reason)  a REAL finding flagged for review (NOT an FP), e.g. a third-party platform login
      - None                  looks real
    Gate aware: sec-sqli-004 / sec-ratelimit-001 / sec-csrf-001 / qa-crash-010 route through the liveness gate,
    so a surviving fire is on a real endpoint, never a catch-all phantom. Rate limit on a catch-all frontend
    host is the one nuance: the login is live but is often a THIRD-PARTY platform login (real endpoint, wrong
    OWNER), so it is an advisory, not an FP, it dissolves when teams submit their own URLs."""
    pid = f.get("probe_id", "")
    ev = f.get("evidence") or {}
    if pid.startswith("sec-xss") and (ev.get("field") or "").lower() in _VENDOR_FIELDS:
        return ("fp", f"reflection is a vendor anti-bot field ({ev.get('field')}), not app controlled XSS")
    if pid == "sec-ratelimit-001" and catch_all:
        return ("advisory", "rate limit on a live login on a catch-all frontend host, likely a third-party "
                            "platform login (real endpoint, verify it is the team's own app)")
    if pid in _SIGNAL_SENSITIVE:   # timing, or an error caused by load: reliable only if graded in isolation.
        return ("unconfirmed", "a timing signal, or an error caused by load, not verifiable from batch data; "
                               "clean if graded in isolation, else fire it again in isolation to confirm "
                               "(not counted clean or FP)")
    if pid in _GATE_VETTED or pid in _EFFECT_CONFIRMED:
        return None   # liveness gated OR effect confirmed: a surviving fire is real, not a catch-all phantom
    if _phantom_sensitive(pid) and catch_all:
        return ("fp", "catch-all / soft 404 host, the targeted endpoint likely doesn't exist server side "
                      "(an ungated phantom sensitive probe)")
    # Exposure fires on a catch-all host are deliberately NOT flagged. The shell guard now lives at the PROBE
    # level (response_is_dotenv rejects an HTML shell body/content-type; .git/.aws use signatures HTML can't
    # satisfy; 006 validates the .map parses), so a SURVIVING exposure fire has already cleared it and is REAL.
    # Verified live: 8yhjs2.csb.app is a soft 404 SPA that ALSO serves a genuine /.env (application/octet-stream,
    # real Amplitude/Sentry keys). A host level catch-all heuristic here DISMISSES real leaks, a false negative
    # on the most severe finding class, strictly worse than the false positive it was meant to catch.
    if pid.startswith("sec-secret") and catch_all:
        return ("advisory", "secret pattern match in the bundle of a catch-all frontend host, verify it's a "
                            "real embedded key (sk-ant / sk-live / AKIA…), not a library constant or the shell")
    # NOTE: a login wall is NOT flagged, its login form + rate limiting ARE real, testable surface.
    return None


def _gated(r):
    """DNF class: excluded from scoring. functional=False is the grader's authoritative verdict (set with
    corroboration, a deterministic broken signal, or no real surface); the page_state fallback covers records
    graded before the veto. A `disputed_broken` record is the veto's product, the LLM called it broken but
    real surface was captured, so it's SCORED, never gated (and its fires ARE audited like any scored app)."""
    if r.get("disputed_broken"):
        return False
    # entry challenge withholds (bot_challenge from the first fetch) score 0 but are NOT real grades, gate them
    # too so they don't inflate the SCORED count (precision predates the challenge_stage field).
    return (r.get("functional") is False or _page_state(r) in _NON_WORKING
            or is_ungradeable_challenge(r))


def analyze(recs):
    have_score = [r for r in recs if isinstance(r.get("slop_score"), (int, float))]
    gated = [r for r in have_score if _gated(r)]          # correctly DNF'd by the gate -> not a precision problem
    scored = [r for r in have_score if not _gated(r)]     # the apps that ACTUALLY count toward the score
    per_probe = defaultdict(lambda: [0, 0])              # pid -> [fires, FALSE positives]
    unaudited = defaultdict(lambda: [0, 0])              # pid -> [fires, penalty] the audit has NO rule for
    vouched = 0                                          # fires where a real precision rule ran and passed
    scored_penalty = 0                                   # total penalty across scored fires (for the share)
    fp_reasons, adv_reasons, unconf_reasons = Counter(), Counter(), Counter()
    flagged, advisories, unconfirmed = [], [], []        # (repo, pid, penalty, count, reason)
    catchall_apps = 0
    for r in scored:                                     # measure precision ONLY on what's actually scored
        catch_all = _soft404(r) or bool((r.get("observed_surface") or {}).get("catch_all"))
        catchall_apps += bool(catch_all)
        damped = _damped_by_probe(r.get("findings") or [])   # the real cost inside the score, not raw penalty*count
        for f in r.get("findings", []):
            pid = f["probe_id"]
            pen = damped.get(pid, 0.0)
            per_probe[pid][0] += 1
            scored_penalty += pen
            res = _suspect(f, catch_all)
            if not res:                                  # `looks real` forks: a rule vouched for it, OR no rule
                if _audited(pid):                        # exists and the audit simply has no opinion (unaudited)
                    vouched += 1
                else:
                    unaudited[pid][0] += 1
                    unaudited[pid][1] += pen
                continue
            klass, why = res
            row = (r.get("repo", ""), pid, f.get("penalty", 0), f.get("count", 1), why)
            if klass == "fp":
                per_probe[pid][1] += 1
                fp_reasons[why.split(", ")[0].split(" (")[0]] += 1
                flagged.append(row)
            elif klass == "unconfirmed":                 # concurrency/latency sensitive, NOT counted clean or FP
                unconf_reasons[why.split(", ")[0].split(" (")[0]] += 1
                unconfirmed.append(row)
            else:                                        # advisory: a REAL finding flagged for review, not an FP
                adv_reasons[why.split(", ")[0].split(" (")[0]] += 1
                advisories.append(row)
    return {"scored": scored, "gated": gated, "gated_slop": sum(r.get("slop_score") or 0 for r in gated),
            "per_probe": per_probe, "fp_reasons": fp_reasons, "adv_reasons": adv_reasons,
            "unconf_reasons": unconf_reasons, "unconfirmed": unconfirmed,
            "vouched": vouched, "unaudited": dict(unaudited), "scored_penalty": scored_penalty,
            "flagged": flagged, "advisories": advisories, "catchall_apps": catchall_apps}


def _wilson(k, n, z=1.96):
    """95% Wilson score interval for a binomial proportion. Unlike the normal approximation it stays inside
    [0,1] and does not collapse to a fake tight band at k=0 (0/30 audited by hand is NOT '0% FP, done', Wilson
    reports it as ~0–11%, which is the honest read on a small sample). This is the whole point of the CI."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _fire_target(f):
    ev = f.get("evidence") or {}
    return ev.get("endpoint") or ev.get("target") or ev.get("path") or ""


def _sample_worksheet(recs, n, seed):
    """Emit N random SCORED fires as a worksheet you audit by hand (TSV). The human fills the `verdict` column
    (fp | ok), then `precision.py --tally FILE` turns it into a real FP rate + 95% CI, the ground truth
    number the heuristic audit structurally cannot produce (it has no oracle; this IS the oracle)."""
    a = analyze(recs)
    fires = [(r.get("repo", ""), f) for r in a["scored"] for f in r.get("findings", [])]
    random.Random(seed).shuffle(fires)                   # seeded -> the draw is reproducible / auditable
    pick = fires[: min(n, len(fires))]
    print(f"# a worksheet you audit by hand, {len(pick)} of {len(fires)} scored fires (seed={seed}). Reproduce each")
    print(f"# and set VERDICT = fp (false positive) | ok (real) | blank to skip. Then:")
    print(f"#   uv run python scripts/stats.py THIS_FILE --tally")
    print("verdict\trepo\tprobe_id\tpenalty\ttarget\trepro")
    for repo, f in pick:
        repro = " ".join(str((f.get("evidence") or {}).get("repro") or "").split())[:200]
        print(f"\t{repo}\t{f.get('probe_id', '')}\t{f.get('penalty', 0)}\t{_fire_target(f)}\t{repro}")


def _tally(path):
    """Read a filled worksheet and print the FP rate audited by hand, + 95% Wilson CI over the resolved verdicts."""
    k = n = 0
    per_probe = defaultdict(lambda: [0, 0])              # pid -> [audited, fp]
    for line in open(path):
        if line.startswith("#") or line.startswith("verdict\t"):
            continue
        cols = line.rstrip("\n").split("\t")
        v = (cols[0].strip().lower() if cols else "")
        if v not in ("fp", "ok"):
            continue                                     # blank / unresolved -> not counted either way
        n += 1
        k += (v == "fp")
        pid = cols[2] if len(cols) > 2 else "?"
        per_probe[pid][0] += 1
        per_probe[pid][1] += (v == "fp")
    if not n:
        print("no resolved verdicts (fill the `verdict` column with fp/ok, then run --tally again)")
        return
    lo, hi = _wilson(k, n)
    print(f"\n═══ precision audited by hand, {n} fires resolved, {k} false positive(s) ═══")
    print(f"    FP rate    {k / n * 100:5.1f}%     95% CI  {lo * 100:4.1f}% – {hi * 100:4.1f}%")
    print(f"    precision  {(1 - k / n) * 100:5.1f}%     95% CI  {(1 - hi) * 100:4.1f}% – {(1 - lo) * 100:4.1f}%")
    print(f"    -> at n={n}, the TRUE FP rate is plausibly as high as {hi * 100:.1f}%. Widen the draw to tighten it.")
    worst = sorted(((pid, c, fp) for pid, (c, fp) in per_probe.items() if fp), key=lambda x: -x[2])
    if worst:
        print("    by probe (only those with an FP):")
        for pid, c, fp in worst:
            print(f"      {fp}/{c}  {pid}")
    print()


def precision_report(recs, args):
    a = analyze(recs)
    scored = a["scored"]
    total_fires = sum(v[0] for v in a["per_probe"].values())
    total_fp = sum(v[1] for v in a["per_probe"].values())
    fp_apps = len({x[0] for x in a["flagged"]})
    adv_apps = len({x[0] for x in a["advisories"]})
    total_unconf = len(a["unconfirmed"])
    unconf_apps = len({x[0] for x in a["unconfirmed"]})
    vouched = a["vouched"]
    unaudited = a["unaudited"]                            # pid -> [fires, penalty]
    unaudited_fires = sum(v[0] for v in unaudited.values())
    unaudited_pen = sum(v[1] for v in unaudited.values())
    pen_share = (unaudited_pen / a["scored_penalty"] * 100) if a["scored_penalty"] else 0.0

    if args.json:
        print(json.dumps({
            "n_scored": len(scored), "n_gated_dnf": len(a["gated"]), "gated_slop": a["gated_slop"],
            "scored_fires": total_fires, "false_positive_fires": total_fp, "fp_apps": fp_apps,
            "advisory_fires": len(a["advisories"]), "advisory_apps": adv_apps, "catchall_apps": a["catchall_apps"],
            "vouched_fires": vouched, "unaudited_fires": unaudited_fires,
            "unvalidated_zero_fire": [{"id": pid, "penalty": pen} for pid, pen in _unvalidated_probes(recs)],
            "unaudited_penalty_pct": round(pen_share, 1),
            "unaudited_by_probe": {pid: v[0] for pid, v in sorted(unaudited.items(), key=lambda x: -x[1][1])},
            "unconfirmed_fires": total_unconf, "unconfirmed_apps": unconf_apps,
            "unconfirmed_reasons": dict(a["unconf_reasons"].most_common()),
            "per_probe_precision": {pid: {"fires": v[0], "false_positives": v[1],
                                          "precision_pct": round((v[0] - v[1]) / v[0] * 100, 1) if v[0] else None}
                                    for pid, v in sorted(a["per_probe"].items())},
            "fp_reasons": dict(a["fp_reasons"].most_common()),
            "advisory_reasons": dict(a["adv_reasons"].most_common()),
        }, indent=2))
        return

    print(f"\n═══ precision audit, {len(scored)} SCORED apps  ({len(a['gated'])} DNF'd by the gate, excluded) ═══")
    print(f"\n⚠  NOT a true precision number. This audit recognizes a FIXED list of FP classes (catch-all")
    print(f"   phantom | vendor reflection | signal instability) and has NO ground truth oracle. It is blind")
    print(f"   to scope/attribution FPs, a REAL finding on the wrong owner's page (the asi1 perf case). For")
    print(f"   the real number, audit by hand:  python scripts/stats.py {args.results} --precision --sample 30 > w.tsv")

    print(f"\n(0) DNF GATE, {len(a['gated'])} apps broken/not-an-app -> DNF class, EXCLUDED "
          f"({a['gated_slop']} slop correctly kept out of the distribution; not a precision gap).")

    print(f"\n(1) WHAT THE AUDIT CAN / CANNOT VOUCH FOR")
    print(f"    {vouched:>5} / {total_fires} VOUCHED    , a precision rule ran and passed (liveness gate / "
          f"catch-all / vendor field).")
    print(f"    {unaudited_fires:>5} / {total_fires} UNAUDITED  , NO rule exists; neither confirmed nor suspect. "
          f"{pen_share:.0f}% of the DAMPED penalty inside the score. Audit these by hand:")
    for pid, (fires, pen) in sorted(unaudited.items(), key=lambda x: -x[1][1])[:12]:
        print(f"            {fires:>5} fires | {pen:>7.0f} pen inside the score   {pid}")
    unval = _unvalidated_probes(recs)
    if unval:
        print(f"\n(1b) UNVALIDATED, {len(unval)} high-penalty probe(s) fired 0× on this corpus.")
        print(f"     0 fires is ABSENCE OF EVIDENCE, not precision (corpus auth-dark / no applicable surface).")
        print(f"     Do NOT read their 0 FP as 'precise', unvalidated until they fire on real surface:")
        for pid, pen in unval[:15]:
            print(f"            pen {pen:>3}   {pid}")
    if total_unconf:
        print(f"    {total_unconf:>5} / {total_fires} UNCONFIRMED, timing, or an error caused by load ({unconf_apps} apps); "
              f"fire them again in isolation to resolve:")
        for why, n in a["unconf_reasons"].most_common():
            print(f"            {n:>5}  {why}")
    print(f"    {total_fp:>5} / {total_fires} KNOWN CLASS FP ({fp_apps} apps), only the classes this audit can see:")
    for why, n in a["fp_reasons"].most_common():
        print(f"            {n:>5}  {why}")
    if not a["fp_reasons"]:
        print(f"            (none of the KNOWN classes survived, this says NOTHING about the unaudited surface above)")

    if a["advisories"]:
        print(f"\n(1b) OWNERSHIP FLAGGED, REAL findings on live endpoints, NOT false positives")
        print(f"    {len(a['advisories'])} fires across {adv_apps} apps. These dissolve when teams submit their OWN URLs:")
        for why, n in a["adv_reasons"].most_common():
            print(f"      {n:>4}  {why}")

    print(f"\n(2) PER PROBE CATCH-ALL/PHANTOM PRECISION  (audited probes only, NOT the whole surface; "
          f"[gated] = vetted by the liveness gate)")
    rows = [(pid, v[0], v[1]) for pid, v in a["per_probe"].items() if _phantom_sensitive(pid) and v[0]]
    for pid, fires, fp in sorted(rows, key=lambda x: -x[2]) or [(None, 0, 0)]:
        if pid is None:
            print("    (no phantom sensitive probes fired on scored apps)")
            break
        prec = (fires - fp) / fires * 100
        tag = " [gated]" if pid in _GATE_VETTED else " [effect]" if pid in _EFFECT_CONFIRMED else ""
        print(f"    {pid:20} {fires:>4} fires | {fp:>4} FP | {prec:5.0f}% not phantom {'█' * int(round(prec / 5))}{tag}")

    combined = [("   ", *x) for x in a["flagged"]] + [("[A]", *x) for x in a["advisories"]]
    if combined:
        print(f"\n(3) FLAGGED FINDINGS  (top {args.show} by penalty; [A] = advisory/ownership, not an FP)")
        for mark, repo, pid, pen, cnt, why in sorted(combined, key=lambda x: -x[3])[:args.show]:
            print(f"    {mark} {(repo or '').rsplit('/', 1)[-1][:28]:28} {pid:18} pen={pen:>3}×{cnt:<2}, {why[:52]}")

    # SCORE TRUST (parity x precision join), per scored app: is its slop trustworthy? Two ways it is not, we were
    # BLIND (coverage <= Q1 -> a low score is uninformative, not clean, parity's concern) OR the score is INFLATED
    # (a fire from a known FP class, precision's concern). Everything else is a trustworthy score.
    flagged_repos = {x[0] for x in a["flagged"]}
    covs = [c for r in a["scored"] if (c := (r.get("coverage") or {}).get("pct_applicable")) is not None]
    q1 = (statistics.quantiles(covs, n=4)[0] if len(covs) >= 4 else min(covs)) if covs else 0

    def _cov(r):
        return (r.get("coverage") or {}).get("pct_applicable")
    blind, inflated, trust = [], [], 0
    for r in a["scored"]:
        if r.get("repo") in flagged_repos:
            inflated.append(r)
        elif _cov(r) is not None and _cov(r) <= q1:
            blind.append(r)
        else:
            trust += 1
    if a["scored"]:
        print(f"\n(4) SCORE TRUST  (parity x precision join, over {len(a['scored'])} scored apps)")
        print(f"    {trust:>4} trustworthy   |   {len(blind):>4} UNDER OBSERVED (cov <= Q1 {q1:.0f}%, score "
              f"uninformative)   |   {len(inflated):>4} INFLATED (>=1 fire from a known FP class)")
        # INFLATED: highest slop first (most affected by FP). BLIND: LOWEST slop first, a low score on low coverage
        # is the suspect case (looks clean but we barely tested it, not the same as genuinely clean).
        for r in sorted(inflated, key=lambda r: -(r.get("slop_score") or 0))[:6]:
            label = (r.get("repo") or "").rstrip("/").rsplit("/", 1)[-1][:32] or "?"
            print(f"      INFLATED  {label:32} slop {r['slop_score']:>6.1f}   cov {_cov(r)}%   (a phantom fire inflates it)")
        for r in sorted(blind, key=lambda r: (r.get("slop_score") or 0))[:6]:
            label = (r.get("repo") or "").rstrip("/").rsplit("/", 1)[-1][:32] or "?"
            print(f"      BLIND     {label:32} slop {r['slop_score']:>6.1f}   cov {_cov(r)}%   (low score may be blindness)")
    print()



# ==========================================================================================================
# DIFF (run to run regression): join a CURRENT run against a PREVIOUS one -> what moved. The grade -> fix ->
# regrade loop's answer to "did my change help, and what moved?"
# ==========================================================================================================
def diff_report(cur, prev, args):
    """Join CURRENT vs a PREVIOUS run by app (repo) and report what moved, score deltas, per probe fire gains /
    losses, coverage / challenge / DNF shifts. Apps present in only one run are counted but never differenced."""
    cg = {r.get("repo"): r for r in cur if _is_graded(r)}
    pg = {r.get("repo"): r for r in prev if _is_graded(r)}
    common = sorted(set(cg) & set(pg))
    added, removed = sorted(set(cg) - set(pg)), sorted(set(pg) - set(cg))
    deltas = sorted(((k, cg[k]["slop_score"] - pg[k]["slop_score"]) for k in common), key=lambda x: x[1])

    def fired(r):
        return {f["probe_id"] for f in r.get("findings", []) if _scored(f)}
    probe_delta, new_pairs, gone_pairs = Counter(), 0, 0     # per probe app fire gain/loss over common apps
    for k in common:
        cf, pf = fired(cg[k]), fired(pg[k])
        new_pairs += len(cf - pf)
        gone_pairs += len(pf - cf)
        for pid in cf - pf:
            probe_delta[pid] += 1
        for pid in pf - cf:
            probe_delta[pid] -= 1
    covc = [x for k in common if (x := (cg[k].get("coverage") or {}).get("pct_applicable")) is not None]
    covp = [x for k in common if (x := (pg[k].get("coverage") or {}).get("pct_applicable")) is not None]

    def chal(recs):
        return sum(1 for r in recs if r.get("bot_challenge"))

    def ndnf(recs):
        return sum(1 for r in recs if not r.get("skipped") and not _is_graded(r))
    net = sum(d for _, d in deltas)
    moved = [d for _, d in deltas if d]

    if args.json:
        print(json.dumps({
            "common": len(common), "added": added, "removed": removed,
            "score_delta": {"net": round(net, 1), "mean": round(net / (len(common) or 1), 1),
                            "improved": sum(1 for _, d in deltas if d < 0),
                            "regressed": sum(1 for _, d in deltas if d > 0),
                            "biggest_improvement": deltas[0] if deltas else None,
                            "biggest_regression": deltas[-1] if deltas else None},
            "probe_fire_delta": dict(probe_delta.most_common()),
            "new_fire_pairs": new_pairs, "gone_fire_pairs": gone_pairs,
            "coverage_pct": {"prev_mean": round(statistics.mean(covp), 1) if covp else None,
                             "cur_mean": round(statistics.mean(covc), 1) if covc else None},
            "bot_challenge": {"prev": chal(prev), "cur": chal(cur)},
            "dnf": {"prev": ndnf(prev), "cur": ndnf(cur)}}, indent=2))
        return

    print(f"\n═══ run diff, {len(common)} common apps (current {len(cg)} graded | previous {len(pg)}) ═══")
    print(f"\n(1) APP SET   {len(common)} in both | {len(added)} new this run | {len(removed)} gone from last run")
    if added:
        print("    new:  " + ", ".join((a or "").rstrip("/").rsplit("/", 1)[-1] for a in added[:8]) + (" ..." if len(added) > 8 else ""))
    if removed:
        print("    gone: " + ", ".join((a or "").rstrip("/").rsplit("/", 1)[-1] for a in removed[:8]) + (" ..." if len(removed) > 8 else ""))

    print(f"\n(2) SCORE  (over the {len(common)} common apps; negative = CLEANER now, positive = WORSE)")
    print(f"    net {net:+.1f}   mean {net/(len(common) or 1):+.1f}/app   |   "
          f"{sum(1 for d in moved if d < 0)} improved | {sum(1 for d in moved if d > 0)} regressed | "
          f"{len(common)-len(moved)} unchanged")
    if deltas:
        print("    biggest improvements (score dropped):")
        for k, d in deltas[:6]:
            if d < 0:
                print(f"      {((k or '').rstrip('/').rsplit('/', 1)[-1] or '?')[:34]:34} {pg[k]['slop_score']:>6.1f} -> {cg[k]['slop_score']:<6.1f} ({d:+.1f})")
        print("    biggest regressions (score rose):")
        for k, d in reversed(deltas[-6:]):
            if d > 0:
                print(f"      {((k or '').rstrip('/').rsplit('/', 1)[-1] or '?')[:34]:34} {pg[k]['slop_score']:>6.1f} -> {cg[k]['slop_score']:<6.1f} ({d:+.1f})")

    print(f"\n(3) FIRES  ({new_pairs} new app fires | {gone_pairs} gone | per probe net over common apps)")
    gained = [(p, n) for p, n in probe_delta.most_common() if n > 0]
    lost = [(p, n) for p, n in sorted(probe_delta.items(), key=lambda x: x[1]) if n < 0]
    if gained:
        print("    firing MORE now:  " + "  ".join(f"{p} {n:+d}" for p, n in gained[:8]))
    if lost:
        print("    firing LESS now:  " + "  ".join(f"{p} {n:+d}" for p, n in lost[:8]))
    if not gained and not lost:
        print("    (no per probe fire changes over the common apps)")

    print(f"\n(4) COVERAGE / TAINT")
    if covc and covp:
        print(f"    pct applicable   prev mean {statistics.mean(covp):.1f}%  ->  cur mean {statistics.mean(covc):.1f}%  "
              f"({statistics.mean(covc)-statistics.mean(covp):+.1f})")
    print(f"    bot challenged   prev {chal(prev)}  ->  cur {chal(cur)}   |   "
          f"DNF   prev {ndnf(prev)}  ->  cur {ndnf(cur)}")
    print(f"\n    → per probe / per app detail: --json, or --audit <probe id> on either run\n")


def main():
    ap = argparse.ArgumentParser(
        description="Analyze deploy_and_grade results: the default RECALL report, plus --parity (cross stack "
                    "visibility) and --precision (false positive audit). One tool, three lenses on one file.")
    ap.add_argument("results", help="the JSONL from deploy_and_grade --record (or a filled worksheet, with --tally)")
    ap.add_argument("--audit", metavar="PROBE", help="list every app + evidence where PROBE fired, then exit")
    ap.add_argument("--json", action="store_true", help="emit a machine readable summary instead of the report")
    ap.add_argument("--sigma", type=float, default=2.0, help="high outlier threshold in stdevs (default 2)")
    ap.add_argument("--charts", action="store_true",
                    help="render the corpus writeup PNG charts (+ sibling CSVs) to docs/charts/, then exit "
                         "(needs matplotlib: run via `uv run --with matplotlib`)")
    # --- PARITY mode (cross stack visibility): observed vs expected surface, blind spots ---
    ap.add_argument("--parity", action="store_true", help="run the cross stack PARITY dashboard instead of the report")
    ap.add_argument("--by", default="routing", choices=["routing", "framework", "api_style"],
                    help="parity group key (default routing, the discovery relevant axis)")
    ap.add_argument("--csv", metavar="FILE", help="parity: write the per app rows to FILE (the ledger) and exit")
    # --- PRECISION mode (false positive audit) ---
    ap.add_argument("--precision", action="store_true", help="run the PRECISION (false positive) audit instead")
    ap.add_argument("--show", type=int, default=20, help="precision: how many flagged findings to list")
    ap.add_argument("--sample", type=int, metavar="N",
                    help="precision: emit N random fires as a worksheet you audit by hand (TSV), then exit")
    ap.add_argument("--tally", action="store_true",
                    help="precision: treat `results` as a filled worksheet -> FP rate + 95%% Wilson CI")
    ap.add_argument("--seed", type=int, default=0, help="precision: RNG seed for --sample (reproducible draw)")
    ap.add_argument("--diff", metavar="PREV", help="run to run regression: diff `results` against a PREVIOUS run's JSONL")
    args = ap.parse_args()

    if args.tally:                                    # precision: `results` is a filled worksheet, not a JSONL
        _tally(args.results)
        return
    recs = load(args.results)
    if not recs:
        sys.exit("no records")
    if args.diff:
        diff_report(recs, load(args.diff), args)
        return
    if args.parity:
        parity_report(recs, args)
        return
    if args.precision:
        if args.sample:
            _sample_worksheet(recs, args.sample, args.seed)
        else:
            precision_report(recs, args)
        return
    if args.audit:
        audit(recs, args.audit)
        return
    if args.charts:
        import pathlib

        from charts import render_all
        written = render_all(recs, run_name=pathlib.Path(args.results).name)
        print(f"wrote {len(written)} charts + sibling CSVs to docs/charts/ (run: {pathlib.Path(args.results).name})")
        for p in written:
            print("  " + p)
        return

    # cohorts: REPO apps are cloned + deploy tested from source (the reproducibility metric applies to
    # them). URL INGEST apps were already live and graded raw over HTTP(S), NOT deployed by us, and only
    # the HTTPS-only probes apply to them. Keep them distinct so neither the deploy rate nor the score
    # cohorts get silently conflated.
    url_apps = [r for r in recs if _source(r) == "url"]
    repo_recs = [r for r in recs if _source(r) == "repo"]
    deployed = [r for r in repo_recs if r.get("deployed")]      # deploy success is a REPO only concept
    # non functional = the audit judged it broken/not-an-app/placeholder -> DNF CLASS: ranks below every
    # working submission, so it's EXCLUDED from the score distribution (never rescued to a low slop score).
    nonfunctional = [r for r in recs if r.get("functional") is False]
    disputed = [r for r in recs if r.get("disputed_broken") and r.get("functional") is not False]  # veto: scored, flagged
    graded = [r for r in recs if _is_graded(r)]
    ungraded = [r for r in deployed if "slop_score" not in r]   # repo app came up but grading aborted
    scores = [r["slop_score"] for r in graded]
    # (g) pairing: a submission graded BOTH ways, keyed by project, the delta is the reproducibility signal
    by_project = defaultdict(dict)
    for r in recs:
        if r.get("project"):
            by_project[r["project"]][_source(r)] = r
    paired = {p: d for p, d in by_project.items() if "repo" in d and "url" in d}
    timed = [r for r in recs if r.get("timings")]               # per phase wall clock, as measurement
    _PHASES = [("clone_s", "clone"), ("plan_s", "plan(LLM)"), ("deploy_s", "deploy"),
               ("grade_s", "grade"), ("audit_s", "audit(LLM)"), ("total_s", "total")]

    def _phase(key):
        return [r["timings"][key] for r in timed if r["timings"].get(key)]

    # ---- (a) deploy success rate (the hackathon reproducibility finding) ----
    skipped = [r for r in repo_recs if r.get("skipped")]   # not a web app -> OUT OF SCOPE, not a failure
    fails = [r for r in repo_recs if not r.get("deployed") and not r.get("skipped")]
    err_kinds = Counter((r.get("deploy_error") or "unknown")[:60] for r in fails)
    timeouts = Counter(r["timeout"] for r in recs if r.get("timeout"))   # 'took forever', a signal itself

    # ---- per app category subtotals (rebuilt, faithful) ----
    per_app_cats = {r["repo"]: cat_subtotals(r) for r in graded}
    cat_total = defaultdict(float)       # category -> damped slop summed across apps
    for cats in per_app_cats.values():
        for (bundle, cat), v in cats.items():
            cat_total[f"{bundle}/{cat}"] += v
    all_slop = sum(cat_total.values()) or 1.0

    # ---- (c) per probe fire frequency (app level) + most frequent findings ----
    probe_apps = defaultdict(set)        # probe_id -> {repos}
    probe_meta = {}                      # probe_id -> (bundle, category)
    for r in graded:
        for f in r.get("findings", []):
            if not _scored(f):   # off score diagnostics (report_only) don't belong in the fire frequency
                continue
            probe_apps[f["probe_id"]].add(r["repo"])
            probe_meta[f["probe_id"]] = (f["bundle"], f["category"])
    freq = sorted(((pid, len(apps)) for pid, apps in probe_apps.items()), key=lambda x: -x[1])

    # ---- email verification family breakdown (now scoring): the qa-email-001 ladder + qa-email-002 inert.
    # Read off the FIRED findings' evidence (email_gated apps that CLEANED leave no finding), so this sizes the
    # lockouts, not the whole email gated subset. Self suppresses when the family never fired. ----
    def _email_fires(pid):
        return [(r, f) for r in graded for f in r.get("findings", []) if f["probe_id"] == pid and _scored(f)]

    def _ev_count(fires, key):
        return sum(1 for _, f in fires if (f.get("evidence") or {}).get(key))
    email_001, email_002 = _email_fires("qa-email-001"), _email_fires("qa-email-002")
    email_break = {"unreliable_flow_apps": len(email_001), "inert_link_apps": len(email_002),
                   "no_email_60s": _ev_count(email_001, "no_email_60s"),
                   "email_late_30s": _ev_count(email_001, "email_late_30s"),
                   "no_resend_button": _ev_count(email_001, "no_resend_button")}

    # ---- (d) winners vs non winners ----
    def split(pred):
        return [r for r in recs if r.get("winner") is True and pred(r)], \
               [r for r in recs if r.get("winner") is False and pred(r)]
    win_all, non_all = split(lambda r: True)
    # SAME population as (b) graded, via the shared _is_graded, excludes non functional/DNF, recon, AND
    # entry challenge withholds, so the winner comparison isn't contaminated and its min can't disagree with (b).
    win_scores = [r["slop_score"] for r in win_all if _is_graded(r)]
    non_scores = [r["slop_score"] for r in non_all if _is_graded(r)]

    # ---- (a2) by hackathon: the source hackathon attribution rolled up into per hackathon stats ----
    hk_rows = by_hackathon(recs)
    hk_ranked = [r for r in hk_rows if r["graded"] >= 10 and r["median_slop"] is not None]  # min n so a 1-app slug can't top it

    # ---- (e) anomalies ----
    mean = statistics.mean(scores) if scores else 0
    sd = statistics.pstdev(scores) if len(scores) >= 2 else 0
    hi_cut = mean + args.sigma * sd
    zeros = [r for r in graded if r["slop_score"] == 0]
    thin = [r for r in graded if r["slop_score"] > 0 and len(r.get("findings", [])) < 2]
    highs = [r for r in graded if sd > 0 and r["slop_score"] > hi_cut]

    # ---- LLM pointer precision (build #2, OFF SCORE): of the endpoints the LLM UNIQUELY seeded from source
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

    # rendered PERCEPTION pointer (proactive discovery, --proactive), the same honesty measure on surface an
    # LLM read off the RENDERED page (client side logins/uploads/actions). Kept SEPARATE from the source pointer
    # above so a --proactive A/B is legible. Forms are counted (they survived phantom suppression to be probed);
    # endpoint reachable/hallucinated via the frozen baseline. Off score: measures perception, never scores it.
    pcv_active = [p for r in recs for p in [_ptr(r)]
                  if p and (p.get("perceived_endpoints_seeded") or p.get("perceived_forms_seeded"))]
    pcv_eps = sum(p.get("perceived_endpoints_seeded", 0) for p in pcv_active)
    pcv_reach = sum(p.get("perceived_endpoints_reachable", 0) for p in pcv_active)
    pcv_halluc = sum(p.get("perceived_endpoints_hallucinated", 0) for p in pcv_active)
    pcv_forms = sum(p.get("perceived_forms_seeded", 0) for p in pcv_active)
    pcv_judged = pcv_reach + pcv_halluc
    pcv_prec = round(pcv_reach / pcv_judged * 100, 1) if pcv_judged else None

    # BACKEND TIER distribution (OFF SCORE): WHOSE is each host the app's traffic hits (classify hosts). Sizes the
    # Move-2 gap = how many apps have an ATTRIBUTED own off origin backend (same domain / self hosted PaaS) we could
    # safely probe. Tiers OVERLAP (an app can have a same origin API + a BaaS + a custom backend) -> each count is
    # "how many apps have ANY host of this tier". opaque = unattributable off origin (not probed; flagged instead).
    def _tiers(r):
        s = r.get("observed_surface")
        t = s.get("host_tiers") if isinstance(s, dict) else None
        return t if isinstance(t, dict) and isinstance(t.get("counts"), dict) else None
    tiered = [t for r in recs for t in [_tiers(r)] if t and sum(t["counts"].values())]
    n_tier = len(tiered)
    tier_same = sum(1 for t in tiered if t["counts"].get("same_origin"))
    tier_own = sum(1 for t in tiered if t["counts"].get("own_backend"))     # ATTRIBUTED own backend = Move-2 target
    tier_baas = sum(1 for t in tiered if t["counts"].get("managed_baas"))
    tier_vendor = sum(1 for t in tiered if t["counts"].get("vendor"))       # consumed third party, not graded
    tier_opaque = sum(1 for t in tiered if t["counts"].get("opaque"))       # unattributable -> flagged, not probed
    own_hosts = Counter(h for t in tiered for h in (t.get("own_hosts") or []))
    opaque_hosts = Counter(h for t in tiered for h in (t.get("opaque_hosts") or []))

    # PLATFORM + BUILDER (off score, platform_id): host platform (headers+suffix), AI builder (served markup),
    # and the payoff -- slop BY builder (are AI-built apps sloppier than ones deployed by hand?). Empty on records
    # graded before the field existed (old runs) -> the section self suppresses.
    platted = [(r, r["platform"]) for r in recs if isinstance(r.get("platform"), dict) and r["platform"]]
    host_dist = Counter((p.get("host_platform") or "unknown") for _, p in platted)
    edge_dist = Counter(p["edge"] for _, p in platted if p.get("edge"))
    builder_dist = Counter((p.get("builder") or "none / hand built") for _, p in platted)

    def _slop_by(keyfn):
        b = defaultdict(list)
        for r, p in platted:
            if r.get("slop_score") is not None:
                b[keyfn(p)].append(r["slop_score"])
        return sorted(((k, len(v), round(statistics.median(v), 1)) for k, v in b.items()), key=lambda x: -x[1])
    slop_by_builder = _slop_by(lambda p: p.get("builder") or "none / hand built")
    slop_by_host = _slop_by(lambda p: p.get("host_platform") or "unknown")

    models = Counter(r.get("model") for r in recs if r.get("model"))   # LLM(s) used (a file may mix runs)

    # BOT CHALLENGE / TAINT (net.is_bot_challenge): apps that answered with a WAF/challenge/sleep interstitial
    # instead of the app. Excluded from `graded`, but COUNTED here per host platform so a disproportionately
    # challenged platform (e.g. Vercel Attack Challenge Mode) is visible as a taint signal -- rather than
    # inferred from the compression proxy. Rate = challenged / (all records on that platform).
    def _host_of(r):
        p = r.get("platform")
        return (p.get("host_platform") if isinstance(p, dict) else None) or "unknown"
    challenged = [r for r in recs if r.get("bot_challenge")]
    entry_ch = [r for r in challenged if is_ungradeable_challenge(r)]       # withheld (ungradeable)
    late_ch = [r for r in challenged if r.get("challenge_stage") == "late"]  # RECOVERED -> counted in `graded`
    chal_by_host = Counter(_host_of(r) for r in challenged)
    # WHICH probe's traffic first tripped the WAF (net.challenge_onset) -> the gate/reorder candidates
    onset_by_probe = Counter(r["challenge_onset"] for r in challenged if r.get("challenge_onset"))
    # per probe REQUEST VOLUME (net.request_counts): which probes send abnormally many requests (the WAF trip /
    # pacing / trim candidates). Median across apps that ran the probe, + the worst single app.
    probe_reqs: dict = defaultdict(list)
    for r in recs:
        for pid, k in (r.get("request_counts") or {}).items():
            probe_reqs[pid].append(k)
    req_rank = sorted(((pid, statistics.median(v), max(v), len(v)) for pid, v in probe_reqs.items() if v),
                      key=lambda x: -x[1])
    host_totals = Counter(_host_of(r) for r in recs)
    challenge_by_host = sorted(
        ((h, n, host_totals[h], round(100 * n / (host_totals[h] or 1), 1)) for h, n in chal_by_host.items()),
        key=lambda x: -x[1])

    # ---- ATTRITION (the DNF rate) + AUTH SURFACE: the headline yield the deploy rate alone hides (a repo can
    # deploy yet still DNF on a broken app or an entry challenge), and the login/signup/SSO reach. Both computed
    # by module level functions (unit tested); unpacked to locals so the JSON + print blocks stay unchanged. ----
    attempted = [r for r in recs if not r.get("skipped")]
    dnf = [r for r in attempted if not _is_graded(r)]
    dnf_reasons = Counter(_dnf_reason(r) for r in dnf)
    A = auth_surface(graded)
    n_sf, sf_login, sf_signup, sf_pw = A["n"], A["has_login"], A["has_signup"], A["self_registerable"]
    sf_sso, sf_ssoonly, no_auth = A["has_sso"], A["sso_only"], A["no_auth"]
    sso_providers, captcha_kinds = A["sso_providers"], A["captcha"]
    # reach x yield: of the self registerable apps (a password signup we can drive), how many actually got an
    # authed cluster finding, i.e. did establishing a session surface a defect. Ties the reach to real coverage.
    reg_apps = [r for r in graded if isinstance(r.get("observed_surface"), dict)
                and r["observed_surface"].get("has_password_form")]
    reg_fired = [r for r in reg_apps if any(_scored(f) and f["probe_id"] in _AUTHED_PROBES
                                            for f in r.get("findings", []))]
    authed_fire_probes = Counter(f["probe_id"] for r in reg_apps for f in r.get("findings", [])
                                 if _scored(f) and f["probe_id"] in _AUTHED_PROBES)

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
            "bot_challenge": {"n": len(challenged), "pct": round(100 * len(challenged) / (len(recs) or 1), 1),
                              "by_host": {h: {"challenged": n, "total": t, "pct": pct}
                                          for h, n, t, pct in challenge_by_host},
                              "tripped_by_probe": dict(onset_by_probe.most_common())},
            "attrition": {"attempted": len(attempted), "graded": len(graded),
                          "graded_pct": round(100 * len(graded) / (len(attempted) or 1), 1),
                          "dnf": len(dnf), "dnf_pct": round(100 * len(dnf) / (len(attempted) or 1), 1),
                          "skipped_out_of_scope": len(skipped), "dnf_by_reason": dict(dnf_reasons.most_common())},
            "clean_rate": {"clean": len(zeros), "graded": len(graded),
                           "pct": round(100 * len(zeros) / (len(graded) or 1), 1)},
            "auth_surface": {"n": n_sf, "has_login": sf_login, "has_signup": sf_signup,
                             "has_password_form": sf_pw, "self_registerable": sf_pw, "has_sso": sf_sso,
                             "sso_only_hard_blocked": sf_ssoonly, "no_auth": no_auth,
                             "partition": dict(A["partition"].most_common()),
                             "sso_providers": dict(sso_providers.most_common()),
                             "captcha": dict(captcha_kinds.most_common()),
                             "reach_yield": {"registerable": sf_pw, "with_authed_finding": len(reg_fired),
                                             "authed_fire_probes": dict(authed_fire_probes.most_common())}},
            "finding_severity": {t: {"findings": sum(1 for r in graded for f in r.get("findings", [])
                                                     if _scored(f) and _severity_tier(f["penalty"]) == t),
                                     "apps": len({r["repo"] for r in graded for f in r.get("findings", [])
                                                  if _scored(f) and _severity_tier(f["penalty"]) == t})}
                                 for t in ("critical", "serious", "moderate", "minor")},
            "category_concentration": {k: round(v, 1) for k, v in sorted(cat_total.items(), key=lambda x: -x[1])},
            "probe_fire_frequency": {pid: n for pid, n in freq},
            "email_verification": email_break,
            "by_hackathon": hk_rows,
            "lighthouse_scores": lighthouse_scores(graded),
            "lighthouse_by_winner": {
                "winners": lighthouse_scores([r for r in graded if r.get("winner") is True])["performance"],
                "non_winners": lighthouse_scores([r for r in graded if r.get("winner") is False])["performance"]},
            "winners": {"n": len(win_scores), "avg": round(statistics.mean(win_scores), 1) if win_scores else None},
            "non_winners": {"n": len(non_scores), "avg": round(statistics.mean(non_scores), 1) if non_scores else None},
            "anomalies": {"zeros": [r["repo"] for r in zeros], "thin": [r["repo"] for r in thin],
                          "high_outliers": [(r["repo"], r["slop_score"]) for r in highs]},
            "timing_s": {label: {"avg": round(statistics.mean(xs), 1), "median": round(statistics.median(xs), 1),
                                 "max": max(xs)} for key, label in _PHASES for xs in [_phase(key)] if xs},
            "grade_timeouts": sum(1 for r in timed if r.get("grade_timeout")),
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

    print(f"\n═══ deploy_and_grade stats, {len(recs)} apps ═══")
    if models:
        print("    model(s): " + ", ".join(f"{m} ({n})" for m, n in models.most_common()))

    _sec_n = [0]

    def sec(title):
        _sec_n[0] += 1
        print(f"\n[{_sec_n[0]}] {title}")

    # (a)
    sec(f"YIELD & ATTRITION  (of every app we attempted; skips are out of scope, not failures)")
    print(f"    {len(graded)}/{len(attempted)} graded ({100 * len(graded) / (len(attempted) or 1):.0f}%)"
          f"   |   {len(dnf)} DNF ({100 * len(dnf) / (len(attempted) or 1):.0f}%)"
          + (f"   |   {len(skipped)} skipped (not a web app)" if skipped else ""))
    for reason, n in dnf_reasons.most_common():
        print(f"      {n:>3} DNF  {reason}")
    print(f"    clean: {len(zeros)}/{len(graded)} graded scored 0 (fully clean, no slop found)"
          f"   |   {100 * len(zeros) / (len(graded) or 1):.0f}% clean rate")
    print(f"\n    deploy success (reproducibility, REPO apps only):")
    n_try = len(repo_recs) - len(skipped)   # over REPO web apps we tried to deploy (not skips, not live URLs)
    print(f"    {len(deployed)}/{n_try} deployed  ({len(deployed)/(n_try or 1)*100:.0f}%)   "
          f"{n_try - len(deployed)} failed to come up"
          + (f"   ({len(skipped)} skipped as non web, excluded)" if skipped else ""))
    for kind, n in err_kinds.most_common(6):
        print(f"      {n:>3}× {kind}")
    if ungraded:   # deployed but no score (grade timeout / abort), else these vanish from every view
        print(f"    {len(ungraded)} deployed but NOT graded:")
        for kind, n in Counter((r.get("deploy_error") or "unknown")[:60] for r in ungraded).most_common(4):
            print(f"      {n:>3}× {kind}")
    if skipped:    # not web apps -> correctly NOT deployed/graded (out of scope, not a reproducibility fail)
        print(f"    {len(skipped)} SKIPPED (not a web app, out of scope, not a failure):")
        for kind, n in Counter(r.get("app_kind") or "?" for r in skipped).most_common():
            print(f"      {n:>3}× {kind}")
    if timeouts:   # the 'took forever' signal, bloated build / broken grade / wedge
        print(f"    TOOK FOREVER (timeouts, a deployability/quality signal): "
              + ", ".join(f"{n}× {k}" for k, n in timeouts.most_common()))
    if url_apps:   # graded directly from a live URL, never deploy tested, so OUTSIDE the rate above
        u_scored = [r for r in url_apps if "slop_score" in r and r.get("functional") is not False]
        u_broken = [r for r in url_apps if r.get("functional") is False]
        u_dead = len(url_apps) - len(u_scored) - len(u_broken)
        print(f"    LIVE URL COHORT: {len(url_apps)} app(s) graded directly (not deploy tested), "
              f"{len(u_scored)} scored, {len(u_broken)} non functional (DNF class), {u_dead} unreachable/ungraded")
    if nonfunctional:   # visible, not silently dropped: broken/not-an-app apps rank DNF, out of the distribution
        print(f"    NON FUNCTIONAL (audit): {len(nonfunctional)} app(s) broken/not-an-app/placeholder, ranked "
              f"DNF class, EXCLUDED from the score distribution below (not rescued to a low slop score)")
    if disputed:   # veto: LLM called it broken but discovery kept real surface + no deterministic signal agreed
        print(f"    DISPUTED BROKEN (veto): {len(disputed)} app(s) the audit called broken but that KEPT real "
              f"surface, SCORED (not DNF'd on the LLM alone), FLAGGED for human review")

    # (a2)
    def _f(v):   # a stat cell: em dash when undefined (too small a sample), else one decimal
        return "-" if v is None else f"{v:.1f}"
    sec(f"BY HACKATHON  ({len(hk_rows)} hackathons, source attribution)   [slop = whole cohort | w.* = winners only]")
    print(f"     {'hackathon':<28}{'subs':>5}{'grd':>4}{'min':>6}{'med':>6}{'mean':>6}{'max':>6}{'sd':>5}"
          f"{'win':>5}{'w.grd':>6}{'w.min':>6}{'w.med':>6}{'w.mean':>7}{'w.max':>6}{'w.sd':>5}")
    for row in hk_rows:
        print(f"     {row['hackathon'][:28]:<28}{row['subs']:>5}{row['graded']:>4}"
              f"{_f(row['min_slop']):>6}{_f(row['median_slop']):>6}{_f(row['mean_slop']):>6}"
              f"{_f(row['max_slop']):>6}{_f(row['stdev_slop']):>5}"
              f"{row['winners']:>5}{row['winner_graded']:>6}{_f(row['winner_min']):>6}"
              f"{_f(row['winner_median']):>6}{_f(row['winner_mean']):>7}{_f(row['winner_max']):>6}"
              f"{_f(row['winner_stdev']):>5}")
    if hk_ranked:   # which hackathons produced the sloppiest / cleanest apps (min 10 graded, so it's not noise)
        top = sorted(hk_ranked, key=lambda x: -x["median_slop"])[:3]
        bot = sorted(hk_ranked, key=lambda x: x["median_slop"])[:3]
        print("     sloppiest (median slop, n≥10 graded): " + ", ".join(f"{r['hackathon']} {r['median_slop']}" for r in top))
        print("     cleanest  (median slop, n≥10 graded): " + ", ".join(f"{r['hackathon']} {r['median_slop']}" for r in bot))

    # (a3) AUTH SURFACE, the login/signup/SSO shape of the graded apps, and the reach it implies for the authed
    # probes. self registerable (a password signup we can drive) is the slice the authed surface + email + browser
    # data plane probes can reach; SSO only + captcha is the hard blocked slice they honestly abstain on.
    if n_sf:
        sec(f"AUTH SURFACE  ({n_sf} graded apps carry the surface fields)")
        print(f"     has login {sf_login} ({100*sf_login/n_sf:.0f}%)   |   has signup {sf_signup} "
              f"({100*sf_signup/n_sf:.0f}%)   |   SSO present {sf_sso} ({100*sf_sso/n_sf:.0f}%)")
        # auth TYPE as a mutually exclusive partition (sums to n_sf) so the password+SSO app is visible and the
        # 'has_signup but not drivable' gap is named, instead of overlapping counts that can't be reconciled.
        part = A["partition"]
        print(f"     auth type (partition of {n_sf}, one per app):")
        for key, label in (("password_only", "password signup, drivable"),
                           ("password_and_sso", "password signup + SSO, both drivable"),
                           ("sso_only", "SSO only, no drivable signup (blocked)"),
                           ("signup_undrivable", "signup present but not drivable (SDK/SSO/wizard)"),
                           ("login_only", "login wall, no signup to drive"),
                           ("no_auth", "no auth at all")):
            v = part.get(key, 0)
            if v:
                print(f"       {label:48s} {v:4d} ({100*v/n_sf:2.0f}%)")
        # reach = the DRIVABLE slice = password_only + password_and_sso (== self_registerable / sf_pw)
        print(f"     -> self registerable (drivable password signup): {sf_pw} ({100*sf_pw/n_sf:.0f}%)"
              f"   <- the reach for the authed / email / browser data plane probes")
        if sf_pw:   # reach x yield: did that reach actually surface a defect?
            note = ("  ".join(f"{p} {n}" for p, n in authed_fire_probes.most_common())
                    if authed_fire_probes else "no authed finding, the reach did not surface a defect")
            print(f"       reach x yield: {len(reg_fired)}/{sf_pw} of them had an authed surface finding  ({note})")
        if sso_providers:
            print("     SSO providers: " + "  ".join(f"{p} {c}" for p, c in sso_providers.most_common()))
        if captcha_kinds:
            print("     captcha gated: " + "  ".join(f"{k} {c}" for k, c in captcha_kinds.most_common()))

    # (b)
    sec(f"SLOP SCORE DISTRIBUTION  (all graded apps)")
    print(f"    {_stat_line(scores)}")
    if url_apps:   # don't conflate cohorts, live apps grade over HTTPS with only the HTTPS-only probes applying
        print(f"      ├─ repo deployed  {_stat_line([r['slop_score'] for r in graded if _source(r) == 'repo'])}")
        print(f"      └─ live URL       {_stat_line([r['slop_score'] for r in graded if _source(r) == 'url'])}")
    for line in _histogram(scores):
        print(line)
    print(f"\n    modalities  (score clumps, float/spectrum scoring should keep this mostly unique):")
    for line in _modalities(scores):
        print(line)
    print(f"\n    slop concentration by category (damped, summed across apps):")
    for cat, v in sorted(cat_total.items(), key=lambda x: -x[1])[:12]:
        print(f"      {cat:34} {v:7.1f}   {v/all_slop*100:4.1f}%")
    print(f"\n    most frequent findings across apps:")
    for pid, n in freq[:10]:
        b, c = probe_meta[pid]
        print(f"      {pid:20} {n:>3}/{len(graded)} apps   {b}/{c}")

    # SLOP BY AXIS, the score's top level split: security / qa / performance. The per axis damped subtotals
    # (axis_slop) summed + median across graded apps, and each axis's share of all slop, so you see WHICH axis
    # drives the corpus before drilling into categories. Self suppresses on a corpus that predates axis_slop.
    axis_vals = defaultdict(list)
    for r in graded:
        for ax, v in (r.get("axis_slop") or {}).items():
            axis_vals[ax].append(v)
    if axis_vals:
        axis_total = {ax: sum(v) for ax, v in axis_vals.items()}
        all_axis = sum(axis_total.values()) or 1.0
        sec("SLOP BY AXIS  (the score's security / qa / performance split, across graded apps)")
        for ax in sorted(axis_total, key=lambda a: -axis_total[a]):
            xs = axis_vals[ax]
            print(f"    {ax:12} {axis_total[ax]/all_axis*100:4.0f}% of all slop   "
                  f"median {statistics.median(xs):5.1f}   mean {statistics.mean(xs):5.1f}   (n {len(xs)} apps)")

    # FINDING SEVERITY, the scored findings bucketed by risk priced penalty into tiers, with the # of apps carrying
    # at least one at that tier. Shows the SHAPE of the harm (are the fires a few critical breaches or a long tail
    # of minor ones), which the summed score alone hides.
    sev_findings, sev_apps = Counter(), defaultdict(set)
    for r in graded:
        for f in r.get("findings", []):
            if _scored(f):
                t = _severity_tier(f["penalty"])
                sev_findings[t] += 1
                sev_apps[t].add(r["repo"])
    if sev_findings:
        sec("FINDING SEVERITY  (scored findings by risk priced penalty tier; apps = # with >=1 at that tier)")
        for tier in ("critical", "serious", "moderate", "minor"):
            print(f"    {tier:9} (pen {'>=30' if tier=='critical' else '16-29' if tier=='serious' else '8-15' if tier=='moderate' else '1-7':>5})"
                  f"   {sev_findings.get(tier, 0):>4} findings   across {len(sev_apps.get(tier, set())):>3} apps")

    # (b2) Lighthouse PERFORMANCE score, 0-100, the number the perf axis grades on, surfaced here. Absent on a
    # corpus from before the switch to Lighthouse, so the section self skips. (a11y is scored by qa-a11y, not shown here.)
    s = lighthouse_scores(graded)["performance"]
    if s["n"]:
        sec(f"LIGHTHOUSE PERFORMANCE (0-100)   higher is better")
        print(f"     5-number:  min {s['min']}  |  Q1 {s['q1']}  |  median {s['median']}  |  Q3 {s['q3']}  |  max {s['max']}")
        print(f"     mean {s['mean']}  |  stdev {s['stdev']}  (n {s['n']})")
        print(f"     green (>=90 -> ZERO perf slop): {s['green_n']}/{s['n']} ({s['pct_green']}%)")
        win = lighthouse_scores([r for r in graded if r.get("winner") is True])["performance"]
        non = lighthouse_scores([r for r in graded if r.get("winner") is False])["performance"]
        if win["n"] and non["n"]:
            print(f"     winners     (n {win['n']:>4}):  median {win['median']:>3}  mean {win['mean']:>5}  green {win['pct_green']}%")
            print(f"     non winners (n {non['n']:>4}):  median {non['median']:>3}  mean {non['mean']:>5}  green {non['pct_green']}%")

    # (c)
    sec(f"PER PROBE FIRE FREQUENCY  (# of the {len(graded)} graded apps each probe fired on)")
    for pid, n in freq:
        b, c = probe_meta[pid]
        bar = "█" * round(n / (freq[0][1] or 1) * 30)
        print(f"      {pid:20} {n:>3} │ {bar}")

    # (c2) NEVER APPLIED, probes that were N/A on EVERY graded app: the intersection of the n/a sets.
    # They never reached a target, either the surface they need is absent from every app, or the probe is
    # gated wrong or broken. This is DISTINCT from a probe that applied and found nothing (working, just rare);
    # that split is shown for contrast. Exact per probe when records carry coverage.applied; else the
    # coarser kind level intersection (older records predate the per probe field).
    try:
        cat = {p.id: p.bundle for p in load_catalog(str(_ROOT / "catalog"))}
    except Exception:                          # never let a catalog hiccup break the whole report
        cat = {}
    cov = [r for r in graded if r.get("coverage")]
    per_probe = [r for r in cov if r["coverage"].get("applied") is not None]
    if cat and per_probe:                      # exact: probes n/a everywhere = catalog − union(applied)
        applied = set().union(*(set(r["coverage"]["applied"]) for r in per_probe))
        never = sorted(pid for pid in cat if pid not in applied)
        ran_clean = sum(1 for pid in applied if pid in cat and pid not in probe_apps)
        sec(f"NEVER APPLIED across all {len(per_probe)} graded apps  "
              f"({len(never)}/{len(cat)} probes never reached a target):")
        if never:
            grp = defaultdict(list)
            for pid in never:
                grp[cat[pid]].append(pid)
            for b in sorted(grp):
                print(f"      [{b}]  " + ", ".join(sorted(grp[b])))
            print(f"      ↳ surface absent everywhere, OR the probe is gated wrong or broken, audit any that SHOULD apply")
        else:
            print("      (every probe applied to at least one app)")
        print(f"      (for contrast: {ran_clean} probes DID apply somewhere but never fired, working, just rare)")
    elif cov:                                  # legacy records: only kind level n/a survives
        na = [set(r["coverage"].get("na_kinds", [])) for r in cov]
        ran = [set(r["coverage"].get("ran_kinds", [])) for r in cov]
        na_all = sorted(set.intersection(*na) - set().union(*ran)) if na else []
        sec(f"NEVER APPLIED across all {len(cov)} graded apps  (KIND level, these records predate "
              f"per probe coverage; regrade for probe granularity):")
        print("      " + (", ".join(na_all) if na_all else "(every kind applied on ≥1 app)"))

    # (d)
    sec(f"WINNERS vs NON WINNERS")
    if not win_all and not non_all:
        print("    (no winner labels in the records, pass winner status via deploy_and_grade --meta)")
    else:
        print(f"    winners      deploy {sum(r.get('deployed', False) for r in win_all)}/{len(win_all)}   "
              f"slop {_stat_line(win_scores)}")
        print(f"    non winners  deploy {sum(r.get('deployed', False) for r in non_all)}/{len(non_all)}   "
              f"slop {_stat_line(non_scores)}")

    # (e)
    sec(f"ANOMALIES, hand verify (fuzzer bugs & interesting apps hide here)")
    print(f"    surprising 0s  (deployed but scored 0, did the fuzzer see a real surface?):")
    for r in zeros or [None]:
        print("      " + (f"{r['repo']}   0 findings" if r else "(none)"))
    print(f"    thin  (deployed, scored >0 but <2 findings, possible discovery blind spot):")
    for r in thin or [None]:
        print("      " + (f"{r['repo']}   score {r['slop_score']}, {len(r['findings'])} finding(s)" if r else "(none)"))
    print(f"    high outliers  (> mean+{args.sigma:g}σ = {hi_cut:.0f}, terrible app OR a bug firing too much):")
    for r in sorted(highs, key=lambda r: -r["slop_score"]) or [None]:
        if r:
            top = sorted(cat_subtotals(r).items(), key=lambda x: -x[1])[:3]
            print(f"      {r['repo']}   {r['slop_score']}   top: " + ", ".join(f"{k[1]} {v:.0f}" for k, v in top))
        else:
            print("      (none)")
    print(f"\n    → audit any probe: scripts/stats.py {args.results} --audit <probe id>\n")

    # (f) TIMING, the wall clock as its own signal: where time goes, and the slowest apps
    if timed:
        sec(f"TIMING  (wall clock seconds per phase, across {len(timed)} apps)")
        for key, label in _PHASES:
            xs = _phase(key)
            if xs:
                print(f"    {label:10} {_stat_line(xs)}")
        gs = _phase("grade_s")   # the grading phase is where the injection/browser cost + the timeout tail live
        if gs:
            print(f"\n    grade_s distribution (seconds):")
            for line in _histogram(gs):
                print(line)
            killed = [r for r in timed if r.get("grade_timeout")]   # the grader flagged these, robust to the timeout value
            if killed:
                print(f"    {len(killed)} app(s) ({100 * len(killed) / len(gs):.0f}%) timed out and were killed "
                      f"(a render wedged, or the probes ran away); they scored almost nothing")
        slow = sorted((r for r in timed if r["timings"].get("total_s")),
                      key=lambda r: -r["timings"]["total_s"])[:5]
        if slow:
            print("    slowest (total):")
            for r in slow:
                t = r["timings"]
                print(f"      {r['repo'][:48]:48} {t['total_s']:>5.0f}s   "
                      f"(deploy {t.get('deploy_s', 0):.0f} | grade {t.get('grade_s', 0):.0f})")

    # (g) PAIRED, same submission graded BOTH ways (repo deploy vs live URL). The DELTA is the signal:
    # the repo failed but the URL works = pure reproducibility failure; URL much cleaner = their infra hardens or
    # the repo is missing config; similar = genuinely clean AND reproducible. Never a blended average.
    if paired:
        repro_fail = [(p, d) for p, d in paired.items()
                      if "slop_score" not in d["repo"] and "slop_score" in d["url"]]
        both = [(p, d["repo"]["slop_score"], d["url"]["slop_score"]) for p, d in paired.items()
                if "slop_score" in d["repo"] and "slop_score" in d["url"]]
        sec(f"PAIRED repo vs URL  ({len(paired)} submissions graded both ways, the delta is signal)")
        print(f"    {len(both)} scored on both | {len(repro_fail)} where the repo FAILED but the URL works "
              f"(pure reproducibility failures)")
        for p, rs, us in sorted(both, key=lambda x: -(x[1] - x[2]))[:12]:
            tag = ("URL cleaner, their infra hardens / repo missing config" if rs - us >= 20 else
                   "repo cleaner, live infra adds slop (their headers/CDN)" if us - rs >= 20 else
                   "similar, clean AND reproducible")
            print(f"      {p.rsplit('/', 1)[-1][:30]:30} repo {rs:>4} | url {us:>4} | Δ{rs - us:>+5}  {tag}")
        for p, d in repro_fail[:6]:
            print(f"      {p.rsplit('/', 1)[-1][:30]:30} repo FAILED | url {d['url']['slop_score']:>4}  "
                  f"→ live only (not reproducible from source)")

    # (h) COVERAGE AUDIT (LLM), surface the fuzzer's discovery MISSED, per the LLM critic, aggregated into
    # a fixable backlog (the AfroSecured-style incidents), plus page state classification (placeholder/broken).
    audited = [r for r in recs if r.get("coverage_audit")]
    if audited:
        misses = [(r["repo"], m) for r in audited for m in (r["coverage_audit"].get("missed") or [])]
        states = Counter((r["coverage_audit"].get("page_state") or "?") for r in audited)
        sec(f"COVERAGE AUDIT (LLM), {len(audited)} apps audited | page states {dict(states)}")
        if misses:
            gap_apps = len({repo for repo, _ in misses})
            print(f"    DISCOVERY GAPS, surface the fuzzer missed: {len(misses)} across {gap_apps} apps  "
                  f"(by kind: {dict(Counter(m.get('kind') for _, m in misses))})")
            for repo, m in misses[:15]:
                print(f"      {repo.rsplit('/', 1)[-1][:26]:26} {(m.get('kind') or '?'):8} "
                      f"{(m.get('label') or '')[:28]:28}, {(m.get('why') or '')[:50]}")
            print(f"    → fix these in discovery, then regrade; audit any probe: --audit <probe id>")
        else:
            print("    DISCOVERY GAPS: none flagged, discovery covered the audited pages")

    # (i) LLM POINTER PRECISION (build #2, off score), of the endpoints the LLM UNIQUELY seeded from source
    # (the crawler missed them), how many were REAL on the deployed app vs hallucinated 404s. Measures the
    # pointer's accuracy without EVER letting it touch the score: the separation that keeps the pointer from
    # ever judging, quantified.
    if ptr_active:
        sec(f"LLM POINTER PRECISION (build #2, off score), {len(ptr_active)} apps where the LLM seeded "
              f"endpoints the crawler missed")
        print(f"    {ptr_seeded} endpoints seeded | {ptr_reach} reachable | {ptr_halluc} hallucinated (404) | "
              f"{ptr_params} injection params added")
        if ptr_judged:
            print(f"    precision {ptr_prec:.0f}%  (reachable / {ptr_judged} judged)   "
                  f"  (high = the pointer names real paths; low = it invents ghost endpoints)")
        worst = sorted((r for r in recs if (_ptr(r) or {}).get("endpoints_hallucinated")),
                       key=lambda r: -_ptr(r)["endpoints_hallucinated"])[:6]
        if worst:
            print("    most hallucinated paths (pointer misfires, inspect the plan):")
            for r in worst:
                pp = _ptr(r)
                print(f"      {r['repo'].rsplit('/', 1)[-1][:30]:30} {pp['endpoints_hallucinated']} ghost "
                      f"/ {pp['endpoints_seeded']} seeded")

    # (i2) PERCEPTION POINTER (proactive discovery, off score), of the surface an LLM perceived off the
    # RENDERED page (the client side logins/uploads/actions the crawl missed), how much turned out REAL. The
    # recall counterpart to (h) DISCOVERY GAPS: (h) says what's still missed, this says how good the fix is.
    if pcv_active:
        pcv_pw = sum(p.get("perceived_password_forms", 0) for p in pcv_active)   # perceived forms w/ a password field
        pcv_unjudged = pcv_eps - pcv_judged                                      # seeded but no baseline (not 200/404)
        sec(f"PERCEPTION POINTER (proactive discovery, off score), {len(pcv_active)} apps where the LLM "
              f"perceived surface the crawl missed")
        pw = f" ({pcv_pw} w/ a password field -> auth self oracle surface)" if pcv_pw else ""
        print(f"    {pcv_forms} forms{pw} + {pcv_eps} endpoints perceived (survived suppression) | "
              f"{pcv_reach} reachable | {pcv_halluc} hallucinated (404)"
              + (f" | {pcv_unjudged} unjudged (no baseline)" if pcv_unjudged else ""))
        if pcv_judged:
            print(f"    endpoint precision {pcv_prec:.0f}%  (reachable / {pcv_judged} judged), how much of the "
                  f"perceived ENDPOINT surface was real (forms show up as woken probes / a fuller has_login)")
        rows = [r for r in recs if (_ptr(r) or {}).get("perceived_forms_seeded")
                or (_ptr(r) or {}).get("perceived_endpoints_seeded")]
        if rows:
            print(f"    per app, what perception ADDED (cross check against the DISCOVERY GAPS section above):")
            for r in rows[:15]:
                p = _ptr(r)
                bits = []
                if p.get("perceived_form_actions"):
                    bits.append(f"forms {p['perceived_form_actions']}")
                if p.get("perceived_endpoint_paths"):
                    bits.append(f"endpoints {p['perceived_endpoint_paths']}")
                label = (r.get("repo") or "").rstrip("/").rsplit("/", 1)[-1][:28] or "?"   # trailing '/' -> host, not ''
                print(f"      {label:28} {' | '.join(bits)}")
            if len(rows) > 15:
                print(f"      ... and {len(rows) - 15} more (jq the per app records for the rest)")
        ghosts = [(r.get("repo", ""), p) for r in recs for p in ((_ptr(r) or {}).get("perceived_ghost_paths") or [])]
        if ghosts:
            print(f"    ghost paths perception INVENTED (404, eyeball these when endpoint precision dips):")
            for repo, path in ghosts[:8]:
                print(f"      {repo.rsplit('/', 1)[-1][:30]:30} {path}")

    # (i3) BACKEND TIER DISTRIBUTION (off score), WHERE each app's runtime traffic goes (classify hosts). Sizes
    # the SPA off origin gap: same origin = testable now, managed BaaS = config test lane, OWN off origin = the
    # Move-2 recall frontier we can't yet reach. Tiers OVERLAP (an app can span all three).
    if n_tier:
        sec(f"BACKEND TIER DISTRIBUTION (off score), {n_tier} apps with observed runtime traffic")
        print(f"    same origin (testable now):          {tier_same:>4} ({tier_same/n_tier*100:.0f}%)")
        print(f"    OWN off origin backend (attributed): {tier_own:>4} ({tier_own/n_tier*100:.0f}%)   <- Move-2 target (same domain / self hosted PaaS)")
        print(f"    managed BaaS (config test lane):     {tier_baas:>4} ({tier_baas/n_tier*100:.0f}%)")
        print(f"    vendor (consumed, not graded):       {tier_vendor:>4} ({tier_vendor/n_tier*100:.0f}%)")
        print(f"    opaque off origin (unattributable):  {tier_opaque:>4} ({tier_opaque/n_tier*100:.0f}%)   <- not probed (safety); no clean bill credit")
        if own_hosts:
            print("    top own backend hosts: " + ", ".join(f"{h}({c})" for h, c in own_hosts.most_common(6)))
        if opaque_hosts:
            print("    top opaque hosts:      " + ", ".join(f"{h}({c})" for h, c in opaque_hosts.most_common(6)))

    # (i4) PLATFORM + AI BUILDER (off score), WHERE it is served and WHAT built it, plus slop by builder
    if platted:
        n_pl = len(platted)
        sec(f"PLATFORM + AI BUILDER (off score), {n_pl} apps classified")
        print("    host platform: " + ", ".join(f"{k} {c}({c/n_pl*100:.0f}%)" for k, c in host_dist.most_common()))
        if edge_dist:
            print("    edge / CDN:    " + ", ".join(f"{k} {c}" for k, c in edge_dist.most_common()))
        print("    AI builder:    " + ", ".join(f"{k} {c}({c/n_pl*100:.0f}%)" for k, c in builder_dist.most_common()))
        print("    slop by builder (median|n): " + "  ".join(f"{k}={med}(n{n})" for k, n, med in slop_by_builder))
        print("    slop by host   (median|n): " + "  ".join(f"{k}={med}(n{n})" for k, n, med in slop_by_host[:8]))

    # (i5) BOT CHALLENGE / TAINT, how many apps served a WAF/challenge/sleep page (excluded from the grade),
    # broken down by host platform so a disproportionately challenged platform is visible as a taint signal.
    if challenged:
        sec(f"BOT CHALLENGE / TAINT, {len(challenged)} of {len(recs)} records "
              f"({100 * len(challenged) / (len(recs) or 1):.1f}%) served a challenge/interstitial")
        print(f"    LATE (all probes ran, then challenged -> grade VALID, KEPT): {len(late_ch)}"
              f"   |   ENTRY (challenged from the start -> withheld): {len(entry_ch)}")
        print("    by host (challenged / total on platform): "
              + "  ".join(f"{h}={n}/{t}({pct:.0f}%)" for h, n, t, pct in challenge_by_host))
        inc_axis = [r for r in recs if r.get("incomplete_axes")]   # KEPT grades whose severe tail was edge blocked
        if inc_axis:
            axc = Counter(a for r in inc_axis for a in (r.get("incomplete_axes") or []))
            print(f"    INCOMPLETE axes (grade KEPT but that axis NOT clean tested, severe edge blocked): "
                  f"{len(inc_axis)} apps  |  " + "  ".join(f"{a}={n}" for a, n in axc.most_common()))
        if onset_by_probe:   # which probe's traffic first tripped the WAF -> the gate/reorder candidates
            print("    tripped BY probe (first challenge status): "
                  + "  ".join(f"{p}={n}" for p, n in onset_by_probe.most_common(8)))

    if req_rank:   # (i6) which probes send the most requests -> WAF trip / pacing / trim candidates
        sec("REQUEST VOLUME per probe (median across apps | worst single app), the high fan out probes")
        for pid, med, mx, n in req_rank[:12]:
            print(f"    {pid:<22} median {med:>5.0f}   worst {mx:>5}   (n={n} apps)")

        # PROBE COST vs VALUE, the request volume (cost) joined to the fire rate (value). A high cost, low/zero
        # yield probe is a WAF trip / pacing / trim candidate (the sec-dos / sec-cmdi fan out that trips Vercel).
        sec("PROBE COST vs VALUE  (median requests = cost | apps fired on = value | worst cost per fire first)")
        cv = [(pid, med, len(probe_apps.get(pid, set()))) for pid, med, mx, n in req_rank]
        cv = [(pid, med, fires, med / fires if fires else med * 2) for pid, med, fires in cv]   # never fired ranks worst
        for pid, med, fires, ratio in sorted(cv, key=lambda x: -x[3])[:12]:
            flag = ("   <- expensive, ZERO yield (trim / pace)" if fires == 0 and med >= 30
                    else "   <- high cost per fire" if ratio >= 100 else "")
            print(f"    {pid:<22} cost {med:>5.0f} req | value {fires:>3} apps | {ratio:>6.0f} req/fire{flag}")

    # (i7) EMAIL VERIFICATION (qa-email, now scoring), of the email gated signups, which locked a user out. The
    # qa-email-001 ladder (no mail in 60s = locked out | only after the 30s checkpoint = unreliable | no resend
    # control = resilience gap) + qa-email-002's inert link. Counts are over FIRED findings, so an email gated app
    # whose flow WORKED leaves no row here (it cleaned). Self suppresses on a corpus where the family never fired.
    if email_001 or email_002:
        sec(f"EMAIL VERIFICATION (qa-email, scoring), {len(email_001)} app(s) with an unreliable "
              f"confirmation flow (qa-email-001) | {len(email_002)} with an inert verification link (qa-email-002)")
        print(f"    qa-email-001 ladder:  {email_break['no_email_60s']} no mail in 60s (locked out)  |  "
              f"{email_break['email_late_30s']} only after the 30s checkpoint (unreliable)  |  "
              f"{email_break['no_resend_button']} missing a resend control")
        for r, f in [(r, f) for r, f in email_001 if (f.get("evidence") or {}).get("no_email_60s")][:8]:
            print(f"      {r['repo'].rsplit('/', 1)[-1][:34]:34} no mail, {(f.get('reason') or '')[:48]}")
        print(f"    → audit: scripts/stats.py {args.results} --audit qa-email-001")


if __name__ == "__main__":
    main()
