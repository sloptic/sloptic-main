#!/usr/bin/env python3
"""Make a slop score mean something: rank it against a FROZEN reference distribution.

    uv run python scripts/benchmark.py build multihacksfinalv9.jsonl --version 2026.1
    uv run python scripts/benchmark.py rank 120
    uv run python scripts/benchmark.py rank --results run.jsonl --app theirapp.vercel.app

A deduction-only score has no natural scale. "120" is uninterpretable the way "a resting heart rate of 58"
is uninterpretable without a population. `build` casts the ruler from a corpus run; `rank` places one app on
it and names the band.

Four rules the design commits to, each because the obvious shortcut is wrong:

* Rank PER AXIS over the sub-population where that axis was APPLICABLE. Totals are not comparable across
  apps: one app's score was summed over 60 applicable probes and another's over 30, so ranking raw totals
  partly ranks "how much surface did you even have". An app with no reachable auth surface is not thereby
  secure, and it must not out-rank an app that had one and got it right.
* FREEZE and version the curve. A credential has to be reproducible: if the reference drifts, the same
  unchanged app earns a different rank next month. Rolling percentiles are fine for a live dashboard, never
  for a badge.
* Report the POPULATION with the number. "p82" alone is a lie of omission; "p82 of 1110 live hackathon apps,
  2026.1" is a claim someone can check.
* Never percentile a catastrophe. "You leaked a live key, but so did 30% of apps, so you're p70" is exactly
  backwards. Absolute-gate classes are reported as gates, whatever the rank says.

Excluded from the reference: anchors (deliberately-vulnerable calibration targets would drag the curve),
--probe subset runs (their slop is a fraction of a full grade), dead URLs, and DNF/non-functional apps
(ranked below every working app, never rescued to a flattering percentile).
"""
import argparse
import collections
import json
import pathlib
import statistics
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_DEFAULT_CURVE = _HERE.parent / "validation" / "benchmark-curve.json"
_AXES = ("security", "qa", "performance")
_PREFIX = {"sec-": "security", "qa-": "qa", "perf-": "performance"}
_LANDMARKS = (10, 25, 50, 75, 90, 95, 99)
# A fired probe in one of these classes means "not certifiable", independent of rank: the app is exploitable
# now, and a favourable comparison to equally-broken peers is not a mitigation.
_ABSOLUTE = {"access-control", "backend-exposure", "secrets-exposure", "sql-injection", "xss", "dom-xss",
             "command-injection", "template-injection", "path-traversal", "file-upload", "ssrf", "xxe",
             "data-exposure"}


def _axis_of(probe_id: str) -> str | None:
    for pre, axis in _PREFIX.items():
        if probe_id.startswith(pre):
            return axis
    return None


def _eligible(r: dict) -> bool:
    """A row that belongs in the reference distribution (see the exclusions in the module docstring)."""
    return bool(
        r.get("deployed") and r.get("slop_score") is not None
        and not r.get("probe_filter")            # a subset grade is not a full grade
        and not r.get("dead_url") and not r.get("recon")
        and r.get("functional") is not False     # DNF ranks below every working app, not inside the curve
        and not str(r.get("project") or "").startswith("anchor-")
    )


def _axis_applicable(r: dict) -> dict:
    """Which axes actually had probes apply to this app, from coverage.applied."""
    counts = collections.Counter()
    for pid in (r.get("coverage") or {}).get("applied") or []:
        axis = _axis_of(pid)
        if axis:
            counts[axis] += 1
    return counts


def _pcts(values: list) -> dict:
    xs = sorted(values)
    n = len(xs)
    out = {"n": n, "min": xs[0], "max": xs[-1], "mean": round(statistics.mean(xs), 1)}
    for p in _LANDMARKS:
        idx = min(n - 1, max(0, int(round((p / 100) * (n - 1)))))
        out[f"p{p}"] = xs[idx]
    return out


def build(recs: list, version: str, source: str, status: str = "provisional") -> dict:
    rows = [r for r in recs if _eligible(r)]
    if not rows:
        sys.exit("ERROR: no eligible rows (need deployed + scored + not anchor/subset/dead/DNF)")
    # status rides ON the curve and into every ranked result. A curve built before the catalog's calibration
    # settles will be regraded, and a percentile quoted from it must say so: a provisional number presented as
    # final is the failure mode a versioned reference exists to prevent.
    curve = {"version": version, "source": source, "status": status,
             "population": "live hackathon web apps",
             "overall": _pcts([r["slop_score"] for r in rows]), "axes": {}}
    for axis in _AXES:
        vals = [(r.get("axis_slop") or {}).get(axis, 0) for r in rows if _axis_applicable(r).get(axis)]
        if vals:
            curve["axes"][axis] = _pcts(vals)
    return curve


def _percentile_of(curve_part: dict, score) -> int:
    """Where `score` sits on a landmark curve, as a percentile. Interpolates between the landmarks we froze
    (we store landmarks, not every value, so the curve file stays small and readable)."""
    pts = [(0, curve_part["min"])] + [(p, curve_part[f"p{p}"]) for p in _LANDMARKS] + [(100, curve_part["max"])]
    pts = sorted(set(pts), key=lambda t: t[0])
    if score <= pts[0][1]:
        return 0
    for (p0, v0), (p1, v1) in zip(pts, pts[1:]):
        if score <= v1:
            if v1 == v0:
                return p1
            return int(round(p0 + (p1 - p0) * (score - v0) / (v1 - v0)))
    return 100


def _band(pct: int) -> str:
    return "pristine" if pct <= 25 else "typical" if pct <= 75 else "rough" if pct <= 95 else "catastrophic"


def rank(curve: dict, score, record: dict | None = None) -> dict:
    """Place one app on the frozen curve. Lower slop is better, so a LOW percentile is good: pct is the share
    of the reference population this app is cleaner than... inverted at the end for readability."""
    pct = _percentile_of(curve["overall"], score)
    cleaner_than = 100 - pct
    status = curve.get("status", "provisional")
    out = {"slop": score, "percentile": pct, "cleaner_than_pct": cleaner_than, "band": _band(pct),
           "reference": f"{curve['population']}, n={curve['overall']['n']}, {curve['version']}"
                        + (f" ({status.upper()})" if status != "final" else ""), "axes": {}}
    if record:
        applicable = _axis_applicable(record)
        for axis, part in curve["axes"].items():
            if not applicable.get(axis):
                out["axes"][axis] = {"applicable": False}   # no surface -> no rank, NOT a good rank
                continue
            a = (record.get("axis_slop") or {}).get(axis, 0)
            p = _percentile_of(part, a)
            out["axes"][axis] = {"applicable": True, "slop": a, "percentile": p,
                                 "cleaner_than_pct": 100 - p, "band": _band(p)}
        gates = sorted({f["category"] for f in record.get("findings") or []
                        if f.get("category") in _ABSOLUTE})
        if gates:
            out["absolute_gates"] = gates      # reported REGARDLESS of rank; a percentile never excuses these
    return out


def _report(res: dict) -> None:
    print(f"\n  slop {res['slop']}  ->  {res['band'].upper()}   (cleaner than {res['cleaner_than_pct']}% "
          f"of the reference population)")
    print(f"  reference: {res['reference']}")
    if res.get("axes"):
        print("\n  per axis (ranked only where the axis had probes apply):")
        for axis, a in res["axes"].items():
            if not a.get("applicable"):
                print(f"    {axis:<12} no applicable surface — unranked (absence of a finding is not a pass)")
            else:
                print(f"    {axis:<12} slop {a['slop']:<5} {a['band']:<13} cleaner than {a['cleaner_than_pct']}%")
    if res.get("absolute_gates"):
        print(f"\n  ABSOLUTE GATE — not certifiable regardless of rank: {', '.join(res['absolute_gates'])}")
        print("    a favourable comparison to equally-broken peers is not a mitigation")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description="Build or query a frozen slop-score reference distribution.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="freeze a reference curve from a corpus run")
    b.add_argument("results")
    b.add_argument("--version", required=True, help="curve version, e.g. 2026.1 (a badge must cite one)")
    b.add_argument("--out", default=str(_DEFAULT_CURVE))
    b.add_argument("--status", default="provisional", choices=("provisional", "final"),
                   help="provisional (default) until the catalog's calibration settles and the corpus is "
                        "regraded; it is stamped on the curve and shown with every rank")
    q = sub.add_parser("rank", help="place a score (or a graded app) on the curve")
    q.add_argument("score", nargs="?", type=float, help="a raw slop score")
    q.add_argument("--results", help="a results JSONL to read the app from (enables per-axis + gates)")
    q.add_argument("--app", help="substring of the app's target/project in --results")
    q.add_argument("--curve", default=str(_DEFAULT_CURVE))
    q.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.cmd == "build":
        recs = [json.loads(l) for l in pathlib.Path(args.results).read_text().splitlines() if l.strip()]
        curve = build(recs, args.version, pathlib.Path(args.results).name, args.status)
        pathlib.Path(args.out).write_text(json.dumps(curve, indent=2) + "\n")
        o = curve["overall"]
        print(f"\n  froze {args.out}  ({curve['version']}, {curve['status']}, "
              f"n={o['n']} from {curve['source']})")
        print(f"  overall  p10 {o['p10']}  p25 {o['p25']}  median {o['p50']}  p75 {o['p75']}  "
              f"p90 {o['p90']}  p99 {o['p99']}  max {o['max']}")
        for axis, a in curve["axes"].items():
            print(f"  {axis:<12} n={a['n']:<5} median {a['p50']:<5} p90 {a['p90']:<5} max {a['max']}")
        print("\n  bands: <=p25 pristine · <=p75 typical · <=p95 rough · >p95 catastrophic\n")
        return

    curve = json.loads(pathlib.Path(args.curve).read_text())
    record = None
    if args.results:
        rows = [json.loads(l) for l in pathlib.Path(args.results).read_text().splitlines() if l.strip()]
        cands = [r for r in rows if not args.app or args.app in str(r.get("repo", "")) + str(r.get("project", ""))]
        cands = [r for r in cands if r.get("slop_score") is not None]
        if not cands:
            sys.exit(f"ERROR: no scored app matching {args.app!r} in {args.results}")
        record = cands[-1]
    score = args.score if args.score is not None else record and record["slop_score"]
    if score is None:
        sys.exit("ERROR: give a score, or --results with --app")
    res = rank(curve, score, record)
    if args.json:
        json.dump(res, sys.stdout, indent=2)
        print()
    else:
        _report(res)


if __name__ == "__main__":
    main()
