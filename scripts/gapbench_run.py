#!/usr/bin/env python3
"""Grade GapBench scenario-by-scenario with ONLY the probes for each one's declared class.

    uv run python scripts/gapbench_run.py --results gapbench-recall2.jsonl --delay 60
    uv run python scripts/gapbench_run.py --dry-run          # show the plan + traffic estimate, send nothing

Why this exists: a full battery is ~685 requests per target (measured), and even `--probe 'sec-*'` keeps the
three injection families that are HALF of that volume, which tripped vibe-eval's bot challenge after four
scenarios. But GapBench declares each scenario's CWEs in its manifest, so nothing has to be inferred: map the
declared CWEs to the probes that can evidence them and run only those. Median 3 probes instead of 45, and the
19 scenarios whose classes we don't cover at all are skipped rather than probed pointlessly.

Least privilege, and also just courtesy: it is their infrastructure, published for scanners to point at, and
a scanner that sends a tenth of the traffic to learn the same thing is the one worth being allowed back.

RECALL ONLY. Each row is a subset grade (marked probe_filter by deploy_and_grade), so the slop is a fraction
of a full grade and must never feed a score distribution. The 7 clean controls are the exception: they get the
FULL battery, because a false positive can come from any probe and that is the whole point of a control.
"""
import argparse
import collections
import json
import pathlib
import subprocess
import sys
import time

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))
from gapbench_score import _CWE_BY_CATEGORY, _PROBE_OVERRIDES  # noqa: E402

from hacklet_runner.catalog import load_catalog  # noqa: E402

# Requests each probe actually sends, MEASURED server-side against VAmPI (count the target's own access log
# before/after a --probe run). The injection families dominate: cmdi + sqli + lfi are half of a full battery's
# 685 requests, which is why `--probe 'sec-*'` still tripped the bot challenge. Used for the dry-run estimate,
# so the delay can be chosen from arithmetic instead of optimism.
_REQ_COST = {"sec-cmdi-001": 165, "sec-lfi-001": 45, "sec-xss-001": 15}
_REQ_SQLI = 24          # per sec-sqli-* probe (119 across the five)
_REQ_DEFAULT = 4
_REQ_DISCOVERY = 15     # the crawl each grade pays before any probe runs
_REQ_FULL_BATTERY = 685


def _est_requests(sel: list) -> int:
    if not sel:
        return _REQ_FULL_BATTERY
    n = _REQ_DISCOVERY
    for pid in sel:
        n += _REQ_COST.get(pid, _REQ_SQLI if pid.startswith("sec-sqli-") else _REQ_DEFAULT)
    return n


_VENV_PY = _HERE.parent / ".venv" / "bin" / "python"
PY = [str(_VENV_PY)] if _VENV_PY.exists() else [sys.executable]
_MANIFEST = _HERE.parent / "validation" / "vuln-corpus" / "gapbench-manifest.json"


def probes_for_cwes(cwes, cwe2probe) -> list:
    return sorted({pid for w in (cwes or []) for pid in cwe2probe.get(w, ())})


def build_index(catalog_dir) -> dict:
    """CWE -> the probe ids that can evidence it, inverted from gapbench_score's category map (one table, so
    the runner and the scorer can never disagree about what covers what)."""
    idx = collections.defaultdict(set)
    for p in load_catalog(catalog_dir):
        for w in (_PROBE_OVERRIDES.get(p.id) or _CWE_BY_CATEGORY.get(p.category, ())):
            idx[w].add(p.id)
    return idx


def already_done(results_path) -> set:
    """Scenario ids already recorded with a real grade, so a resumed run re-sends nothing it needn't. A row
    that recorded a 403/dead URL is NOT done: that is exactly what a resume should retry."""
    done = set()
    p = pathlib.Path(results_path)
    if not p.exists():
        return done
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue      # a valid JSON scalar is not a record; .get would raise and kill the whole run
        proj = str(r.get("project") or "")
        if proj.startswith("anchor-gapbench-") and r.get("slop_score") is not None and not r.get("dead_url"):
            done.add(proj[len("anchor-gapbench-"):])
    return done


def main() -> None:
    ap = argparse.ArgumentParser(description="Grade GapBench with per-scenario probe selection.")
    ap.add_argument("--results", default="gapbench-recall2.jsonl")
    ap.add_argument("--manifest", default=str(_MANIFEST))
    ap.add_argument("--catalog", default=str(_HERE.parent / "catalog"))
    ap.add_argument("--delay", type=float, default=60.0, metavar="SECONDS",
                    help="gap between scenarios (default 60; raise it for an unattended overnight run)")
    ap.add_argument("--grade-timeout", type=float, default=300.0)
    ap.add_argument("--limit", type=int, default=0, help="stop after N scenarios (0 = all)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and traffic estimate, send nothing")
    args = ap.parse_args()

    scenarios = json.load(open(args.manifest))["scenarios"]
    cwe2probe = build_index(args.catalog)
    done = already_done(args.results)

    plan, skipped, controls = [], [], []
    for s in scenarios:
        sid = s["id"]
        is_control = str(s.get("vulnerability", "")).startswith("None")
        sel = probes_for_cwes(s.get("cwes"), cwe2probe)
        if sid in done:
            continue
        if is_control:
            controls.append((sid, []))          # full battery: an FP can come from ANY probe
        elif sel:
            plan.append((sid, sel))
        else:
            skipped.append(sid)                 # no probe of ours covers its class -> nothing to learn

    jobs = plan + controls
    if args.limit:
        jobs = jobs[:args.limit]
    est = sum(_est_requests(sel) for _sid, sel in jobs)
    heaviest = sorted(((_est_requests(sel), sid) for sid, sel in jobs), reverse=True)[:3]
    print(f"\n  {len(scenarios)} scenarios: {len(plan)} targeted, {len(controls)} controls (full battery), "
          f"{len(skipped)} skipped (no covering probe), {len(done)} already done")
    print(f"  running {len(jobs)} now · ~{est} requests total (vs ~{len(jobs) * _REQ_FULL_BATTERY} for full "
          f"batteries) · {args.delay:.0f}s apart · ~{len(jobs) * args.delay / 60:.0f} min of gaps")
    print("  heaviest: " + ", ".join(f"{sid} ~{n}" for n, sid in heaviest))
    print(f"  skipped: {', '.join(skipped[:10])}{' ...' if len(skipped) > 10 else ''}\n")
    if args.dry_run:
        for sid, sel in jobs[:15]:
            print(f"    {sid:<28} {len(sel) or 'FULL':>4}  {','.join(sel[:5])}")
        print("\n  (dry run — nothing sent)\n")
        return

    for i, (sid, sel) in enumerate(jobs, 1):
        url = f"https://gapbench.vibe-eval.com/site/{sid}/"
        cmd = PY + [str(_HERE / "deploy_and_grade.py"), url, "--url", "--record", args.results,
                    "--grade-timeout", str(args.grade_timeout),
                    "--meta", json.dumps({"project": f"anchor-gapbench-{sid}", "hackathon": "gapbench"})]
        for pid in sel:
            cmd += ["--probe", pid]
        t0 = time.monotonic()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=args.grade_timeout + 120)
        except subprocess.TimeoutExpired:
            print(f"  [{i}/{len(jobs)}] {sid:<28} TIMEOUT")
            continue
        except KeyboardInterrupt:
            print("\n  interrupted — rerun the same command to resume (graded scenarios are skipped)\n")
            return
        rec = None
        with open(args.results) as fh:
            for line in fh:
                with __import__("contextlib").suppress(json.JSONDecodeError):
                    r = json.loads(line)
                    if r.get("project") == f"anchor-gapbench-{sid}":
                        rec = r
        state = ("slop %s" % rec["slop_score"]) if rec and rec.get("slop_score") is not None else (
            str((rec or {}).get("deploy_error") or "no record")[:34])
        print(f"  [{i}/{len(jobs)}] {sid:<28} {len(sel) or 'FULL':>4}p  {state:<36} ·{time.monotonic()-t0:5.0f}s",
              flush=True)
        if i < len(jobs):
            time.sleep(args.delay)
    print(f"\n  done. score it:  uv run python scripts/gapbench_score.py {args.results}\n")


if __name__ == "__main__":
    main()
