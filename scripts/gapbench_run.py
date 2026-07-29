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
import fnmatch
import json
import pathlib
import subprocess
import sys
import time

import httpx

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))
from gapbench_score import (_CWE_BY_CATEGORY, _FP_EXEMPT_CATEGORIES, _finding_cwes,  # noqa: E402
                            _PROBE_OVERRIDES)

from sloptic.catalog import load_catalog  # noqa: E402

# Requests each probe actually sends, MEASURED server-side against VAmPI (count the target's own access log
# before/after a --probe run). The injection families dominate: cmdi + sqli + lfi are half of a full battery's
# 685 requests, which is why `--probe 'sec-*'` still tripped the bot challenge. Used for the dry-run estimate,
# so the delay can be chosen from arithmetic instead of optimism.
_REQ_COST = {"sec-cmdi-001": 165, "sec-lfi-001": 45, "sec-xss-001": 15}
_REQ_SQLI = 24          # per sec-sqli-* probe (119 across the five)
_REQ_DEFAULT = 4        # NOT measured per-probe: only the injection families above were counted server-side.
#     The overnight run showed this understates the exposure/secrets/backend families badly enough that the
#     estimate never predicted a single block, so treat _est_requests as an ORDER-OF-MAGNITUDE figure for the
#     dry run and never as the throttle input. _CHUNK_PROBES below is the measured control.
_REQ_DISCOVERY = 15     # the crawl each grade pays before any probe runs
_REQ_FULL_BATTERY = 685

# THE MEASURED THRESHOLD. Attributing each block in the overnight log to the scenario that ran before it, the
# split by SELECTION SIZE is unusually sharp:
#
#     probes in selection    scenarios    caused a block
#        0- 5                   43            0   ( 0%)
#        6-10                   12            0   ( 0%)
#       11-15                   17           15   (88%)
#       16-20                   14           14   (100%)
#       21+ (full battery)       7            5   (71%)
#
# 55 scenarios at <=10 probes tripped the challenge zero times; at >=11 it is near-certain. Each block then
# costs a flat 7 minutes (34 blocks -> 242 wait-minutes -> 4.0h of the 8.7h run, against grades that take
# 2-15s each). So the run was ~97% waiting.
#
# Splitting a selection into <=10-probe batches keeps every grade inside the envelope that never tripped it.
# It also works whichever way the host actually counts: a smaller batch is both less VOLUME per burst and,
# since each batch is its own process with its own discovery, a lower sustained RATE. The evidence cannot
# separate those two hypotheses — request/sec did not discriminate (blocked median 19.6/s vs clean 11.2/s,
# with clean showing the higher MEAN) — so the fix deliberately does not depend on knowing which.
#
# Falsifiable: if a <=10-probe batch ever blocks, the per-burst reading is wrong and this constant is not the
# control it appears to be. That shows up in the first few scenarios, not at the end of a night.
_CHUNK_PROBES = 10


def _chunks(seq, n):
    """Split a probe selection into <=n batches. An empty selection (a control, i.e. the full battery) is
    returned as-is by the caller, which expands it explicitly rather than passing 'no --probe flags'."""
    return [seq[i:i + n] for i in range(0, len(seq), n)] or [[]]


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
# The bot challenge clears on a ROLLING window of about 5-10 minutes, not a long ban. So the run should wait
# it out rather than plough on: a blocked scenario recorded as dead is a lost measurement, and 92 of them is a
# lost night. One request tells us the state, versus ~68 wasted discovering it the hard way.
_HEALTH_URL = "https://gapbench.vibe-eval.com/site/ref0/"


def is_blocked(url: str = _HEALTH_URL, timeout: float = 10.0) -> bool:
    """One request: is the host refusing us right now? 403 is the JS bot challenge (our client can never solve
    it), 429 an explicit rate limit, and a transport error is what a block looks like mid-tighten — all mean
    'do not spend a scenario yet'."""
    try:
        return httpx.get(url, timeout=timeout, follow_redirects=True).status_code in (403, 429)
    except httpx.HTTPError:
        return True


def wait_until_clear(check_every: float, max_wait: float, log=print, blocked=is_blocked) -> bool:
    """Block until the host answers again, or give up after max_wait. False -> stop the run; the caller's
    resume skips whatever already graded, so stopping costs nothing but time."""
    waited = 0.0
    while blocked():
        if waited >= max_wait:
            return False
        log(f"    blocked — waiting {check_every:.0f}s (waited {waited / 60:.0f}m of {max_wait / 60:.0f}m)")
        time.sleep(check_every)
        waited += check_every
    return True


def probes_for_cwes(cwes, cwe2probe) -> list:
    return sorted({pid for w in (cwes or []) for pid in cwe2probe.get(w, ())})


class ScenarioSelectionError(SystemExit):
    """A pattern that matches nothing is fatal. Silently running zero scenarios would print a clean summary
    and read as 'nothing to fix', the same failure mode --probe already guards against in the catalog."""


def select_scenarios(scenarios, only: str):
    """Narrow the manifest to `only` (comma-separated ids or fnmatch globs). Empty -> everything."""
    pats = [p.strip() for p in (only or "").split(",") if p.strip()]
    if not pats:
        return scenarios
    ids = [s["id"] for s in scenarios]
    for p in pats:
        if not any(fnmatch.fnmatchcase(i, p) or i == p for i in ids):
            raise ScenarioSelectionError(f"--only: no scenario matches {p!r}")
    keep = {i for i in ids for p in pats if fnmatch.fnmatchcase(i, p) or i == p}
    return [s for s in scenarios if s["id"] in keep]


# Probes that need a SESSION but don't declare has_auth_entrypoint, because they mint their own identities
# (two accounts for a cross-user read, a throwaway for the authed BaaS tier, a create to round-trip). The
# catalog gate alone would under-report, and a missing session turns a real test into a silent N/A that the
# scorer would count as a miss.
_ALSO_NEEDS_AUTH = ("sec-idor-", "sec-backend-002", "qa-integrity-", "sec-upload-", "sec-xss-002")


def build_index(catalog_dir):
    """(cwe -> probe ids, probes needing the browser, probes needing a session).

    The CWE map is inverted from gapbench_score's category table, so the runner and the scorer can never
    disagree about what covers what. The other two drive per-scenario flags: the browser render and the
    self-registration are the two most expensive things a grade can do, and most scenarios' selections need
    neither, so paying for them everywhere is the same waste as running all 86 probes."""
    idx = collections.defaultdict(set)
    needs_browser, needs_auth = set(), set()
    for p in load_catalog(catalog_dir):
        for w in (_PROBE_OVERRIDES.get(p.id) or _CWE_BY_CATEGORY.get(p.category, ())):
            idx[w].add(p.id)
        requires = list(getattr(p.applicability, "requires", None) or [])
        if "browser" in requires:
            needs_browser.add(p.id)
        if "has_auth_entrypoint" in requires or p.id.startswith(_ALSO_NEEDS_AUTH) or p.id in _ALSO_NEEDS_AUTH:
            needs_auth.add(p.id)
    return idx, needs_browser, needs_auth


def verdict(rec, scenario, selected) -> tuple:
    """(verdict, applied, fired) for one graded scenario, using the scorer's own CWE matching so the live line
    and the final report can never disagree.

    A subset grade's SLOP is meaningless (it is a fraction of a battery), so the number to watch is whether the
    DECLARED class was caught. And a miss only means something if the probes ran: 0 applied is UNTESTED, which
    is a different problem from a detector that ran and found nothing. Conflating them is how a recall number
    becomes uninterpretable in both directions."""
    if rec is None or rec.get("slop_score") is None:
        return "dead", 0, []
    expected = set(scenario.get("cwes") or [])
    findings_all = rec.get("findings") or []
    if str(scenario.get("vulnerability", "")).startswith("None"):
        # A CONTROL inverts the vocabulary: there is nothing to catch, so a fire is a FALSE POSITIVE and
        # silence is the pass. Calling that a "miss" would read as failure when it is the result we want.
        # Hygiene is exempt for the same reason the scorer exempts it: a missing header is a verifiable fact
        # about the response, and the benchmark's own edge omits them on every scenario, controls included.
        fps = sorted({f["probe_id"] for f in findings_all
                      if _finding_cwes(f) and f.get("category") not in _FP_EXEMPT_CATEGORIES})
        n_applied = len((rec.get("coverage") or {}).get("applied") or [])
        return (f"FP({len(fps)})" if fps else "clean"), n_applied, fps
    applied = {p for p in (rec.get("coverage") or {}).get("applied") or [] if not selected or p in set(selected)}
    findings = rec.get("findings") or []
    fired = sorted({f["probe_id"] for f in findings})
    if any(_finding_cwes(f) & expected for f in findings):
        return "HIT", len(applied), fired
    if not applied:
        return "untested", 0, fired          # nothing engaged: not a recall failure, a reach failure
    return "miss", len(applied), fired


def already_done(results_path) -> set:
    """(scenario id, chunk) pairs already recorded with a real grade, so a resumed run re-sends nothing it
    needn't. A row that recorded a 403/dead URL is NOT done: that is exactly what a resume should retry.

    Keyed by CHUNK, not scenario: a chunked scenario is only finished when every one of its batches is, and
    treating the first recorded batch as 'the scenario is done' would silently drop the rest of its probes on
    every resume — the same erasure the scorer's merge exists to prevent, arriving by a different route. Rows
    written before chunking carry no `chunk` field and read as chunk 0, which is what an unchunked run is."""
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
            done.add((proj[len("anchor-gapbench-"):], int(r.get("chunk") or 0)))
    return done


def child_cmd(sid, sel, results, grade_timeout, needs_browser, needs_auth, chunk: int = 0) -> list:
    """The deploy_and_grade invocation for one scenario, including the two capability decisions.

    LEAST PRIVILEGE for the expensive capabilities, not just the probe list: a render costs every chunk the
    page loads, a self-registration costs a browser launch plus the signup round trip, and most selections
    need neither. A control (empty selection) keeps both, since it runs the full battery and a false positive
    can come from any probe. grade_timeout is stringified as an INT because deploy_and_grade declares
    type=int and rejects "300.0" with an argparse error the parent would otherwise swallow."""
    cmd = PY + [str(_HERE / "deploy_and_grade.py"), f"https://gapbench.vibe-eval.com/site/{sid}/",
                "--url", "--record", str(results), "--grade-timeout", str(int(grade_timeout)),
                # project stays the bare scenario tag so the scorer still groups every batch under it; `chunk`
                # rides alongside so a resume can tell WHICH batches are already recorded.
                "--meta", json.dumps({"project": f"anchor-gapbench-{sid}", "hackathon": "gapbench",
                                      "chunk": chunk})]
    for pid in sel:
        cmd += ["--probe", pid]
    if not ((not sel) or set(sel) & needs_browser):
        cmd += ["--no-browser"]
    if (not sel) or set(sel) & needs_auth:
        cmd += ["--browser-auth"]
    return cmd


def main() -> None:
    ap = argparse.ArgumentParser(description="Grade GapBench with per-scenario probe selection.")
    ap.add_argument("--results", default="gapbench-recall2.jsonl")
    ap.add_argument("--manifest", default=str(_MANIFEST))
    ap.add_argument("--catalog", default=str(_HERE.parent / "catalog"))
    ap.add_argument("--delay", type=float, default=60.0, metavar="SECONDS",
                    help="gap between scenarios (default 60; raise it for an unattended overnight run)")
    ap.add_argument("--grade-timeout", type=int, default=300,
                    help="per-scenario grading cap in SECONDS (int: deploy_and_grade rejects a float)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N scenarios (0 = all)")
    ap.add_argument("--only", default="", metavar="IDS",
                    help="comma-separated scenario ids or fnmatch globs (e.g. 'ssti,*redirect*'). Re-checking "
                         "a handful of fixed probes costs ~100 requests instead of ~9700, which matters on a "
                         "shared host that rate-limits us. Unmatched patterns are fatal, not silently empty.")
    ap.add_argument("--light-delay", type=float, default=25.0, dest="light_delay", metavar="SECONDS",
                    help="gap after a batch that ran clean (default 25). Batches are capped at "
                         "%d probes, the size that caused zero blocks across 55 scenarios overnight, so this "
                         "is the normal spacing; --delay is the fallback after one that still blocked."
                         % _CHUNK_PROBES)
    ap.add_argument("--recheck", type=float, default=60.0, metavar="SECONDS",
                    help="while blocked, re-test the host this often (one request per check)")
    ap.add_argument("--max-wait", type=float, default=1800.0, dest="max_wait", metavar="SECONDS",
                    help="give up if the block outlasts this (default 30m); rerunning resumes")
    ap.add_argument("--max-retries", type=int, default=2, dest="max_retries",
                    help="requeue a scenario the block killed, up to N times")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and traffic estimate, send nothing")
    args = ap.parse_args()

    scenarios = json.load(open(args.manifest))["scenarios"]
    scenarios = select_scenarios(scenarios, args.only)
    cwe2probe, needs_browser, needs_auth = build_index(args.catalog)
    # "already done" only means anything relative to what we were ASKED to run: with --only, the full-run
    # count reads as nonsense ("4 scenarios ... 91 already done") and hides why the plan came out empty.
    done = already_done(args.results)
    sel_ids = {s["id"] for s in scenarios}
    done = {(sid, ch) for sid, ch in done if sid in sel_ids}
    # A control's full battery is expanded to an EXPLICIT probe list so it can be batched like anything else.
    # Passing "no --probe flags" is unbatchable, and it also made every control pay a browser launch and a
    # self-registration; with explicit batches only the batches that actually contain a browser/auth probe do.
    all_probes = sorted(p.id for p in load_catalog(args.catalog))

    plan, skipped, controls = [], [], []
    for s in scenarios:
        sid = s["id"]
        is_control = str(s.get("vulnerability", "")).startswith("None")
        sel = probes_for_cwes(s.get("cwes"), cwe2probe)
        if is_control:
            controls.append((sid, all_probes))   # an FP can come from ANY probe, so a control keeps them all
        elif sel:
            plan.append((sid, sel))
        else:
            skipped.append(sid)                  # no probe of ours covers its class -> nothing to learn

    # BATCH: every job is <=_CHUNK_PROBES probes, the envelope that never tripped the challenge. `done` is
    # consulted per BATCH so a resume re-sends only what is actually missing.
    jobs = [(sid, batch, i) for sid, sel in plan + controls
            for i, batch in enumerate(_chunks(sel, _CHUNK_PROBES)) if (sid, i) not in done]
    if args.limit:
        jobs = jobs[:args.limit]
    est = sum(_est_requests(sel) for _sid, sel, _i in jobs)
    heaviest = sorted(((_est_requests(sel), sid) for sid, sel, _i in jobs), reverse=True)[:3]
    n_sc = len({sid for sid, _s, _i in jobs})
    print(f"\n  {len(scenarios)} scenarios: {len(plan)} targeted, {len(controls)} controls, "
          f"{len(skipped)} skipped (no covering probe), {len(done)} batches already done")
    print(f"  running {len(jobs)} batches across {n_sc} scenarios · <={_CHUNK_PROBES} probes each (the size "
          f"that never tripped the bot challenge) · ~{est} requests total")
    print(f"  spacing {args.light_delay:.0f}s · ~{len(jobs) * args.light_delay / 60:.0f} min of gaps "
          f"(a flat {args.delay:.0f}s would be ~{len(jobs) * args.delay / 60:.0f} min)")
    print("  heaviest: " + ", ".join(f"{sid} ~{n}" for n, sid in heaviest))
    if args.only and not jobs and done:
        # the whole point of --only is re-checking a FIXED probe, and those ids are already in the old file.
        # Never append a new code version's rows to an old run's file: the mixture is unscoreable.
        print(f"\n  all {len(done)} selected scenario(s) are already graded in {args.results}.")
        print("  a post-fix re-check must write a NEW file, so the run measures one code version:")
        print(f"    --only '{args.only}' --results gapbench-recheck.jsonl\n")
        return
    print(f"  skipped: {', '.join(skipped[:10])}{' ...' if len(skipped) > 10 else ''}\n")
    if args.dry_run:
        for sid, sel, ci in jobs[:15]:
            caps = ("B" if (not sel) or set(sel) & needs_browser else "-") + \
                   ("A" if (not sel) or set(sel) & needs_auth else "-")
            print(f"    {sid:<26} #{ci:<2} {len(sel) or 'FULL':>4}p {caps}  {','.join(sel[:5])}")
        nb = sum(1 for _s, sel, _i in jobs if sel and not set(sel) & needs_browser)
        na = sum(1 for _s, sel, _i in jobs if sel and not set(sel) & needs_auth)
        print(f"\n  capabilities: {nb} of {len(jobs)} skip the browser render, {na} skip self-registration"
              f"  (B=browser, A=auth)")
        print("\n  (dry run — nothing sent)\n")
        return

    by_id = {s['id']: s for s in scenarios}
    tally: dict = {}
    queue = list(jobs)
    attempts: dict = {}
    i = 0
    while queue:
        sid, sel, ci = queue.pop(0)
        i += 1
        if not wait_until_clear(args.recheck, args.max_wait):
            print(f"\n  still blocked after {args.max_wait / 60:.0f}m — stopping. Rerun to resume "
                  f"(graded scenarios are skipped).\n")
            return
        cmd = child_cmd(sid, sel, args.results, args.grade_timeout, needs_browser, needs_auth, chunk=ci)
        caps = ("B" if "--no-browser" not in cmd else "-") + ("A" if "--browser-auth" in cmd else "-")
        t0 = time.monotonic()
        proc = None
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.grade_timeout + 120)
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
                    # match THIS batch: with chunking a scenario has several rows, and taking any of them
                    # would report another batch's verdict on this line.
                    if r.get("project") == f"anchor-gapbench-{sid}" and int(r.get("chunk") or 0) == ci:
                        rec = r
        scen = by_id.get(sid, {})
        if rec is None and proc is not None and proc.returncode != 0:
            # the child never wrote a row AND exited nonzero -> surface its own words, then stop. An
            # unattended run that keeps going on a broken command line just wastes the whole night.
            tail = (proc.stderr or proc.stdout or "").strip().splitlines()
            print(f"  [{i}/{len(jobs)}] {sid:<28} CHILD FAILED (exit {proc.returncode}): "
                  f"{tail[-1][:120] if tail else '(no output)'}")
            print("\n  aborting: every scenario would fail the same way. Fix the command and rerun "
                  "(graded scenarios are skipped).\n")
            return
        v, n_applied, fired = verdict(rec, scen, sel)
        tally[v] = tally.get(v, 0) + 1
        if v == "dead":
            state = str((rec or {}).get("deploy_error") or "no record")[:30]
        else:
            shown = ",".join(fired[:2]) + (f" +{len(fired) - 2}" if len(fired) > 2 else "")
            state = f"applied {n_applied}/{len(sel) or 'all':<3} {shown or '—'}"[:44]
        # denominator = the ORIGINAL job count plus however many the block forced back on; using
        # len(queue) made it count DOWN as work completed, which reads like the total is shrinking.
        print(f"  [{i:>3}/{len(jobs) + sum(attempts.values())}] {sid:<22} #{ci:<2} "
              f"{str(scen.get('vulnerability', ''))[:22]:<22} {v:<8} {state:<46} ·{time.monotonic()-t0:4.0f}s",
              flush=True)
        # a scenario killed BY THE BLOCK is a lost measurement, not a result: put it back and let the
        # pre-flight gate above wait the window out before it runs again.
        if rec is not None and rec.get("dead_url") and "403" in str(rec.get("deploy_error") or ""):
            attempts[(sid, ci)] = attempts.get((sid, ci), 0) + 1
            if attempts[(sid, ci)] <= args.max_retries:
                queue.append((sid, sel, ci))
                print(f"    -> blocked; requeued (attempt {attempts[(sid, ci)]} of {args.max_retries})")
        if queue:
            # every batch is <=_CHUNK_PROBES, the size that never tripped the challenge, so the LIGHT spacing
            # is the normal case. --delay remains for a batch that somehow still blocked, where the host has
            # told us it wants more room.
            time.sleep(args.delay if (rec is not None and rec.get("dead_url")) else args.light_delay)
    print(f"\n  {sum(tally.values())} run: "
          + ", ".join(f"{n} {k}" for k, n in sorted(tally.items(), key=lambda kv: -kv[1]))
          + f"\n  HIT = the declared class was caught · miss = probes ran, nothing matched · "
            f"untested = nothing applied (a reach problem, not a recall one)")
    print(f"  score it:  uv run python scripts/gapbench_score.py {args.results}\n")


if __name__ == "__main__":
    main()
