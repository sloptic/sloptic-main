#!/usr/bin/env python3
"""End-to-end batch: fetch hackathon repos from Devpost -> LLM-deploy + fuzz-grade each -> record results
-> print aggregate statistics. Ties devpost_repos.py -> deploy_and_grade.py --record -> stats.py, threading
each repo's {hackathon, project, winner} into the record so the stats are labelled and auditable.

    export OPENROUTER_API_KEY=sk-or-...
    uv run python scripts/run_batch.py --hackathon madhacks-fall-2025 --limit 15 --results run1.jsonl
    uv run python scripts/run_batch.py --search flask --completed --hackathons 5 --limit 20 \
        --results run2.jsonl          # browser grade by default; add --no-browser for a fast pass

Builds + runs UNTRUSTED code in Docker per repo — use a sandboxed/firewalled box. Failures don't stop the
batch (they're recorded as deployed=False for the reproducibility stat). Re-running with the same
--results appends; stats dedupes by repo (latest wins).
"""
import argparse
import contextlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

_HERE = pathlib.Path(__file__).resolve().parent
PY = [sys.executable]   # the uv-run venv interpreter (hacklet_runner importable)


def _hard_kill(proc):
    """SIGKILL the child AND its descendants (headless chrome, docker CLI) via the process group. An
    external SIGKILL is the ONLY thing that stops a GIL-holding C-spin (e.g. Playwright's sync transport
    busy-looping after the browser dies) — an in-process alarm/watchdog can't get a turn to run."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait(timeout=10)


def _cleanup_containers():
    subprocess.run(["docker", "rm", "-f", "-v", "hl-deploy-app", "hl-db"], capture_output=True)


def _done_repos(results_path):
    """Repos already FINISHED in a prior run of this --results file: successfully graded (has a slop_score)
    OR skipped as non-web (out of scope). A re-run doesn't retest these — only untested (new) repos and
    FAILED ones (deploy-failed / wedged / timed-out, i.e. no score and not skipped) run again."""
    done = set()
    p = pathlib.Path(results_path)
    if not p.exists():
        return done
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        with contextlib.suppress(json.JSONDecodeError):
            r = json.loads(line)
            if r.get("slop_score") is not None or r.get("skipped"):
                done.add(r.get("repo"))
    return done


def _record_wedge(results, rec, secs, extra=None):
    """A wedged app is killed mid-run, so its own finally never writes a record — write one here so it
    isn't silently dropped from the batch (shows as a distinct WEDGED reason in the stats deploy view).
    `extra` is the stack-ID the child checkpointed before it wedged, so the app keeps its classification
    (app_kind / routing) for deploy-parity — else wedged apps show as '?' and can't be grouped by stack."""
    row = {
        "repo": rec["repo"], "deployed": False, "timeout": "wedge",
        "timings": {"total_s": float(secs)},   # it ran at least this long before we killed it
        "deploy_error": f"WEDGED — killed after {secs}s (hung past internal build/grade caps)",
        "ts": time.time(), "hackathon": rec.get("hackathon"),
        "project": rec.get("project"), "winner": rec.get("winner"),
    }
    for k, v in (extra or {}).items():
        row.setdefault(k, v)   # recovered stack_profile / app_kind / features / expected_surface
    with open(results, "a") as f:
        f.write(json.dumps(row) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Devpost -> deploy + grade -> stats, in one run.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hackathon", metavar="SLUG", help="one hackathon subdomain slug")
    mode.add_argument("--search", metavar="QUERY", help="auto-pick hackathons matching QUERY")
    ap.add_argument("--hackathons", type=int, default=5, help="(--search) how many hackathons")
    ap.add_argument("--completed", action="store_true", help="(--search) only ended hackathons")
    ap.add_argument("--max-pages", type=int, default=25, dest="max_pages",
                    help="safety cap on gallery pages per hackathon (pages auto-fetched to fill --limit)")
    ap.add_argument("--limit", type=int, default=25, help="max repos to grade")
    ap.add_argument("--results", required=True, metavar="FILE", help="JSONL to append results to")
    ap.add_argument("--no-browser", dest="browser", action="store_false",
                    help="skip the browser-rendered surface (faster; default is browser ON for grading — "
                         "the render finds SPA forms a static crawl misses, the #1 recall win)")
    ap.add_argument("--attempts", type=int, default=3, help="deploy attempts per repo")
    ap.add_argument("--build-timeout", type=int, default=480, dest="build_timeout",
                    help="per-repo docker build timeout in seconds (default 480; lower = more throughput)")
    ap.add_argument("--grade-timeout", type=int, default=480, dest="grade_timeout",
                    help="grading's OWN wall-clock budget in seconds (default 480), externally enforced — "
                         "independent of deploy time so a slow 3-attempt deploy can't leave grading no room")
    ap.add_argument("--app-timeout", type=int, default=None, dest="app_timeout",
                    help="HARD per-repo wall-clock backstop (default: DERIVED from the phase caps — clone + "
                         "attempts x build + grade + margin). Build and grade are each separately bounded "
                         "now (grade in its own killable subprocess), so this only fires on a whole-child "
                         "runaway; deriving it means deploy time can't starve grading's budget")
    ap.add_argument("--model", metavar="ID", help="OpenRouter model (default: deploy_and_grade's)")
    args = ap.parse_args()
    if args.app_timeout is None:   # sum of the phase budgets (clone 300 + per-attempt build + grade) + margin
        args.app_timeout = 300 + args.attempts * (args.build_timeout + 90) + args.grade_timeout + 120

    # 1) fetch repos (+ metadata) from Devpost
    dp = PY + [str(_HERE / "devpost_repos.py"), "--json", "--limit", str(args.limit),
               "--max-pages", str(args.max_pages)]
    if args.hackathon:
        dp += ["--hackathon", args.hackathon]
    else:
        dp += ["--search", args.search, "--hackathons", str(args.hackathons)]
        if args.completed:
            dp += ["--completed"]
    print("== fetching repos from Devpost ==", flush=True)
    got = subprocess.run(dp, capture_output=True, text=True)
    sys.stderr.write(got.stderr)
    records = json.loads(got.stdout or "[]")
    if not records:
        sys.exit("no repos found")
    # resume: skip repos already graded/skipped in this --results file; re-run only new + failed ones
    done = _done_repos(args.results)
    to_run = [rec for rec in records if rec["repo"] not in done]
    if done:
        print(f"== {len(records)} repos · {len(done)} already done (graded/skipped) → "
              f"{len(to_run)} to (re)run ==\n", flush=True)
    else:
        print(f"== {len(to_run)} repos to deploy + grade ==\n", flush=True)

    # 2) deploy + grade each, appending to --results (failures recorded, batch continues)
    for i, rec in enumerate(to_run, 1):
        print(f"\n{'#' * 60}\n[{i}/{len(to_run)}] {rec['repo']}\n{'#' * 60}", flush=True)
        ckpt = pathlib.Path(tempfile.gettempdir()) / "hl-deploy-ckpt.json"
        ckpt.unlink(missing_ok=True)   # stale from the previous app -> clear before this one writes its own
        cmd = PY + [str(_HERE / "deploy_and_grade.py"), rec["repo"], "--record", args.results,
                    "--attempts", str(args.attempts), "--build-timeout", str(args.build_timeout),
                    "--grade-timeout", str(args.grade_timeout), "--checkpoint", str(ckpt),
                    "--meta", json.dumps(
                        {"hackathon": rec.get("hackathon"), "project": rec.get("project"),
                         "winner": rec.get("winner")})]
        if not args.browser:
            cmd += ["--no-browser"]
        if args.model:
            cmd += ["--model", args.model]
        # own process group (start_new_session) so a wedge -> we SIGKILL the child + its chrome/docker
        # descendants. Live output inherits our stdio.
        proc = subprocess.Popen(cmd, start_new_session=True)
        try:
            proc.wait(timeout=args.app_timeout)   # non-zero exit doesn't stop the batch; a WEDGE does get killed
        except subprocess.TimeoutExpired:
            _hard_kill(proc)
            _cleanup_containers()
            stack = {}                            # recover the stack-ID the child checkpointed before wedging
            if ckpt.exists():
                with contextlib.suppress(Exception):
                    stack = json.loads(ckpt.read_text())
            _record_wedge(args.results, rec, args.app_timeout, extra=stack)
            print(f"\n  !! WEDGED — killed after {args.app_timeout}s (hung past its internal caps); "
                  f"recorded{' (stack recovered)' if stack else ''}, moving on", flush=True)
        except KeyboardInterrupt:
            _hard_kill(proc)
            _cleanup_containers()
            print("\ninterrupted — running stats on what we have so far ...")
            break

    # 3) aggregate: slop distribution/anomalies, then the cross-stack parity (blind-spot calibration)
    print(f"\n\n{'=' * 60}\nAGGREGATE STATISTICS\n{'=' * 60}", flush=True)
    subprocess.run(PY + [str(_HERE / "stats.py"), args.results])
    print(f"\n\n{'=' * 60}\nCROSS-STACK PARITY (is a low score clean, or were we blind?)\n{'=' * 60}",
          flush=True)
    subprocess.run(PY + [str(_HERE / "parity.py"), args.results])


if __name__ == "__main__":
    main()
