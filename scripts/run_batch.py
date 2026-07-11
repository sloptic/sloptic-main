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
from urllib.parse import urlparse

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


def _results_index(results_path):
    """From a prior run of this --results file: (attempted targets, successfully-done targets, touched
    projects). A target is a repo URL or a live URL (the record's "repo" field); done = graded or skipped
    (out of scope); a project is 'touched' if any of its grades landed a row."""
    attempted, done, touched = set(), set(), set()
    p = pathlib.Path(results_path)
    if not p.exists():
        return attempted, done, touched
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        with contextlib.suppress(json.JSONDecodeError):
            r = json.loads(line)
            t = r.get("repo")
            if t is None:
                continue
            attempted.add(t)
            if r.get("slop_score") is not None or r.get("skipped"):
                done.add(t)
            if r.get("project"):
                touched.add(r["project"])
    return attempted, done, touched


def _plan_jobs(records):
    """Expand each submission into up to two grade JOBS — a repo deploy-grade and a live-URL raw-grade —
    each its own source-tagged result row (distinct target identity). A submission with both yields both:
    the two are complementary lenses (our controlled Docker deploy vs their live URL with real keys)."""
    jobs = []
    for rec in records:
        if rec.get("repo"):
            jobs.append({"target": rec["repo"], "source": "repo", "rec": rec})
        if rec.get("url"):
            jobs.append({"target": rec["url"], "source": "url", "rec": rec})
    return jobs


def _pending(jobs, results_path, mode):
    """Jobs still needing to run under resume `mode`:
      "default"        every job not yet SUCCESSFULLY done — retries failed repos+urls, AND catches a
                       missing url on a submission whose repo already graded.
      "no_repeat_repo" repo jobs skip once ATTEMPTED (no expensive re-deploys); url jobs as default.
      "whatsoever"     skip any job whose PROJECT already has a record — brand-new submissions only."""
    attempted, done, touched = _results_index(results_path)
    out = []
    for j in jobs:
        t, src, proj = j["target"], j["source"], j["rec"].get("project")
        if mode == "whatsoever":
            run = t not in attempted and (not proj or proj not in touched)
        elif mode == "no_repeat_repo" and src == "repo":
            run = t not in attempted
        else:
            run = t not in done
        if run:
            out.append(j)
    return out


def _load_urls(path, hackathon=None):
    """Parse a file of ALREADY-DEPLOYED app URLs to raw-fuzz (no clone/deploy). One entry per line:
    `URL`, or `URL,project`, or `URL,project,winner`; blank lines and `#` comments skipped. Each becomes a
    record with a `url` field (no repo) — a single url grade job routed to `deploy_and_grade --url`."""
    recs = []
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [c.strip() for c in line.split(",")]
        url = parts[0]
        project = parts[1] if len(parts) > 1 and parts[1] else (urlparse(url).netloc or url)
        winner = len(parts) > 2 and parts[2].lower() in ("1", "true", "yes", "winner", "y")
        recs.append({"url": url, "project": project, "winner": winner, "hackathon": hackathon})
    return recs


def _record_wedge(results, rec, secs, target, source, extra=None):
    """A wedged app is killed mid-run, so its own finally never writes a record — write one here so it
    isn't silently dropped from the batch (shows as a distinct WEDGED reason in the stats deploy view).
    `extra` is the stack-ID the child checkpointed before it wedged, so the app keeps its classification
    (app_kind / routing) for deploy-parity — else wedged apps show as '?' and can't be grouped by stack."""
    row = {
        "repo": target, "source": source, "deployed": False, "timeout": "wedge",
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
    mode = ap.add_mutually_exclusive_group(required=False)
    mode.add_argument("--hackathon", metavar="SLUG", help="one hackathon subdomain slug")
    mode.add_argument("--search", metavar="QUERY", help="auto-pick hackathons matching QUERY")
    ap.add_argument("--urls", metavar="FILE", help="also grade a file of ALREADY-DEPLOYED app URLs (one "
                    "per line, `URL[,project[,winner]]`) — raw-fuzz over HTTP(S), no clone/plan/deploy. "
                    "For submissions that ship a live Vercel/Railway/*.app link but no gradeable repo. "
                    "Combines with a Devpost source or stands alone.")
    resume = ap.add_mutually_exclusive_group()
    resume.add_argument("--no-repeat-repo", action="store_true", help="on re-run, don't re-attempt a REPO "
                        "job that already has ANY record (failed deploys included) — deploys are the "
                        "expensive part; url jobs still retry-failed + catch a missing url. (Default retries "
                        "everything not successfully done.)")
    resume.add_argument("--no-repeat-whatsoever", action="store_true", help="on re-run, skip any job whose "
                        "PROJECT already has a record — only brand-new submissions run (don't even chase a "
                        "missing url on an already-touched submission).")
    ap.add_argument("--hackathons", type=int, default=5, help="(--search) how many hackathons")
    ap.add_argument("--completed", action="store_true", help="(--search) only ended hackathons")
    ap.add_argument("--max-pages", type=int, default=25, dest="max_pages",
                    help="safety cap on gallery pages per hackathon (pages auto-fetched to fill --limit)")
    ap.add_argument("--limit", type=int, default=25, help="max repos to grade")
    ap.add_argument("--results", required=True, metavar="FILE", help="JSONL to append results to")
    ap.add_argument("--no-browser", dest="browser", action="store_false",
                    help="skip the browser-rendered surface (faster; default is browser ON for grading — "
                         "the render finds SPA forms a static crawl misses, the #1 recall win)")
    ap.add_argument("--audit-coverage", action="store_true", dest="audit_coverage",
                    help="LLM audits discovery coverage per app — notes missed surface (AfroSecured-style) + "
                         "placeholder pages onto each record. One cheap LLM call + light render per app; "
                         "stats' (h) DISCOVERY GAPS aggregates them into a fixable backlog.")
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
    if not (args.hackathon or args.search or args.urls):
        ap.error("need a source: --hackathon, --search, or --urls")
    if args.app_timeout is None:   # sum of the phase budgets (clone 300 + per-attempt build + grade) + margin
        args.app_timeout = 300 + args.attempts * (args.build_timeout + 90) + args.grade_timeout + 120

    # 1) gather work: Devpost repos (+ metadata) and/or a file of already-deployed app URLs
    records = []
    if args.hackathon or args.search:
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
    if args.urls:   # already-deployed apps: grade raw over HTTP(S), no clone/deploy
        url_recs = _load_urls(args.urls, args.hackathon)
        print(f"== + {len(url_recs)} live-app URL(s) from {args.urls} (raw-fuzz, no deploy) ==", flush=True)
        records += url_recs
    if not records:
        sys.exit("no repos or urls found")
    # expand submissions into repo+url grade jobs, then resume-filter them by mode (see _pending)
    mode = ("whatsoever" if args.no_repeat_whatsoever else
            "no_repeat_repo" if args.no_repeat_repo else "default")
    jobs = _plan_jobs(records)
    to_run = _pending(jobs, args.results, mode)
    n_repo = sum(j["source"] == "repo" for j in to_run)
    done_n = len(jobs) - len(to_run)
    print(f"== {len(records)} submissions → {len(jobs)} grade jobs · "
          + (f"{done_n} already done [{mode}] → " if done_n else "")
          + f"{len(to_run)} to run ({n_repo} repo, {len(to_run) - n_repo} url) ==\n", flush=True)

    # 2) run each job (repo deploy-grade or url raw-grade), appending to --results (failures recorded)
    for i, j in enumerate(to_run, 1):
        rec, target, source = j["rec"], j["target"], j["source"]
        print(f"\n{'#' * 60}\n[{i}/{len(to_run)}] {target}  [{source}]\n{'#' * 60}", flush=True)
        ckpt = pathlib.Path(tempfile.gettempdir()) / "hl-deploy-ckpt.json"
        ckpt.unlink(missing_ok=True)   # stale from the previous app -> clear before this one writes its own
        cmd = PY + [str(_HERE / "deploy_and_grade.py"), target, "--record", args.results,
                    "--grade-timeout", str(args.grade_timeout), "--meta", json.dumps(
                        {"hackathon": rec.get("hackathon"), "project": rec.get("project"),
                         "winner": rec.get("winner")})]
        if source == "url":   # live app: grade raw, no clone/plan/Docker deploy
            cmd += ["--url"]
        else:
            cmd += ["--attempts", str(args.attempts), "--build-timeout", str(args.build_timeout),
                    "--checkpoint", str(ckpt)]
        if not args.browser:
            cmd += ["--no-browser"]
        if args.audit_coverage:
            cmd += ["--audit-coverage"]
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
            if source == "repo" and ckpt.exists():   # url jobs never plan, so never checkpoint
                with contextlib.suppress(Exception):
                    stack = json.loads(ckpt.read_text())
            _record_wedge(args.results, rec, args.app_timeout, target=target, source=source, extra=stack)
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
