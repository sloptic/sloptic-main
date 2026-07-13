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
import concurrent.futures
import contextlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.jsonl import append_jsonl  # noqa: E402  (lock-guarded results append, safe under concurrency)

_HERE = pathlib.Path(__file__).resolve().parent
# Launch children (deploy_and_grade / devpost_repos / stats / parity) with the PROJECT'S OWN venv python —
# it has PyYAML + httpx + playwright + all deps. NOT sys.executable: a bare `python3 run_batch.py` (no
# `uv run`) would otherwise spawn every child on a system interpreter missing yaml, and each grade dies at
# `import yaml`. Fall back to sys.executable only if the venv is absent (e.g. a non-uv checkout).
_VENV_PY = pathlib.Path(__file__).resolve().parent.parent / ".venv" / "bin" / "python"
PY = [str(_VENV_PY)] if _VENV_PY.exists() else [sys.executable]


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


def _only(jobs, only):
    """Restrict to a single cohort (--repo-only / --url-only). `only` is 'repo' | 'url' | None (both). The
    repo cohort is the permanent, reproducible one (fires #2 + the pointer telemetry); the url cohort is
    cheap (no clone/plan/Docker deploy). Splitting them lets a concluded hackathon whose URLs have rotted be
    graded repo-only, or a quick live-app pass be run url-only."""
    return [j for j in jobs if only is None or j["source"] == only]


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
    append_jsonl(results, row)   # lock-guarded (a parent-thread wedge record races the concurrent url graders)


# --- job execution (extracted so url jobs can fan out through a bounded thread pool; see main) -----------
_active: dict = {}                # pid -> Popen, so a KeyboardInterrupt can SIGKILL every in-flight child
_active_lock = threading.Lock()
_print_lock = threading.Lock()    # serialize a captured job's output block so concurrent logs don't garble


# --- --tldr: one compact line per app instead of the full grading dump -----------------------------------
class _Progress:
    """Thread-safe batch progress for the ETA. Uses throughput = done / elapsed (self-corrects for whatever
    concurrency is actually running); ETA = elapsed / done * remaining. Same shape as the manual estimate."""
    def __init__(self, total):
        self.total, self.done, self.t0 = total, 0, time.monotonic()
        self.lock = threading.Lock()

    def tick(self):
        with self.lock:
            self.done += 1
            elapsed = time.monotonic() - self.t0
            eta = elapsed / self.done * (self.total - self.done) if self.done else 0.0
            return self.done, eta


def _label(j):
    """A short human tag for the app: the Devpost project slug if we have it, else owner/repo or the URL host."""
    rec, target, source = j["rec"], j["target"], j["source"]
    proj = rec.get("project") or ""
    if "/software/" in proj:
        return proj.rstrip("/").rsplit("/", 1)[-1][:30]
    if source == "repo":
        return "/".join(target.rstrip("/").split("/")[-2:])[:30]
    return (urlparse(target).netloc or target)[:30]


def _last_record_for(results_path, target):
    """The most-recent result row for this target — the record the child just appended (latest wins, matching
    stats' dedup). Read after the child exits, so the row is fully written; safe to read under concurrency."""
    rec, p = None, pathlib.Path(results_path)
    if not p.exists():
        return None
    for line in p.read_text().splitlines():
        if line.strip():
            with contextlib.suppress(json.JSONDecodeError):
                r = json.loads(line)
                if r.get("repo") == target:
                    rec = r
    return rec


def _tldr_line(done, total, label, rec, secs, eta, tail):
    """The compact per-app line: [i/N] label  <slop N | DNF | FAIL>  missed: kinds  · Ns ETA m:ss."""
    prog = f"[{done}/{total}]"
    eta_s = f"ETA {int(eta) // 60}:{int(eta) % 60:02d}" if eta else ""
    if tail:                                    # wedged / job error — tail carries the reason
        return f"{prog} {label:<30} ✗ {tail.strip().lstrip('!').strip()[:50]}  ·{secs:4.0f}s {eta_s}"
    if rec is None:
        return f"{prog} {label:<30} ? no record  ·{secs:4.0f}s {eta_s}"
    audit = rec.get("coverage_audit") or {}
    state = audit.get("page_state")
    if rec.get("functional") is False or state in ("broken", "not-an-app", "placeholder"):
        score = f"DNF ({state or 'non-functional'})"        # ranked last — never rescued to a low score
    elif rec.get("slop_score") is not None:                 # a DNF app keeps its slop for reference; check DNF first
        score = f"slop {rec['slop_score']}"
    elif rec.get("deployed") is False:
        score = "FAIL deploy"
    elif rec.get("skipped"):
        score = "skipped"
    else:
        score = "—"
    missed = audit.get("missed") or []
    miss = ("missed: " + ", ".join(dict.fromkeys(m.get("kind", "?") for m in missed))) if missed else ""
    return f"{prog} {label:<30} {score:<20} {miss:<26} ·{secs:4.0f}s {eta_s}"


def _build_cmd(j, args, ckpt):
    rec, target, source = j["rec"], j["target"], j["source"]
    cmd = PY + [str(_HERE / "deploy_and_grade.py"), target, "--record", args.results,
                "--grade-timeout", str(args.grade_timeout), "--meta", json.dumps(
                    {"hackathon": rec.get("hackathon"), "project": rec.get("project"), "winner": rec.get("winner")})]
    if source == "url":            # live app: grade raw, no clone/plan/Docker deploy
        cmd += ["--url"]
    else:
        cmd += ["--attempts", str(args.attempts), "--build-timeout", str(args.build_timeout), "--checkpoint", str(ckpt)]
    if not args.browser:
        cmd += ["--no-browser"]
    if args.audit_coverage:
        cmd += ["--audit-coverage"]
    if args.proactive:
        cmd += ["--proactive"]
    if args.browser_auth:
        cmd += ["--browser-auth"]
    for h in (args.headers or []):
        cmd += ["--header", h]
    if args.model:
        cmd += ["--model", args.model]
    return cmd


def _run_job(j, idx, total, args, capture, progress=None):
    """Grade one job in a child process with a hard wall-clock kill. capture=True buffers the child's output
    and prints it as ONE block on completion (concurrent url jobs, so logs don't interleave); capture=False
    streams live (serial repo jobs). Under --tldr the buffered dump is dropped and ONE compact line is printed
    from the child's result record instead. A wedge or error is RECORDED, never fatal to the batch."""
    t0 = time.monotonic()
    rec, target, source = j["rec"], j["target"], j["source"]
    ckpt = pathlib.Path(tempfile.gettempdir()) / "hl-deploy-ckpt.json"
    if source == "repo":           # only repo jobs plan+checkpoint; url jobs never touch it (safe concurrently)
        ckpt.unlink(missing_ok=True)
    hdr = f"\n{'#' * 60}\n[{idx}/{total}] {target}  [{source}]\n{'#' * 60}"
    if not capture:
        print(hdr, flush=True)
    kw = {"start_new_session": True}   # own process group -> a wedge SIGKILLs the child + its chrome/docker kids
    if capture:
        kw.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    proc = subprocess.Popen(_build_cmd(j, args, ckpt), **kw)
    with _active_lock:
        _active[proc.pid] = proc
    out, tail = "", ""
    try:
        if capture:
            out, _ = proc.communicate(timeout=args.app_timeout)   # reads the pipe (else it fills + deadlocks)
        else:
            proc.wait(timeout=args.app_timeout)   # non-zero exit doesn't stop the batch; a WEDGE gets killed
    except subprocess.TimeoutExpired:
        _hard_kill(proc)
        if source == "repo":
            _cleanup_containers()
        if capture:
            with contextlib.suppress(Exception):
                out, _ = proc.communicate(timeout=5)
        stack = {}                                # recover the stack-ID the child checkpointed before wedging
        if source == "repo" and ckpt.exists():
            with contextlib.suppress(Exception):
                stack = json.loads(ckpt.read_text())
        _record_wedge(args.results, rec, args.app_timeout, target=target, source=source, extra=stack)
        tail = (f"  !! WEDGED — killed after {args.app_timeout}s (hung past its internal caps); "
                f"recorded{' (stack recovered)' if stack else ''}, moving on")
    except Exception as e:                        # a single job's failure must never kill an overnight batch
        with contextlib.suppress(Exception):
            _hard_kill(proc)
        tail = f"  !! job error: {type(e).__name__}: {e}; moving on"
    finally:
        with _active_lock:
            _active.pop(proc.pid, None)
    secs = time.monotonic() - t0
    if args.tldr:                          # terse: one line from the child's record, not its full dump
        rec_out = _last_record_for(args.results, target)
        done, eta = progress.tick() if progress else (idx, 0.0)
        with _print_lock:
            print(_tldr_line(done, progress.total if progress else total, _label(j),
                             rec_out, secs, eta, tail), flush=True)
    elif capture:
        with _print_lock:
            print(hdr + "\n" + (out or "").rstrip() + (("\n" + tail) if tail else ""), flush=True)
    elif tail:
        print(tail, flush=True)


def _kill_all_active():
    with _active_lock:
        for p in list(_active.values()):
            with contextlib.suppress(Exception):
                _hard_kill(p)


def main():
    ap = argparse.ArgumentParser(description="Devpost -> deploy + grade -> stats, in one run.")
    mode = ap.add_mutually_exclusive_group(required=False)
    mode.add_argument("--hackathon", metavar="SLUG", nargs="+",
                      help="one or more hackathon subdomain slugs (space-separated), pooled into one run — "
                           "the --limit is balanced across them for a diverse corpus")
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
    cohort = ap.add_mutually_exclusive_group()
    cohort.add_argument("--repo-only", dest="only", action="store_const", const="repo",
                        help="grade ONLY repo jobs (skip live URLs) — the permanent, reproducible cohort that "
                             "fires #2 + pointer telemetry; use for a concluded hackathon whose URLs have rotted.")
    cohort.add_argument("--url-only", dest="only", action="store_const", const="url",
                        help="grade ONLY live-URL jobs (skip repos) — cheap + fast (no clone/plan/Docker deploy); "
                             "a quick dead-controls / coverage-audit / HTTPS pass over live apps.")
    ap.add_argument("--hackathons", type=int, default=5, help="(--search) how many hackathons")
    ap.add_argument("--completed", action="store_true", help="(--search) only ended hackathons")
    ap.add_argument("--max-pages", type=int, default=25, dest="max_pages",
                    help="safety cap on gallery pages per hackathon (pages auto-fetched to fill --limit)")
    ap.add_argument("--limit", type=int, default=25, help="max repos to grade")
    ap.add_argument("--ingest-cache", metavar="FILE", dest="ingest_cache", default=None,
                    help="forward to devpost_repos: JSONL memo of Devpost fetches so a re-run of an already-"
                         "scraped hackathon does ~zero network (default: $HL_CACHE_DIR/devpost-ingest.jsonl).")
    ap.add_argument("--no-ingest-cache", action="store_true", dest="no_ingest_cache",
                    help="forward to devpost_repos: disable the ingest cache (fetch every page/project fresh).")
    ap.add_argument("--results", required=True, metavar="FILE", help="JSONL to append results to")
    ap.add_argument("--no-browser", dest="browser", action="store_false",
                    help="skip the browser-rendered surface (faster; default is browser ON for grading — "
                         "the render finds SPA forms a static crawl misses, the #1 recall win)")
    ap.add_argument("--audit-coverage", action="store_true", dest="audit_coverage",
                    help="LLM audits discovery coverage per app — notes missed surface (AfroSecured-style) + "
                         "placeholder pages onto each record. One cheap LLM call + light render per app; "
                         "stats' (h) DISCOVERY GAPS aggregates them into a fixable backlog.")
    ap.add_argument("--proactive", action="store_true",
                    help="forward to deploy_and_grade: PROACTIVE discovery — an LLM perceives the rendered "
                         "pages and feeds the probeable surface the crawl missed INTO forms/endpoints (opt-in; "
                         "probes self-gate, so it only widens targets, never touches the score). Pair with "
                         "--audit-coverage to watch the DISCOVERY GAPS shrink as it closes them.")
    ap.add_argument("--browser-auth", action="store_true", dest="browser_auth",
                    help="forward to deploy_and_grade: SPA auth — when httpx self-registration gets no session, "
                         "drive the browser to fill+submit the signup so the app's JS registers, and use the "
                         "cookie/token it sets (wakes session/idor on self-hosted SPAs; opt-in, extra browser launch).")
    ap.add_argument("--header", action="append", dest="headers", metavar="'Name: Value'",
                    help="forward to deploy_and_grade (repeatable): a request header sent on the whole run — the "
                         "Option-B auth fallback (--header 'Cookie: …' or --header 'Authorization: Bearer …') so "
                         "the authed-surface probes reach the logged-in surface when self-registration can't.")
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
    ap.add_argument("--concurrency", type=int, default=1, metavar="N",
                    help="grade N URL jobs in parallel (default 1). URL grading is network/render-bound with "
                         "no Docker, so 6-10 is a big overnight speedup; the results append is lock-guarded so "
                         "concurrent writes won't corrupt it. REPO jobs always run serially (fixed Docker "
                         "container names can't coexist), regardless of this value.")
    ap.add_argument("--tldr", action="store_true",
                    help="terse progress: suppress each app's full grading dump; print ONE line per app "
                         "(count · slop score / DNF / FAIL · what the coverage-audit says the fuzzer missed · "
                         "elapsed + ETA). The full per-app record still lands in --results and the aggregate "
                         "stats still print at the end. Pair with --audit-coverage for the 'missed' column.")
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
        if args.no_ingest_cache:
            dp += ["--no-ingest-cache"]
        elif args.ingest_cache:
            dp += ["--ingest-cache", args.ingest_cache]
        if args.hackathon:
            dp += ["--hackathon", *args.hackathon]
        else:
            dp += ["--search", args.search, "--hackathons", str(args.hackathons)]
            if args.completed:
                dp += ["--completed"]
        print("== fetching repos from Devpost ==", flush=True)
        got = subprocess.run(dp, capture_output=True, text=True)
        sys.stderr.write(got.stderr)
        records = json.loads(got.stdout or "[]")
    if args.urls:   # already-deployed apps: grade raw over HTTP(S), no clone/deploy
        url_recs = _load_urls(args.urls, ",".join(args.hackathon) if args.hackathon else None)
        print(f"== + {len(url_recs)} live-app URL(s) from {args.urls} (raw-fuzz, no deploy) ==", flush=True)
        records += url_recs
    if not records:
        sys.exit("no repos or urls found")
    # expand submissions into repo+url grade jobs, then resume-filter them by mode (see _pending)
    mode = ("whatsoever" if args.no_repeat_whatsoever else
            "no_repeat_repo" if args.no_repeat_repo else "default")
    jobs = _only(_plan_jobs(records), args.only)   # --repo-only / --url-only cohort filter (None = both)
    to_run = _pending(jobs, args.results, mode)
    n_repo = sum(j["source"] == "repo" for j in to_run)
    done_n = len(jobs) - len(to_run)
    only_tag = f" [{args.only}-only]" if args.only else ""
    print(f"== {len(records)} submissions → {len(jobs)} grade jobs{only_tag} · "
          + (f"{done_n} already done [{mode}] → " if done_n else "")
          + f"{len(to_run)} to run ({n_repo} repo, {len(to_run) - n_repo} url) ==\n", flush=True)

    # 2) run each job (repo deploy-grade or url raw-grade), appending to --results (failures recorded).
    # REPO jobs run SERIALLY (fixed Docker container names hl-deploy-app/hl-db can't coexist); URL jobs fan
    # out N-wide (no Docker — network/render-bound). The lock-guarded append keeps --results intact.
    repo_jobs = [j for j in to_run if j["source"] == "repo"]
    url_jobs = [j for j in to_run if j["source"] == "url"]
    conc = max(1, args.concurrency)
    if conc > 1:
        note = f" · url {conc}-wide" + (f", {len(repo_jobs)} repo serial" if repo_jobs else "")
        print(f"   concurrency: {conc}{note}", flush=True)
    prog = _Progress(len(repo_jobs) + len(url_jobs)) if args.tldr else None
    cap = args.tldr        # --tldr captures (suppresses) each child's dump; we print one line from its record
    try:
        for i, j in enumerate(repo_jobs, 1):                       # serial repo phase
            _run_job(j, i, len(repo_jobs), args, capture=cap, progress=prog)
        if url_jobs and conc > 1:                                  # parallel url phase
            with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
                futs = [ex.submit(_run_job, j, i, len(url_jobs), args, True, prog)
                        for i, j in enumerate(url_jobs, 1)]
                try:
                    for f in concurrent.futures.as_completed(futs):
                        f.result()                                # _run_job self-contains errors; surfaces only KI
                except KeyboardInterrupt:
                    _kill_all_active()                            # unblock the workers so the pool can shut down
                    raise
        else:
            for i, j in enumerate(url_jobs, 1):                    # serial url phase (concurrency 1)
                _run_job(j, i, len(url_jobs), args, capture=cap, progress=prog)
    except KeyboardInterrupt:
        _kill_all_active()
        _cleanup_containers()
        print("\ninterrupted — running stats on what we have so far ...")

    # 3) aggregate: slop distribution/anomalies, then the cross-stack parity (blind-spot calibration)
    print(f"\n\n{'=' * 60}\nAGGREGATE STATISTICS\n{'=' * 60}", flush=True)
    subprocess.run(PY + [str(_HERE / "stats.py"), args.results])
    print(f"\n\n{'=' * 60}\nCROSS-STACK PARITY (is a low score clean, or were we blind?)\n{'=' * 60}",
          flush=True)
    subprocess.run(PY + [str(_HERE / "parity.py"), args.results])


if __name__ == "__main__":
    main()
