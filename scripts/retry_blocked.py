#!/usr/bin/env python3
"""Retry the WAF-blocked probe tail on each challenged app, AFTER the main corpus run (the ~10-min Vercel
reset is long elapsed by then). Re-grades ONLY each app's `blocked_probes` via `deploy_and_grade --probe`
(a subset = little traffic, so it mostly clears the WAF before re-tripping), then folds the recovered
outcomes back into the record: clears `incomplete_axes` where the tail came back clean, adds any findings,
recomputes the score. Injection fires ~0% on the corpus, so this mostly converts "incomplete" -> "tested
clean" (the completeness point) and LOUDLY surfaces anything that actually fires.

Safety: the main results file is never mutated. Subset retry grades go to <results>.retry.jsonl (marked
`probe_filter`, RECALL-ONLY -> only ever used to SUPPLEMENT a full-grade record, never as a standalone
score), and the folded grades to <results>.merged.jsonl. So a retry failure can never corrupt the
calibration data.

    python scripts/retry_blocked.py --results run.jsonl [--browser-auth] [--concurrency N]

One pass by default (recovers most of the tail on fresh-budget apps; sticky apps stay flagged, honestly).

An IP-LEVEL flag is NOT per-app challenging: it re-challenges every app at entry and recovers nothing, and
this tool cannot dig one out (the ~10-min per-app reset does not apply -- IP reputation lasts hours). A circuit
breaker detects that pattern and ABORTS early, because each further retry only re-warms the flag and resets its
decay -- let the IP decay (halt Vercel traffic, confirm with waf_probe), then re-run.

Re-fold an already-run retry without re-grading (pure, seconds — e.g. after a merge() fix):

    python scripts/retry_blocked.py --results run.jsonl --remerge
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))
from sloptic.aggregate import compute_axis_slop, compute_slop_score  # noqa: E402
from sloptic.catalog import load_catalog  # noqa: E402
from sloptic.schema import Outcome  # noqa: E402

_VENV_PY = _ROOT / ".venv" / "bin" / "python"
PY = [str(_VENV_PY)] if _VENV_PY.exists() else [sys.executable]
_print_lock = threading.Lock()

_SKIPPED = object()      # sentinel record: this app was NOT retried because the IP-block circuit breaker tripped
_IP_BLOCK_SAMPLE = 8     # entry-challenged apps with ZERO recovery before we call it an IP-level flag (not per-app)


def _read_jsonl(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _url_of(rec):
    """The live URL a url-ingest record grades (stored in `repo`); None for non-url records."""
    u = (rec.get("repo") or "").strip()
    return u if u.startswith("http") else None


def _to_outcome(f):
    # PRODUCTION serialization (deploy_and_grade.py) stores the variant group under "group" and writes NO
    # "outcome" key (findings are all fired). Read "group" first — reading the dataclass field name
    # `variant_group_id` here silently dropped every group, so from-scratch recompute stopped collapsing
    # multi-syntax findings (5 SQLi variants scored as 5, not 1) and inflated the merged score.
    return Outcome(probe_id=f.get("probe_id", ""), bundle=f.get("bundle", ""), category=f.get("category", ""),
                   outcome=f.get("outcome", "slop_detected"), penalty=f.get("penalty", 0) or 0,
                   variant_group_id=f.get("group") or f.get("variant_group_id"), target=f.get("target", ""),
                   reason=f.get("reason", ""), evidence=f.get("evidence") or {})


def _graded(rec):
    """True only for a retry record that ACTUALLY graded — not a DNF (dead url, deploy fail, timeout, crash).
    A real grade always writes deployed=true + slop_score + blocked_probes; a DNF has none of them, and must
    count as 'recovered nothing' so a failed retry never spuriously clears the block."""
    return bool(rec) and bool(rec.get("deployed")) and "slop_score" in rec


def merge(main_rec, retry_rec, bundle_of):
    """Fold a subset-retry record into the full-grade record (pure). A None/DNF retry reproduces the original
    record exactly (the score invariant). `bundle_of`: probe_id -> bundle, for the residual axes."""
    main_blocked = list(main_rec.get("blocked_probes") or [])
    if not main_blocked:
        return dict(main_rec)
    # a DNF retry recovered nothing -> keep the whole original block (never false-clear on a failed retry)
    still_blocked = set(retry_rec.get("blocked_probes") or []) if _graded(retry_rec) else set(main_blocked)
    still_blocked &= set(main_blocked)                              # never invent a block the main run didn't have
    recovered = [p for p in main_blocked if p not in still_blocked]  # ran in the retry (clean OR fired)
    new_findings = list((retry_rec or {}).get("findings") or [])
    findings = list(main_rec.get("findings") or []) + new_findings
    merged = dict(main_rec)
    merged["findings"] = findings
    # A CLEAN recovery (tail ran, nothing fired) changes COVERAGE, not the score — keep main's exact stored
    # slop_score/axis_slop. Only a genuine new finding recomputes. (Serialized findings are deduped by
    # (probe_id, reason) with a `count`, so a from-scratch recompute can drift a point or two off the
    # pipeline's score; recomputing only when the retry actually fired keeps the 700+ clean recoveries exact.)
    if new_findings:
        outs = [_to_outcome(f) for f in findings]
        merged["slop_score"] = compute_slop_score(outs)
        merged["axis_slop"] = compute_axis_slop(outs)
    merged["blocked_probes"] = sorted(still_blocked)
    merged["incomplete_axes"] = sorted({bundle_of[p] for p in still_blocked if p in bundle_of})
    merged["retry"] = {
        "recovered": sorted(recovered),
        "fired": [f.get("probe_id") for f in (retry_rec or {}).get("findings") or []],
        "still_blocked": sorted(still_blocked),
    }
    return merged


def _status(blocked, rec):
    """How the retry went for one app: (kind, recovered, total, onset). kind is
      full    — every blocked probe ran; the WAF did NOT re-challenge
      partial — got SOME back, then re-challenged (fresh-budget app, tail too long for one pass)
      none    — re-challenged immediately, recovered nothing (sticky/collapse app)
      dnf     — the retry grade itself failed (dead url / timeout) -> recovered nothing, NOT a WAF verdict"""
    total = len(blocked)
    if not _graded(rec):
        return "dnf", 0, total, None
    still = set(rec.get("blocked_probes") or []) & set(blocked)
    recovered = total - len(still)
    onset = rec.get("challenge_onset") or ""
    if not still:
        return "full", recovered, total, onset
    return ("partial" if recovered else "none"), recovered, total, onset


def _looks_like_ip_block(statuses):
    """True when the retry so far shows a SYSTEMIC IP-level flag, not per-app challenging. On a clean IP a thin
    subset retry recovers most tails; an IP-reputation block re-challenges EVERY app at entry and recovers
    nothing. Verdict: ANY recovery means it is NOT an IP block (per-app, retry_blocked's normal case), else
    >= _IP_BLOCK_SAMPLE apps that re-challenged at entry ('none' WITH a bot_challenge). `statuses` is
    [(kind, bot_challenge_bool)] for the graded apps so far; dnf/plain-none entries are neutral (never a WAF
    verdict), so a dead-URL streak alone never trips it."""
    challenged_none = sum(1 for kind, chal in statuses if kind == "none" and chal)
    recovered = sum(1 for kind, _ in statuses if kind in ("full", "partial"))
    return recovered == 0 and challenged_none >= _IP_BLOCK_SAMPLE


def _retry_one(url, blocked, tmpdir, extra_flags, grade_timeout, abort=None):
    """Subset re-grade one app to its OWN temp record, read it back, return (url, blocked, record|None).
    If `abort` is already set when this job starts (the IP-block circuit breaker tripped), skip it and return
    _SKIPPED -- spending more traffic on a flagged IP only re-warms the flag and resets its decay."""
    if abort is not None and abort.is_set():
        return url, blocked, _SKIPPED
    rec_path = os.path.join(tmpdir, hashlib.md5(url.encode()).hexdigest() + ".jsonl")
    cmd = PY + [str(_HERE / "deploy_and_grade.py"), url, "--url", "--record", rec_path,
                "--grade-timeout", str(grade_timeout)]
    for pid in blocked:
        cmd += ["--probe", pid]
    cmd += extra_flags
    try:
        subprocess.run(cmd, timeout=grade_timeout + 300, capture_output=True)
        recs = _read_jsonl(rec_path)
        return url, blocked, (recs[-1] if recs else None)
    except Exception:
        return url, blocked, None   # DNF -> _status reports dnf, merge recovers nothing


def _load_jobs(records):
    """The challenged apps to (re-)fold: (url, blocked_probes), deduped by url (a url is graded once)."""
    seen, jobs = set(), []
    for r in records:
        url = _url_of(r)
        if r.get("blocked_probes") and url and url not in seen:
            seen.add(url)
            jobs.append((url, r.get("blocked_probes")))
    return jobs


def _fold_and_summary(records, collected, tally, merged_file, results_path, retry_file):
    """Fold every graded retry record into its full-grade record -> .merged.jsonl (main untouched), then
    print the run summary. Shared by the live retry and --remerge so a fold is byte-identical either way."""
    bundle_of = {p.id: p.bundle for p in load_catalog(str(_ROOT / "catalog"))}
    n_recovered = n_fired = n_apps = 0
    with open(merged_file, "w") as out:
        for r in records:
            url = _url_of(r)
            if r.get("blocked_probes") and collected.get(url) is not None:
                r = merge(r, collected[url], bundle_of)
                n_apps += 1
                n_recovered += len(r["retry"]["recovered"])
                n_fired += len(r["retry"]["fired"])
            out.write(json.dumps(r) + "\n")
    print(f"\nRETRY DONE — apps: FULL={tally['full']}  partial={tally['partial']}  none={tally['none']}  "
          f"dnf={tally['dnf']}   ·   {n_recovered} probes recovered · {n_fired} NEW findings")
    if n_fired:
        print("  ⚠ NEW findings on previously-blocked apps — inspect .merged.jsonl (retry.fired)")
    if not n_recovered:
        print("  (NO recovery — every blocked app re-challenged or DNF'd; blocked tails stay flagged)")
    print(f"  merged -> {merged_file}   ·   raw retry -> {retry_file}   ·   main untouched: {results_path}")


def main():
    ap = argparse.ArgumentParser(description="retry the WAF-blocked tail on challenged apps, post-run")
    ap.add_argument("--results", required=True, help="the main run's results .jsonl (never mutated)")
    ap.add_argument("--concurrency", type=int, default=4, help="apps retried in parallel (default 4)")
    ap.add_argument("--grade-timeout", type=int, default=900, help="per-app subset-grade timeout (s)")
    ap.add_argument("--browser-auth", action="store_true", help="pass through to the grader (MATCH the main run)")
    ap.add_argument("--no-browser", action="store_true", help="pass through to the grader (MATCH the main run)")
    # email-verification flags: MATCH the main run, else a WAF-blocked authed probe on an email-gated app is
    # retried with no receiver -> reads N/A -> the recall the email lane added is lost exactly on the retry path.
    ap.add_argument("--email-domain", help="pass through to the grader (MATCH the main run)")
    ap.add_argument("--email-endpoint", help="pass through to the grader (MATCH the main run)")
    ap.add_argument("--email-token", default="", help="pass through to the grader (MATCH the main run)")
    ap.add_argument("--remerge", action="store_true",
                    help="skip grading: re-fold the EXISTING <results>.retry.jsonl into .merged.jsonl (use "
                         "after a merge-logic fix — the fold is pure, so no re-grade is needed)")
    args = ap.parse_args()

    records = _read_jsonl(args.results)
    jobs = _load_jobs(records)
    print(f"blocked apps to retry: {len(jobs)} of {len(records)} records", flush=True)
    if not jobs:
        print("nothing blocked — no retry needed."); return

    retry_file = args.results + ".retry.jsonl"
    merged_file = args.results + ".merged.jsonl"

    # --remerge: the retry already ran; just re-fold its records (e.g. after fixing merge()). Pure, seconds.
    if args.remerge:
        collected = {_url_of(r): r for r in _read_jsonl(retry_file) if _url_of(r)}
        if not collected:
            print(f"no retry records at {retry_file} — run the retry first (without --remerge)."); return
        print(f"re-merge only: folding {len(collected)} existing retry records from {retry_file}", flush=True)
        tally = Counter()
        for url, bp in jobs:
            tally[_status(bp, collected.get(url))[0]] += 1
        _fold_and_summary(records, collected, tally, merged_file, args.results, retry_file)
        return

    extra = (["--browser-auth"] if args.browser_auth else []) + (["--no-browser"] if args.no_browser else [])
    if args.email_domain:
        extra += ["--email-domain", args.email_domain]
    if args.email_endpoint:
        extra += ["--email-endpoint", args.email_endpoint]
    if args.email_token:
        extra += ["--email-token", args.email_token]
    tmpdir = tempfile.mkdtemp(prefix="sloptic-retry-")
    collected = {}                    # url -> retry record (None on DNF or a circuit-breaker skip)
    tally = Counter()
    done = skipped = 0
    abort = threading.Event()         # set by the IP-block circuit breaker; pending jobs then skip immediately
    statuses = []                     # (kind, bot_challenge) per graded app, for the breaker's verdict
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(_retry_one, url, bp, tmpdir, extra, args.grade_timeout, abort) for url, bp in jobs]
        for f in as_completed(futs):
            done += 1
            url, blocked, rec = f.result()
            if rec is _SKIPPED:
                collected[url] = None    # not retried -> merge keeps the original block (recovered nothing)
                skipped += 1
                continue
            collected[url] = rec
            kind, n, tot, onset = _status(blocked, rec)
            tally[kind] += 1
            mark = {"full": "✓ FULL", "partial": "~ part", "none": "✗ none", "dnf": "· dnf "}[kind]
            note = f" re-challenge@{onset}" if kind in ("partial", "none") and onset else ""
            with _print_lock:
                print(f"  [{done}/{len(jobs)}] {mark} {n:>2}/{tot:<2}{note:<28} {url}", flush=True)
            # CIRCUIT BREAKER: retry_blocked's whole premise is that a thin subset retry clears a PER-APP
            # challenge. An IP-level flag re-challenges every app at entry and recovers nothing, which this tool
            # cannot dig out -- and every further retry only re-warms the flag. When that pattern is unmistakable,
            # STOP (pending jobs skip via the abort event; in-flight ones finish).
            statuses.append((kind, bool((rec or {}).get("bot_challenge"))))
            if not abort.is_set() and _looks_like_ip_block(statuses):
                abort.set()
                with _print_lock:
                    print(f"\n  ⚠ IP-LEVEL FLAG DETECTED — the first {_IP_BLOCK_SAMPLE} apps all re-challenged at "
                          f"entry and recovered nothing. This is a Vercel IP-reputation block, not per-app "
                          f"challenging.\n    Stopping: this tool cannot dig out an IP block, and retrying the "
                          f"rest only re-warms the flag and resets its (hours-long) decay. Halt Vercel traffic "
                          f"from this box, confirm the flag cleared (waf_probe.py), then re-run this retry.",
                          flush=True)

    # persist raw retry records (for inspection + later --remerge), then fold into the merged grades
    with open(retry_file, "w") as rf:
        for rec in collected.values():
            if rec is not None:
                rf.write(json.dumps(rec) + "\n")
    _fold_and_summary(records, collected, tally, merged_file, args.results, retry_file)
    if abort.is_set():
        print(f"  ⚠ ABORTED on an IP-level flag — {skipped} apps left un-retried; their blocked tails stay "
              f"flagged in .merged.jsonl. Re-run after the IP decays to recover them.")
    shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
