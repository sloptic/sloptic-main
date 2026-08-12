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
"""
import argparse
import json
import subprocess
import sys
import threading
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
    return Outcome(probe_id=f.get("probe_id", ""), bundle=f.get("bundle", ""), category=f.get("category", ""),
                   outcome=f.get("outcome", "slop_detected"), penalty=f.get("penalty", 0) or 0,
                   variant_group_id=f.get("variant_group_id"), target=f.get("target", ""),
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
    findings = list(main_rec.get("findings") or []) + list((retry_rec or {}).get("findings") or [])
    outs = [_to_outcome(f) for f in findings]
    merged = dict(main_rec)
    merged["findings"] = findings
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


def _retry_one(url, blocked, retry_file, extra_flags, grade_timeout):
    cmd = PY + [str(_HERE / "deploy_and_grade.py"), url, "--url", "--record", retry_file,
                "--grade-timeout", str(grade_timeout)]
    for pid in blocked:
        cmd += ["--probe", pid]
    cmd += extra_flags
    try:
        subprocess.run(cmd, timeout=grade_timeout + 300, capture_output=True)
        return url, True
    except Exception as e:
        with _print_lock:
            print(f"  retry FAILED {url}: {type(e).__name__}", flush=True)
        return url, False


def main():
    ap = argparse.ArgumentParser(description="retry the WAF-blocked tail on challenged apps, post-run")
    ap.add_argument("--results", required=True, help="the main run's results .jsonl (never mutated)")
    ap.add_argument("--concurrency", type=int, default=4, help="apps retried in parallel (default 4)")
    ap.add_argument("--grade-timeout", type=int, default=900, help="per-app subset-grade timeout (s)")
    ap.add_argument("--browser-auth", action="store_true", help="pass through to the grader (MATCH the main run)")
    ap.add_argument("--no-browser", action="store_true", help="pass through to the grader (MATCH the main run)")
    args = ap.parse_args()

    records = _read_jsonl(args.results)
    blocked = [(_url_of(r), r.get("blocked_probes")) for r in records
               if r.get("blocked_probes") and _url_of(r)]
    # dedup by url (a url graded once); keep the first blocked list
    seen, jobs = set(), []
    for url, bp in blocked:
        if url not in seen:
            seen.add(url)
            jobs.append((url, bp))
    print(f"blocked apps to retry: {len(jobs)} of {len(records)} records", flush=True)
    if not jobs:
        print("nothing blocked — no retry needed."); return

    retry_file = args.results + ".retry.jsonl"
    Path(retry_file).write_text("")   # fresh
    extra = (["--browser-auth"] if args.browser_auth else []) + (["--no-browser"] if args.no_browser else [])

    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(_retry_one, url, bp, retry_file, extra, args.grade_timeout) for url, bp in jobs]
        for f in as_completed(futs):
            done += 1
            url, ok = f.result()
            with _print_lock:
                print(f"  [{done}/{len(jobs)}] {'ok ' if ok else 'ERR'} {url}", flush=True)

    # merge phase (reads the appended retry records; matches to the main records by url)
    retry_by_url = {}
    for r in _read_jsonl(retry_file):
        u = _url_of(r)
        if u:
            retry_by_url[u] = r   # last write wins (one subset grade per url)
    bundle_of = {p.id: p.bundle for p in load_catalog(str(_ROOT / "catalog"))}
    merged_file = args.results + ".merged.jsonl"
    n_recovered = n_fired = n_apps_touched = 0
    with open(merged_file, "w") as out:
        for r in records:
            url = _url_of(r)
            if r.get("blocked_probes") and url in retry_by_url:
                r = merge(r, retry_by_url[url], bundle_of)
                n_apps_touched += 1
                n_recovered += len(r["retry"]["recovered"])
                n_fired += len(r["retry"]["fired"])
            out.write(json.dumps(r) + "\n")

    print(f"\nRETRY DONE — {n_apps_touched} apps folded in · {n_recovered} probes recovered · "
          f"{n_fired} NEW findings")
    if n_fired:
        print("  ⚠ NEW findings surfaced on previously-blocked apps — inspect .merged.jsonl (retry.fired)")
    print(f"  merged grades -> {merged_file}   (main results untouched: {args.results})")


if __name__ == "__main__":
    main()
