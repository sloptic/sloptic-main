"""run_batch's hard per-app kill: a wedge that ignores polite signals (a GIL-holding CPU spin) must be
SIGKILLed via its process group, taking its descendants (headless chrome) with it. No network/Docker.
"""
import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from run_batch import _hard_kill, _load_urls, _pending, _plan_jobs, _record_wedge  # noqa: E402


def _runset(jobs, path, mode):
    return {(j["target"], j["source"]) for j in _pending(jobs, path, mode)}


def test_plan_jobs_expands_a_submission_into_repo_and_url_jobs():
    jobs = _plan_jobs([
        {"repo": "gh/a", "url": "https://a.app", "project": "p/a"},   # both -> two jobs
        {"repo": "gh/b", "project": "p/b"},                           # repo only -> one
        {"url": "https://c.app", "project": "p/c"},                   # url only -> one
    ])
    assert [(j["target"], j["source"]) for j in jobs] == [
        ("gh/a", "repo"), ("https://a.app", "url"), ("gh/b", "repo"), ("https://c.app", "url")]


def test_pending_default_retries_failed_and_catches_missing_url(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in [
        {"repo": "gh/a", "source": "repo", "project": "p/a", "deployed": True, "slop_score": 40},  # graded
        {"repo": "gh/b", "source": "repo", "project": "p/b", "deployed": False},                   # failed
    ]))
    jobs = _plan_jobs([
        {"repo": "gh/a", "url": "https://a.app", "project": "p/a"},   # repo graded, url missing -> url runs
        {"repo": "gh/b", "url": "https://b.app", "project": "p/b"},   # repo failed -> retry; url -> run
        {"repo": "gh/c", "project": "p/c"},                          # brand new -> run
    ])
    assert _runset(jobs, str(f), "default") == {
        ("https://a.app", "url"),                        # caught the missing url on an already-graded repo
        ("gh/b", "repo"), ("https://b.app", "url"),      # retried the failed repo + its url
        ("gh/c", "repo")}                                 # new
    # gh/a repo already graded -> not repeated


def test_pending_no_repeat_repo_skips_failed_repo_but_still_catches_url(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text(json.dumps({"repo": "gh/b", "source": "repo", "project": "p/b", "deployed": False}))
    jobs = _plan_jobs([{"repo": "gh/b", "url": "https://b.app", "project": "p/b"}])
    assert _runset(jobs, str(f), "no_repeat_repo") == {("https://b.app", "url")}   # repo locked, url runs


def test_pending_whatsoever_skips_any_touched_project(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text(json.dumps({"repo": "gh/b", "source": "repo", "project": "p/b", "deployed": False}))
    jobs = _plan_jobs([
        {"repo": "gh/b", "url": "https://b.app", "project": "p/b"},   # project touched -> BOTH jobs skipped
        {"repo": "gh/c", "project": "p/c"},                          # untouched -> runs
    ])
    assert _runset(jobs, str(f), "whatsoever") == {("gh/c", "repo")}


def test_pending_all_when_file_absent(tmp_path):
    jobs = _plan_jobs([{"repo": "gh/a", "project": "p"}])
    assert len(_pending(jobs, str(tmp_path / "nope.jsonl"), "default")) == 1


def test_load_urls_parses_url_project_winner_and_skips_comments(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text("# live apps with no gradeable repo\n"
                 "https://cool.vercel.app\n"
                 "\n"
                 "https://api.example.railway.app , My API , winner\n")
    recs = _load_urls(str(f), hackathon="hackharvard")
    assert [r["url"] for r in recs] == ["https://cool.vercel.app", "https://api.example.railway.app"]
    assert "repo" not in recs[0]                                                     # url-only record
    assert recs[0]["project"] == "cool.vercel.app" and recs[0]["winner"] is False    # host fallback
    assert recs[1]["project"] == "My API" and recs[1]["winner"] is True              # explicit project+winner
    assert all(r["hackathon"] == "hackharvard" for r in recs)

# a child that IGNORES SIGTERM (so only SIGKILL ends it) + spawns a 'chrome-like' descendant + CPU-spins
_SPIN = (
    "import signal, os, subprocess\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "gc = subprocess.Popen(['sleep', '300'])\n"
    "open(os.environ['MARK'], 'w').write(str(gc.pid))\n"
    "while True: pass\n"
)


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_hard_kill_reaps_the_whole_process_group(tmp_path):
    mark = tmp_path / "gc.pid"
    proc = subprocess.Popen([sys.executable, "-c", _SPIN], start_new_session=True,
                            env={**os.environ, "MARK": str(mark)})
    gc_pid = None
    try:
        for _ in range(50):                       # wait for the child to record its descendant's pid
            if mark.exists() and mark.read_text().strip():
                break
            time.sleep(0.1)
        gc_pid = int(mark.read_text().strip())
        try:
            proc.wait(timeout=1)
            raise AssertionError("the spinner should not have exited on its own")
        except subprocess.TimeoutExpired:
            pass
        _hard_kill(proc)                          # the fix: SIGKILL the group
        assert proc.poll() is not None            # SIGTERM-ignoring spinner is dead (so it was SIGKILL)
        deadline = time.monotonic() + 3
        while _alive(gc_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(gc_pid), "descendant must be reaped via the process group (chrome-leak guard)"
    finally:
        if gc_pid and _alive(gc_pid):
            os.kill(gc_pid, 9)


def test_record_wedge_writes_a_findable_row(tmp_path):
    f = tmp_path / "r.jsonl"
    _record_wedge(str(f), {"hackathon": "h", "project": "p", "winner": False}, 900,
                  target="gh/x", source="repo")
    r = json.loads(f.read_text())
    assert r["repo"] == "gh/x" and r["source"] == "repo"
    assert r["deployed"] is False and "WEDGED" in r["deploy_error"]


def test_record_wedge_recovers_checkpointed_stack_id(tmp_path):
    # a wedged app keeps the classification the child checkpointed before it was killed -> deploy-parity
    f = tmp_path / "r.jsonl"
    extra = {"app_kind": "web-app", "stack_profile": {"routing": "spa-path"}, "features": [{"name": "x"}]}
    _record_wedge(str(f), {"hackathon": "h", "project": "p", "winner": False}, 900,
                  target="gh/w", source="repo", extra=extra)
    r = json.loads(f.read_text())
    assert r["app_kind"] == "web-app" and r["stack_profile"]["routing"] == "spa-path"
    assert r["timeout"] == "wedge" and r["deployed"] is False   # base fields not clobbered by extra
