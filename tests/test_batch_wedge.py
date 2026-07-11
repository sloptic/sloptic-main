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
from run_batch import _done_repos, _hard_kill, _load_urls, _record_wedge  # noqa: E402


def test_done_repos_skips_graded_and_skipped_but_not_failed(tmp_path):
    # resume semantics: successfully graded + skipped-as-non-web = done; deploy-failed / wedged = retry
    f = tmp_path / "r.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in [
        {"repo": "gh/graded", "deployed": True, "slop_score": 40},
        {"repo": "gh/skipped", "skipped": True, "app_kind": "mobile"},
        {"repo": "gh/build-failed", "deployed": False, "deploy_error": "BUILD FAILED:"},
        {"repo": "gh/wedged", "deployed": False, "timeout": "wedge"},
        {"repo": "gh/grade-timeout", "deployed": True, "grade_timeout": True},   # deployed but no score -> retry
    ]))
    assert _done_repos(str(f)) == {"gh/graded", "gh/skipped"}


def test_done_repos_no_repeat_also_skips_failed(tmp_path):
    # --no-repeat (include_failed): ANY prior record counts as done, so failed deploys aren't retried either
    f = tmp_path / "r.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in [
        {"repo": "gh/graded", "deployed": True, "slop_score": 40},
        {"repo": "gh/build-failed", "deployed": False, "deploy_error": "BUILD FAILED:"},
        {"repo": "gh/wedged", "deployed": False, "timeout": "wedge"},
        {"nope": "no repo key -> ignored"},
    ]))
    assert _done_repos(str(f), include_failed=True) == {"gh/graded", "gh/build-failed", "gh/wedged"}


def test_done_repos_empty_when_file_absent(tmp_path):
    assert _done_repos(str(tmp_path / "nope.jsonl")) == set()


def test_load_urls_parses_url_project_winner_and_skips_comments(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text("# live apps with no gradeable repo\n"
                 "https://cool.vercel.app\n"
                 "\n"
                 "https://api.example.railway.app , My API , winner\n")
    recs = _load_urls(str(f), hackathon="hackharvard")
    assert [r["repo"] for r in recs] == ["https://cool.vercel.app", "https://api.example.railway.app"]
    assert recs[0]["project"] == "cool.vercel.app" and recs[0]["winner"] is False   # host fallback
    assert recs[1]["project"] == "My API" and recs[1]["winner"] is True             # explicit project + winner
    assert all(r["url_ingest"] and r["hackathon"] == "hackharvard" for r in recs)

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
    _record_wedge(str(f), {"repo": "gh/x", "hackathon": "h", "project": "p", "winner": False}, 900)
    r = json.loads(f.read_text())
    assert r["repo"] == "gh/x" and r["deployed"] is False and "WEDGED" in r["deploy_error"]


def test_record_wedge_recovers_checkpointed_stack_id(tmp_path):
    # a wedged app keeps the classification the child checkpointed before it was killed -> deploy-parity
    f = tmp_path / "r.jsonl"
    extra = {"app_kind": "web-app", "stack_profile": {"routing": "spa-path"}, "features": [{"name": "x"}]}
    _record_wedge(str(f), {"repo": "gh/w", "hackathon": "h", "project": "p", "winner": False}, 900, extra=extra)
    r = json.loads(f.read_text())
    assert r["app_kind"] == "web-app" and r["stack_profile"]["routing"] == "spa-path"
    assert r["timeout"] == "wedge" and r["deployed"] is False   # base fields not clobbered by extra
