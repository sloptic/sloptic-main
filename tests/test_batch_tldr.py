"""run_batch --tldr: the compact per-app line + its inputs (label, record lookup, progress/ETA). Pure — no
subprocess, no network; canned records fed through the formatter."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from run_batch import _eta_footer, _Progress, _label, _last_record_for, _tldr_line  # noqa: E402


def test_label_prefers_devpost_slug_then_repo_then_host():
    assert _label({"rec": {"project": "https://devpost.com/software/cool-thing"},
                   "target": "x", "source": "repo"}) == "cool-thing"
    assert _label({"rec": {}, "target": "https://github.com/alice/proj", "source": "repo"}) == "alice/proj"
    assert _label({"rec": {}, "target": "https://foo.vercel.app/x", "source": "url"}) == "foo.vercel.app"


def test_tldr_line_shows_slop_and_missed_kinds_and_eta():
    rec = {"slop_score": 340, "coverage_audit": {"page_state": "working",
           "missed": [{"kind": "login", "label": "Sign in"}, {"kind": "upload", "label": "Upload"}]}}
    line = _tldr_line(3, 60, "cool-thing", rec, 47.0, 323.0, tail="")
    assert "[3/60]" in line and "slop 340" in line
    assert "missed: login, upload" in line and "ETA 5:23" in line


def test_tldr_line_marks_dnf_for_a_broken_shell_and_hides_slop():
    # a broken 404-shell keeps its slop_score for reference but functional=False -> ranks DNF, not rescued
    rec = {"slop_score": 12, "functional": False, "coverage_audit": {"page_state": "broken", "missed": []}}
    line = _tldr_line(1, 10, "brokenapp", rec, 8.0, 72.0, tail="")
    assert "DNF (broken)" in line and "slop 12" not in line


def test_tldr_line_marks_a_wedge_or_error_from_tail():
    line = _tldr_line(5, 20, "hunger", None, 900.0, 100.0,
                      tail="!! WEDGED — killed after 900s; recorded, moving on")
    assert "✗" in line and "WEDGED" in line


def test_last_record_for_returns_latest_matching_target(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text("\n".join(json.dumps(x) for x in [
        {"repo": "T", "slop_score": 1}, {"repo": "OTHER", "slop_score": 9},
        {"repo": "T", "slop_score": 2}]) + "\n")
    assert _last_record_for(str(f), "T")["slop_score"] == 2      # latest wins (matches stats' dedup)
    assert _last_record_for(str(f), "MISSING") is None


def test_progress_eta_is_nonnegative_and_counts():
    p = _Progress(10)
    d1, _ = p.tick()
    d2, eta2 = p.tick()
    assert d1 == 1 and d2 == 2 and eta2 >= 0


def test_eta_footer_shows_batch_progress_and_eta_for_the_full_dump():
    # non-tldr full-dump footer: batch [done/total], this-app seconds, and the same throughput ETA as --tldr
    assert _eta_footer(180, 398, 294, 5999) == "    └─ batch [180/398] · 294s this app · ETA 99:59"
    assert "ETA" not in _eta_footer(1, 398, 2, 0)      # first app: no throughput yet -> no ETA shown
