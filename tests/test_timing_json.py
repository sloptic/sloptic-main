"""stats.py --timing-json: what a grade COSTS, aggregated for a hosted grader's ETA.

Two things have to hold. The outcome classes must be read in the runner's own order, since a timeout and a
dead URL both also carry a deploy_error and a naive check would file them as generic errors and lose the
900 second tail. And the file is published, so it must carry no app identifier, the same rule the corpus
figures follow.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from stats import timing_json  # noqa: E402


def _rec(url, secs, grade_s=None, coverage=102, platform="vercel", ts=1000.0, **kw):
    r = {"repo": url, "url": url, "project": "some project", "ts": ts,
         "timings": {"clone_s": 0.0, "plan_s": 0.0, "deploy_s": 0.0,
                     "grade_s": grade_s if grade_s is not None else max(secs - 7, 0.0), "total_s": secs},
         "coverage": {"probes_total": coverage}, "platform": {"host_platform": platform, "host": url},
         "provenance": {"host": {"node": "ian-sloptic", "cores": 4, "cpu": "Test CPU"},
                        "versions": {"lighthouse": "13.4.1"},
                        "flags": {"concurrency": "4", "grade_timeout": 900, "browser": True}}}
    r.update(kw)
    return r


def _graded(url, secs, **kw):
    return _rec(url, secs, slop_score=42.0, findings=[], **kw)


def test_a_timeout_is_its_own_class_not_a_generic_error():
    """A timeout carries deploy_error too. Filed as an error it would vanish from the tail, and the ETA
    would stop knowing that some targets burn the entire budget."""
    recs = [_graded(f"https://a{i}.test", 100.0, ts=1000.0 + i) for i in range(5)]
    recs.append(_rec("https://slow.test", 915.5, grade_s=900.1, ts=1100.0,
                     timeout="grade", grade_timeout=True, deploy_error="GRADE TIMEOUT (>900s)"))
    out = timing_json(recs)
    assert out["outcomes"]["timeout"]["n"] == 1
    assert out["outcomes"]["timeout"]["seconds"]["median"] == 915.5
    assert "timeout" not in out["outcomes"].get("error", {}).get("probe_ids", [])
    assert out["outcomes"].get("error", {"n": 0})["n"] == 0 or "error" not in out["outcomes"]


def test_a_dead_url_is_its_own_class_and_costs_almost_nothing():
    recs = [_graded(f"https://a{i}.test", 100.0, ts=1000.0 + i) for i in range(3)]
    recs += [_rec(f"https://dead{i}.test", 0.2, grade_s=0.0, ts=1100.0 + i,
                  deployed=False, dead_url=True, deploy_error="URL DEAD") for i in range(4)]
    out = timing_json(recs)
    assert out["outcomes"]["dead_url"]["n"] == 4
    assert out["outcomes"]["dead_url"]["seconds"]["median"] == 0.2
    assert out["seconds"]["n"] == 3               # the headline covers scored grades only


def test_the_headline_seconds_describe_only_grades_that_scored():
    recs = [_graded("https://a.test", 100.0, ts=1.0), _graded("https://b.test", 200.0, ts=2.0),
            _rec("https://c.test", 900.0, ts=3.0, timeout="grade", grade_timeout=True)]
    out = timing_json(recs)
    assert out["seconds"]["n"] == 2 and out["seconds"]["median"] == 150.0
    assert out["n_records"] == 3                  # while the record count covers everything


def test_the_battery_labels_itself_from_coverage():
    assert timing_json([_graded("https://a.test", 90.0, coverage=44)])["battery"] == "passive"
    assert timing_json([_graded("https://a.test", 90.0, coverage=102)])["battery"] == "full"


def test_measurement_keeps_the_runs_own_types():
    """A consumer comparing concurrency to a number should not be handed the string "4"."""
    m = timing_json([_graded("https://a.test", 90.0)])["measurement"]
    assert m["concurrency"] == 4 and m["grade_timeout_s"] == 900
    assert m["browser"] is True and m["cores"] == 4


def test_contention_is_stated_rather_than_left_for_the_reader_to_infer():
    recs = [_graded(f"https://a{i}.test", 100.0, ts=1000.0 + i) for i in range(10)]
    out = timing_json(recs)
    assert out["measurement"]["effective_parallelism"] > 1     # 10 * 100s of work inside a 9s span
    assert "upper bound" in out["measurement"]["caveat"]


def test_a_platform_group_too_small_to_be_stable_is_not_quoted():
    recs = ([_graded(f"https://v{i}.test", 100.0, ts=float(i)) for i in range(25)]
            + [_graded(f"https://r{i}.test", 300.0, platform="render", ts=100.0 + i) for i in range(3)])
    out = timing_json(recs)
    assert "vercel" in out["by_platform"] and "render" not in out["by_platform"]


def test_it_publishes_no_app_identifier():
    """The file is public. Platform is a group key; a host, a URL or a project name is not."""
    recs = [_graded(f"https://secret-app-{i}.vercel.app", 100.0, ts=float(i)) for i in range(25)]
    recs[0]["project"] = "Some Team's Hackathon App"
    blob = json.dumps(timing_json(recs))
    assert "secret-app" not in blob and "vercel.app" not in blob
    assert "Hackathon App" not in blob
    assert "ian-sloptic" not in blob               # the grading box's hostname is an identifier too
    assert "vercel" in blob                        # the platform group key survives


def test_the_committed_file_carries_both_batteries():
    doc = json.loads((ROOT / "validation" / "grade-timing.json").read_text())
    assert set(doc["batteries"]) == {"full", "passive"}
    for battery, block in doc["batteries"].items():
        assert block["battery"] == battery
        assert block["seconds"]["n"] > 1000 and block["outcomes"]["timeout"]["n"] > 0
    # the passive lane is the cheaper one, which is the whole reason the hosted tier runs it
    assert doc["batteries"]["passive"]["seconds"]["median"] < doc["batteries"]["full"]["seconds"]["median"]


def test_the_timeout_rate_is_quoted_against_grades_that_actually_ran():
    """A hosted service filters dead URLs with its own liveness check before quoting a wait, so a rate
    diluted by 28% dead rows would understate the risk of the long tail."""
    recs = ([_graded(f"https://a{i}.test", 100.0, ts=float(i)) for i in range(8)]
            + [_rec("https://slow.test", 915.0, ts=50.0, timeout="grade", grade_timeout=True)]
            + [_rec(f"https://dead{i}.test", 0.2, ts=60.0 + i, dead_url=True) for i in range(91)])
    reach = timing_json(recs)["reach"]
    assert reach["records"] == 100 and reach["attempted"] == 9
    assert reach["timeout_pct_of_attempted"] == 11.1        # 1 of 9, not 1 of 100
