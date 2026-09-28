"""A challenge that cuts the battery BELOW the keepable fraction (pipeline._MIN_VALID_FRACTION) no longer
withholds the grade: the pre-onset outcomes stand as a LIMITED grade (challenge_stage="limited", a real
partial score), because the old withhold reported a grade cut short as if nothing had run. What must NOT
change is comparability: a limited battery is excluded from the reference distribution (eligibility, shared
with stats) and refused by rank(), exactly like an entry withhold. These tests pin both halves."""
import importlib.util
import pathlib
import sys

import pytest

from sloptic.eligibility import is_limited_battery, is_ungradeable_challenge

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "benchmark", _HERE.parent / "scripts" / "benchmark.py")
benchmark = importlib.util.module_from_spec(_SPEC)
sys.modules["benchmark"] = benchmark
_SPEC.loader.exec_module(benchmark)


def test_limited_stage_predicate():
    assert is_limited_battery({"challenge_stage": "limited"}) is True
    assert is_limited_battery({"challenge_stage": "late"}) is False
    assert is_limited_battery({"challenge_stage": "entry"}) is False
    assert is_limited_battery({"challenge_stage": ""}) is False
    assert is_limited_battery({}) is False


def test_limited_records_are_distinct_from_entry_withholds():
    # an entry withhold is ungradeable (nothing ran); a limited grade ran and scored partially. Both are
    # kept out of the curve, but they must never be the same predicate result or the reports conflate
    # "nothing was measured" with "part of the battery was measured".
    rec = {"challenge_stage": "limited", "bot_challenge": True}
    assert is_limited_battery(rec) and not is_ungradeable_challenge(rec)


def _curve():
    # a minimal FULL-tagged distribution: rank() needs dist + overall.n + the status/population strings.
    return {"version": "test", "status": "final", "probe_set": "full", "population": "test apps",
            "overall": {"n": 2}, "axes": {}, "dist": [[8, 0, 8, 20, 3], [30, 0, 30, 40, 5]]}


def _record(stage):
    return {"slop_score": 10, "challenge_stage": stage, "bot_challenge": stage != "",
            "coverage": {"probes_total": 102, "applied": ["sec-headers-001", "sec-tls-001"],
                         "ran_kinds": ["security-headers", "transport-security"]},
            "findings": [{"probe_id": "sec-headers-001", "bundle": "security",
                          "category": "security-headers", "penalty": 10.0}]}


def test_rank_refuses_a_limited_battery():
    with pytest.raises(ValueError, match="challenge-cut"):
        benchmark.rank(_curve(), 10, _record("limited"))


def test_rank_refuses_an_entry_withhold():
    # the worker ranks every finished grade, so an entry withhold (slop 0, nothing ran) reaching rank()
    # must be refused too, not placed as a flawless 0.
    with pytest.raises(ValueError, match="challenge-cut"):
        benchmark.rank(_curve(), 0, _record("entry"))


def test_rank_still_places_a_late_challenge_grade():
    # a challenge that fired after the probes ran is a valid completed grade: it keeps its percentile.
    out = benchmark.rank(_curve(), 10, _record("late"))
    assert out["percentile"] is not None
    assert out["cleaner_than_pct"] is not None


def test_eligibility_excludes_limited_from_the_reference_distribution():
    # _eligible is what builds the frozen curve; a partial battery must never become a reference point.
    rec = _record("limited")
    rec.update(deployed=True, project="some-app")
    assert not benchmark._eligible(rec)
    rec["challenge_stage"] = "late"
    assert benchmark._eligible(rec)
