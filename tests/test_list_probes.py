"""list_probes.py must reflect the post-repricing severity model: a probe's real penalty is a severity RANGE
(floor + evidence escalators), not the nominal `penalty:` floor. This drifted silently once (no test guarded
it), so pin the penalty model + the worst-case using range-highs."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import list_probes  # noqa: E402

from sloptic.catalog import default_catalog_dir, load_catalog  # noqa: E402

_BY_ID = {p.id: p for p in load_catalog(default_catalog_dir())}


def test_pen_model_shows_a_severity_range_and_its_escalator_ladder():
    lo, hi, disp, note = list_probes._pen_model(_BY_ID["qa-reset-001"])
    assert (lo, hi, disp) == (24, 60, "24-60")            # the range, not just the floor
    assert "no_reset_email_60s->60" in note               # the escalator ladder is surfaced


def test_pen_model_off_score_and_computed_and_flat():
    assert list_probes._pen_model(_BY_ID["perf-cache-001"])[:3] == (0, 0, "0")   # report_only -> off-score
    assert list_probes._pen_model(_BY_ID["qa-a11y-001"])[2] == "*"               # computed at grade time
    # a fixed single-value severity renders as one number, not a range
    _lo, _hi, disp, _n = list_probes._pen_model(_BY_ID["sec-exposure-001"])
    assert disp == "90" and _lo == _hi == 90


def test_worst_case_uses_range_high_not_the_floor():
    # a maximally-bad app hits the top escalator, so a repriced probe's ceiling must count. qa-reset alone: its
    # range-high 60 must drive the worst case, never the floor 24.
    only_reset = [_BY_ID["qa-reset-001"]]
    assert list_probes._worst_case(only_reset) == 60


def test_rows_carry_min_max_for_export():
    row = next(r for r in list_probes._rows(load_catalog(default_catalog_dir())) if r["id"] == "qa-input-002")
    assert row["penalty_min"] == 32 and row["penalty_max"] == 72 and row["penalty_display"] == "32-72"
