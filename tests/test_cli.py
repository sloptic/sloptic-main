"""CLI output renderers — pure text builders, no server/Docker, so they run on the dev box."""
from hacklet_runner.aggregate import compute_axis_slop, compute_slop_score, coverage_metrics
from hacklet_runner.cli import (
    _coverage_text,
    _failed_text,
    _fmt_evidence,
    _report_payload,
    _score_breakdown_text,
    _summary_text,
)
from hacklet_runner.schema import Outcome, Report


def _report() -> Report:
    # xss 30 + security-headers 3 = 33 (distinct categories, single-member -> no decay); consistent so
    # the breakdown's "total" matches slop_score.
    return Report(slop_score=33, axis_slop={"security": 33}, outcomes=[
        Outcome("sec-xss-001", "security", "xss", "slop_detected", 30, target="/search"),
        Outcome("sec-xss-001", "security", "xss", "clean", 0, target="/login"),
        Outcome("sec-headers-001", "security", "security-headers", "slop_detected", 3, target="/"),
        Outcome("perf-ttfb-001", "performance", "speed", "not_applicable", 0, target="/heavy"),
    ])


def test_score_breakdown_shows_dampers_and_sums_to_total():
    outs = [
        Outcome("sqli-a", "security", "sql-injection", "slop_detected", 40, variant_group_id="sqli"),
        Outcome("sqli-b", "security", "sql-injection", "slop_detected", 40, variant_group_id="sqli"),  # once
        Outcome("crash-a", "qa", "crash", "slop_detected", 30),
        Outcome("crash-b", "qa", "crash", "slop_detected", 30),   # 30 + 30*0.6 = 48 (within-category decay)
    ]
    r = Report(slop_score=compute_slop_score(outs), outcomes=outs, axis_slop=compute_axis_slop(outs))
    t = _score_breakdown_text(r)
    assert "sqli ×2→40 once" in t        # variant-group collapse is shown
    assert "30 + 18" in t                # within-category decay is shown (30 + 30×0.6)
    assert f"total  {r.slop_score}" in t and r.slop_score == 88  # 40 + 48


def test_score_breakdown_empty_when_clean():
    r = Report(slop_score=0, outcomes=[Outcome("x", "security", "xss", "clean", 0)], axis_slop={})
    assert _score_breakdown_text(r) == ""


def test_summary_shows_score_and_tally_and_breakdown():
    t = _summary_text(_report(), "references/vulnerable/app.py")
    assert "Slop score: 33" in t
    assert "2 slop · 1 clean · 1 n/a" in t
    # the summary now embeds the point-based score breakdown (not misleading fire-COUNTS)
    assert "how the score is built" in t
    assert "xss" in t and "security-headers" in t
    assert "total  33" in t   # the breakdown sums back to the score


def test_summary_clean_app():
    r = Report(slop_score=0, outcomes=[Outcome("x", "security", "xss", "clean", 0, target="/")])
    t = _summary_text(r, "hardened")
    assert "Slop score: 0" in t
    assert "no slop detected" in t


def test_failed_lists_only_slop():
    t = _failed_text(_report(), "vuln")
    assert "sec-xss-001" in t and "/search" in t
    assert "sec-headers-001" in t
    assert "/login" not in t       # the clean xss outcome is excluded
    assert "perf-ttfb-001" not in t  # the n/a outcome is excluded


def test_report_payload_shape():
    p = _report_payload(_report())
    assert p["slop_score"] == 33
    assert "surface" in p                      # observed-surface fingerprint rides in --json
    assert "coverage" in p                      # test-coverage fingerprint rides in --json too
    assert len(p["outcomes"]) == 4
    assert p["outcomes"][0]["probe_id"] == "sec-xss-001"
    assert p["outcomes"][0]["target"] == "/search"


def test_coverage_text_shows_pct_and_na_kinds():
    outs = [Outcome("h", "security", "security-headers", "slop_detected", 3),
            Outcome("s", "security", "sql-injection", "not_applicable", 0)]
    t = _coverage_text(Report(slop_score=3, outcomes=outs, coverage=coverage_metrics(outs)))
    assert "1/2 tests applicable (50%)" in t
    assert "sql-injection" in t                 # the n/a kind is named — the calibration signal


def test_coverage_text_empty_without_coverage():
    assert _coverage_text(Report(slop_score=0)) == ""   # old/coverage-less reports render nothing


def test_report_payload_carries_evidence():
    # evidence rides on every outcome (clean/n/a too) so a display can show what was measured
    r = Report(slop_score=0, outcomes=[Outcome(
        "perf-loadtime-001", "performance", "speed", "clean", 0, target="/",
        evidence={"load_time_s": 0.35, "ceiling_s": 5.0})])
    ev = _report_payload(r)["outcomes"][0]["evidence"]
    assert ev == {"load_time_s": 0.35, "ceiling_s": 5.0}


def test_fmt_evidence():
    assert _fmt_evidence({"ttfb_s": 0.03, "threshold_s": 0.8}) == "ttfb_s=0.03  threshold_s=0.8"
    assert _fmt_evidence({}) == ""
