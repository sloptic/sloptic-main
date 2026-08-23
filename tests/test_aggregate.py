"""Aggregation dampers: a variant group fires once at its max, and repeated instances within a category decay."""
from sloptic.aggregate import compute_axis_slop, compute_slop_score, coverage_metrics
from sloptic.schema import Outcome


def _o(pid, category, penalty, outcome="slop_detected", group=None, bundle="security"):
    return Outcome(
        probe_id=pid, bundle=bundle, category=category,
        outcome=outcome, penalty=penalty, variant_group_id=group,
    )


def test_variant_group_fires_once():
    # two syntactic variants of one logical flaw -> one penalty, not two
    outs = [_o("sqli-1", "sql-injection", 40, group="g1"),
            _o("sqli-2", "sql-injection", 40, group="g1")]
    assert compute_slop_score(outs) == 40


def test_backend_schema_disclosure_subsumed_by_data_leak():
    # sec-backend-001 (data readable, 40) and sec-backend-003 (schema disclosed, 12) share a variant group:
    # both firing on the same anon-access misconfig scores once at the max (40), never 40+12
    both = [_o("sec-backend-001", "backend-exposure", 40, group="backend-anon-exposure"),
            _o("sec-backend-003", "backend-exposure", 12, group="backend-anon-exposure")]
    assert compute_slop_score(both) == 40
    # a schema disclosure ALONE (RLS still protects the data) keeps its standalone penalty
    alone = [_o("sec-backend-003", "backend-exposure", 12, group="backend-anon-exposure")]
    assert compute_slop_score(alone) == 12


def test_diminishing_returns_within_category():
    # 10 + 10*0.6 + 10*0.36 = 19.6 (1-decimal float scoring keeps the fractional part now)
    outs = [_o("a", "crash", 10), _o("b", "crash", 10), _o("c", "crash", 10)]
    assert compute_slop_score(outs) == 19.6


def test_distinct_categories_sum_in_full():
    outs = [_o("a", "cat1", 10), _o("b", "cat2", 10)]
    assert compute_slop_score(outs) == 20


def test_clean_and_na_contribute_zero():
    outs = [_o("a", "cat1", 10, outcome="clean"),
            _o("b", "cat2", 10, outcome="not_applicable")]
    assert compute_slop_score(outs) == 0


def test_highest_penalty_anchors_a_category():
    # within a category the worst counts full, the cheaper one decays: 40 + 8*0.6 = 44.8
    outs = [_o("a", "injection", 8), _o("b", "injection", 40)]
    assert compute_slop_score(outs) == 44.8


def test_axis_slop_decomposes_and_sums_to_total():
    # per-bundle damped subtotals in the same units; they sum to the total slop score (no reweighting)
    outs = [_o("s1", "sql-injection", 40, bundle="security"),
            _o("q1", "crash", 30, bundle="qa"), _o("q2", "crash", 30, bundle="qa"),  # 30 + 30*0.6 = 48
            _o("p1", "speed", 12, bundle="performance"),
            _o("c1", "cat", 10, outcome="clean", bundle="qa")]  # clean -> contributes nothing
    axis = compute_axis_slop(outs)
    assert axis == {"security": 40, "qa": 48, "performance": 12}
    assert sum(axis.values()) == compute_slop_score(outs)


def test_coverage_counts_applicable_vs_na_by_probe_and_kind():
    outs = [
        _o("headers-1", "security-headers", 3, outcome="slop_detected"),   # ran (fired)
        _o("headers-1", "security-headers", 3, outcome="clean"),           # same probe, fan-out -> still ran
        _o("xss-1", "xss", 30, outcome="clean"),                           # ran (clean = applicable)
        _o("sqli-1", "sql-injection", 40, outcome="not_applicable"),       # no input surface -> n/a
        _o("csrf-1", "csrf", 15, outcome="not_applicable"),                # n/a
    ]
    c = coverage_metrics(outs)
    assert c["probes_total"] == 4 and c["probes_applicable"] == 2 and c["probes_na"] == 2
    assert c["pct_applicable"] == 50                       # half the battery applied
    assert c["ran_kinds"] == ["security-headers", "xss"]   # kinds that ran (any probe applied)
    assert c["na_kinds"] == ["csrf", "sql-injection"]      # kinds entirely n/a — the calibration signal
    assert c["applied"] == ["headers-1", "xss-1"]          # exact probe_ids that ran (batch union -> never-applied)


def test_coverage_surfaces_na_reason_only_for_entirely_na_kinds():
    # telemetry: a probe that goes N/A on a precondition sets evidence["na_reason"]; coverage surfaces it
    # for kinds that were ENTIRELY N/A (the honest "we tried this, here's why it couldn't run"), but NOT
    # for a kind that partly ran (that kind is covered, not blind).
    outs = [
        Outcome(probe_id="idor-1", bundle="security", category="access-control", outcome="not_applicable",
                penalty=40, evidence={"na_reason": "couldn't establish two accounts"}),
        Outcome(probe_id="csrf-1", bundle="security", category="csrf", outcome="clean", penalty=15),
        Outcome(probe_id="csrf-2", bundle="security", category="csrf", outcome="not_applicable", penalty=15,
                evidence={"na_reason": "no form"}),
    ]
    c = coverage_metrics(outs)
    assert c["na_reasons"] == {"access-control": "couldn't establish two accounts"}
    assert "csrf" not in c["na_reasons"]      # partially-covered kind isn't reported as blind


def test_coverage_empty_outcomes():
    c = coverage_metrics([])
    assert c["probes_total"] == 0 and c["pct_applicable"] == 0 and c["na_kinds"] == []
    assert c["na_reasons"] == {}


# --- corroboration escalation: a tax finding escalates when a vuln it would have contained also fires ---------

def test_csp_escalates_when_xss_fires():
    # a toothless CSP (5) is cheap alone; with a real XSS (35) it escalates to 24 -> total 35 + 24 = 59
    tax_only = [_o("sec-csp-001", "security-headers", 5)]
    assert compute_slop_score(tax_only) == 5
    with_xss = [_o("sec-csp-001", "security-headers", 5), _o("sec-xss-001", "xss", 35)]
    assert compute_slop_score(with_xss) == 35 + 24


def test_session_flags_escalate_on_xss_and_decay_together():
    # no-HttpOnly (15) + JWT-in-localStorage (15) both escalate to 28 under XSS; same 'session' category so the
    # second decays: 28 + 28*0.6 = 44.8; plus the XSS (35) -> 79.8 (1-decimal float scoring)
    outs = [_o("sec-session-001", "session", 15), _o("sec-session-005", "session", 15),
            _o("sec-xss-001", "xss", 35)]
    assert compute_slop_score(outs) == round(35 + 28 + 28 * 0.6, 1)


def test_no_escalation_without_the_corroborating_vuln():
    # missing HttpOnly with NO xss stays at its base 15 (the risk is still only theoretical)
    assert compute_slop_score([_o("sec-session-001", "session", 15)]) == 15


def test_domxss_also_corroborates_csp():
    with_dom = [_o("sec-csp-001", "security-headers", 5), _o("sec-domxss-001", "dom-xss", 30)]
    assert compute_slop_score(with_dom) == 30 + 24


def test_escalation_reflected_in_axis_decomposition_and_still_sums():
    outs = [_o("sec-csp-001", "security-headers", 5), _o("sec-xss-001", "xss", 35),
            _o("perf-x", "loadtime", 20, bundle="performance")]
    axis = compute_axis_slop(outs)
    assert axis["security"] == 35 + 24 and axis["performance"] == 20
    assert sum(axis.values()) == compute_slop_score(outs)   # decomposition still sums to the total
