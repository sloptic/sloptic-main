"""format_spec §4.2's Result Reporting bundle, plus the credential gate built on it.

The spec required this and nothing implemented it: grepping the runner for limited_engagement / clean_rate /
attack_surface returned nothing. Its stated reason — "A slop score in isolation can be ambiguous: a low score
could mean a clean submission with broad surface (excellent) or a trivial one with almost no surface to test
(Limited Engagement)" — and its consequence: a DNF or Limited Engagement submission "is ranked below every
completed submission regardless of its trivially-low raw slop."

Thresholds are corpus-derived and RE-DERIVED per calibration run. On v10 (n=865): Limited Engagement below 40
applicable probes fires on 0.8%, the genuinely trivial tail; the Attack Surface tertiles are 48/58, splitting the
population 31.0 / 42.5 / 26.5. The v9-era 46/55 awarded BROAD to 47.7% of v10 — the boundary test below now pins
the exact cut points, because the loose 45/50/60 sample it used before passed under both sets of thresholds and
would have let a recalibration change grader output with the suite still green.

`untested_families` is OURS and keeps its own name deliberately. Limited Engagement is a spec term defined by an
applicable-COUNT threshold, and quietly redefining it to also mean "a family never ran" is exactly the drift this
separation prevents. Measured on v9: 39% of the CLEANEST QUARTILE has a login or signup and yet no session or
access-control probe ever ran on it — 109 of 282 top-quartile apps that a score-only credential would have
badged. Every bug found this week was a false NEGATIVE, so the risk guarded here is not a wrong penalty; it is a
badge that means nothing.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from benchmark import build, rank, reporting_bundle  # noqa: E402

_KINDS_FULL = {"session": {"ran": 4, "na": 0}, "access-control": {"ran": 6, "na": 1},
               "file-upload": {"ran": 2, "na": 0}, "input-validation": {"ran": 1, "na": 0},
               "xss": {"ran": 2, "na": 0}}


def _rec(surface=None, by_kind=None, applicable=53, findings=None, slop=20, **kw):
    """applicable defaults to the corpus median (53) so a fixture is Completed unless it says otherwise."""
    return {"deployed": True, "slop_score": slop, "axis_slop": {"security": 10, "qa": 10},
            "findings": findings or [],
            "observed_surface": {"has_login": False, "has_signup": False, "has_upload": False,
                                 "accepts_text_input": False, "forms": 0, **(surface or {})},
            "coverage": {"probes_applicable": applicable, "pct_applicable": round(100 * applicable / 87),
                         "applied": ["sec-csp-001", "qa-a11y-001"],
                         "by_kind": dict(_KINDS_FULL, **(by_kind or {}))}, **kw}


def _curve():
    return build([dict(_rec(slop=i), project=f"p{i}") for i in range(1, 101)], "2026.1", "test.jsonl")


# ---------------------------------------------------------------- the spec's bundle

def test_the_bundle_reports_every_field_the_spec_names():
    b = reporting_bundle(_rec(findings=[{"probe_id": "sec-csp-001"}, {"probe_id": "qa-a11y-001"}]))
    assert b["status"] == "completed"
    assert b["probes_applicable"] == 53 and b["slop_detected"] == 2
    assert b["attack_surface_coverage"] == "moderate"
    assert b["clean_rate"] == round(100 * 51 / 53, 1)


def test_clean_rate_is_over_applicable_probes_only():
    # a probe that was N/A is neither a pass nor a failure; counting it would inflate the rate
    b = reporting_bundle(_rec(applicable=50, findings=[{"probe_id": "x"}] * 1))
    assert b["clean_rate"] == 98.0


def test_repeated_findings_from_one_probe_count_once_as_slop_detected():
    # "Slop Detected: count of probes that fired" — a header missing on 9 routes is one probe
    b = reporting_bundle(_rec(findings=[{"probe_id": "sec-headers-001"}] * 9))
    assert b["slop_detected"] == 1


def test_attack_surface_coverage_uses_the_corpus_tertiles():
    """Pins the v10 cut points EXACTLY (48/58), on both sides of each boundary. A sample of 45/50/60 satisfies
    46/55 and 48/58 alike, so it would have gone green through a recalibration that moved a third of the corpus
    between bands."""
    for applicable, band in ((21, "narrow"), (47, "narrow"), (48, "moderate"), (58, "moderate"),
                             (59, "broad"), (69, "broad")):
        assert reporting_bundle(_rec(applicable=applicable))["attack_surface_coverage"] == band, applicable


def test_a_trivial_surface_is_limited_engagement():
    b = reporting_bundle(_rec(applicable=12))
    assert b["status"] == "limited_engagement"
    assert "only 12 probes applicable" in " ".join(b["why"])


def test_a_normal_app_is_never_limited_engagement():
    # the threshold sits below the corpus p5 (42) on purpose: 2.0% of apps, not 16%
    assert reporting_bundle(_rec(applicable=42))["status"] == "completed"


def test_a_non_deploying_submission_is_dnf_not_a_clean_zero():
    for kw in ({"dead_url": True}, {"functional": False}):
        b = reporting_bundle(_rec(slop=0, **kw))
        assert b["status"] == "dnf" and b["clean_rate"] is None


def test_a_record_with_no_coverage_telemetry_is_unknown_not_fine():
    b = reporting_bundle({"slop_score": 10})
    assert b["status"] == "unknown" and b["probes_applicable"] is None
    assert "cannot be verified" in " ".join(b["why"])


# ---------------------------------------------------------------- untested families (ours)

def test_an_app_with_a_login_whose_session_probes_never_ran():
    b = reporting_bundle(_rec({"has_login": True}, {"session": {"ran": 0, "na": 4}}))
    assert "session" in b["untested_families"]
    assert "no session probe ran" in " ".join(b["why"])
    assert b["status"] == "completed"          # NOT redefined as Limited Engagement — that is a spec term


def test_the_same_app_with_session_probes_running_has_none():
    assert reporting_bundle(_rec({"has_login": True}))["untested_families"] == []


def test_access_control_is_gated_by_the_same_auth_surface():
    b = reporting_bundle(_rec({"has_signup": True}, {"access-control": {"ran": 0, "na": 6}}))
    assert "access-control" in b["untested_families"]


def test_an_upload_surface_that_was_never_probed():
    b = reporting_bundle(_rec({"has_upload": True}, {"file-upload": {"ran": 0, "na": 2}}))
    assert "file-upload" in b["untested_families"]


def test_text_input_needs_either_input_validation_or_xss():
    b = reporting_bundle(_rec({"accepts_text_input": True},
                              {"input-validation": {"ran": 0, "na": 1}, "xss": {"ran": 0, "na": 2}}))
    assert "input-validation" in b["untested_families"]
    # EITHER family satisfies it: they overlap on the same reflected-input surface
    ok = reporting_bundle(_rec({"accepts_text_input": True}, {"input-validation": {"ran": 0, "na": 1}}))
    assert ok["untested_families"] == []


def test_a_form_count_counts_as_text_input():
    b = reporting_bundle(_rec({"forms": 2}, {"input-validation": {"ran": 0}, "xss": {"ran": 0}}))
    assert b["untested_families"] == ["input-validation"]


def test_a_static_site_with_no_auth_surface_has_nothing_untested():
    # THE fairness rule: gating simplicity would punish an app for not having a login to break
    b = reporting_bundle(_rec(by_kind={"session": {"ran": 0, "na": 4}, "access-control": {"ran": 0, "na": 6},
                                       "file-upload": {"ran": 0, "na": 2}}))
    assert b["untested_families"] == []


def test_data_integrity_is_deliberately_not_a_rule():
    """It would fire on 59.9% of the corpus because a black-box create+read pair genuinely does not exist on
    most apps. A rule that fires on everything says nothing."""
    b = reporting_bundle(_rec({"has_login": True}, {"data-integrity": {"ran": 0, "na": 2}}))
    assert b["untested_families"] == []


# ---------------------------------------------------------------- rank() integration

def test_the_band_stays_factual_while_the_credential_is_refused():
    # a genuinely clean-scoring app never assessed on auth: it really IS cleaner than its peers, and it still
    # may not be badged. Conflating the two is the whole bug.
    res = rank(_curve(), 2, _rec({"has_login": True}, {"session": {"ran": 0, "na": 4}}, slop=2))
    assert res["band"] == "pristine"
    assert res["certifiable"] is False
    assert "session" in res["reporting"]["untested_families"]


def test_a_completed_fully_exercised_grade_is_certifiable():
    res = rank(_curve(), 2, _rec({"has_login": True}, slop=2))
    assert res["certifiable"] is True and res["reporting"]["status"] == "completed"


def test_limited_engagement_can_never_be_a_credential():
    # format_spec §4.2: it ranks below every completed submission regardless of its trivially-low raw slop
    res = rank(_curve(), 1, _rec(applicable=9, slop=1))
    assert res["reporting"]["status"] == "limited_engagement"
    assert res["certifiable"] is False


def test_an_absolute_gate_refuses_the_credential_even_when_fully_exercised():
    leaky = _rec({"has_login": True}, slop=2,
                 findings=[{"probe_id": "sec-sqli-001", "category": "sql-injection", "penalty": 40}])
    res = rank(_curve(), 2, leaky)
    assert res["reporting"]["untested_families"] == []   # we DID test everything ...
    assert res["certifiable"] is False                  # ... and found something disqualifying
    assert "sql-injection" in res["absolute_gates"]


def test_a_rank_without_a_record_makes_no_certification_claim():
    res = rank(_curve(), 50)
    assert "certifiable" not in res and "reporting" not in res
