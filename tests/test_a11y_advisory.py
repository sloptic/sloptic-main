"""v2.0 Family 2: the WCAG 2.2 / best-practice axe candidates ride along as OFF-SCORE advisory evidence. They
must NOT change the a11y fire, penalty, or scored impacts -- they exist only so the 2026.3 re-grade can measure
each rule's decorrelation from the existing a11y carrier before any of it is promoted to the score."""
import sloptic.probes as probes
from sloptic.probes import _a11y_scored


def _ctx():
    return type("C", (), {"base_url": "http://x", "headers": None, "evidence": {},
                          "profile": type("P", (), {"landing_path": "/"})()})()


def _run(viols):
    orig = probes.browser.a11y_violations
    probes.browser.a11y_violations = lambda url, headers=None, **kw: viols
    try:
        ctx = _ctx()
        fired = probes.a11y_violations_present(ctx, type("Pr", (), {"probe": {"target": "/"}})())
        return fired, ctx.evidence
    finally:
        probes.browser.a11y_violations = orig


def test_partition_scores_only_wcag2_a_aa_tags():
    assert _a11y_scored({"id": "label", "impact": "critical", "tags": ["wcag2a", "cat.forms"]}) is True
    assert _a11y_scored({"id": "color-contrast", "impact": "serious", "tags": ["wcag2aa"]}) is True
    assert _a11y_scored({"id": "target-size", "impact": "serious", "tags": ["wcag22aa"]}) is False
    assert _a11y_scored({"id": "region", "impact": "moderate", "tags": ["best-practice"]}) is False
    assert _a11y_scored({"id": "x", "impact": "minor"}) is True   # missing tags -> preserve the pre-expansion set


def test_advisory_violations_do_not_change_fire_penalty_or_impacts():
    scored = [{"id": "label", "impact": "critical", "tags": ["wcag2a"]}]
    with_adv = scored + [{"id": "target-size", "impact": "serious", "tags": ["wcag22aa"]},
                         {"id": "region", "impact": "moderate", "tags": ["best-practice"]}]
    f1, e1 = _run(scored)
    f2, e2 = _run(with_adv)
    assert f1 is True and f2 is True                              # scored violation fires either way
    assert e1["penalty_override"] == e2["penalty_override"]       # advisory adds nothing to the price
    assert e1["impacts"] == e2["impacts"] == {"critical": 1}
    assert e1.get("violations") == e2.get("violations") == 1      # `violations` counts the SCORED set only
    assert "advisory_a11y" not in e1                              # no advisory -> field absent
    assert e2["advisory_a11y"]["rules"] == ["region", "target-size"]
    assert e2["advisory_a11y"]["impacts"] == {"serious": 1, "moderate": 1}


def test_a_page_failing_only_advisory_candidates_is_clean_on_score():
    f, e = _run([{"id": "target-size", "impact": "serious", "tags": ["wcag22aa"]}])
    assert f is False                                            # no scored violation -> not a fire
    assert e["penalty_override"] == 0 and e["impacts"] == {}
    assert e["advisory_a11y"]["rules"] == ["target-size"]        # but the candidate is still captured off-score
