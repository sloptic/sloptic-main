"""The generic Lighthouse-backed perf predicate: tier on Lighthouse's own score bands (green/orange/red ->
pass / half / full via penalty_override), or on a numericValue threshold; the WORST of several audits drives
the tier; N/A when the pipeline captured no report. This replaces ~12 hand-rolled perf predicates."""
from sloptic.probes import lighthouse_audit


class _Probe:
    def __init__(self, penalty, **cfg):
        self.penalty, self.probe = penalty, cfg


class _Ctx:
    def __init__(self, report):
        self.lighthouse, self.evidence = report, {}


def _rep(audits, runs=3):
    return {"lighthouseResult": {"audits": audits}, "runs": runs}


def test_score_green_is_clean():
    ctx = _Ctx(_rep({"font-display-insight": {"score": 1.0}}))
    assert lighthouse_audit(ctx, _Probe(6, audit="font-display-insight", mode="score")) is False


def test_score_orange_fires_half():
    ctx = _Ctx(_rep({"cache-insight": {"score": 0.7, "displayValue": "Est savings of 2 KiB"}}))
    assert lighthouse_audit(ctx, _Probe(16, audit="cache-insight", mode="score")) is True
    assert ctx.evidence["tier"] == "needs-improvement" and ctx.evidence["penalty_override"] == 8


def test_score_red_fires_full():
    ctx = _Ctx(_rep({"largest-contentful-paint": {"score": 0.03}}))
    assert lighthouse_audit(ctx, _Probe(28, audits=["largest-contentful-paint"], mode="score")) is True
    assert ctx.evidence["tier"] == "fail" and ctx.evidence["penalty_override"] == 28


def test_score_worst_of_several_drives_it():
    ctx = _Ctx(_rep({"largest-contentful-paint": {"score": 0.9}, "total-blocking-time": {"score": 1.0},
                     "cumulative-layout-shift": {"score": 0.3}}))
    p = _Probe(28, audits=["largest-contentful-paint", "total-blocking-time", "cumulative-layout-shift"])
    assert lighthouse_audit(ctx, p) is True
    assert ctx.evidence["audit"] == "cumulative-layout-shift" and ctx.evidence["tier"] == "fail"


def test_numeric_tiers_on_thresholds():
    for nodes, tier, pen in [(900, None, None), (1600, "needs-improvement", 4), (3000, "fail", 7)]:
        ctx = _Ctx(_rep({"dom-size-insight": {"numericValue": nodes}}))
        p = _Probe(7, audit="dom-size-insight", mode="numeric", needs_above=1400, fail_above=2200)
        res = lighthouse_audit(ctx, p)
        assert res is False if tier is None else (
            res is True and ctx.evidence["tier"] == tier and ctx.evidence["penalty_override"] == pen)


def test_na_when_no_report_or_audit_absent():
    ctx = _Ctx(None)
    assert lighthouse_audit(ctx, _Probe(6, audit="font-display-insight")) is None
    assert "no lighthouse result" in ctx.evidence["na_reason"]
    ctx = _Ctx(_rep({"other": {"score": 1}}))
    assert lighthouse_audit(ctx, _Probe(6, audit="font-display-insight")) is None
    assert "not applicable" in ctx.evidence["na_reason"]


def test_report_only_still_fires_but_at_zero_penalty():
    # the 11 per-audit perf probes are OFF-SCORE: they fire (a per-metric diagnostic finding) but add 0 slop,
    # because the axis is scored once on the overall headline (perf-lighthouse-001).
    ctx = _Ctx(_rep({"largest-contentful-paint": {"score": 0.03}}))
    p = _Probe(28, audits=["largest-contentful-paint"], mode="score", report_only=True)
    assert lighthouse_audit(ctx, p) is True                 # still fires -> visible as a finding
    assert ctx.evidence["tier"] == "fail" and ctx.evidence["report_only"] is True
    assert ctx.evidence["penalty_override"] == 0            # ...but charges nothing
    # numeric mode honors it too
    ctx = _Ctx(_rep({"dom-size-insight": {"numericValue": 3000}}))
    pn = _Probe(7, audit="dom-size-insight", mode="numeric", needs_above=1400, fail_above=2200, report_only=True)
    assert lighthouse_audit(ctx, pn) is True and ctx.evidence["penalty_override"] == 0
