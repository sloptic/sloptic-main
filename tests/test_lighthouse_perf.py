"""The perf axis is scored ONCE, off Lighthouse's overall weighted headline: slop = round(max(0, green_floor -
score) * 100 * scale) -- the shortfall below Lighthouse's own green line (0.90). At/above green -> 0 (clean),
an 84 -> 6, a 25 -> 65. Flooring at green (not a perfect 100) refuses to score the 90-100 jitter and keeps a
clean sheet achievable. This replaces summing the per-audit tiers (which double-counted metrics the headline
already weighed and penalized apps Lighthouse rates good). The per-metric breakdown rides along OFF-SCORE."""
from sloptic import lighthouse as lh
from sloptic.probes import lighthouse_perf_score


class _Probe:
    def __init__(self, **cfg):
        self.penalty, self.probe = 50, cfg


class _Ctx:
    def __init__(self, report):
        self.lighthouse, self.evidence = report, {}


def _rep(perf, audits=None, runs=3):
    return {"lighthouseResult": {"categories": {"performance": {"score": perf}},
                                 "audits": audits or {}}, "runs": runs}


def test_green_is_clean():
    # at/above Lighthouse's green line (0.90) -> 0 slop -> CLEAN (no finding). A green sheet is achievable;
    # 90-100 is within measurement jitter, so we don't score a 95 vs a 92.
    for perf in (1.0, 0.95, 0.90):
        ctx = _Ctx(_rep(perf))
        assert lighthouse_perf_score(ctx, _Probe()) is False
        assert ctx.evidence["penalty_override"] == 0 and ctx.evidence["tier"] == "good"
        assert ctx.evidence["performance"] == round(perf * 100)


def test_shortfall_below_green_is_the_slop():
    for perf, slop, tier in [(0.84, 6, "needs-improvement"), (0.50, 40, "needs-improvement"), (0.25, 65, "poor")]:
        ctx = _Ctx(_rep(perf))
        assert lighthouse_perf_score(ctx, _Probe()) is True
        assert ctx.evidence["penalty_override"] == slop and ctx.evidence["tier"] == tier
        assert ctx.evidence["performance"] == round(perf * 100)


def test_scale_dials_the_axis_without_touching_the_mapping():
    ctx = _Ctx(_rep(0.50))
    assert lighthouse_perf_score(ctx, _Probe(scale=0.5)) is True
    assert ctx.evidence["penalty_override"] == 20          # max(0, 0.90-0.50)*100*0.5


def test_breakdown_rides_along_as_offscore_diagnostics():
    ctx = _Ctx(_rep(0.60, audits={"largest-contentful-paint": {"displayValue": "4.3 s"},
                                   "cumulative-layout-shift": {"displayValue": "0.21"},
                                   "unrelated-audit": {"displayValue": "x"}}))
    lighthouse_perf_score(ctx, _Probe())
    m = ctx.evidence["metrics"]
    assert m["largest-contentful-paint"] == "4.3 s" and m["cumulative-layout-shift"] == "0.21"
    assert "unrelated-audit" not in m                      # only the known headline metrics


def test_na_when_no_report_or_no_score():
    ctx = _Ctx(None)
    assert lighthouse_perf_score(ctx, _Probe()) is None
    assert "no lighthouse result" in ctx.evidence["na_reason"]
    ctx = _Ctx(_rep(None))                                  # report present, but no performance category score
    assert lighthouse_perf_score(ctx, _Probe()) is None
    assert "no overall performance score" in ctx.evidence["na_reason"]


def test_metric_breakdown_helper_reads_either_shape():
    rep = {"audits": {"speed-index": {"displayValue": "3.1 s"}}}
    assert lh.metric_breakdown(rep)["speed-index"] == "3.1 s"
    assert lh.metric_breakdown({"lighthouseResult": rep})["speed-index"] == "3.1 s"
    assert lh.metric_breakdown({}) == {}
