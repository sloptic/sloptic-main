"""The perf axis is scored ONCE, off Lighthouse's overall weighted headline, inverted to slop: slop = round(
(1 - score) * 100 * scale). A 100 -> 0 (clean), an 84 -> 16, a 25 -> 75. This replaces summing the per-audit
tiers (which double-counted metrics the headline already weighed and penalized apps Lighthouse rates fast).
The per-metric breakdown rides along as OFF-SCORE diagnostics only."""
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


def test_perfect_score_is_clean():
    ctx = _Ctx(_rep(1.0))
    assert lighthouse_perf_score(ctx, _Probe()) is False       # a perfect 100 -> 0 slop -> clean, no finding
    assert ctx.evidence["penalty_override"] == 0 and ctx.evidence["performance"] == 100


def test_distance_from_100_is_the_slop():
    for perf, slop, tier in [(0.84, 16, "needs-improvement"), (0.25, 75, "poor"), (0.95, 5, "good")]:
        ctx = _Ctx(_rep(perf))
        assert lighthouse_perf_score(ctx, _Probe()) is True
        assert ctx.evidence["penalty_override"] == slop and ctx.evidence["tier"] == tier
        assert ctx.evidence["performance"] == round(perf * 100)


def test_scale_dials_the_axis_without_touching_the_mapping():
    ctx = _Ctx(_rep(0.50))
    assert lighthouse_perf_score(ctx, _Probe(scale=0.5)) is True
    assert ctx.evidence["penalty_override"] == 25          # (1-0.5)*100*0.5


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
