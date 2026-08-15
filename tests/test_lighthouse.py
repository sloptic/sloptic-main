"""The PSI / local-lighthouse accessors must read EITHER shape: PSI nests the Lighthouse report under
`lighthouseResult`, the local CLI returns it top-level. Audit ids are pinned + verified against a live
13.4.1 response in lighthouse.py (they rename between versions); this locks the extraction + the id set."""
from sloptic import lighthouse as lh

_REPORT = {"audits": {"font-display-insight": {"score": 1, "scoreDisplayMode": "metricSavings"},
                      "dom-size-insight": {"score": 1, "scoreDisplayMode": "informative", "numericValue": 660},
                      "largest-contentful-paint": {"score": 0.41, "numericValue": 4338.0}},
           "categories": {"performance": {"score": 0.72}}}


def test_reads_local_cli_top_level_shape():
    assert lh.perf_score(_REPORT) == 0.72
    assert lh.audits(_REPORT)["font-display-insight"]["score"] == 1
    assert lh.metric_ms(_REPORT, "largest-contentful-paint") == 4338.0


def test_reads_psi_wrapped_shape():
    psi = {"lighthouseResult": _REPORT}
    assert lh.perf_score(psi) == 0.72
    assert lh.audits(psi)["dom-size-insight"]["numericValue"] == 660


def test_missing_report_is_empty_not_crash():
    assert lh.audits({}) == {}
    assert lh.perf_score({}) is None
    assert lh.metric_ms({}, "largest-contentful-paint") is None


def test_mapped_audit_ids_are_declared_and_versions_pinned():
    ids = lh.INSIGHT_AUDITS + lh.NUMERIC_AUDITS + lh.METRIC_AUDITS
    assert len(ids) == 19 and all(isinstance(a, str) and a for a in ids)
    assert lh.LIGHTHOUSE_VERSION and lh.DEFAULT_RUNS == 3   # pinned version + median default


def _rep(lcp_score, lcp_ms, cls_score, cls_num, perf):
    return {"audits": {"largest-contentful-paint": {"score": lcp_score, "numericValue": lcp_ms},
                       "cumulative-layout-shift": {"score": cls_score, "numericValue": cls_num},
                       "font-display-insight": {"score": 1}},
            "categories": {"performance": {"score": perf}}}


def test_measure_medians_every_audit_across_runs():
    # the measured jitter: LCP 7950/7255/7897, CLS band-flips 0.44/1/1, perf 0.72/0.70/0.71
    reports = iter([_rep(0.03, 7950, 0.44, 0.274, 0.72), _rep(0.05, 7255, 1.0, 0.0, 0.70),
                    _rep(0.03, 7897, 1.0, 0.0, 0.71)])
    c = lh.measure("http://x", runs=3, runner=lambda u, **k: next(reports))
    au = lh.audits(c)
    assert c["runs"] == 3
    assert au["largest-contentful-paint"]["numericValue"] == 7897   # median(7950,7255,7897)
    assert au["cumulative-layout-shift"]["score"] == 1.0            # median(0.44,1,1) -> majority no-shift
    assert au["cumulative-layout-shift"]["numericValue"] == 0.0
    assert au["font-display-insight"]["score"] == 1                 # stable audit: median is a no-op
    assert lh.perf_score(c) == 0.71                                  # median(0.72,0.70,0.71)


def test_measure_survives_partial_failures():
    it = iter([_rep(1, 1, 1, 0, 0.5), None, _rep(1, 1, 1, 0, 0.5)])
    def flaky(u, **k):
        v = next(it)
        if v is None:
            raise lh.PSIError("boom")
        return v
    assert lh.measure("http://x", runs=3, runner=flaky)["runs"] == 2   # medianed over the 2 survivors
