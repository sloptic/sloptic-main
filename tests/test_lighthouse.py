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
    # pinned CLI version. (The median-of-N DEFAULT is 3, but DEFAULT_RUNS is env-derived at import, so asserting
    # it here breaks a suite run with SLOPTIC_LIGHTHOUSE_RUNS set, e.g. mid-grade tuning -> the default is locked
    # env-isolated in test_runs_env_override via monkeypatch.delenv instead.)
    assert lh.LIGHTHOUSE_VERSION


def test_runs_env_override(monkeypatch):
    # SLOPTIC_LIGHTHOUSE_RUNS dials median-of-N (throughput vs per-app smoothing on the serialized trace lane)
    monkeypatch.delenv("SLOPTIC_LIGHTHOUSE_RUNS", raising=False)
    assert lh._env_runs() == 3
    for val, exp in [("1", 1), ("2", 2), ("5", 5), ("0", 3), ("-2", 3), ("junk", 3), ("", 3)]:
        monkeypatch.setenv("SLOPTIC_LIGHTHOUSE_RUNS", val)
        assert lh._env_runs() == exp, val


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


# ── host speed: recorded because nothing in Lighthouse corrects for it ──────────────────────────────────
def _rep_bi(bi, perf=0.8):
    r = {"audits": {}, "categories": {"performance": {"score": perf}}}
    if bi is not None:
        r["environment"] = {"benchmarkIndex": bi}
    return r


def test_benchmark_index_is_read_from_the_report_environment():
    assert lh.benchmark_index(_rep_bi(1342.5)) == 1342.5
    assert lh.benchmark_index({"lighthouseResult": _rep_bi(900)}) == 900     # PSI-wrapped shape too


def test_benchmark_index_absent_or_junk_is_none_not_a_crash():
    assert lh.benchmark_index(_rep_bi(None)) is None                        # no environment block at all
    assert lh.benchmark_index({"environment": {}}) is None
    assert lh.benchmark_index({"environment": {"benchmarkIndex": "fast"}}) is None


def test_measure_medians_the_host_speed_and_records_its_spread():
    """The median is the host's speed for this grade. The spread across the three runs is a contention
    signal in its own right: a quiet box repeats its benchmark closely, a loaded one does not."""
    reports = iter([_rep_bi(1200.0), _rep_bi(1000.0), _rep_bi(1100.0)])
    c = lh.measure("http://x", runs=3, runner=lambda u, **k: next(reports))
    env = lh._lhr(c)["environment"]
    assert env["benchmarkIndex"] == 1100.0
    assert env["benchmarkIndexSpread"] == 200.0


def test_a_report_without_a_host_index_leaves_no_environment_key():
    """Absence stays absence. A record carrying benchmark_index: null would read as 'measured and unknown'."""
    c = lh.measure("http://x", runs=2, runner=lambda u, **k: _rep_bi(None))
    assert "benchmarkIndex" not in (lh._lhr(c).get("environment") or {})
    assert lh.benchmark_index(c) is None
