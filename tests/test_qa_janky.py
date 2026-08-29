"""The qa-janky reference anchors the QA + performance probes in ISOLATION: it is security-clean but
deliberately bad on quality/perf, so those probes must fire while every security probe stays clean."""
import pathlib

from sloptic.catalog import load_catalog
from sloptic.deploy import SubprocessDeployer
from sloptic.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_qa_janky_fires_qa_and_perf_but_not_security():
    # perf is Lighthouse now (slow + environment-variable on a local ref app, covered separately); exclude it.
    # perf-load-001 (the burst-stress probe) is not Lighthouse-backed and still represents the perf axis here.
    catalog = [p for p in load_catalog(ROOT / "catalog") if p.probe.get("predicate") != "lighthouse_audit"]
    report = run(SubprocessDeployer(str(ROOT / "references" / "qa-janky" / "app.py")), catalog)
    fired = {o.probe_id for o in report.outcomes if o.outcome == "slop_detected"}
    # QA + performance jank is caught (non-browser subset; console/a11y/cwv need --browser)
    assert {"qa-crash-010", "qa-errhyg-001"} <= fired          # crash-resistance + error hygiene
    assert {"qa-a11y-002", "qa-seo-001"} <= fired              # WCAG hard-fails + missing viewport/description
    assert "qa-http-001" not in fired                          # qa-janky 404s correctly -> no soft-404
    assert "perf-load-001" in fired    # load resilience under a burst (the one non-Lighthouse perf probe)
    # but the app is security-clean: NO security probe fires
    sec = {o.probe_id for o in report.outcomes
           if o.bundle == "security" and o.outcome == "slop_detected"}
    assert sec == set(), f"security must be clean on qa-janky, got {sec}"
