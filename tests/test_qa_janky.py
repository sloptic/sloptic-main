"""The qa-janky reference anchors the QA + performance probes in ISOLATION: it is security-clean but
deliberately bad on quality/perf, so those probes must fire while every security probe stays clean."""
import pathlib

from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import SubprocessDeployer
from hacklet_runner.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_qa_janky_fires_qa_and_perf_but_not_security():
    report = run(SubprocessDeployer(str(ROOT / "references" / "qa-janky" / "app.py")),
                 load_catalog(ROOT / "catalog"))
    fired = {o.probe_id for o in report.outcomes if o.outcome == "slop_detected"}
    # QA + performance jank is caught (non-browser subset; console/a11y/cwv need --browser)
    assert {"qa-crash-010", "qa-errhyg-001"} <= fired          # crash-resistance + error hygiene
    assert {"qa-a11y-002", "qa-seo-001"} <= fired              # WCAG hard-fails + missing viewport/description
    assert "qa-http-001" not in fired                          # qa-janky 404s correctly -> no soft-404
    assert {"perf-compress-001", "perf-load-001"} <= fired                     # compression / load
    # the two-tier perf RUBRIC: slow homepage breaches the profile TTFB tier (not the absolute ceiling)
    # and the chatty homepage blows the request budget
    assert {"perf-ttfb-002", "perf-requests-001"} <= fired
    assert "perf-ttfb-003" not in fired      # 0.9s < 3s absolute ceiling -> that tier stays clean
    # but the app is security-clean: NO security probe fires
    sec = {o.probe_id for o in report.outcomes
           if o.bundle == "security" and o.outcome == "slop_detected"}
    assert sec == set(), f"security must be clean on qa-janky, got {sec}"
