"""Docker calibration: the same three-way reference suite, deployed via DockerDeployer instead of
SubprocessDeployer, must produce IDENTICAL slop scores — proof the production deployer is
behavior-equivalent to the dev/CI one (same catalog, same probes, same scores; just a sandboxed
container instead of a local subprocess).

Asserts equality between the two deployers rather than a hard-coded number, so it self-tracks: adding
or re-weighting a probe never needs an edit here (tests/test_pipeline.py holds the single authoritative
score). Skipped where Docker is absent (the dev box has none); runs on the VM / CI.
"""
import pathlib
import shutil

import pytest

from sloptic.catalog import load_catalog
from sloptic.deploy import DockerDeployer, SubprocessDeployer
from sloptic.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
REFS = ROOT / "references"

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="Docker not available (run on the VM/CI)"
)


def _cat():
    # exclude the Lighthouse-backed perf probes: a real Lighthouse run per grade is slow + environment-variable,
    # which would break the docker==subprocess score equivalence this file exists to prove.
    return [p for p in load_catalog(CATALOG) if p.probe.get("predicate") != "lighthouse_audit"]


def _docker_score(app: str) -> int:
    return run(DockerDeployer(str(REFS / app)), _cat()).slop_score


def _subprocess_score(app: str) -> int:
    return run(SubprocessDeployer(str(REFS / app / "app.py")), _cat()).slop_score


def test_docker_vulnerable_matches_subprocess():
    assert _docker_score("vulnerable") == _subprocess_score("vulnerable") > 0


def test_docker_hardened_is_clean():
    assert _docker_score("hardened") == 0


def test_docker_minimal_is_clean():
    assert _docker_score("minimal") == 0
