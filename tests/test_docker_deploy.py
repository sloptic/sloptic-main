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

from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import DockerDeployer, SubprocessDeployer
from hacklet_runner.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
REFS = ROOT / "references"

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="Docker not available (run on the VM/CI)"
)


def _docker_score(app: str) -> int:
    return run(DockerDeployer(str(REFS / app)), load_catalog(CATALOG)).slop_score


def _subprocess_score(app: str) -> int:
    return run(SubprocessDeployer(str(REFS / app / "app.py")), load_catalog(CATALOG)).slop_score


def test_docker_vulnerable_matches_subprocess():
    assert _docker_score("vulnerable") == _subprocess_score("vulnerable") > 0


def test_docker_hardened_is_clean():
    assert _docker_score("hardened") == 0


def test_docker_minimal_is_clean():
    assert _docker_score("minimal") == 0
