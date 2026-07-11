"""Hardened-mode Docker calibration: the production sandbox flags must (1) preserve behavior and
(2) actually block egress.

Two unknowns this resolves on the VM (the Docker-less dev box can't test them):
  * does host port-publishing (`-p`) still reach the container on a `--internal`, egress-blocked
    network? If `test_hardened_calibration_preserves_scores` fails at the health gate, it does not,
    and the runner must move to the runner-in-container model (shared internal network, no host
    publishing).
  * does a read-only root filesystem break the reference apps?

Docker-gated (skipped where Docker is absent). Asserts the hardened-mode score EQUALS the plain
SubprocessDeployer baseline (not a hard-coded number), so "hardening preserves behavior" is tested
directly and this file self-tracks any scoring change.
"""
import pathlib
import shutil

import pytest

from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import DockerDeployer, SubprocessDeployer, _docker
from hacklet_runner.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog"
REFS = ROOT / "references"
NET = "hacklet-fuzz-test-net"

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="Docker not available (run on the VM/CI)"
)


def _subprocess_score(app: str) -> int:
    """The deployer-independent baseline: the same reference graded via a local subprocess."""
    return run(SubprocessDeployer(str(REFS / app / "app.py")), load_catalog(CATALOG)).slop_score

# Run inside a container: try to open an outbound internet connection.
_EGRESS_PROBE = (
    "import socket\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 443), timeout=4).close()\n"
    "    print('REACHED')\n"
    "except OSError:\n"
    "    print('BLOCKED')\n"
)


@pytest.fixture(scope="module")
def internal_net():
    """A throwaway egress-blocked network, created and removed here so the suite needs no setup."""
    _docker("network", "create", "--internal", NET)
    try:
        yield NET
    finally:
        _docker("network", "rm", NET)


def test_hardened_calibration_preserves_scores(internal_net):
    """Read-only rootfs + egress-blocked network must not change any score — and `-p` must still
    reach the container (else the health gate times out and this fails)."""
    def score(app: str) -> int:
        d = DockerDeployer(str(REFS / app), read_only=True, network=internal_net)
        return run(d, load_catalog(CATALOG)).slop_score

    # hardening flags must not change any score -> equals the plain-subprocess baseline for each app
    for app in ("vulnerable", "hardened", "minimal"):
        assert score(app) == _subprocess_score(app)


def test_read_only_preserves_scores():
    """Isolate read-only from the network change: on the default bridge (known-good reachability),
    a read-only root filesystem must not change any score."""
    def score(app: str) -> int:
        return run(DockerDeployer(str(REFS / app), read_only=True), load_catalog(CATALOG)).slop_score

    for app in ("vulnerable", "hardened", "minimal"):
        assert score(app) == _subprocess_score(app)


def test_internal_network_blocks_egress(internal_net):
    """A container on the internal network cannot reach the internet."""
    proc = _docker(
        "run", "--rm", "--network", internal_net,
        "python:3.12-slim", "python", "-c", _EGRESS_PROBE,
    )
    assert "BLOCKED" in proc.stdout, f"egress not blocked: {proc.stdout!r} {proc.stderr!r}"


def test_default_network_reaches_internet():
    """Positive control: the same probe DOES reach on the default bridge, proving the block above is
    the internal network and not a broken probe. (Requires the VM to have outbound internet.)"""
    proc = _docker("run", "--rm", "python:3.12-slim", "python", "-c", _EGRESS_PROBE)
    assert "REACHED" in proc.stdout, f"control could not reach internet: {proc.stdout!r}"
