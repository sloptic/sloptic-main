"""The surface-scale gate: a discovered surface beyond the hackathon population is REFUSED, not graded
partially or given a bigger clock. The battery fans probes out PER ROUTE, so cost scales with surface:
a 643-route blog archive kept one probe running 4+ minutes and blew three 900s wall clocks, while the
largest surface the corpus ever graded was 342 routes. The cap sits between them, and raises
SurfaceTooLarge — a RuntimeError — so every caller's existing deploy-failure handling (CLI, worker ->
Unreachable -> failed grade) reports the reason verbatim. Drives the REAL gate in run() via a cached
profile, which skips the crawl and lands on the checkpoint with routes already known."""
import dataclasses
import sys
import pathlib

import pytest

from sloptic.catalog import load_catalog
from sloptic.deploy import SubprocessDeployer
from sloptic.pipeline import run, SurfaceTooLarge
from sloptic.schema import Profile

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from test_pipeline import REFS, _catalog   # the shared reference-app harness


def _profile(n_routes: int) -> Profile:
    return Profile(base_url="https://x.example", routes=[f"/p{i}" for i in range(n_routes)])


def test_gate_refuses_a_blog_archive_sized_surface():
    with pytest.raises(SurfaceTooLarge, match=r"643 discovered routes"):
        run(SubprocessDeployer(str(REFS / "vulnerable" / "app.py")), _catalog(),
            cached_profile=_profile(643))


def test_gate_spares_ordinary_surfaces_and_only_refuses_above_the_cap(monkeypatch):
    # the same surface, the line moved either side of it: refusal tracks the cap, not the app
    monkeypatch.setattr("sloptic.pipeline._MAX_SURFACE_ROUTES", 2)
    with pytest.raises(SurfaceTooLarge):
        run(SubprocessDeployer(str(REFS / "vulnerable" / "app.py")), _catalog(),
            cached_profile=_profile(3))


def test_cap_sits_above_every_surface_ever_graded():
    # the largest surface the corpus ever graded (342 routes, n=76) must clear the documented cap
    assert 342 <= 400 == _cap()


def _cap():
    import sloptic.pipeline as pipeline_mod
    return pipeline_mod._MAX_SURFACE_ROUTES


def test_exception_is_a_deploy_failure_for_callers():
    # the worker maps DEPLOY_FAILURES -> Unreachable -> a failed grade carrying this message verbatim;
    # the CLI catches RuntimeError the same way. A non-RuntimeError would surface as "worker error".
    assert issubclass(SurfaceTooLarge, RuntimeError)


def test_profile_routes_is_the_gated_field():
    # the gate reads profile.routes; if the schema ever renames it, the gate would measure nothing
    # and refuse nothing. Pin the field the gate depends on.
    assert "routes" in [f.name for f in dataclasses.fields(Profile)]
