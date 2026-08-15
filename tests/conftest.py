"""Test-suite fixtures.

The perf axis grades via a real `npx lighthouse` run (sloptic/lighthouse.run_local). The pipeline INTEGRATION
tests that grade ref apps through the full catalog would each pay a ~3-minute Chrome run for it -- ~9 min of
suite time for a path already covered by test_lighthouse_audit (mocked ctx), test_lighthouse (mocked runner),
and a live validation. This autouse fixture no-ops run_local so those graded perf probes read N/A (the pipeline
catches PSIError -> ctx.lighthouse stays None), keeping the suite fast without changing any non-perf outcome.
Tests exercising the runner itself pass their own `runner=` to measure() (test_lighthouse), so they're unaffected.
"""
import pytest


@pytest.fixture(autouse=True)
def _no_real_lighthouse(monkeypatch):
    import sloptic.lighthouse as lh

    def _disabled(*_a, **_k):
        raise lh.PSIError("run_local disabled in the test suite (see tests/conftest.py)")

    monkeypatch.setattr(lh, "run_local", _disabled)
