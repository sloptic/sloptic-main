"""The liveness gate must outlast the TTFB ceiling, or the slowest apps become DNFs instead of findings.

Measured on supavulnbase's perf-005 fixture (PERF_MODE=on), which answers HTTP 200 with a TTFB of 3.01s BY
CONSTRUCTION: curl returned a clean 200 and the runner recorded "URL DEAD — target did not respond". Both
constants were 3.0 — RemoteDeployer's per-request read timeout and perf.TTFB_CEILING — so an app slow enough
to trip perf-ttfb-003 (26 points, ">3s to first byte is pathological anywhere") was declared dead before the
probe could run. The probe was structurally unreachable, and a DNF ranks BELOW every completed submission
(format_spec §4.2), so the failure was harsher than the finding it displaced.

The corpus could never have surfaced this: perf probes fire on ~22% of it, so the axis looked healthy. It took
a fixture with a guaranteed-slow route and an answer key.
"""
from hacklet_runner import perf
from hacklet_runner.deploy import _LIVENESS_READ_TIMEOUT


def test_liveness_gate_outlasts_the_ttfb_ceiling():
    """Pins the RELATIONSHIP, not the values, so neither can drift back into collision."""
    assert _LIVENESS_READ_TIMEOUT > perf.TTFB_CEILING, (
        "liveness read timeout %.1fs must exceed the TTFB ceiling %.1fs, or an app that trips perf-ttfb-003 "
        "is recorded DEAD instead of slow" % (_LIVENESS_READ_TIMEOUT, perf.TTFB_CEILING))


def test_there_is_real_headroom_not_just_a_hairline():
    """3.01s vs a 3.0s timeout is what the bug looked like in the wild — a 10ms margin. Require enough room
    that ordinary jitter on a genuinely slow app cannot re-create it."""
    assert _LIVENESS_READ_TIMEOUT >= perf.TTFB_CEILING * 2


def test_the_ceiling_probe_is_reachable_at_its_own_threshold():
    """A response arriving just past the ceiling — exactly the case perf-ttfb-003 exists to catch — must still
    be inside the liveness budget, otherwise the probe can never observe it."""
    just_over_ceiling = perf.TTFB_CEILING + 0.01
    assert just_over_ceiling < _LIVENESS_READ_TIMEOUT
