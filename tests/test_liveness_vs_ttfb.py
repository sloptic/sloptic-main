"""The liveness gate must outlast the TTFB ceiling, or the slowest apps become DNFs instead of findings.

Measured on supavulnbase's perf-005 fixture (PERF_MODE=on), which answers HTTP 200 with a TTFB of 3.01s BY
CONSTRUCTION: curl returned a clean 200 and the runner recorded "URL DEAD — target did not respond". Both
constants were 3.0 — RemoteDeployer's per-request read timeout and perf.TTFB_CEILING — so an app slow enough
to trip perf-ttfb-003 (26 points, ">3s to first byte is pathological anywhere") was declared dead before the
probe could run. The probe was structurally unreachable, and a DNF ranks BELOW every completed submission,
so the failure was harsher than the finding it displaced.

The corpus could never have surfaced this: perf probes fire on ~22% of it, so the axis looked healthy. It took
a fixture with a guaranteed-slow route and an answer key.
"""
from sloptic import perf
from sloptic.deploy import _LIVENESS_READ_TIMEOUT


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


# --------------------------------------------------------------- provenance (same file: both are run-context)

def test_provenance_records_what_cannot_be_reconstructed_later():
    """Three times in one session an unrecorded invocation cost a real answer: --browser-auth was inferred to
    be off from coverage rates (it was on), --concurrency could not be checked at all, and a v10-vs-v11
    comparison had no way to know the runs used different machines, Pythons and Playwrights. Every other
    question about a corpus run can be re-measured from the same corpus; this one cannot."""
    from sloptic import perf, provenance

    p = provenance.collect(flags={"browser_auth": True, "concurrency": "6"})
    assert p["run_id"] and p["run_id"] == provenance.run_id(), "run_id must be stable within a process"
    assert p["host"]["cores"] and p["host"]["platform"]
    assert p["versions"]["python"] and p["versions"]["playwright"]
    assert p["flags"]["browser_auth"] is True and p["flags"]["concurrency"] == "6"


def test_the_qa_and_perf_axes_get_their_engine_versions():
    """This is why provenance matters MORE for qa/perf than for security. A missing CSP header is missing on any
    machine; a11y comes out of axe-core, whose RULE SET changes between versions, and it is ~25% of total corpus
    penalty. Bump axe and a11y findings move with no app having changed — so a curve comparison without the
    version cannot tell an app that got worse from a rule that got stricter."""
    from sloptic import provenance

    v = provenance.collect()["versions"]
    assert v["axe_core"], "axe-core version missing — a11y findings become incomparable across runs"
    assert v["axe_core"][0].isdigit()
    # the perf PROFILE is not environmental, it IS the definition of perf-loadtime-001 and the tier thresholds
    prof = provenance.collect()["perf_profile"]
    assert prof["bandwidth_mbps"] and prof["rtt_ms"]
    th = provenance.collect()["perf_thresholds"]
    assert th["ttfb_ceiling"] and th["requests_profile"]


def test_provenance_never_stores_a_credential():
    """--header carries a live session and --login carries a password. Only WHETHER one was supplied may be
    recorded. A results file is also the thing we must never publish (see .gitignore), so a leaked credential
    there would be doubly wrong."""
    import json

    from sloptic import provenance

    blob = json.dumps(provenance.collect(flags={
        "header_supplied": True, "login_supplied": True,
    })).lower()
    for secret in ("bearer ", "password", "sb-", "eyj", "cookie:"):
        assert secret not in blob, "provenance leaked %r" % secret
