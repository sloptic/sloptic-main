"""The per-probe wall clock: one hung probe costs its own slice, not the whole grade.

The v24 discovery run attributed 107 of its 120 timeouts to a SINGLE probe hanging after 54-88 of 106 had
already run fine — the grade DNF'd at 900s and threw away everything completed. The bounded runner runs each
probe in a daemon thread inside a copy of the submitting context (so the tally, cap, onset recorder, trace
id and egress scope keep working — a fresh thread would read their defaults) and abandons it on expiry.
GIL-honest: a socket-parked hang releases the GIL and the grade continues; a GIL-pinning hang still wedges
the process and the parent's 900s SIGKILL remains the backstop, exactly as before.
"""
import time

_ROOT = __import__('pathlib').Path(__file__).resolve().parent.parent
from sloptic.pipeline import _probe_deadline, _run_bounded
from sloptic.schema import Probe


def _probe(max_seconds=None):
    probe = {"max_requests": 10}
    if max_seconds is not None:
        probe["max_seconds"] = max_seconds
    return Probe(id="p", bundle="security", category="c", outcome=None, penalty=10, probe=probe)


def test_a_fast_probe_returns_its_result_not_hung():
    out, hung = _run_bounded(lambda: ["result"], 5)
    assert out == ["result"] and hung is False


def test_a_hung_probe_is_abandoned_at_its_deadline():
    t0 = time.monotonic()
    out, hung = _run_bounded(lambda: time.sleep(60), 0.4)
    assert time.monotonic() - t0 < 5            # abandoned at the deadline, not waited out
    assert out is None and hung is True


def test_a_raising_thunk_reads_as_none_not_hung():
    """The loop converts None to the probe's N/A outcome — the same degrade the loop's old except did. A
    raised exception must NOT read as 'hung', or every crashy probe would land in blocked_probes."""
    def boom():
        raise RuntimeError("x")
    out, hung = _run_bounded(boom, 5)
    assert out is None and hung is False


def test_the_deadline_comes_from_the_probe_then_the_env_default():
    assert _probe_deadline(_probe(45)) == 45.0
    assert _probe_deadline(_probe(None)) == _probe_deadline(_probe("junk"))  # junk falls back safely


def test_a_probe_thread_carries_the_submitting_context(monkeypatch):
    """The tally/cap/onset/trace all live in ContextVars. A fresh thread would read their defaults and blind
    the grade (the same defect the fan-out pools had); the runner copies the submitting context."""
    import contextvars
    from sloptic import net
    var = contextvars.ContextVar("hl_probe_deadline_marker", default=None)
    seen = []
    var.set("from-main")
    _run_bounded(lambda: seen.append(var.get()), 5)
    assert seen == ["from-main"]


def test_the_deadline_default_is_env_tunable():
    """The env var is read at IMPORT time, so this is verified in a THROWAWAY subprocess: reloading the
    pipeline module mid-session re-creates its classes (SurfaceTooLarge included), and every later test
    holding the OLD class then fails to catch the NEW exception — reload poison that poisoned the rest of
    the suite (observed: the surface-cap gate stopped refusing)."""
    import subprocess
    import sys
    code = ("import os, sys; os.environ['SLOPTIC_PROBE_TIMEOUT'] = '77';"
            "sys.path.insert(0, %r);"
            "from sloptic.pipeline import _PROBE_DEADLINE_S; print(_PROBE_DEADLINE_S)" % str(_ROOT))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "77.0"


def test_the_probe_loop_is_wired_through_the_bounded_runner():
    """Guards silent regression of the wiring: the loop must run every probe through the bounded runner and
    fold hung probes into blocked_probes, where the retry pass recovers them. (Source-pinned because a full
    run() needs a live deployer.)"""
    import inspect
    from sloptic import pipeline
    src = inspect.getsource(pipeline.run)
    assert "_run_bounded(_thunk, _probe_deadline(probe))" in src
    assert "hung_probes.append(probe.id)" in src
    assert "set(hung_probes)" in src            # merged into blocked_probes beside the challenge tail


def test_browser_probes_run_inline_not_bounded():
    """Playwright's sync API is thread-affine (greenlets bind to the creating thread), so moving a browser
    probe to a fresh thread breaks it — the crawler-wedge lesson. The gate must exempt them; the httpx-only
    majority of the v24 hang list (secrets-001, session-006, redirect-001, xss-001) is still bounded."""
    import inspect
    from sloptic import pipeline
    src = inspect.getsource(pipeline.run)
    assert '"browser" in probe.applicability.requires' in src
    assert src.index('"browser" in probe.applicability.requires') < src.index("_run_bounded(_thunk")
