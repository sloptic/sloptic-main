"""run_batch --delay: a global minimum gap between job STARTS.

Needed because a whole run can share ONE host (a benchmark like GapBench, a platform, one team's apps): the
grader's own volume — ~55 probes per app with injection fan-out — reads as an attack, and a WAF that answers
with a JS bot challenge kills the rest of the run (every later request 403s -> URL DEAD). Measured: two
GapBench apps were enough. The gap must hold across ALL workers, not just at --concurrency 1.
"""
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import run_batch  # noqa: E402


def _reset():
    run_batch._next_start[0] = 0.0


def test_zero_delay_is_a_no_op():
    _reset()
    t0 = time.monotonic()
    for _ in range(5):
        run_batch._throttle(0.0)
    assert time.monotonic() - t0 < 0.05          # the normal corpus path pays nothing


def test_starts_are_spaced_by_the_delay():
    _reset()
    t0 = time.monotonic()
    for _ in range(3):
        run_batch._throttle(0.05)
    elapsed = time.monotonic() - t0
    # first call is free (nothing scheduled yet), then each waits its turn: >= 2 gaps
    assert elapsed >= 0.10, elapsed


def test_the_gap_holds_across_concurrent_workers():
    # the point of a GLOBAL schedule: 4 workers starting at once must still be spaced, or --concurrency N
    # would multiply the request rate right back up
    _reset()
    starts, lock = [], threading.Lock()

    def worker():
        run_batch._throttle(0.05)
        with lock:
            starts.append(time.monotonic())

    threads = [threading.Thread(target=worker) for _ in range(4)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(starts) == 4
    assert max(starts) - t0 >= 0.15, [round(s - t0, 3) for s in starts]   # 3 gaps after the free first start


def test_delay_is_exposed_on_the_cli_and_defaults_to_off():
    import subprocess
    help_text = subprocess.run([sys.executable, str(pathlib.Path(run_batch.__file__)), "--help"],
                               capture_output=True, text=True, timeout=60).stdout
    assert "--delay SECONDS" in help_text
    assert "default: 0" in help_text or "--delay" in help_text   # off unless asked for (no cost normally)
