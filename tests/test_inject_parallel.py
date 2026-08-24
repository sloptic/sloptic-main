"""_fan_out_first: the bounded-pool short-circuit that parallelizes the DETERMINISTIC injection payloads
(cmdi/lfi/ssti/sqli deterministic oracles). Locks the first-hit short-circuit, the request-cap gate, and that
it genuinely runs concurrently -- so the per-app injection phase speeds up without touching the grade box cores
(it's I/O-bound) and without changing the verdict (same payloads + same oracle, only the order changes)."""
import time

from sloptic.probes import _fan_out_first


def test_returns_the_first_oracle_hit():
    # only spec 7 "hits"; concurrency reorders completion but the unique hit is still what comes back
    got = _fan_out_first(lambda s: (s, "HIT" if s == 7 else None),
                         range(20), lambda s, r: r == "HIT", pool=4)
    assert got == (7, "HIT")


def test_none_when_nothing_hits():
    assert _fan_out_first(lambda s: (s, None), range(10), lambda s, r: True, pool=4) is None


def test_a_worker_that_raises_is_a_miss_not_a_crash():
    def send(spec):
        if spec == 3:
            raise ValueError("boom")
        return spec, ("HIT" if spec == 8 else None)
    assert _fan_out_first(send, range(12), lambda s, r: r == "HIT", pool=4) == (8, "HIT")


def test_cap_check_stops_submission_well_before_the_end():
    fired = []
    def send(spec):
        fired.append(spec)
        return spec, None
    _fan_out_first(send, range(100), lambda s, r: False, pool=2,
                   cap_check=lambda: len(fired) >= 5)   # stop submitting once 5 have gone out
    assert len(fired) < 20                              # nowhere near 100 -> the cap gated submission
    assert 5 <= len(fired) <= 5 + 2 + 1                 # the cap + at most the in-flight pool


def test_actually_runs_concurrently():
    # 8 sends each sleeping 0.1s: sequential is ~0.8s, pool=8 overlaps the waits -> well under
    def send(spec):
        time.sleep(0.1)
        return spec, None
    t = time.monotonic()
    _fan_out_first(send, range(8), lambda s, r: False, pool=8)
    assert time.monotonic() - t < 0.5
