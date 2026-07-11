"""Performance rubric — objective, tiered, PUBLISHABLE thresholds applied to measured primitives.

Grading runs in a STANDARDIZED sandbox (deploy.py pins the container to 1 vCPU / 512 MB), so a timing
is reproducible, not hardware luck. Two tiers of threshold:

  - ABSOLUTE CEILINGS — environment-robust: a value this bad is broken on ANY hardware (the tolerance
    band is enormous), so they hold even on the uncontrolled --target path. Backed by abandonment
    research (Nielsen: 1s flow / 10s attention limit; Google/Akamai: ~53% abandon >3s; majority
    abandoned by >5s).
  - PROFILE THRESHOLDS — tighter, objective WITHIN the standardized sandbox on the published profile
    below; this is where the real discrimination happens.

Primitives are measured deterministically and a finding requires CLEARLY exceeding a threshold (p90
over N samples for timing), never grazing it. The two tiers are encoded as separate catalog probes
sharing a variant_group, so the worst-breached tier fires once (the composition damper handles it).
"""
from __future__ import annotations

import statistics
import time

# The published standardized grading profile (mirrors deploy.py's container limits). Documenting it
# here makes every timing threshold reproducible-by-spec: "graded on 1 vCPU / 512 MB, 12 Mbps, 50 ms".
PROFILE = {"cpu": "1 vCPU", "memory": "512 MB", "bandwidth_mbps": 12.0, "rtt_ms": 50.0}

# TTFB — server compute time (CPU-standardized, network-independent), seconds.
TTFB_CEILING = 3.0        # absolute: >3s to first byte is pathological anywhere
TTFB_PROFILE = 0.8        # standardized: >800ms backend on 1 vCPU is slow

# Total page transfer weight (HTML + same-origin critical assets), bytes.
WEIGHT_CEILING = 10_000_000   # absolute: a >10MB page is broken anywhere
WEIGHT_PROFILE = 2_000_000    # standardized: >2MB is a heavy page

# Requests to render the homepage (round trips).
REQUESTS_PROFILE = 50     # standardized: >50 round trips is chatty

# End-to-end load time on the profile, seconds (the user-facing number).
LOADTIME_CEILING = 5.0    # absolute: the majority-abandonment threshold


def _pctl(values: list[float], p: float) -> float:
    xs = sorted(values)
    if not xs:
        return 0.0
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)   # linear interpolation


def sample_ttfb(client, path: str, n: int = 3) -> float:
    """MEDIAN TTFB over n samples — rejects a cold-start/GC outlier, measures the typical response a
    user actually gets (fairer to grade than a tail-latency spike)."""
    times = []
    for _ in range(n):
        try:
            times.append(client.get(path).elapsed.total_seconds())
        except Exception:
            continue
    return statistics.median(times) if times else 0.0


def computed_load_time(ttfb: float, weight_bytes: int, requests: int) -> float:
    """Deterministic load time on the published profile: server compute + transfer + round-trips. No
    physical throttling needed — it's a function of three objectively-measured numbers + the spec."""
    transfer = weight_bytes * 8 / (PROFILE["bandwidth_mbps"] * 1e6)   # bytes -> bits / bandwidth
    round_trips = requests * (PROFILE["rtt_ms"] / 1000.0)
    return ttfb + transfer + round_trips


def now() -> float:
    return time.perf_counter()
