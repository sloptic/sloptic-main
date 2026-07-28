"""How a grade was produced — recorded on every row, because it cannot be reconstructed afterwards.

Three times in one session an unrecorded invocation cost a real answer: `--browser-auth` was inferred to be
off from coverage rates (it was on), `--concurrency` could not be checked at all, and a v10-vs-v11 comparison
had no way to know the two runs used different machines, Python versions and Playwright versions. Every other
question about a corpus run can be re-measured from the same corpus; this one cannot.

WHY IT MATTERS MORE FOR QA AND PERF THAN FOR SECURITY. A security finding is a property of the app: a missing
CSP header is missing on any machine, with any browser. The qa and perf axes are not like that, and together
they are the larger share of corpus penalty:

  * `qa-a11y-001/002` are ~25% of total corpus penalty and are produced by **axe-core**, whose RULE SET changes
    between versions. Bump axe and a11y findings move with no app having changed. The engine is vendored and
    git-tracked (`vendor/axe.min.js`, pinned at 4.10.2) so a run is reproducible — but without the version in
    the row, a future curve comparison cannot tell an app that got worse from a rule that got stricter.
  * `perf-cwv-001/002` are measured **inside Chromium** under a CDP CPU throttle, so they move with the browser
    build. `perf-ttfb-*` and `perf-load-001` are wall-clock and move with host load and core count.
  * The one thing that does NOT need this is `perf-loadtime-001`, which computes against a fixed published
    PROFILE instead of measuring — recorded here anyway, because the profile IS the definition of that number.

So this module is not bookkeeping. For two thirds of the score it is what makes a number comparable to the same
number from another run at all.

NEVER RECORD A CREDENTIAL. `--header` and `--login` carry live sessions and passwords. Only whether one was
supplied is recorded, never the value.
"""
from __future__ import annotations

import contextlib
import os
import pathlib
import platform
import re
import secrets

from . import perf

_AXE_VERSION = re.compile(r'axe\.version\s*=\s*"([0-9][0-9.]*)"')

# One id per batch, so every row of a run can be grouped and two runs never merge silently. run_batch exports
# it to children; a standalone grade mints its own.
_RUN_ID_ENV = "HL_RUN_ID"
# The chromium build, discovered once by run_batch's preflight and passed down, so recording it costs no extra
# browser launch per app.
_CHROMIUM_ENV = "HL_CHROMIUM_VERSION"


def run_id() -> str:
    """The batch id, from the environment if a parent set one, else a fresh one for this process."""
    rid = os.environ.get(_RUN_ID_ENV)
    if not rid:
        rid = "r" + secrets.token_hex(5)
        os.environ[_RUN_ID_ENV] = rid
    return rid


def _cpu_model() -> str | None:
    with contextlib.suppress(Exception):
        for line in pathlib.Path("/proc/cpuinfo").read_text("utf-8", "ignore").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()[:64]
    return (platform.processor() or None)


def _axe_version() -> str | None:
    """Parsed from the vendored bundle rather than a browser, so it costs nothing. `axe.version="4.10.2"` is a
    literal assignment in the minified source."""
    with contextlib.suppress(Exception):
        src = (pathlib.Path(__file__).resolve().parent / "vendor" / "axe.min.js").read_text("utf-8", "ignore")
        m = _AXE_VERSION.search(src)
        if m:
            return m.group(1)
    return None


def _dist_version(name: str) -> str | None:
    with contextlib.suppress(Exception):
        import importlib.metadata as md
        return md.version(name)
    return None


def collect(*, flags: dict | None = None) -> dict:
    """The provenance block for one grade. `flags` is the invocation, already reduced to booleans/values that
    are safe to store — the caller must not pass credential VALUES."""
    return {
        "run_id": run_id(),
        "host": {
            "node": platform.node() or None,
            "cpu": _cpu_model(),
            "cores": os.cpu_count(),
            "platform": platform.platform(terse=True),
        },
        "versions": {
            "python": platform.python_version(),
            "playwright": _dist_version("playwright"),
            # from run_batch's single preflight; None on a standalone grade that never launched a browser
            "chromium": os.environ.get(_CHROMIUM_ENV) or None,
            "axe_core": _axe_version(),
        },
        # the profile IS the definition of perf-loadtime-001 and the tier thresholds, so a curve comparison
        # needs it even though it never varies with the machine
        "perf_profile": dict(perf.PROFILE),
        "perf_thresholds": {
            "ttfb_profile": perf.TTFB_PROFILE, "ttfb_ceiling": perf.TTFB_CEILING,
            "weight_profile": perf.WEIGHT_PROFILE, "weight_ceiling": perf.WEIGHT_CEILING,
            "requests_profile": perf.REQUESTS_PROFILE, "loadtime_ceiling": perf.LOADTIME_CEILING,
        },
        "flags": dict(flags or {}),
    }
