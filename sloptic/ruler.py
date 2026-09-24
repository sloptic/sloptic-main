"""The RULER: the frozen reference this build interprets scores against.

A slop score is only comparable within one ruler. Continuous scoring and the frozen reference curve together
define what the number means, and they move together at a release: when the scoring model or the curve
changes, the same app scores differently, so a score from an old ruler must never be read as a current one.

These are release CONSTANTS, bumped at the freeze in lockstep with the curve files in `validation/` and the
package version. `test_ruler.py::test_ruler_matches_the_frozen_curve` guards the drift against those files.
They are STAMPED on every grade record at grade time (never read from the current curve at render time) so a
STORED grade carries the ruler it was produced under, and the report card labels it as such -- a legacy grade
whose record predates this stamp renders with no ruler, not silently as the current one.

The curve files themselves are not shipped in the wheel (only `sloptic/` + `catalog` are), so the record's
stamped value, not a file read, is the source of truth wherever an installed grader renders a stored card.
"""
from __future__ import annotations

# The full-battery reference and the passive-battery reference, versioned independently.
FULL = "2026.4"
PASSIVE = "passive-2026.1"


def ruler() -> dict:
    """The full + passive reference versions this grader interprets scores against, for stamping on a record."""
    return {"full": FULL, "passive": PASSIVE}
