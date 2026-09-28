"""The RULER stamp: the frozen reference a grade was produced under, carried on the record and shown on the
card so a STORED grade never silently reads as current after the ruler moves at a release.

The package constants (sloptic.ruler) are the runtime source of truth -- the curve files are not shipped in
the wheel -- so this guards them against drifting from the curves they name. It runs in the repo, where the
curve files exist; an installed-only checkout without them skips the file comparison rather than failing.
"""
import json
import pathlib

import pytest

from sloptic import ruler as ruler_mod
from sloptic.reportcard import build_card, to_html, to_markdown

_VALIDATION = pathlib.Path(__file__).resolve().parent.parent / "validation"


def _curve_version(name: str):
    p = _VALIDATION / name
    if not p.exists():
        pytest.skip(f"{name} not present (installed-only checkout)")
    return json.loads(p.read_text())["version"]


def test_ruler_matches_the_frozen_curve_files():
    # the constant is what gets stamped at runtime; it must name the curve actually frozen, or a grade would
    # advertise a reference it was not scored against. Bump BOTH together at the freeze.
    assert ruler_mod.FULL == _curve_version("benchmark-curve.json")
    assert ruler_mod.PASSIVE == _curve_version("benchmark-curve-passive.json")


def test_ruler_shape():
    r = ruler_mod.ruler()
    assert r == {"full": ruler_mod.FULL, "passive": ruler_mod.PASSIVE}


def test_the_card_carries_the_records_stamped_ruler_never_the_current_one():
    # a FRESH grade carries its stamp; the card surfaces exactly that, so a stored record keeps its own ruler.
    rec = {"url": "http://x", "functional": True, "slop_score": 40, "findings": [],
           "coverage": {}, "axis_slop": {"security": 40}, "ruler": {"full": "9999.9", "passive": "p-9999.9"}}
    card = build_card(rec)
    assert card["ruler"] == {"full": "9999.9", "passive": "p-9999.9"}   # the RECORD's ruler, not sloptic.ruler
    assert "9999.9" in to_markdown(card) and "9999.9" in to_html(card)


def test_a_legacy_record_without_a_ruler_reads_as_unspecified_not_current():
    # the discontinuity guard: a stored 2.x grade predates the stamp -> the card must NOT read as the current
    # ruler. It carries None and the label says so.
    card = build_card({"url": "http://old", "functional": True, "slop_score": 12, "findings": [],
                       "coverage": {}, "axis_slop": {}})
    assert card["ruler"] is None
    assert "unspecified" in to_markdown(card)
    assert ruler_mod.FULL not in to_markdown(card)        # never falls back to the current ruler


def test_a_dnf_card_also_carries_the_ruler():
    card = build_card({"url": "http://x", "functional": False, "ruler": {"full": "2026.3"}})
    assert card["dnf"] and card["ruler"] == {"full": "2026.3"}
    assert "2026.3" in to_html(card)
