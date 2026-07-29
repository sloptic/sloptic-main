"""color-contrast graded by HOW unreadable it is, instead of one flat "serious" for everything.

axe hardcodes this rule's impact at "serious", so before this change a page whose worst text sat at 4.4:1
(a hair under the 4.5 bar) was charged exactly what a page of 1.1:1 invisible text was charged. The rule
fires on 55.1% of the corpus and is involved in 14.3% of all penalty, which made it the largest single
flattening in the score.

Severity is measured as SHORTFALL = measured / required, never the raw ratio, because WCAG asks 4.5:1 of
body text but only 3:1 of large text. The tests below pin that distinction, the band boundaries, and the
worst-node rule.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic import probes  # noqa: E402
from sloptic.probes import _a11y_penalty, _contrast_level  # noqa: E402


def n(ratio, required=4.5):
    return {"ratio": ratio, "required": required}


# ---------------------------------------------------------------- band boundaries

def test_each_band_maps_to_its_level():
    assert _contrast_level([n(1.2)])[0] == "critical"     # 0.27
    assert _contrast_level([n(1.8)])[0] == "serious"      # 0.40
    assert _contrast_level([n(2.7)])[0] == "moderate"     # 0.60
    assert _contrast_level([n(3.8)])[0] == "minor"        # 0.84


def test_boundaries_are_inclusive_upward():
    """Exactly on a cut belongs to the milder band: < is the comparison, so 0.30 is serious not critical."""
    assert _contrast_level([n(0.30 * 4.5)])[0] == "serious"
    assert _contrast_level([n(0.50 * 4.5)])[0] == "moderate"
    assert _contrast_level([n(0.75 * 4.5)])[0] == "minor"


def test_the_measured_fixture_values_land_where_expected():
    """Real numbers axe returned for a page of known colors (#949494 / #c9c9c9 / #eeeeee on white)."""
    assert _contrast_level([n(3.03)])[0] == "moderate"    # 0.67
    assert _contrast_level([n(1.65)])[0] == "serious"     # 0.37
    assert _contrast_level([n(1.16)])[0] == "critical"    # 0.26


# ---------------------------------------------------------------- the point of normalizing

def test_the_same_ratio_grades_differently_by_text_size():
    """THE reason shortfall is used instead of the raw ratio. 2.4:1 is a 0.53 shortfall for body text but
    0.80 for large text, because WCAG only asks 3:1 of large glyphs — same pixels, different barrier."""
    body = _contrast_level([n(2.4, required=4.5)])
    large = _contrast_level([n(2.4, required=3.0)])
    assert body[0] == "moderate" and large[0] == "minor"
    assert body[1] < large[1]


# ---------------------------------------------------------------- worst node governs

def test_the_worst_node_sets_the_level_not_the_average():
    """One invisible control is a whole barrier. Averaging would let a page of fine text hide it."""
    level, worst = _contrast_level([n(4.4), n(4.3), n(1.1), n(4.2)])
    assert level == "critical" and round(worst, 2) == 0.24


def test_a_single_mild_failure_is_not_promoted_by_company():
    level, _ = _contrast_level([n(3.6), n(3.7), n(3.9)])
    assert level == "minor"


# ---------------------------------------------------------------- degrade safely

def test_nodes_without_a_required_ratio_are_ignored():
    assert _contrast_level([{"ratio": 1.1, "required": None}, n(3.8)])[0] == "minor"


def test_no_usable_data_returns_None_so_axes_own_impact_stands():
    assert _contrast_level([]) is None
    assert _contrast_level([{"ratio": None, "required": 4.5}]) is None


# ---------------------------------------------------------------- it actually changes the price

def _grade(contrast):
    """Run the probe with a stubbed browser and return (penalty, impacts)."""
    viols = [{"id": "color-contrast", "impact": "serious", "contrast": contrast}]
    orig = probes.browser.a11y_violations
    probes.browser.a11y_violations = lambda url, headers=None, **kw: viols
    try:
        ctx = type("C", (), {"base_url": "http://x", "headers": None, "evidence": {},
                             "profile": type("P", (), {"landing_path": "/"})()})()
        probes.a11y_violations_present(ctx, type("Pr", (), {"probe": {"target": "/"}})())
        return ctx.evidence["penalty_override"], ctx.evidence["impacts"], ctx.evidence.get("contrast_shortfall")
    finally:
        probes.browser.a11y_violations = orig


def test_barely_failing_now_costs_far_less_than_invisible_text():
    mild, mild_impacts, mild_sf = _grade([n(3.8)])       # 0.84 -> minor
    bad, bad_impacts, bad_sf = _grade([n(1.1)])          # 0.24 -> critical
    assert mild_impacts == {"minor": 1} and bad_impacts == {"critical": 1}
    assert mild == _a11y_penalty({"minor": 1}) and bad == _a11y_penalty({"critical": 1})
    assert bad > mild, "a page of invisible text must outscore one that just misses the bar"
    assert mild_sf == 0.84 and bad_sf == 0.24


def test_without_contrast_data_the_price_is_unchanged_from_before():
    """Regression guard: a violation carrying no ratios must still be charged axe's own 'serious', so this
    change can never silently zero the rule on a page where the data didn't come through."""
    pen, impacts, sf = _grade([])
    assert impacts == {"serious": 1} and pen == _a11y_penalty({"serious": 1}) and sf is None
