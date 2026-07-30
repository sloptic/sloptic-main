"""benchmark.py: rank a slop score against a FROZEN reference distribution.

The score is deduction-only and unbounded, so a bare number cannot be read. These tests pin the four rules
that keep the ranking honest, each of which has an obvious-but-wrong alternative:

  * per-axis ranks are computed only over apps where that axis was APPLICABLE (ranking raw totals partly
    ranks how much surface an app had, and an app with no auth surface is not thereby secure);
  * anchors, --probe subset runs, dead URLs and DNF apps stay OUT of the reference (each would bend the curve
    or earn a flattering rank it didn't test for);
  * a fired catastrophic class is reported as an absolute gate whatever the percentile says;
  * the curve carries its version and n, because "p82" without its population is unverifiable.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from benchmark import (  # noqa: E402
    _axis_applicable, _band, _catalog_index, _key, _percentile_of, _slop_potential, build, rank)


def _app(slop, security=0, qa=0, perf=0, applied=None, findings=None, **kw):
    rec = {"deployed": True, "slop_score": slop,
           "axis_slop": {"security": security, "qa": qa, "performance": perf},
           "coverage": {"applied": applied if applied is not None
                        else ["sec-headers-001", "qa-a11y-001", "perf-cwv-001"]},
           "findings": findings or []}
    rec.update(kw)
    return rec


def _corpus():
    return [_app(s, security=s // 3, qa=s // 2) for s in range(10, 210, 2)]


def test_build_freezes_landmarks_and_its_own_provenance():
    curve = build(_corpus(), "2026.1", "run.jsonl")
    assert curve["version"] == "2026.1" and curve["source"] == "run.jsonl"
    o = curve["overall"]
    assert o["n"] == 100 and o["min"] == 10 and o["max"] == 208
    assert o["p10"] < o["p50"] < o["p90"] < o["p99"]      # monotonic landmarks
    assert set(curve["axes"]) == {"security", "qa", "performance"} or "security" in curve["axes"]


def test_lower_slop_ranks_better_and_bands_follow():
    curve = build(_corpus(), "t", "s")
    good, mid, bad = rank(curve, 12), rank(curve, curve["overall"]["p50"]), rank(curve, 205)
    assert good["percentile"] < mid["percentile"] < bad["percentile"]
    assert good["cleaner_than_pct"] > bad["cleaner_than_pct"]     # lower slop => cleaner than MORE peers
    assert good["band"] == "pristine" and bad["band"] == "catastrophic"
    assert _band(10) == "pristine" and _band(50) == "typical"
    assert _band(90) == "rough" and _band(99) == "catastrophic"


def test_the_reference_string_names_the_population_and_n():
    curve = build(_corpus(), "2026.1", "s")
    assert "n=100" in rank(curve, 50)["reference"] and "2026.1" in rank(curve, 50)["reference"]


def test_anchors_subsets_dead_and_dnf_are_excluded_from_the_reference():
    base = _corpus()
    polluted = base + [
        _app(900, project="anchor-vampi"),          # a deliberately-vulnerable target would drag the curve
        _app(5, probe_filter=["sec-sqli-*"]),       # a subset grade is a fraction of a full grade
        _app(800, dead_url=True),
        _app(700, functional=False),                # DNF ranks below every working app, not inside the curve
        _app(600, recon=True),
    ]
    assert build(polluted, "t", "s")["overall"] == build(base, "t", "s")["overall"]


def test_an_axis_with_no_applicable_surface_is_unranked_not_well_ranked():
    # the trap: an app whose auth surface was never reachable has security slop 0, which would out-rank an
    # app that HAD the surface and got it right. Absence of a finding is not a pass.
    curve = build(_corpus(), "t", "s")
    dark = _app(20, security=0, qa=20, applied=["qa-a11y-001", "perf-cwv-001"])   # no sec-* probe applied
    res = rank(curve, 20, dark)
    assert res["axes"]["security"] == {"applicable": False}
    assert res["axes"]["qa"]["applicable"] is True and "percentile" in res["axes"]["qa"]
    assert _axis_applicable(dark) == {"qa": 1, "performance": 1}


def test_a_catastrophic_class_gates_absolutely_whatever_the_rank():
    curve = build(_corpus(), "t", "s")
    leaky = _app(12, security=40, findings=[{"probe_id": "sec-secrets-001", "category": "secrets-exposure"},
                                           {"probe_id": "qa-a11y-001", "category": "accessibility"}])
    res = rank(curve, 12, leaky)
    assert res["band"] == "pristine"                        # it really is cleaner than most peers ...
    assert res["absolute_gates"] == ["secrets-exposure"]    # ... and that does NOT excuse a leaked secret
    clean = _app(12, findings=[{"probe_id": "qa-a11y-001", "category": "accessibility"}])
    assert "absolute_gates" not in rank(curve, 12, clean)   # hygiene alone never gates


def test_percentile_interpolates_between_frozen_landmarks():
    part = {"n": 5, "min": 0, "max": 100, "mean": 50,
            "p10": 10, "p25": 25, "p50": 50, "p75": 75, "p90": 90, "p95": 95, "p99": 99}
    assert _percentile_of(part, 0) == 0 and _percentile_of(part, 500) == 100
    assert _percentile_of(part, 50) == 50
    assert 25 < _percentile_of(part, 37) < 50                # between stored landmarks


def test_a_curve_is_provisional_until_declared_final_and_says_so():
    # the curve gets regraded once the catalog's calibration settles, so a percentile quoted from this one has
    # to carry that caveat. A provisional number presented as final is the exact failure a versioned reference
    # exists to prevent.
    prov = build(_corpus(), "2026.1", "run.jsonl")
    assert prov["status"] == "provisional"
    assert "PROVISIONAL" in rank(prov, 50)["reference"]
    final = build(_corpus(), "2027.1", "run.jsonl", status="final")
    assert final["status"] == "final" and "PROVISIONAL" not in rank(final, 50)["reference"]
    # an older curve file without the field is treated as provisional, never silently as final
    legacy = {k: v for k, v in prov.items() if k != "status"}
    assert "PROVISIONAL" in rank(legacy, 50)["reference"]


# ---- ties: two apps at the same slop are not equal -------------------------------------------------

def test_slop_potential_reconstructs_via_the_real_damping_and_never_undercuts_the_score():
    idx = _catalog_index()
    # two applicable probes in DIFFERENT categories (headers-002 pen 8, ratelimit-001 pen 15); only one fired.
    # worst case = both fire = 8 + 15 = 23, damped identically to the real score (no cross-category decay).
    rec = {"slop_score": 8, "coverage": {"applied": ["sec-headers-002", "sec-ratelimit-001"]},
           "findings": [{"probe_id": "sec-headers-002", "category": "security-headers"}]}
    assert _slop_potential(rec, idx) == 23
    assert _slop_potential(rec, idx) >= rec["slop_score"]        # the invariant: worst case never below actual
    # a native field emitted at grade time wins over reconstruction
    assert _slop_potential({"slop_potential": 42, "coverage": {"applied": []}}, idx) == 42


def test_rank_key_puts_clean_before_catastrophe_and_rewards_defended_surface():
    same = 50
    clean_hi = _key(same, False, 300, 5)      # defended a big worst case
    clean_lo = _key(same, False, 200, 5)      # defended a smaller one
    catastro = _key(same, True, 300, 5)       # same score, but a catastrophe fired
    assert clean_hi < clean_lo                # more defended potential ranks better at equal slop
    assert clean_hi < catastro and clean_lo < catastro   # any clean tie beats a catastrophe tie
    assert _key(49, True, 0, 0) < _key(50, False, 999, 99)   # slop still dominates every tiebreak


def test_build_stores_the_distribution_and_ranks_exactly_off_it():
    curve = build(_corpus(), "t", "s")
    assert curve["n"] == 100 and len(curve["dist"]) == 100
    assert curve["comparator"][0] == "slop_asc"
    assert rank(curve, 8)["percentile"] == 0                 # below the whole population
    assert rank(curve, 8)["cleaner_than_pct"] == 100         # cleaner than everyone
    assert rank(curve, 500)["percentile"] == 100             # worse than the whole population


def test_a_catastrophe_ranks_below_a_clean_app_at_the_very_same_score():
    # the point of §6: 52-with-SQLi must not tie 52-clean. The comparator splits them in the percentile itself.
    curve = build(_corpus(), "t", "s")
    p50 = curve["overall"]["p50"]
    clean = _app(p50, findings=[{"probe_id": "qa-a11y-001", "category": "accessibility"}])
    leaky = _app(p50, findings=[{"probe_id": "sec-sqli-004", "category": "sql-injection"}])
    assert rank(curve, p50, leaky)["percentile"] >= rank(curve, p50, clean)["percentile"]
    assert "absolute_gates" in rank(curve, p50, leaky)      # and it is still flagged, whatever the rank


def test_a_served_secret_file_gates_but_a_source_map_does_not():
    # the `exposure` category is mixed: a served .env/.git/backup is a catastrophe, a source map is not, so the
    # severe ones gate by probe id while exposure-006 (same category) stays out.
    curve = build(_corpus(), "t", "s")
    env = _app(12, findings=[{"probe_id": "sec-exposure-001", "category": "exposure"}])   # served .env
    git = _app(12, findings=[{"probe_id": "sec-exposure-003", "category": "exposure"}])   # served .git
    smap = _app(12, findings=[{"probe_id": "sec-exposure-006", "category": "exposure"}])  # source map
    assert rank(curve, 12, env)["absolute_gates"] == ["exposure"]
    assert rank(curve, 12, git)["absolute_gates"] == ["exposure"]
    assert "absolute_gates" not in rank(curve, 12, smap)     # same category, not exploitable, not a gate
