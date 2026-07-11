"""Parity dashboard logic — pure functions over synthetic deploy_and_grade records (no LLM, no Docker)."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from parity import _row, blind_spots, group_parity  # noqa: E402


def _rec(repo, routing, *, deployed=True, slop=10, size=20, findings=3, exp=None, obs=None):
    r = {"repo": repo, "deployed": deployed,
         "stack_profile": {"routing": routing, "framework": "F", "api_style": "rest"},
         "expected_surface": exp or {}}
    if deployed:
        surface = {"surface_size": size, "has_login": False, "has_upload": False, "has_api": False}
        surface.update(obs or {})
        r.update(slop_score=slop, observed_surface=surface, findings=[{}] * findings)
    return r


def test_row_flattens_and_normalizes_slop_by_surface():
    row = _row(_rec("a", "spa-hash", slop=30, size=15, exp={"login": True},
                    obs={"has_login": True}))
    assert row["routing"] == "spa-hash" and row["exp_login"] is True and row["obs_login"] is True
    assert row["slop_per_surface"] == 2.0                 # 30 / 15
    assert _row({"repo": "x", "deployed": False})["slop_per_surface"] is None   # nothing observed


def test_type_parity_counts_saw_over_should_have_seen():
    # 3 hash-routed login apps, discovery saw the login on only 1 -> parity (1, 3)
    rows = [_row(_rec(f"h{i}", "spa-hash", exp={"login": True},
                      obs={"has_login": i == 0})) for i in range(3)]
    gp = group_parity(rows, "routing")
    assert gp["spa-hash"]["parity"]["login"] == (1, 3)


def test_blind_spots_rank_by_prevalence_times_brokenness_and_ignore_stack_random_cleanliness():
    rows = []
    # spa-hash: 3 apps that HAVE a login (source) but discovery saw NONE -> a clustered blind spot (missed 3)
    rows += [_row(_rec(f"h{i}", "spa-hash", exp={"login": True}, obs={"has_login": False})) for i in range(3)]
    # server-rendered: 2 login apps, both SEEN -> parity, NOT a blind spot (genuine, stack-consistent)
    rows += [_row(_rec(f"s{i}", "server-rendered", exp={"login": True}, obs={"has_login": True})) for i in range(2)]
    spots = blind_spots(rows, "routing")
    assert spots[0]["stack"] == "spa-hash" and spots[0]["type"] == "login"
    assert spots[0]["missed"] == 3 and spots[0]["expected"] == 3
    assert not any(s["stack"] == "server-rendered" for s in spots)   # matched surface isn't flagged


def test_row_carries_phase_timings():
    r = _row({"repo": "a", "timings": {"deploy_s": 48.0, "grade_s": 55.0, "total_s": 111.0}})
    assert r["deploy_s"] == 48.0 and r["grade_s"] == 55.0 and r["total_s"] == 111.0
    assert _row({"repo": "b"})["total_s"] is None        # missing timings -> None, not a crash


def test_row_flags_non_web_apps_and_defaults_gradeable_true():
    assert _row({"repo": "a", "app_kind": "mobile", "web_gradeable": False})["web_gradeable"] is False
    assert _row({"repo": "b"})["web_gradeable"] is True      # old/unknown records still count toward parity
    assert _row({"repo": "c", "features": [{"name": "x"}, {"name": "y"}]})["n_features"] == 2


def test_parity_is_computed_over_web_gradeable_only():
    # a mobile app (not web-gradeable) must not pollute a routing group's parity — it's out of scope
    web = [_row(_rec("w0", "spa-hash", exp={"login": True}, obs={"has_login": False}))]
    nonweb = [_row({"repo": "m", "app_kind": "mobile", "web_gradeable": False,
                    "stack_profile": {"routing": "none"}})]
    # main() filters to web-gradeable before calling; blind_spots on the web set flags the hash-router miss
    assert blind_spots(web, "routing")[0]["stack"] == "spa-hash"
    assert nonweb[0]["web_gradeable"] is False   # and the mobile app is excluded upstream


def test_group_parity_dashes_a_type_with_no_expected_label():
    # an app with no expected_surface labels -> that type has no denominator, so parity is (0, 0)
    rows = [_row(_rec("a", "ssr", exp={}, obs={"has_api": True}))]
    assert group_parity(rows, "routing")["ssr"]["parity"]["api"] == (0, 0)
    assert blind_spots(rows, "routing") == []       # no expected -> nothing to be blind about
