"""stats.py's score-distribution population must have ONE definition (_is_graded), so sections (b) distribution,
(c) fire-frequency, (d) winner split and (e) anomalies can't drift apart. Regression: (d) once inlined the filter
WITHOUT the entry-challenge exclusion and reported min=0 against (b)'s min=8, because the entry-challenge
WITHHELDS (score 0) leaked into the winner split alone. These lock the predicate that all four now share."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from stats import _dnf_reason, _is_graded, _modalities, auth_surface, by_hackathon, lighthouse_scores  # noqa: E402

from sloptic.eligibility import is_ungradeable_challenge  # noqa: E402


def _rec(**kw):
    base = {"deployed": True, "slop_score": 40, "functional": True}
    base.update(kw)
    return base


def test_entry_challenge_withhold_is_not_graded():
    # withheld at an entry challenge -> scores 0 and is NOT distribution-eligible. THIS is the record that
    # leaked into (d) as min=0 while (b) correctly dropped it (min=8).
    assert is_ungradeable_challenge({"challenge_stage": "entry"})
    assert not _is_graded(_rec(slop_score=0, challenge_stage="entry", bot_challenge=True))


def test_late_challenge_is_a_valid_grade():
    # all probes ran, THEN the origin challenged -> a real completed grade, kept in the distribution
    assert not is_ungradeable_challenge({"challenge_stage": "late", "bot_challenge": True})
    assert _is_graded(_rec(challenge_stage="late", bot_challenge=True))


def test_legacy_bot_challenge_without_stage_is_ungradeable():
    # old records: bot_challenge set, no stage -> conservatively treated as entry
    assert is_ungradeable_challenge({"bot_challenge": True})
    assert not _is_graded(_rec(bot_challenge=True))


def test_dnf_recon_undeployed_and_unscored_are_not_graded():
    assert not _is_graded(_rec(functional=False))                  # non-functional / DNF
    assert not _is_graded(_rec(recon=True))                        # recon: host_tiers only, no probes
    assert not _is_graded(_rec(deployed=False))                    # never came up
    assert not _is_graded({"deployed": True, "functional": True})  # came up but grading aborted (no slop_score)


def test_a_plain_url_grade_including_score_zero_is_graded():
    assert _is_graded(_rec(slop_score=8))
    assert _is_graded(_rec(slop_score=0))   # a genuine 0 (no challenge) IS a real grade, kept


def test_shell_only_streamlit_is_not_a_graded_entry_but_a_rendered_one_is():
    # a short-circuited error/stuck Streamlit scores 0 but is NOT a real grade -> kept out of the descriptive
    # distribution (so it can't show as a spurious 0); a RENDERED Streamlit is a real grade and stays.
    for rs in ("error", "stuck"):
        assert not _is_graded(_rec(slop_score=0, observed_surface={"render_state": rs},
                                   platform={"host_platform": "streamlit"}))
    assert _is_graded(_rec(slop_score=40, observed_surface={"render_state": "rendered"},
                           platform={"host_platform": "streamlit"}))


# --- (a2) per-hackathon breakdown: source attribution rolled up ---------------------------------------------

def test_by_hackathon_computes_slop_and_winner_stats():
    recs = [
        _rec(hackathon="treehacks-2026", source="repo", slop_score=40, winner=True),
        _rec(hackathon="treehacks-2026", source="repo", slop_score=60, winner=True),
        _rec(hackathon="treehacks-2026", source="repo", slop_score=50),                # non-winner
        _rec(hackathon="treehacks-2026", source="repo", deployed=False, winner=True),   # winner DNF -> no score
        _rec(hackathon="la-hacks-2026", url_ingest="https://x", slop_score=20),         # URL app (not deploy-tested)
    ]
    rows = by_hackathon(recs)
    assert [r["hackathon"] for r in rows] == ["treehacks-2026", "la-hacks-2026"]        # sorted by subs desc
    t = rows[0]
    assert t["subs"] == 4 and t["graded"] == 3 and t["deploy_pct"] == 75               # 3 of 4 repo apps deployed
    assert t["median_slop"] == 50 and t["mean_slop"] == 50.0 and t["stdev_slop"] == 8.2  # pstdev(40,50,60)
    assert t["min_slop"] == 40 and t["max_slop"] == 60                                  # pool range (40,50,60)
    assert t["winners"] == 3 and t["winner_graded"] == 2                                # 3 flagged, 2 graded
    assert t["winner_median"] == 50 and t["winner_mean"] == 50.0                        # over the graded winners 40,60
    assert t["winner_stdev"] == 10.0                                                    # pstdev(40,60)
    assert t["winner_min"] == 40 and t["winner_max"] == 60                              # winner range (40,60)
    la = rows[1]
    assert la["deploy_pct"] is None and la["graded"] == 1                               # URL cohort -> deploy N/A
    assert la["median_slop"] == 20 and la["stdev_slop"] is None                         # n=1 -> stdev undefined
    assert la["min_slop"] == 20 and la["max_slop"] == 20                                # n=1 -> min==max==the value
    assert la["winners"] == 0 and la["winner_median"] is None and la["winner_stdev"] is None


def test_by_hackathon_labels_missing_slug_and_excludes_ungraded_from_slop():
    recs = [_rec(slop_score=30), _rec(hackathon="x", functional=False, slop_score=5)]  # no slug; a DNF
    rows = {r["hackathon"]: r for r in by_hackathon(recs)}
    assert rows["(unlabeled)"]["median_slop"] == 30 and rows["(unlabeled)"]["stdev_slop"] is None
    assert rows["x"]["graded"] == 0 and rows["x"]["median_slop"] is None   # DNF doesn't count toward slop
    assert rows["x"]["winner_median"] is None


def test_lighthouse_scores_summarize_performance_and_empty_otherwise():
    def _lh(perf):
        return _rec(observed_surface={"lighthouse": {"performance": perf}})
    recs = [_lh(90), _lh(60), _lh(None), _rec()]   # last two lack a perf score / any lighthouse block
    s = lighthouse_scores(recs)["performance"]
    assert s["n"] == 2 and s["median"] == 75 and s["min"] == 60 and s["max"] == 90   # median(60,90)
    assert s["green_n"] == 1 and s["pct_green"] == 50.0   # only the 90 is >=90 (green -> zero perf slop)
    # a pre-Lighthouse corpus (no scores) -> n=0, all None -> the (b2) section self-skips
    assert lighthouse_scores([_rec(), _rec()])["performance"]["n"] == 0


def test_modalities_reports_spread_and_clumps():
    # the float/spectrum scoring de-clumps the distribution; _modalities surfaces the residual clumps + the
    # unique fraction so you can SEE the spread. 8 scores, 5 distinct: 13.7×3, 0.0×2, and three singletons.
    scores = [13.7, 13.7, 13.7, 0.0, 0.0, 45.6, 12.5, 88.1]
    out = _modalities(scores)
    assert "5/8 distinct (62% unique)" in out[0]
    assert "3 app(s) tied" in out[0] and "biggest clump 3×13.7" in out[0]
    assert "3×13.7" in out[1] and "2×0" in out[1]         # both real clumps listed; the three singletons omitted


def test_modalities_none_when_every_score_is_distinct():
    out = _modalities([12.5, 13.7, 45.6])
    assert "100% unique" in out[0] and "none — every score is distinct" in out[1]


def test_dnf_reason_buckets_each_failure_most_specific_first():
    # the (a) attrition breakdown: one bucket per DNF record, most specific first, so it sums to the DNF total.
    assert _dnf_reason({"dead_url": True}).startswith("dead URL")
    assert _dnf_reason({"challenge_stage": "entry", "bot_challenge": True}).startswith("entry challenge")
    assert _dnf_reason({"functional": False}).startswith("non functional")
    assert _dnf_reason({"source": "repo", "deployed": False}).startswith("deploy failed")
    assert _dnf_reason({"source": "repo", "deployed": True}).startswith("ungraded")   # deployed, no slop_score
    # most specific wins: a dead URL that also did not deploy reads as dead URL, not deploy failed
    assert _dnf_reason({"dead_url": True, "deployed": False}).startswith("dead URL")


def test_auth_surface_sizes_registerable_hard_blocked_and_no_auth_slices():
    def app(**kw):
        s = {"has_login": False, "has_signup": False, "has_password_form": False, "has_sso": False,
             "sso_only": False, "sso_providers": [], "captcha": None}
        s.update(kw)
        return _rec(observed_surface=s)
    graded = [
        app(has_login=True, has_signup=True, has_password_form=True),                 # self registerable
        app(has_login=True, has_sso=True, sso_only=True, sso_providers=["google"]),   # SSO only, hard blocked
        app(has_login=True, captcha="hcaptcha"),                                      # captcha gated (not password)
        app(),                                                                        # no auth at all
        {"deployed": True, "slop_score": 40},                                         # no observed_surface -> excluded
    ]
    a = auth_surface(graded)
    assert a["n"] == 4                                          # the surface-less record drops out
    assert a["self_registerable"] == 1 and a["sso_only"] == 1 and a["no_auth"] == 1
    assert a["has_sso"] == 1 and a["sso_providers"]["google"] == 1 and a["captcha"]["hcaptcha"] == 1


def test_auth_surface_empty_on_a_pre_field_corpus():
    a = auth_surface([{"deployed": True, "slop_score": 40}, {"deployed": True, "slop_score": 10}])
    assert a["n"] == 0 and a["self_registerable"] == 0 and dict(a["sso_providers"]) == {}
