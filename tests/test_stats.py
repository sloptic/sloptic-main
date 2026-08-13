"""stats.py's score-distribution population must have ONE definition (_is_graded), so sections (b) distribution,
(c) fire-frequency, (d) winner split and (e) anomalies can't drift apart. Regression: (d) once inlined the filter
WITHOUT the entry-challenge exclusion and reported min=0 against (b)'s min=8, because the entry-challenge
WITHHELDS (score 0) leaked into the winner split alone. These lock the predicate that all four now share."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from stats import _is_graded  # noqa: E402

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
