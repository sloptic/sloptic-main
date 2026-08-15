"""The shared record-eligibility predicates that gate the curve (benchmark.py) and the score stats (stats.py).
One definition each so the consumers can't drift (they did once: stats' winner split omitted the entry-challenge
rule and reported min=0 vs the distribution's min=8)."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from sloptic.eligibility import (SHELL_ONLY_PLATFORMS, is_shell_only,  # noqa: E402
                                 is_ungradeable_challenge, is_wrong_owner, wrong_owner_reason)
from sloptic.platform_id import wrong_owner_host  # noqa: E402


def test_entry_challenge_is_ungradeable():
    assert is_ungradeable_challenge({"challenge_stage": "entry"})
    assert is_ungradeable_challenge({"challenge_stage": "entry", "bot_challenge": True})


def test_late_challenge_is_gradeable():
    # all probes ran, THEN the origin challenged -> a valid completed grade
    assert not is_ungradeable_challenge({"challenge_stage": "late", "bot_challenge": True})
    assert not is_ungradeable_challenge({})                         # no challenge at all


def test_legacy_bot_challenge_without_stage_is_conservatively_entry():
    assert is_ungradeable_challenge({"bot_challenge": True})        # old record, no stage recorded
    assert not is_ungradeable_challenge({"bot_challenge": False})


def test_streamlit_is_shell_only():
    assert is_shell_only({"platform": {"host_platform": "streamlit"}})
    assert "streamlit" in SHELL_ONLY_PLATFORMS


def test_normal_hosts_are_not_shell_only():
    for host in ("vercel", "netlify", "render", "lovable", "github-pages"):
        assert not is_shell_only({"platform": {"host_platform": host}})
    assert not is_shell_only({})                                    # no platform block -> not shell-only
    assert not is_shell_only({"platform": {}})


def test_render_state_is_capture_based_and_overrides_platform():
    # once the render-await runs, the record's render_state decides — a RENDERED Streamlit app is a real grade
    # that counts (not shell-only), even though its platform is streamlit; error/stuck stay excluded.
    def st(rs):
        return {"platform": {"host_platform": "streamlit"}, "observed_surface": {"render_state": rs}}
    assert not is_shell_only(st("rendered"))     # real app painted -> counts in the curve
    assert is_shell_only(st("error"))            # Streamlit crash screen -> excluded
    assert is_shell_only(st("stuck"))            # never came up -> excluded


def test_legacy_streamlit_without_render_state_falls_back_to_platform():
    # v17 records predate render_state -> the platform heuristic still excludes them (pre-render-fix behaviour)
    assert is_shell_only({"platform": {"host_platform": "streamlit"}, "observed_surface": {}})
    assert is_shell_only({"platform": {"host_platform": "streamlit"}})
    # a non-streamlit new record: render_state absent -> platform fallback -> not shell-only
    assert not is_shell_only({"platform": {"host_platform": "vercel"}, "observed_surface": {"render_state": None}})


# --- wrong-owner hosts: a graded URL that is not the team's own engineered app ------------------------------

def test_wrong_owner_host_flags_third_party_and_editor_surfaces():
    cases = {
        "bye-buy.s3.us-east-1.amazonaws.com": "s3-bucket",   # raw object storage
        "s3.amazonaws.com": "s3-bucket",
        "lixingzhi8890.atlassian.net": "atlassian",          # Jira
        "team.sharepoint.com": "sharepoint",
        "teachablemachine.withgoogle.com": "google-product",
        "deck.gamma.app": "presentation",
        "art.canva.site": "design-tool",
        "zula85294.softr.app": "no-code-site",
        "my-site.wix-vibe.com": "no-code-site",
        "id-preview--abc123.lovable.app": "editor-preview",  # the Lovable EDITOR, not the deploy
    }
    for host, cat in cases.items():
        assert wrong_owner_host(host) == cat, host


def test_wrong_owner_host_keeps_first_party_apps():
    # real code hosts + AI-code-generators that emit owned code + tiiny (team's uploaded dist) are NOT wrong-owner
    for host in ("mappy-ai.vercel.app", "app.onrender.com", "x.up.railway.app", "user.github.io",
                 "punya.base44.app", "myapp.lovable.app", "cool.bolt.host", "myapp.tiiny.site",
                 "myapp.elasticbeanstalk.com"):     # elasticbeanstalk/EC2 run the team's own app -> kept
        assert wrong_owner_host(host) is None, host


def test_is_wrong_owner_reads_platform_host_then_falls_back_to_url():
    assert is_wrong_owner({"platform": {"host": "bye-buy.s3.us-east-1.amazonaws.com"}})
    assert wrong_owner_reason({"platform": {"host": "x.atlassian.net"}}) == "atlassian"
    assert is_wrong_owner({"repo": "https://zula85294.softr.app/dashboard"})   # legacy: no platform.host -> URL
    assert not is_wrong_owner({"platform": {"host": "mappy-ai.vercel.app"}})
    assert not is_wrong_owner({"repo": "https://punya.base44.app/"})
    assert not is_wrong_owner({})                                              # no host at all -> not wrong-owner
