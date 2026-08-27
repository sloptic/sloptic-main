"""The post-run retry folds a subset re-grade of the WAF-blocked tail back into the full-grade record. The
orchestration needs live URLs (can't unit-test), but the MERGE is pure and must be exactly right: it moves
recovered probes out of `blocked`, clears an axis only when its whole blocked share came back, adds any new
findings, and recomputes the score, while an empty retry reproduces the record untouched."""
import json
import pathlib
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from retry_blocked import (  # noqa: E402
    _IP_BLOCK_SAMPLE, _fold_and_summary, _load_jobs, _looks_like_ip_block, _session_flags, _status,
    _throttle, _to_outcome, merge)

from sloptic.aggregate import compute_slop_score  # noqa: E402

BUNDLE = {"sec-cmdi-001": "security", "sec-ssti-001": "security", "sec-idor-002": "security",
          "sec-headers-001": "security", "qa-a11y-001": "qa", "qa-crash-010": "qa"}


def _f(pid, cat, pen, bundle="security", vg=None):
    # Mirror the PRODUCTION finding serialization (deploy_and_grade.py _record): the variant group is stored
    # under "group", and there is NO "outcome" key (every finding is a fired slop). Earlier fixtures used the
    # dataclass field name "variant_group_id", so they never exercised the key merge() actually parses.
    return {"probe_id": pid, "bundle": bundle, "category": cat, "penalty": pen, "group": vg,
            "target": "", "reason": "", "count": 1, "targets": [], "evidence": {}}


def _scored(findings, blocked, incomplete):
    return {"slop_score": compute_slop_score([_to_outcome(x) for x in findings]),
            "findings": findings, "blocked_probes": blocked, "incomplete_axes": incomplete}


def _retry(blocked, findings):
    # a retry record that ACTUALLY graded (carries the deployed=true + slop_score a real grade writes)
    return {"deployed": True, "slop_score": compute_slop_score([_to_outcome(x) for x in findings]),
            "blocked_probes": blocked, "findings": findings, "probe_filter": True}


def test_empty_retry_reproduces_the_record():
    main = _scored([_f("sec-headers-001", "security-headers", 6), _f("qa-a11y-001", "accessibility", 12, "qa")],
                   ["sec-cmdi-001", "sec-ssti-001"], ["security"])
    m = merge(main, None, BUNDLE)                     # None retry = nothing recovered
    assert m["slop_score"] == main["slop_score"]      # score invariant
    assert m["blocked_probes"] == ["sec-cmdi-001", "sec-ssti-001"]
    assert m["incomplete_axes"] == ["security"]
    assert m["retry"]["recovered"] == []


def test_full_clean_recovery_clears_the_axis():
    main = _scored([_f("sec-headers-001", "security-headers", 6), _f("qa-a11y-001", "accessibility", 12, "qa")],
                   ["sec-cmdi-001", "sec-ssti-001", "sec-idor-002"], ["security"])
    retry = _retry([], [])                            # the whole tail ran, all clean
    m = merge(main, retry, BUNDLE)
    assert m["blocked_probes"] == []                  # nothing still blocked
    assert m["incomplete_axes"] == []                 # security now fully tested -> complete
    assert m["slop_score"] == main["slop_score"]      # no new findings -> score unchanged
    assert set(m["retry"]["recovered"]) == {"sec-cmdi-001", "sec-ssti-001", "sec-idor-002"}
    assert m["retry"]["fired"] == []


def test_partial_recovery_with_a_real_injection_finding():
    main = _scored([_f("sec-headers-001", "security-headers", 6)],
                   ["sec-cmdi-001", "sec-ssti-001", "sec-idor-002"], ["security"])
    retry = _retry(["sec-idor-002"],                  # cmdi + ssti ran; idor re-tripped
                   [_f("sec-cmdi-001", "command-injection", 40)])   # cmdi FIRED
    m = merge(main, retry, BUNDLE)
    assert m["blocked_probes"] == ["sec-idor-002"]    # idor still blocked
    assert m["incomplete_axes"] == ["security"]       # idor is security -> axis stays incomplete
    assert m["slop_score"] > main["slop_score"]       # the cmdi finding raised the score
    assert set(m["retry"]["recovered"]) == {"sec-cmdi-001", "sec-ssti-001"}
    assert m["retry"]["fired"] == ["sec-cmdi-001"]
    assert any(f["probe_id"] == "sec-cmdi-001" for f in m["findings"])


def test_status_separates_full_partial_none_dnf():
    blocked = ["sec-cmdi-001", "sec-ssti-001", "sec-idor-002"]
    assert _status(blocked, _retry([], []))[:3] == ("full", 3, 3)            # whole tail ran, no re-challenge
    k, n, tot, onset = _status(blocked, {"deployed": True, "slop_score": 0,
                                         "blocked_probes": ["sec-idor-002"], "challenge_onset": "sec-idor-002"})
    assert (k, n, tot, onset) == ("partial", 2, 3, "sec-idor-002")           # got 2 back, then re-challenged
    assert _status(blocked, {"deployed": True, "slop_score": 0, "blocked_probes": blocked})[0] == "none"  # re-tripped at once
    assert _status(blocked, {"deployed": False})[0] == "dnf"                 # grade failed
    assert _status(blocked, None)[0] == "dnf"


def test_status_counts_a_preflight_waf_block_as_a_challenge():
    # deploy_and_grade now records a preflight 403/429/503 as a CHALLENGE (bot_challenge, not dead_url). The retry
    # must count it as 'none' (re-challenged, recovered nothing) -- NOT a neutral dnf -- so a CASCADE of these
    # trips the IP-block breaker and aborts, instead of fast-failing the whole tail (the sample3large DNF wave).
    blocked = ["sec-cmdi-001", "sec-ssti-001"]
    waf = {"bot_challenge": True, "challenge_stage": "entry", "deploy_error": "WAF/edge block — HTTP 403"}
    kind = _status(blocked, waf)[0]
    assert kind == "none"                                                    # a challenge, not a neutral dnf
    assert _looks_like_ip_block([(kind, True)] * _IP_BLOCK_SAMPLE) is True   # a cascade now trips the breaker


def test_variant_group_collapses_through_the_serialized_group_key():
    # REGRESSION: the serialized key is "group", not "variant_group_id". One flaw probed via several SQLi
    # syntaxes (same group) must count ONCE at its max penalty on recompute — not once per variant. If merge
    # reads the wrong key the group scatters into singles and every recovered app with multi-variant findings
    # inflates (here 40 -> 78).
    main = _scored([], ["sec-sqli-001"], ["security"])
    retry = _retry([], [_f("sec-sqli-001", "sql-injection", 40, vg="sqli"),
                        _f("sec-sqli-002", "sql-injection", 40, vg="sqli"),
                        _f("sec-sqli-003", "sql-injection", 40, vg="sqli")])
    m = merge(main, retry, BUNDLE)
    assert m["slop_score"] == 40                       # one group fire, not 3 (would be 78 with decay)


def test_clean_recovery_preserves_the_exact_stored_score():
    # A clean recovery adds no finding -> the merged score must be main's stored value EXACTLY (not a
    # from-scratch recompute, which drifts off the deduped findings). Stored score is deliberately offset
    # from what the findings recompute to, to prove merge kept the stored number rather than recomputing.
    main = _scored([_f("sec-headers-001", "security-headers", 6)], ["sec-cmdi-001"], ["security"])
    main["slop_score"] = 999                            # a value the findings do NOT recompute to
    m = merge(main, _retry([], []), BUNDLE)
    assert m["slop_score"] == 999                       # preserved, not recomputed
    assert m["blocked_probes"] == []                    # coverage still updates
    assert m["incomplete_axes"] == []


def test_retry_never_invents_a_block_outside_the_original():
    # a retry that (spuriously) reports a block the main run never had must not add it
    main = _scored([], ["sec-cmdi-001"], ["security"])
    retry = _retry(["sec-cmdi-001", "sec-ssti-001"], [])
    m = merge(main, retry, BUNDLE)
    assert m["blocked_probes"] == ["sec-cmdi-001"]    # ssti was never in the main block -> ignored


def test_dnf_retry_recovers_nothing():
    # a retry that FAILED (dead url / timeout: deployed=false, no slop_score) must keep the whole block —
    # never let a failed retry masquerade as "tail ran clean" and clear the incomplete flag
    main = _scored([_f("sec-headers-001", "security-headers", 6)],
                   ["sec-cmdi-001", "sec-ssti-001"], ["security"])
    dnf = {"deployed": False, "probe_filter": ["sec-cmdi-001", "sec-ssti-001"]}   # no grade happened
    m = merge(main, dnf, BUNDLE)
    assert m["blocked_probes"] == ["sec-cmdi-001", "sec-ssti-001"]   # block intact
    assert m["incomplete_axes"] == ["security"]                     # still incomplete
    assert m["retry"]["recovered"] == []                           # nothing recovered
    assert m["slop_score"] == main["slop_score"]


def test_ip_block_breaker_trips_on_all_entry_challenged_no_recovery():
    # every app re-challenged at entry ('none' + bot_challenge) and nothing recovered => IP-level flag, abort
    assert _looks_like_ip_block([("none", True)] * _IP_BLOCK_SAMPLE) is True


def test_ip_block_breaker_holds_fire_when_recovery_is_the_most_recent_signal():
    # a recovery in the recent window means we are NOT in a sustained block regime (a re-challenge streak that a
    # fresh recovery broke), so don't abort -- the window is trailing, so a recovery AFTER the nones clears it
    assert _looks_like_ip_block([("none", True)] * _IP_BLOCK_SAMPLE + [("full", False)]) is False
    assert _looks_like_ip_block([("none", True)] * _IP_BLOCK_SAMPLE + [("partial", True)]) is False
    # below the sample threshold it waits for more evidence
    assert _looks_like_ip_block([("none", True)] * (_IP_BLOCK_SAMPLE - 1)) is False


def test_ip_block_breaker_trips_on_midrun_flag_onset_after_early_recoveries():
    # THE regression: the flag develops MID-retry -- dozens recover on a still-clean IP, then the retry's own
    # WAF-tripper traffic re-flags it and every later app entry-challenges with zero recovery. The old global
    # `recovered == 0` was permanently disabled by those early recoveries and never fired; the windowed verdict
    # sees the trailing all-none streak and aborts.
    statuses = [("full", False)] * 40 + [("none", True)] * _IP_BLOCK_SAMPLE
    assert _looks_like_ip_block(statuses) is True
    # and a lone recovery way back in the history does not hold fire on a current sustained block
    assert _looks_like_ip_block([("partial", True)] + [("none", True)] * _IP_BLOCK_SAMPLE) is True


def test_ip_block_breaker_ignores_dnf_and_non_challenge_blocks():
    # dead-URL streaks and blocks WITHOUT a bot-challenge are not a WAF verdict, so they never trip the breaker
    assert _looks_like_ip_block([("dnf", False)] * 20) is False
    assert _looks_like_ip_block([("none", False)] * 20) is False
    # dnf entries are neutral: real entry-challenges still trip even when interleaved with dead URLs
    assert _looks_like_ip_block([("dnf", False), ("none", True)] * _IP_BLOCK_SAMPLE) is True


def test_load_jobs_dedups_by_url_and_skips_unblocked():
    recs = [{"repo": "https://a", "blocked_probes": ["sec-cmdi-001"]},
            {"repo": "https://a", "blocked_probes": ["sec-cmdi-001"]},   # dup url -> once
            {"repo": "https://b", "blocked_probes": []},                 # not blocked -> skip
            {"repo": "local-ingest-id", "blocked_probes": ["sec-cmdi-001"]},  # non-url repo -> skip
            {"repo": "https://c", "blocked_probes": ["sec-ssti-001"]}]
    assert [u for u, _bp, _rec in _load_jobs(recs)] == ["https://a", "https://c"]


def test_session_flags_reuses_a_captured_session_no_rewalk():
    # the main grade established a session -> the retry replays it via --header (auth-crawl off + _authed_headers
    # short-circuits -> NO 26-nav register walk that would re-trip the app's per-app WAF block).
    rec = {"session_replay": {"Authorization": "Bearer TOK", "Cookie": "sid=abc"}, "session_established": True}
    flags, mode = _session_flags(rec, ["--browser-auth"])
    assert mode == "reuse"
    assert "--header" in flags and "Authorization: Bearer TOK" in flags and "Cookie: sid=abc" in flags
    assert "--browser-auth" in flags        # browser probes still run; the supplied session skips the walk


def test_session_flags_skips_a_doomed_signup():
    # the main grade PROVED no self-serve session (attempted + failed) -> drop --browser-auth so the retry never
    # re-walks a signup that cannot succeed (browser render still runs -- --browser is on by default).
    rec = {"session_replay": None, "session_established": False}
    flags, mode = _session_flags(rec, ["--browser-auth"])
    assert mode == "no-signup" and "--browser-auth" not in flags


def test_session_flags_as_is_when_no_session_info():
    # a record with no session outcome (older run, or auth never attempted) -> behave as before (re-walk allowed).
    rec = {}
    flags, mode = _session_flags(rec, ["--browser-auth"])
    assert mode == "as-is" and flags == ["--browser-auth"]


def test_fold_and_summary_folds_blocked_and_copies_the_rest(tmp_path):
    # the shared fold (also the --remerge path): a blocked app with a clean-recovery retry record is folded
    # (block cleared, retry key added); an app that was never blocked is written back untouched.
    main = [{"repo": "https://blk", "blocked_probes": ["sec-cmdi-001"], "findings": [], "slop_score": 7,
             "incomplete_axes": ["security"], "axis_slop": {"security": 7}},
            {"repo": "https://clean", "findings": [], "slop_score": 5}]     # never blocked
    collected = {"https://blk": _retry([], [])}                            # tail ran, nothing fired
    out = tmp_path / "m.jsonl"
    _fold_and_summary(main, collected, Counter(), str(out), "run.jsonl", "run.retry.jsonl")
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    assert rows[0]["blocked_probes"] == [] and rows[0]["incomplete_axes"] == []   # folded
    assert rows[0]["retry"]["recovered"] == ["sec-cmdi-001"]
    assert rows[0]["slop_score"] == 7                                             # clean recovery -> exact
    assert rows[1] == main[1]                                                     # unblocked app untouched


def test_throttle_spaces_job_starts_and_zero_disables():
    # the WAF politeness gap: retry_blocked flooded Vercel with no throttle (first ~50 apps then every request
    # 403s). delay=0 must be a no-op; delay>0 spaces global job starts by ~delay each (first start is free).
    import time

    import retry_blocked as rb
    rb._next_start[0] = 0.0
    t0 = time.monotonic()
    rb._throttle(0)                       # disabled -> returns immediately
    assert time.monotonic() - t0 < 0.05
    rb._next_start[0] = 0.0
    d = 0.15
    t0 = time.monotonic()
    for _ in range(3):                    # 3 starts -> 2 gaps of d (the first is free)
        rb._throttle(d)
    elapsed = time.monotonic() - t0
    assert 2 * d - 0.05 <= elapsed <= 2 * d + 0.20
