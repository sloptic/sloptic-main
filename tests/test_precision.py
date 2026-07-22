"""precision.py classification: a fire on a non-working / catch-all / vendor-field target is flagged as a
likely false positive; a real fire on a clean working app is left alone."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from precision import analyze, _audited, _wilson  # noqa: E402


def _f(pid, pen=10, bundle="security", evidence=None, category=None, count=1, group=None):
    # category defaults to the probe id so each fixture finding sits in its OWN category -> no cross-probe
    # damping unless a test deliberately shares one (see the damped-attribution test).
    return {"probe_id": pid, "penalty": pen, "bundle": bundle, "evidence": evidence or {},
            "count": count, "category": category or pid, "group": group}


def _rec(repo, slop, findings, page_state=None):
    r = {"repo": repo, "slop_score": slop, "findings": findings}
    if page_state:
        r["coverage_audit"] = {"page_state": page_state}
    return r


def test_gate_credits_dnf_and_flags_only_ungated_residual_fps():
    recs = [
        # broken app -> DNF-class (gated), NOT a residual precision problem (the gate excludes it from scoring)
        _rec("gh/broken", 80, [_f("sec-sqli-004", 40), _f("qa-a11y-001", 26, "qa")], page_state="broken"),
        # functional=False (deterministic gate already flagged it) -> also gated
        {"repo": "gh/dnf", "slop_score": 50, "functional": False, "findings": [_f("sec-csrf-001", 25)]},
        # working catch-all: an UN-GATED phantom-sensitive probe (host-header) is a residual FP. A GATED probe
        # (sec-sqli-004, liveness-vetted) is NOT a phantom FP even here — a modern app has a catch-all frontend
        # AND a real API. A gated rate-limit is an ownership ADVISORY (real login, likely third-party), not an FP.
        _rec("gh/catchall", 60, [_f("sec-lfi-001", 30), _f("sec-sqli-004", 40), _f("sec-ratelimit-001", 15),
                                 _f("qa-http-001", 8, "qa"), _f("sec-headers-002", 12)], page_state="working"),
        # working, no catch-all -> nothing flagged
        _rec("gh/clean", 30, [_f("sec-headers-002", 12), _f("qa-a11y-001", 26, "qa")], page_state="working"),
        # XSS "reflection" into a Cloudflare anti-bot field on a working app -> residual FP
        _rec("gh/vendor", 30, [_f("sec-xss-001", 30, evidence={"field": "cf-turnstile-response"})], page_state="working"),
    ]
    a = analyze(recs)
    assert {r["repo"] for r in a["gated"]} == {"gh/broken", "gh/dnf"}          # broken + functional=False -> gated
    assert {r["repo"] for r in a["scored"]} == {"gh/catchall", "gh/clean", "gh/vendor"}   # only working apps scored
    assert a["gated_slop"] == 130                                             # 80 + 50 kept OUT of the distribution
    fp = {(repo, pid) for repo, pid, *_ in a["flagged"]}
    adv = {(repo, pid) for repo, pid, *_ in a["advisories"]}
    assert ("gh/catchall", "sec-lfi-001") in fp                              # UN-GATED phantom-sensitive on catch-all -> FP
    assert ("gh/catchall", "sec-sqli-004") not in fp                         # GATED (liveness-vetted) -> not a phantom FP
    assert ("gh/catchall", "sec-ratelimit-001") not in fp                    # gated -> not an FP...
    assert ("gh/catchall", "sec-ratelimit-001") in adv                       # ...but an ownership ADVISORY (real login)
    assert ("gh/catchall", "sec-headers-002") not in fp                      # a header is real even on a catch-all
    assert ("gh/vendor", "sec-xss-001") in fp                                # residual: vendor anti-bot field
    assert not any(repo in ("gh/broken", "gh/dnf") for repo, *_ in a["flagged"])  # gated apps never counted as FP
    assert ("gh/clean", "sec-headers-002") not in fp


def test_disputed_broken_is_scored_not_gated_and_fires_not_auto_flagged():
    # the veto: LLM said broken but discovery KEPT real surface -> deploy_and_grade set disputed_broken and did
    # NOT set functional=False. precision must SCORE it (page_state alone no longer gates) and judge fires normally.
    recs = [
        {"repo": "gh/disputed", "slop_score": 70, "disputed_broken": "broken",
         "coverage_audit": {"page_state": "broken"},
         "findings": [_f("sec-headers-002", 12), _f("qa-a11y-001", 26, "qa")]},
        _rec("gh/broken", 80, [_f("sec-headers-002", 12)], page_state="broken"),   # plain broken -> still gated
    ]
    a = analyze(recs)
    assert {r["repo"] for r in a["scored"]} == {"gh/disputed"}
    assert {r["repo"] for r in a["gated"]} == {"gh/broken"}
    assert not any(repo == "gh/disputed" for repo, *_ in a["flagged"])   # its real fires aren't flagged as FPs


def test_unaudited_surface_is_split_from_vouched_not_counted_verified():
    # the anti-"0 FP is a lie" fix: a probe with NO precision rule (a11y / headers / perf-requests) is
    # UNAUDITED, not silently 'verified'. Only a gate-vetted probe that passed a real check is VOUCHED.
    recs = [_rec("gh/app", 128, [
        _f("qa-a11y-001", 26, "qa"),                     # no rule -> unaudited
        _f("sec-headers-002", 12),                       # no rule -> unaudited (real signal, unknown owner)
        _f("perf-requests-001", 10, "performance"),      # no rule -> unaudited (the asi1 attribution-FP class)
        _f("sec-csrf-001", 40),                          # gate-vetted, non-signal rule passed -> vouched
        _f("sec-sqli-004", 40),                          # gate-vetted BUT signal-sensitive -> unconfirmed, not vouched
    ], page_state="working")]
    a = analyze(recs)
    assert set(a["unaudited"]) == {"qa-a11y-001", "sec-headers-002", "perf-requests-001"}
    assert a["unaudited"]["perf-requests-001"] == [1, 10]        # [fires, penalty]
    assert a["vouched"] == 1                                      # sec-csrf-001 only
    assert len(a["unconfirmed"]) == 1                             # sec-sqli-004: signal-sensitive beats gate-vetted
    assert a["scored_penalty"] == 26 + 12 + 10 + 40 + 40
    assert not a["flagged"]                                       # unaudited != flagged; the audit has no opinion


def test_damped_penalty_attribution_matches_the_scoring_decay():
    # the audit must report REAL in-score cost, not raw penalty*count: within ONE category the worst fire
    # counts full and each additional decays by CATEGORY_DECAY (0.6). A fan-out probe (sec-headers-001 fires
    # per-ROUTE) is exactly what raw sums over-state — 3 routes read as 30 raw but cost 19.6 in-score.
    recs = [_rec("gh/app", 50, [
        _f("qa-a11y-001", 30, "qa", category="a11y"),
        _f("sec-headers-001", 10, category="security-headers", count=3),
    ], page_state="working")]
    a = analyze(recs)
    assert round(a["unaudited"]["qa-a11y-001"][1], 4) == 30            # alone in its category -> full penalty
    assert round(a["unaudited"]["sec-headers-001"][1], 4) == 19.6      # 10 + 10*.6 + 10*.36, NOT the raw 30
    assert round(a["scored_penalty"], 4) == 49.6


def test_variant_group_counts_once_in_the_damped_attribution():
    # probes sharing a variant_group_id are one logical flaw -> only the highest-penalty member is charged
    recs = [_rec("gh/app", 30, [
        _f("qa-a11y-001", 30, "qa", category="a11y", group="qa-a11y"),
        _f("qa-a11y-002", 18, "qa", category="a11y", group="qa-a11y"),
    ], page_state="working")]
    a = analyze(recs)
    assert round(a["scored_penalty"], 4) == 30                         # the 18 variant is NOT added
    assert round(a["unaudited"]["qa-a11y-001"][1], 4) == 30
    assert a["unaudited"]["qa-a11y-002"][1] == 0                       # collapsed into its group's max


def test_perf_load_is_unconfirmed_not_verified():
    # a 12-connection concurrent burst run under a --concurrency batch is grader-load-confoundable ->
    # UNCONFIRMED (re-fire in isolation), never silently counted clean.
    a = analyze([_rec("gh/app", 10, [_f("perf-load-001", 10, "performance")], page_state="working")])
    assert len(a["unconfirmed"]) == 1 and a["vouched"] == 0
    assert not a["flagged"] and not a["unaudited"]


def test_audited_predicate_and_wilson_keeps_an_honest_upper_bound():
    assert _audited("sec-sqli-004") and _audited("perf-cwv-001") and _audited("sec-secret-006")
    assert not (_audited("perf-requests-001") or _audited("qa-a11y-001") or _audited("sec-headers-002"))
    lo, hi = _wilson(0, 30)                                       # 0/30 is NOT "0% FP, done"
    assert lo == 0.0 and 0.08 < hi < 0.14                         # honest ceiling ~11%
    assert _wilson(0, 0) == (0.0, 0.0)
