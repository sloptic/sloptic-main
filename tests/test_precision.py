"""precision.py classification: a fire on a non-working / catch-all / vendor-field target is flagged as a
likely false positive; a real fire on a clean working app is left alone."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from precision import analyze  # noqa: E402


def _f(pid, pen=10, bundle="security", evidence=None):
    return {"probe_id": pid, "penalty": pen, "bundle": bundle, "evidence": evidence or {}, "count": 1}


def _rec(repo, slop, findings, page_state=None):
    r = {"repo": repo, "slop_score": slop, "findings": findings}
    if page_state:
        r["coverage_audit"] = {"page_state": page_state}
    return r


def test_credits_the_dnf_gate_and_flags_only_residual_fps_on_scored_apps():
    recs = [
        # broken app -> DNF-class (gated), NOT a residual precision problem (the gate excludes it from scoring)
        _rec("gh/broken", 80, [_f("sec-sqli-004", 40), _f("qa-a11y-001", 26, "qa")], page_state="broken"),
        # functional=False (deterministic gate already flagged it) -> also gated
        {"repo": "gh/dnf", "slop_score": 50, "functional": False, "findings": [_f("sec-csrf-001", 25)]},
        # working catch-all (soft-404 fired) -> a RESIDUAL FP on a scored app; the header fire stays real
        _rec("gh/catchall", 60, [_f("sec-csrf-001", 25), _f("qa-http-001", 8, "qa"), _f("sec-headers-002", 12)],
             page_state="working"),
        # working, no catch-all -> nothing flagged
        _rec("gh/clean", 30, [_f("sec-headers-002", 12), _f("qa-a11y-001", 26, "qa")], page_state="working"),
        # XSS "reflection" into a Cloudflare anti-bot field on a working app -> residual FP
        _rec("gh/vendor", 30, [_f("sec-xss-001", 30, evidence={"field": "cf-turnstile-response"})], page_state="working"),
    ]
    a = analyze(recs)
    assert {r["repo"] for r in a["gated"]} == {"gh/broken", "gh/dnf"}          # broken + functional=False -> gated
    assert {r["repo"] for r in a["scored"]} == {"gh/catchall", "gh/clean", "gh/vendor"}   # only working apps scored
    assert a["gated_slop"] == 130                                             # 80 + 50 kept OUT of the distribution
    flagged = {(repo, pid) for repo, pid, *_ in a["flagged"]}
    assert ("gh/catchall", "sec-csrf-001") in flagged                        # residual: phantom-sensitive on catch-all
    assert ("gh/catchall", "sec-headers-002") not in flagged                 # a header is real even on a catch-all
    assert ("gh/vendor", "sec-xss-001") in flagged                           # residual: vendor anti-bot field
    assert not any(repo in ("gh/broken", "gh/dnf") for repo, *_ in a["flagged"])  # gated apps never counted as FP
    assert ("gh/clean", "sec-headers-002") not in flagged


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
