"""The post-run retry folds a subset re-grade of the WAF-blocked tail back into the full-grade record. The
orchestration needs live URLs (can't unit-test), but the MERGE is pure and must be exactly right: it moves
recovered probes out of `blocked`, clears an axis only when its whole blocked share came back, adds any new
findings, and recomputes the score, while an empty retry reproduces the record untouched."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from retry_blocked import _to_outcome, merge  # noqa: E402

from sloptic.aggregate import compute_slop_score  # noqa: E402

BUNDLE = {"sec-cmdi-001": "security", "sec-ssti-001": "security", "sec-idor-002": "security",
          "sec-headers-001": "security", "qa-a11y-001": "qa", "qa-crash-010": "qa"}


def _f(pid, cat, pen, bundle="security", vg=None):
    return {"probe_id": pid, "bundle": bundle, "category": cat, "outcome": "slop_detected",
            "penalty": pen, "variant_group_id": vg, "target": "", "reason": "", "evidence": {}}


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
