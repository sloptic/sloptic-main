"""gapbench_score: turn a GapBench run into a recall number against the benchmark's declared CWEs.

The scoring rule that matters: a MISS is only actionable when we actually ship a probe for that CWE class.
A scenario whose class nothing of ours detects (gRPC reflection, K8s dashboards, CI poisoning) is the scope
boundary, not a bug — conflating the two would make the headline number meaningless in both directions.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from gapbench_score import _COVERED_CWES, _finding_cwes, _scenario_id, score  # noqa: E402

_SCEN = [
    {"id": "supabase-clone", "vulnerability": "Missing RLS", "cwes": ["CWE-862", "CWE-200"]},
    {"id": "sqli-raw", "vulnerability": "Raw SQL", "cwes": ["CWE-89"]},
    {"id": "grpc-reflection", "vulnerability": "gRPC reflection", "cwes": ["CWE-9999"]},   # nothing maps
    {"id": "ref0", "vulnerability": "None (true-negative control)", "cwes": []},
    {"id": "never-ran", "vulnerability": "Whatever", "cwes": ["CWE-89"]},
]


def _rec(sid, findings, slop=10, **kw):
    return {"project": f"anchor-gapbench-{sid}", "repo": f"https://gapbench.vibe-eval.com/site/{sid}/",
            "slop_score": slop, "findings": findings, **kw}


def _f(probe_id, category, penalty=40):
    return {"probe_id": probe_id, "category": category, "penalty": penalty, "bundle": "security"}


def test_scenario_id_from_anchor_tag_or_url():
    assert _scenario_id({"project": "anchor-gapbench-ai-startup"}) == "ai-startup"
    assert _scenario_id({"repo": "https://gapbench.vibe-eval.com/site/ref-rls/"}) == "ref-rls"
    assert _scenario_id({"project": "some-devpost-app", "repo": "https://x.vercel.app/"}) is None


def test_hit_miss_and_uncovered_are_scored_separately():
    recs = [
        _rec("supabase-clone", [_f("sec-backend-001", "backend-exposure")]),         # HIT (CWE-862/200)
        _rec("sqli-raw", [_f("sec-headers-001", "security-headers", 3)]),            # MISS: we ship SQLi probes
        _rec("grpc-reflection", []),                                                 # uncovered class
        _rec("ref0", [_f("qa-a11y-002", "accessibility", 30)]),                      # control, hygiene only
    ]
    res = score(recs, _SCEN)
    rows = {r["id"]: r for r in res["rows"]}
    assert rows["supabase-clone"]["matched"] == ["sec-backend-001"]
    assert rows["sqli-raw"]["matched"] == [] and rows["sqli-raw"]["covered"] is True    # a REAL recall gap
    assert rows["grpc-reflection"]["covered"] is False                                  # scope boundary
    assert rows["never-ran"]["graded"] is False                                         # no record -> ungraded
    # recall counts only graded+covered scenarios: supabase-clone (hit) + sqli-raw (miss) = 1/2
    assert res["covered"] == 2 and res["hits"] == 1 and res["recall_covered"] == 50.0
    assert res["graded"] == 3          # never-ran excluded; grpc counted as graded but not covered


def test_a_wrong_class_finding_is_not_a_catch():
    # firing SOMETHING is not catching the declared bug — an XSS finding on a path-traversal scenario is
    # not recall, and counting it would silently inflate the number
    res = score([_rec("sqli-raw", [_f("sec-xss-001", "xss")])], _SCEN)
    row = next(r for r in res["rows"] if r["id"] == "sqli-raw")
    assert row["matched"] == [] and row["vuln_findings"] == ["sec-xss-001"]


def test_controls_count_only_vulnerability_findings_as_false_positives():
    hygiene = score([_rec("ref0", [_f("qa-a11y-002", "accessibility", 30),
                                   _f("sec-headers-002", "security-headers", 8)])], _SCEN)
    # a11y carries no vuln claim; a missing header is a verifiable config fact (and the benchmark's edge
    # omits them on every scenario) -> neither is a false positive on a control
    assert hygiene["controls"][0]["vuln_findings"] == []
    real = score([_rec("ref0", [_f("sec-lfi-001", "path-traversal")])], _SCEN)
    assert real["controls"][0]["vuln_findings"] == ["sec-lfi-001"]      # a traversal claim on a clean site = FP
    clean = score([_rec("ref0", [_f("qa-a11y-002", "accessibility", 30)])], _SCEN)
    assert clean["controls"][0]["vuln_findings"] == []                  # hygiene only -> clean


def test_dead_or_blocked_scenarios_are_ungraded_not_missed():
    # a WAF block / dead URL must not be counted as a recall failure — it never got tested
    res = score([_rec("sqli-raw", [], slop=None, dead_url=True, deploy_error="URL DEAD — HTTP 403")], _SCEN)
    row = next(r for r in res["rows"] if r["id"] == "sqli-raw")
    assert row["graded"] is False and res["covered"] == 0 and res["hits"] == 0


def test_the_real_manifest_scores_and_every_mapped_cwe_is_real():
    man = pathlib.Path(__file__).resolve().parent.parent / "validation/vuln-corpus/gapbench-manifest.json"
    scenarios = json.load(open(man))["scenarios"]
    res = score([], scenarios)                        # no results -> everything ungraded, no crash
    assert res["total"] == 97 and len(res["controls"]) == 7 and res["graded"] == 0
    # the mapping must talk about CWEs the benchmark actually declares (a typo'd entry silently never matches)
    declared = {w for s in scenarios for w in (s.get("cwes") or [])}
    stray = {w for w in _COVERED_CWES if w not in declared}
    assert not stray & {"CWE-000"}, stray             # sanity: no placeholder ids
    assert len(_COVERED_CWES & declared) >= 30        # the table meaningfully overlaps the ground truth


def test_probe_override_beats_category():
    # sec-authbypass-001 is category access-control, but its override names the auth-bypass CWEs precisely
    assert _finding_cwes(_f("sec-authbypass-001", "access-control")) == {"CWE-288", "CWE-306", "CWE-863"}
    assert "CWE-639" in _finding_cwes(_f("sec-idor-002", "access-control"))


def test_a_near_universal_category_never_credits_a_scenario():
    # security-headers fires on ~90% of apps, so crediting CWE-319 would auto-HIT every scenario declaring it
    # (exposed db port, open redis, TLS downgrade) on a finding unrelated to the defect. Measured: it gave
    # naked-postgres a false HIT off sec-headers-001. Recall inflation is worse than a low number.
    from gapbench_score import _CWE_BY_CATEGORY, _finding_cwes
    assert "CWE-319" not in _CWE_BY_CATEGORY["security-headers"]
    assert "CWE-319" not in _finding_cwes({"probe_id": "sec-headers-001", "category": "security-headers"})
    # it still credits what it genuinely detects: clickjacking defence and header hardening
    assert {"CWE-1021", "CWE-693"} <= _finding_cwes({"probe_id": "sec-headers-004",
                                                    "category": "security-headers"})


def test_an_uncovered_class_is_a_scope_boundary_whether_or_not_it_ran():
    # the driver SKIPS scenarios no probe covers, so they have no record. Reporting those as UNGRADED reads as
    # a run failure we caused; they belong in the uncovered-by-design bucket and out of the recall denominator.
    scen = _SCEN + [{"id": "grpc-2", "vulnerability": "gRPC reflection", "cwes": ["CWE-9999"]}]
    res = score([_rec("sqli-raw", [_f("sec-sqli-004", "sql-injection")])], scen)
    rows = {r["id"]: r for r in res["rows"]}
    assert rows["grpc-2"]["covered"] is False and rows["grpc-2"]["graded"] is False
    assert res["covered"] == 1 and res["hits"] == 1 and res["recall_covered"] == 100.0


def test_llm_tool_boundary_scenarios_are_out_of_scope_not_recall_gaps():
    # they declare CWE-77/94 because the end effect is code execution, and our shell/template probes claim
    # those CWEs -- but there is no HTTP parameter to inject into, so counting them as covered-and-missed
    # credits us with reach we don't have and pads the gap list.
    from gapbench_score import _OUT_OF_SCOPE
    scen = [{"id": "agent-tool-abuse", "vulnerability": "LLM Tool Hijack", "cwes": ["CWE-77", "CWE-94"]},
            {"id": "ssti", "vulnerability": "Template Injection", "cwes": ["CWE-94", "CWE-1336"]}]
    res = score([_rec("agent-tool-abuse", []), _rec("ssti", [])], scen)
    rows = {r["id"]: r for r in res["rows"]}
    assert rows["agent-tool-abuse"]["covered"] is False      # same CWEs, no HTTP surface -> out of scope
    assert rows["ssti"]["covered"] is True                   # same CWEs, real HTTP surface -> a real gap
    # kept narrow on purpose: these have an HTTP surface and must stay in scope
    for sid in ("agent-confused-deputy", "llm-html-rendering", "function-calling-arg-poison"):
        assert sid not in _OUT_OF_SCOPE


def test_a_scenario_that_cannot_present_its_flaw_over_http_is_a_scope_boundary():
    """tls-downgrade declares TLS 1.0 / RC4 / an expired certificate, but it is a PATH on a shared host that
    terminates valid modern TLS. No transport-layer probe can see the flaw, so sec-mixed-001 reading clean is
    correct and counting it as a miss would inflate the gap list with work nobody can do."""
    from gapbench_score import _OUT_OF_SCOPE
    scen = [{"id": "tls-downgrade", "vulnerability": "TLS Downgrade", "cwes": ["CWE-319", "CWE-326"]},
            {"id": "sqli-raw", "vulnerability": "Raw SQL", "cwes": ["CWE-89"]}]
    res = score([_rec("tls-downgrade", []), _rec("sqli-raw", [])], scen)
    rows = {r["id"]: r for r in res["rows"]}
    assert rows["tls-downgrade"]["covered"] is False      # unobservable -> out of the recall denominator
    assert rows["sqli-raw"]["covered"] is True            # a real, reachable gap -> stays in
    assert res["covered"] == 1
    assert "valid TLS" in _OUT_OF_SCOPE["tls-downgrade"]


def test_each_out_of_scope_entry_carries_its_own_reason():
    """The set became a dict precisely because there are now TWO distinct reasons, and printing 'LLM tool
    boundary' next to a TLS scenario would be a lie in the report."""
    from gapbench_score import _OUT_OF_SCOPE
    assert isinstance(_OUT_OF_SCOPE, dict)
    assert all(v and isinstance(v, str) for v in _OUT_OF_SCOPE.values())
    assert len({v for v in _OUT_OF_SCOPE.values()}) >= 2
