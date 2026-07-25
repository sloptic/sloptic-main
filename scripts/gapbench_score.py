#!/usr/bin/env python3
"""Score a GapBench run against its ground truth — the fuzzer's RECALL number.

  uv run python scripts/gapbench_score.py gapbench-recall.jsonl
  uv run python scripts/gapbench_score.py gapbench-recall.jsonl --json

GapBench (vibe-eval's public benchmark) ships 104 scenarios, each declaring the CWEs it deliberately
contains, plus 7 clean controls where ANY vulnerability finding is a false positive. A grade run alone is
104 rows; this turns it into: did we catch each declared bug, and did we invent any on the controls.

The report splits the misses into the two piles that have DIFFERENT answers — the whole point of running it:

  * MISSED (covered class) — we ship a probe for that CWE and it did not fire. A real recall gap: either the
    probe is mis-gated, the discovery never reached the surface, or the detector is too narrow. Actionable.
  * UNCOVERED class — no probe of ours maps to that CWE at all (gRPC reflection, K8s dashboards, CI/supply-
    chain poisoning, MCP tool-spec injection...). NOT a bug: it is the scope boundary. Deliberately separate
    so a low headline number can't be mistaken for broken probes, and so the list doubles as the backlog.

Recall is therefore reported over the COVERED scenarios (what we claim to detect); the all-scenarios number
is printed beside it for honesty, never alone.

The CWE table below is the calibration knob: it maps OUR probe categories to the CWEs they can evidence.
Map conservatively — a too-generous entry counts an unrelated finding as a catch and inflates recall.
"""
import argparse
import collections
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_MANIFEST = _HERE.parent / "validation" / "vuln-corpus" / "gapbench-manifest.json"

# Our probe CATEGORY -> the CWEs a finding in it can legitimately evidence. Category (not probe id) is the
# unit because a category is one vulnerability class by construction; per-probe overrides below handle the
# few categories that span classes.
_CWE_BY_CATEGORY = {
    "access-control":    {"CWE-284", "CWE-285", "CWE-288", "CWE-306", "CWE-566", "CWE-639",
                          "CWE-862", "CWE-863"},
    "backend-exposure":  {"CWE-200", "CWE-284", "CWE-306", "CWE-732", "CWE-862"},
    "exposure":          {"CWE-200", "CWE-489", "CWE-538", "CWE-540"},
    "data-exposure":     {"CWE-200", "CWE-201"},
    "secrets-exposure":  {"CWE-200", "CWE-321", "CWE-522", "CWE-540", "CWE-798"},
    "sql-injection":     {"CWE-89"},
    "xss":               {"CWE-79", "CWE-80"},
    "dom-xss":           {"CWE-79", "CWE-80"},
    "path-traversal":    {"CWE-22", "CWE-23", "CWE-36"},
    "file-upload":       {"CWE-22", "CWE-434"},
    "command-injection": {"CWE-77", "CWE-78"},
    "template-injection": {"CWE-94", "CWE-1336"},
    "ssrf":              {"CWE-918"},
    "xxe":               {"CWE-611"},
    "csrf":              {"CWE-352"},
    "cors":              {"CWE-346", "CWE-942"},
    "open-redirect":     {"CWE-601", "CWE-1275"},
    "host-header":       {"CWE-201", "CWE-644"},
    "response-splitting": {"CWE-93", "CWE-113", "CWE-150"},
    "session":           {"CWE-287", "CWE-294", "CWE-384", "CWE-539", "CWE-614", "CWE-1004"},
    "session-management": {"CWE-287", "CWE-384", "CWE-539"},
    "rate-limiting":     {"CWE-307", "CWE-799"},
    # NB no CWE-319 here, deliberately. A missing HSTS header is cleartext-adjacent, but these probes fire on
    # ~90% of all apps, so crediting CWE-319 would auto-HIT every scenario declaring it (exposed database port,
    # open redis, TLS downgrade) on a finding unrelated to the actual defect. Measured: naked-postgres scored a
    # false HIT off sec-headers-001. A category that fires near-universally must not credit anything.
    "security-headers":  {"CWE-693", "CWE-1021"},
    "mixed-content":     {"CWE-319"},
    "debug-mode":        {"CWE-215", "CWE-489"},
    "error-hygiene":     {"CWE-209", "CWE-210"},
    "dependency":        {"CWE-829", "CWE-1104", "CWE-1357"},
    "input-validation":  {"CWE-20", "CWE-602"},   # qa-input-001: server accepts what its own field rejects
    "race-condition":    {"CWE-362", "CWE-367"},
    "crash-resistance":  {"CWE-248", "CWE-400"},
    "dos-resistance":    {"CWE-400", "CWE-1333"},
    "data-integrity":    {"CWE-345"},
}
# Categories deliberately mapped to NOTHING (they carry no vulnerability claim, so they can never "catch" a
# scenario and never count as a false positive on a control): accessibility, web-vitals, speed, page-weight,
# load-time, load-resilience, seo, caching, compression, request-count, console-errors, broken-links,
# dead-controls, ui-honesty, http-correctness, http-conformance, content-type.
_HYGIENE_CATEGORIES = {
    "accessibility", "web-vitals", "speed", "page-weight", "load-time", "load-resilience", "seo",
    "caching", "compression", "request-count", "console-errors", "broken-links", "dead-controls",
    "ui-honesty", "http-correctness", "http-conformance", "content-type",
}
_PROBE_OVERRIDES = {          # where a category is coarser than the probe
    "sec-authbypass-001": {"CWE-288", "CWE-306", "CWE-863"},   # Next.js middleware auth bypass
}
# Counted for RECALL (GapBench ships a csp-missing scenario, CWE-1021, that we should get credit for) but
# NEVER counted as a control false positive: a missing header is a verifiable config FACT about the response,
# not a claim that this app is exploitable — and the benchmark's own edge omits these on every scenario,
# controls included, so charging them as FPs would measure Vercel's defaults, not our precision.
_FP_EXEMPT_CATEGORIES = {"security-headers", "mixed-content"}
# every CWE ANY probe of ours can evidence -> used to split "we missed it" from "we don't cover it"
_COVERED_CWES = set().union(*_CWE_BY_CATEGORY.values(), *_PROBE_OVERRIDES.values())


def _finding_cwes(f: dict) -> set:
    return set(_PROBE_OVERRIDES.get(f.get("probe_id"), ())) or set(
        _CWE_BY_CATEGORY.get(f.get("category") or "", ()))


def _scenario_id(rec: dict) -> str | None:
    """A record's GapBench scenario: from its anchor tag (project=anchor-gapbench-<id>), else its URL."""
    proj = str(rec.get("project") or "")
    if proj.startswith("anchor-gapbench-"):
        return proj[len("anchor-gapbench-"):]
    url = str(rec.get("repo") or "")
    if "/site/" in url:
        return url.split("/site/", 1)[1].strip("/").split("/")[0] or None
    return None


def load(path) -> list:
    return [json.loads(ln) for ln in pathlib.Path(path).read_text().splitlines() if ln.strip()]


def score(recs: list, scenarios: list) -> dict:
    by_id = {}
    for r in recs:                      # last record per scenario wins (a re-run appends)
        sid = _scenario_id(r)
        if sid:
            by_id[sid] = r
    rows, controls = [], []
    for s in scenarios:
        sid = s["id"]
        expected = set(s.get("cwes") or [])
        is_control = str(s.get("vulnerability", "")).startswith("None")
        rec = by_id.get(sid)
        findings = (rec or {}).get("findings") or []
        vuln_findings = [f for f in findings
                         if _finding_cwes(f) and (f.get("category") not in _FP_EXEMPT_CATEGORIES)]
        matched = [f for f in findings if _finding_cwes(f) & expected]
        row = {
            "id": sid, "vulnerability": s.get("vulnerability", ""), "cwes": sorted(expected),
            "control": is_control,
            "graded": rec is not None and not rec.get("dead_url") and "slop_score" in (rec or {}),
            "covered": bool(expected & _COVERED_CWES),
            "matched": sorted({f["probe_id"] for f in matched}),
            "vuln_findings": sorted({f["probe_id"] for f in vuln_findings}),
            "slop": (rec or {}).get("slop_score"),
            "dead": (rec or {}).get("deploy_error") if rec else "no record in results",
        }
        (controls if is_control else rows).append(row)
    graded = [r for r in rows if r["graded"]]
    cov = [r for r in graded if r["covered"]]
    hits = [r for r in cov if r["matched"]]
    return {
        "total": len(rows), "graded": len(graded), "covered": len(cov), "hits": len(hits),
        "recall_covered": round(len(hits) / len(cov) * 100, 1) if cov else None,
        "recall_all": round(len(hits) / len(graded) * 100, 1) if graded else None,
        "rows": rows, "controls": controls,
    }


def report(res: dict) -> None:
    rows, controls = res["rows"], res["controls"]
    print(f"\n═══ GapBench recall — {res['graded']}/{res['total']} vulnerable scenarios graded ═══")
    rc = res["recall_covered"]
    print(f"\n(a) HEADLINE")
    print(f"    RECALL (covered classes): {res['hits']}/{res['covered']}"
          + (f"  ({rc}%)" if rc is not None else "")
          + "   <- scenarios whose declared CWE we ship a probe for")
    print(f"    across ALL graded:        {res['hits']}/{res['graded']}"
          + (f"  ({res['recall_all']}%)" if res['recall_all'] is not None else "")
          + "   <- includes classes we don't cover (see (d)); never quote this alone")
    cfp = [c for c in controls if c["vuln_findings"]]
    print(f"    CONTROL false positives:  {len(cfp)}/{len(controls)} clean references fired a vuln finding")

    print(f"\n(b) PER-SCENARIO  (declared bug -> did we catch it)")
    for r in sorted(rows, key=lambda x: (not x["graded"], bool(x["matched"]), x["id"])):
        if not r["graded"]:
            verdict, why = "UNGRADED", str(r["dead"] or "")[:46]
        elif r["matched"]:
            verdict, why = "HIT    ", "via " + ", ".join(r["matched"][:3])
        elif not r["covered"]:
            verdict, why = "no-cov ", "no probe maps to " + ",".join(r["cwes"])
        else:
            verdict, why = "MISS   ", "fired: " + (", ".join(r["vuln_findings"][:3]) or "nothing")
        print(f"    {verdict} {r['id']:<28} {r['vulnerability'][:30]:<30} {','.join(r['cwes']):<18} {why}")

    miss = [r for r in rows if r["graded"] and r["covered"] and not r["matched"]]
    print(f"\n(c) RECALL GAPS — we ship a probe for this class but it did NOT fire ({len(miss)})")
    if miss:
        by_cwe = collections.defaultdict(list)
        for r in miss:
            for w in r["cwes"]:
                if w in _COVERED_CWES:
                    by_cwe[w].append(r["id"])
        for w, ids in sorted(by_cwe.items(), key=lambda kv: -len(kv[1])):
            print(f"    {w:10} {len(ids):>2}x  {', '.join(sorted(ids)[:6])}")
        print("    ↳ mis-gated probe, discovery never reached the surface, or too narrow a detector")
    else:
        print("    (none — every covered class was caught)")

    nocov = [r for r in rows if r["graded"] and not r["covered"]]
    print(f"\n(d) UNCOVERED CLASSES — no probe of ours maps to these ({len(nocov)}); scope decision, not a bug")
    seen = collections.Counter(w for r in nocov for w in r["cwes"] if w not in _COVERED_CWES)
    for w, n in seen.most_common():
        ids = [r["id"] for r in nocov if w in r["cwes"]][:4]
        print(f"    {w:10} {n:>2}x  {', '.join(ids)}")

    print(f"\n(e) CONTROLS — any VULNERABILITY finding here is a false positive")
    for c in controls:
        if not c["graded"]:
            print(f"    UNGRADED {c['id']:<22} {str(c['dead'] or '')[:50]}")
        elif c["vuln_findings"]:
            print(f"    FP       {c['id']:<22} slop {c['slop']:<5} {', '.join(c['vuln_findings'])}")
        else:
            print(f"    clean    {c['id']:<22} slop {c['slop']:<5} (hygiene-only findings ignored)")
    print("    ↳ hygiene (headers/a11y/perf) is NOT counted: it carries no vulnerability claim, and the\n"
          "      benchmark's own edge omits those headers on every scenario incl. the controls.\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Score a GapBench run against its declared CWEs.")
    ap.add_argument("results", help="the JSONL from run_batch --urls validation/vuln-corpus/gapbench.txt")
    ap.add_argument("--manifest", default=str(_MANIFEST), help="GapBench ground truth (default: vendored)")
    ap.add_argument("--json", action="store_true", help="machine-readable summary instead of the report")
    args = ap.parse_args()
    scenarios = json.load(open(args.manifest))["scenarios"]
    recs = load(args.results)
    res = score(recs, scenarios)
    if args.json:
        json.dump(res, sys.stdout, indent=2)
        print()
    else:
        report(res)


if __name__ == "__main__":
    main()
