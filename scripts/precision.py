#!/usr/bin/env python3
"""precision.py — audit a results JSONL for likely FALSE POSITIVES, so the slop score can be trusted.

stats.py answers "where does slop concentrate?" (recall). This answers "are the fires REAL?" (precision) —
the half stats.py is blind to, and the half a SCORED competition cannot ship without.

The dominant FP mode on real corpora (found dogfooding the Bolt hackathon): a static-SPA catch-all, or a
broken / soft-404 shell, serves the SAME 200 page for every path. Discovery hallucinates phantom
forms/endpoints from that shell, and the server-side probes (SQLi/CSRF/injection/rate-limit) fire on
endpoints that don't exist server-side — e.g. a submission scored SQLi-40 + CSRF-25 on a literal 404 page.
The tell is already on every record: the LLM coverage-audit's `page_state` (broken/placeholder/not-an-app)
and whether the soft-404 probe fired (catch-all). This tool flags those fires deterministically, estimates
per-probe precision, and quantifies how much of the score is phantom.

OFF-SCORE + advisory: it never mutates a slop score. It tells you which fires to distrust and which probes
to harden (the fix is a catch-all/liveness GATE in discovery so the phantom surface is never scored). Run:
    uv run python scripts/precision.py results.jsonl [--json] [--show N]
"""
import argparse
import json
from collections import Counter, defaultdict

# Probes that require a REAL server-side endpoint or state change — hallucinated on a catch-all/broken shell.
_PHANTOM_SENSITIVE = ("sec-sqli", "sec-csrf", "sec-cmdi", "sec-ssti", "sec-lfi", "sec-hosthdr",
                      "sec-split", "sec-ratelimit", "sec-idor", "sec-redirect", "sec-dos", "sec-xss",
                      "sec-ssrf", "qa-crash", "qa-race")
# These probes now route through the endpoint-level LIVENESS GATE (_endpoint_is_live in probes.py): they
# only fire on an endpoint proven distinct from a nonexistent sibling under its own prefix. So a SURVIVING
# fire is on a REAL server endpoint, and the host-level catch-all flag no longer implies a phantom — a modern
# app routinely pairs a catch-all SPA FRONTEND with a real API BACKEND (roadio's /api/locations/search, a real
# SQLi, was firing correctly but getting false-flagged here just because the frontend is a catch-all). We
# TRUST the gate for these and never call their fires catch-all phantoms.
_GATE_VETTED = ("sec-sqli-004", "sec-ratelimit-001", "sec-csrf-001", "qa-crash-010")
# Everything else (headers/a11y/seo/perf/compression/dead-controls/...) measures the ACTUAL served
# response and stays real even on a catch-all — a missing CSP header is missing regardless.
_NON_WORKING = {"broken", "not-an-app", "placeholder"}   # page states where the WHOLE surface is untrustworthy
# Third-party fields that reflect by design (anti-bot tokens) — an XSS "reflection" here is the vendor's, not the app's.
_VENDOR_FIELDS = ("cf-turnstile-response", "g-recaptcha-response", "h-captcha-response", "__requestverificationtoken")


def _phantom_sensitive(pid):
    return pid.startswith(_PHANTOM_SENSITIVE)


def _page_state(r):
    return (r.get("coverage_audit") or {}).get("page_state")


def _soft404(r):
    return any(f.get("probe_id") == "qa-http-001" for f in r.get("findings", []))


def _suspect(f, catch_all):
    """Classify finding f on a scored app as one of:
      - ("fp", reason)        a likely FALSE POSITIVE (counts toward the precision gap)
      - ("advisory", reason)  a REAL finding flagged for review (NOT an FP), e.g. a third-party platform login
      - None                  looks real
    Gate-aware: sec-sqli-004 / sec-ratelimit-001 / sec-csrf-001 / qa-crash-010 route through the liveness gate,
    so a surviving fire is on a real endpoint — never a catch-all phantom. Rate-limit on a catch-all-frontend
    host is the one nuance: the login is live but is often a THIRD-PARTY platform login (real endpoint, wrong
    OWNER), so it is an advisory, not an FP — it dissolves when teams submit their own URLs."""
    pid = f.get("probe_id", "")
    ev = f.get("evidence") or {}
    if pid.startswith("sec-xss") and (ev.get("field") or "").lower() in _VENDOR_FIELDS:
        return ("fp", f"reflection is a vendor anti-bot field ({ev.get('field')}), not app-controlled XSS")
    if pid == "sec-ratelimit-001" and catch_all:
        return ("advisory", "rate-limit on a live login on a catch-all-frontend host — likely a third-party "
                            "platform login (real endpoint, verify it is the team's own app)")
    if pid in _GATE_VETTED:
        return None   # liveness-gated: a surviving fire is on a REAL endpoint, not a catch-all phantom
    if _phantom_sensitive(pid) and catch_all:
        return ("fp", "catch-all / soft-404 host — the targeted endpoint likely doesn't exist server-side "
                      "(un-gated phantom-sensitive probe)")
    # NOTE: a login-wall is NOT flagged — its login form + rate-limiting ARE real, testable surface.
    return None


def load(path):
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _gated(r):
    """DNF-class: excluded from scoring. functional=False is the grader's authoritative verdict (set with
    corroboration — a deterministic broken signal, or no real surface); the page_state fallback covers records
    graded before the veto. A `disputed_broken` record is the veto's product — the LLM called it broken but
    real surface was captured, so it's SCORED, never gated (and its fires ARE audited like any scored app)."""
    if r.get("disputed_broken"):
        return False
    return r.get("functional") is False or _page_state(r) in _NON_WORKING


def analyze(recs):
    have_score = [r for r in recs if isinstance(r.get("slop_score"), (int, float))]
    gated = [r for r in have_score if _gated(r)]          # correctly DNF'd by the gate -> not a precision problem
    scored = [r for r in have_score if not _gated(r)]     # the apps that ACTUALLY count toward the score
    per_probe = defaultdict(lambda: [0, 0])              # pid -> [fires, FALSE-positives]
    fp_reasons, adv_reasons = Counter(), Counter()
    flagged, advisories = [], []                         # (repo, pid, penalty, count, reason)
    catchall_apps = 0
    for r in scored:                                     # measure precision ONLY on what's actually scored
        catch_all = _soft404(r) or bool((r.get("observed_surface") or {}).get("catch_all"))
        catchall_apps += bool(catch_all)
        for f in r.get("findings", []):
            pid = f["probe_id"]
            per_probe[pid][0] += 1
            res = _suspect(f, catch_all)
            if not res:
                continue
            klass, why = res
            row = (r.get("repo", ""), pid, f.get("penalty", 0), f.get("count", 1), why)
            if klass == "fp":
                per_probe[pid][1] += 1
                fp_reasons[why.split(" —")[0].split(" (")[0]] += 1
                flagged.append(row)
            else:                                        # advisory: a REAL finding flagged for review, not an FP
                adv_reasons[why.split(" —")[0].split(" (")[0]] += 1
                advisories.append(row)
    return {"scored": scored, "gated": gated, "gated_slop": sum(r.get("slop_score") or 0 for r in gated),
            "per_probe": per_probe, "fp_reasons": fp_reasons, "adv_reasons": adv_reasons,
            "flagged": flagged, "advisories": advisories, "catchall_apps": catchall_apps}


def main():
    ap = argparse.ArgumentParser(description="Audit a results JSONL for likely false positives (precision).")
    ap.add_argument("results")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--show", type=int, default=20, help="how many flagged findings to list")
    args = ap.parse_args()
    recs = load(args.results)
    a = analyze(recs)
    scored = a["scored"]
    total_fires = sum(v[0] for v in a["per_probe"].values())
    total_fp = sum(v[1] for v in a["per_probe"].values())
    fp_apps = len({x[0] for x in a["flagged"]})
    adv_apps = len({x[0] for x in a["advisories"]})

    if args.json:
        print(json.dumps({
            "n_scored": len(scored), "n_gated_dnf": len(a["gated"]), "gated_slop": a["gated_slop"],
            "scored_fires": total_fires, "false_positive_fires": total_fp, "fp_apps": fp_apps,
            "advisory_fires": len(a["advisories"]), "advisory_apps": adv_apps, "catchall_apps": a["catchall_apps"],
            "per_probe_precision": {pid: {"fires": v[0], "false_positives": v[1],
                                          "precision_pct": round((v[0] - v[1]) / v[0] * 100, 1) if v[0] else None}
                                    for pid, v in sorted(a["per_probe"].items())},
            "fp_reasons": dict(a["fp_reasons"].most_common()),
            "advisory_reasons": dict(a["adv_reasons"].most_common()),
        }, indent=2))
        return

    print(f"\n═══ precision audit — {len(scored)} SCORED apps  ({len(a['gated'])} DNF'd by the gate, excluded) ═══")
    print(f"\n(0) DNF GATE — {len(a['gated'])} apps flagged broken/not-an-app -> ranked DNF-class, EXCLUDED from "
          f"scoring\n    ({a['gated_slop']} slop the gate correctly kept OUT of the distribution — not a precision gap).")
    print(f"\n(1) RESIDUAL FALSE POSITIVES ON SCORED APPS — the real precision gap that's LEFT")
    print(f"    (sqli/rate-limit/csrf/crash route through the liveness gate, so a surviving fire is on a REAL")
    print(f"     endpoint — never a catch-all phantom. The residual is un-gated probes + vendor-reflection XSS.)")
    if a["fp_reasons"]:
        print(f"    {total_fp}/{total_fires} fires are likely FALSE POSITIVES  ({total_fp/(total_fires or 1)*100:.0f}%), "
              f"across {fp_apps} apps:")
        for why, n in a["fp_reasons"].most_common():
            print(f"      {n:>4}  {why}")
    else:
        print(f"    none — every fire on a scored app looks real (0/{total_fires}). Precision clean.")

    if a["advisories"]:
        print(f"\n(1b) OWNERSHIP-FLAGGED — REAL findings on live endpoints, NOT false positives")
        print(f"    {len(a['advisories'])} fires across {adv_apps} apps. These dissolve when teams submit their OWN URLs:")
        for why, n in a["adv_reasons"].most_common():
            print(f"      {n:>4}  {why}")

    print(f"\n(2) PER-PROBE PRECISION  (phantom-sensitive probes, SCORED apps only; [gated] = liveness-vetted)")
    rows = [(pid, v[0], v[1]) for pid, v in a["per_probe"].items() if _phantom_sensitive(pid) and v[0]]
    for pid, fires, fp in sorted(rows, key=lambda x: -x[2]) or [(None, 0, 0)]:
        if pid is None:
            print("    (no phantom-sensitive probes fired on scored apps)")
            break
        prec = (fires - fp) / fires * 100
        tag = " [gated]" if pid in _GATE_VETTED else ""
        print(f"    {pid:20} {fires:>4} fires · {fp:>4} FP · precision {prec:5.0f}% {'█' * int(round(prec / 5))}{tag}")

    combined = [("   ", *x) for x in a["flagged"]] + [("[A]", *x) for x in a["advisories"]]
    if combined:
        print(f"\n(3) FLAGGED FINDINGS  (top {args.show} by penalty; [A] = advisory/ownership, not an FP)")
        for mark, repo, pid, pen, cnt, why in sorted(combined, key=lambda x: -x[3])[:args.show]:
            print(f"    {mark} {(repo or '').rsplit('/', 1)[-1][:28]:28} {pid:18} pen={pen:>3}×{cnt:<2} — {why[:52]}")
    print()


if __name__ == "__main__":
    main()
