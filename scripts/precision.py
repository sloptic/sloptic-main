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


def _suspect(r, f, catch_all, state):
    """Return a (reason) string if finding f on record r is a likely false positive, else None."""
    pid = f.get("probe_id", "")
    ev = f.get("evidence") or {}
    if state in _NON_WORKING:
        return f"non-working app (page_state={state}) — discovered surface is hallucinated"
    if pid.startswith("sec-xss") and (ev.get("field") or "").lower() in _VENDOR_FIELDS:
        return f"reflection is a vendor anti-bot field ({ev.get('field')}), not app-controlled XSS"
    if _phantom_sensitive(pid) and catch_all:
        return "catch-all / soft-404 host — the targeted endpoint likely doesn't exist server-side"
    if state == "login-wall" and _phantom_sensitive(pid):
        return "login-wall — the app is gated; the tested surface is the wall shell, not the app"
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
    """DNF-class: the gate already excludes it from scoring (functional=False, or the audit says broken/
    not-an-app/placeholder). Its fires aren't residual FPs to chase — they never enter the distribution."""
    return r.get("functional") is False or _page_state(r) in _NON_WORKING


def analyze(recs):
    have_score = [r for r in recs if isinstance(r.get("slop_score"), (int, float))]
    gated = [r for r in have_score if _gated(r)]          # correctly DNF'd by the gate -> not a precision problem
    scored = [r for r in have_score if not _gated(r)]     # the apps that ACTUALLY count toward the score
    per_probe = defaultdict(lambda: [0, 0])              # pid -> [fires, suspect]
    reasons = Counter()
    flagged = []                                         # (repo, pid, penalty, count, reason)
    catchall_apps = 0
    for r in scored:                                     # measure precision ONLY on what's actually scored
        state = _page_state(r)
        catch_all = _soft404(r) or bool((r.get("observed_surface") or {}).get("catch_all"))
        catchall_apps += bool(catch_all)
        for f in r.get("findings", []):
            pid = f["probe_id"]
            per_probe[pid][0] += 1
            why = _suspect(r, f, catch_all, state)
            if why:
                per_probe[pid][1] += 1
                reasons[why.split(" —")[0].split(" (")[0]] += 1
                flagged.append((r["repo"], pid, f.get("penalty", 0), f.get("count", 1), why))
    return {"scored": scored, "gated": gated, "gated_slop": sum(r.get("slop_score") or 0 for r in gated),
            "per_probe": per_probe, "reasons": reasons, "flagged": flagged, "catchall_apps": catchall_apps}


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
    total_suspect = sum(v[1] for v in a["per_probe"].values())
    suspect_apps = len({f[0] for f in a["flagged"]})

    if args.json:
        print(json.dumps({
            "n_scored": len(scored), "n_gated_dnf": len(a["gated"]), "gated_slop": a["gated_slop"],
            "scored_fires": total_fires, "suspect_fires": total_suspect, "suspect_apps": suspect_apps,
            "catchall_apps": a["catchall_apps"],
            "per_probe_precision": {pid: {"fires": v[0], "suspect": v[1],
                                          "precision_pct": round((v[0] - v[1]) / v[0] * 100, 1) if v[0] else None}
                                    for pid, v in sorted(a["per_probe"].items())},
            "residual_reasons": dict(a["reasons"].most_common()),
        }, indent=2))
        return

    print(f"\n═══ precision audit — {len(scored)} SCORED apps  ({len(a['gated'])} DNF'd by the gate, excluded) ═══")
    print(f"\n(0) DNF GATE — {len(a['gated'])} apps flagged broken/not-an-app -> ranked DNF-class, EXCLUDED from "
          f"scoring\n    ({a['gated_slop']} slop the gate correctly kept OUT of the distribution — not a precision gap).")
    print(f"\n(1) RESIDUAL FALSE POSITIVES ON SCORED APPS — the real precision gap that's LEFT")
    if a["reasons"]:
        print(f"    {total_suspect}/{total_fires} fires on scored apps suspect  ({total_suspect/(total_fires or 1)*100:.0f}%), "
              f"across {suspect_apps} apps:")
        for why, n in a["reasons"].most_common():
            print(f"      {n:>4}  {why}")
    else:
        print(f"    none — every fire on a scored app looks real (0/{total_fires}). Precision clean.")
    print(f"\n(2) PER-PROBE PRECISION  (phantom-sensitive probes, SCORED apps only)")
    rows = [(pid, v[0], v[1]) for pid, v in a["per_probe"].items() if _phantom_sensitive(pid) and v[0]]
    for pid, fires, susp in sorted(rows, key=lambda x: -x[2]) or [(None, 0, 0)]:
        if pid is None:
            print("    (no phantom-sensitive probes fired on scored apps)")
            break
        prec = (fires - susp) / fires * 100
        print(f"    {pid:20} {fires:>4} fires · {susp:>4} suspect · precision {prec:5.0f}% {'█' * int(round(prec / 5))}")
    if a["flagged"]:
        print(f"\n(3) FLAGGED FINDINGS  (top {args.show} by penalty)")
        for repo, pid, pen, cnt, why in sorted(a["flagged"], key=lambda x: -x[2])[:args.show]:
            print(f"    {repo.rsplit('/', 1)[-1][:30]:30} {pid:18} pen={pen:>3}×{cnt:<2} — {why[:58]}")
    print()


if __name__ == "__main__":
    main()
