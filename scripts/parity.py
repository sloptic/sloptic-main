#!/usr/bin/env python3
"""Cross-stack PARITY dashboard from deploy_and_grade records.

The point: a low slop score is only meaningful if the fuzzer SAW the app's surface. Objectivity between
apps requires stack-invariant visibility — otherwise a modern SPA scores low because we're blind, not
because it's clean. This groups apps by LLM-identified stack and contrasts OBSERVED surface (what
black-box discovery saw, discovery.surface_metrics) against EXPECTED surface (what the source implies,
per the deploy LLM). A blind spot's signature is low observed-surface + few findings CLUSTERED on a stack
(genuine cleanliness is stack-random; blindness clusters), and — sharper — a surface TYPE the source says
exists on N apps of a stack that we observed on far fewer (five login apps, we should see five logins).

    uv run python scripts/parity.py results.jsonl                 # the dashboard
    uv run python scripts/parity.py results.jsonl --csv rows.csv  # per-app CSV (stack, surface, slop, ratio)
    uv run python scripts/parity.py results.jsonl --by framework  # group by framework (default: routing)
    uv run python scripts/parity.py results.jsonl --json          # machine-readable

Every number traces to specific apps: --csv is the per-app ledger behind the grouped view.
"""
import argparse
import csv
import json
import pathlib
import statistics
import sys
from collections import Counter, defaultdict

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from stats import load  # noqa: E402  (dedupe-by-repo loader, shared with stats.py)

# categorical surfaces with an observed<->expected pair, so parity = "did we see what the source implies?"
_TYPES = ("login", "upload", "api")


def _row(rec: dict) -> dict:
    """Flatten one record to a per-app parity row (stack + observed + expected + slop + ratio)."""
    sp = rec.get("stack_profile") or {}
    obs = rec.get("observed_surface") or {}
    exp = rec.get("expected_surface") or {}
    cov = rec.get("coverage") or {}
    tm = rec.get("timings") or {}
    slop = rec.get("slop_score")
    size = obs.get("surface_size")
    return {
        "repo": rec.get("repo"),
        "deployed": bool(rec.get("deployed")),
        "app_kind": rec.get("app_kind") or "?",
        # web_gradeable defaults True when unknown (old records) so they still count toward parity
        "web_gradeable": rec.get("web_gradeable") is not False,
        "n_features": len(rec.get("features") or []),
        "framework": sp.get("framework") or "?",
        "routing": sp.get("routing") or "?",
        "api_style": sp.get("api_style") or "?",
        "stack": rec.get("stack") or "?",
        "obs_routes": obs.get("routes"), "obs_forms": obs.get("forms"),
        "obs_inputs": obs.get("inputs"), "obs_endpoints": obs.get("endpoints"),
        # endpoints reached vs healthy: many-reached-few-healthy = env-var-dead surface (dummy keys)
        "obs_endpoints_reached": obs.get("endpoints_reached"), "obs_endpoints_dead": obs.get("endpoints_dead"),
        "obs_surface_size": size,
        "obs_login": obs.get("has_login"), "obs_upload": obs.get("has_upload"), "obs_api": obs.get("has_api"),
        "exp_login": exp.get("login"), "exp_upload": exp.get("upload"),
        "exp_search": exp.get("search"), "exp_api": exp.get("api"), "exp_views": exp.get("views"),
        "slop_score": slop, "findings": len(rec.get("findings", [])),
        # how much of the battery APPLIED — the fuzzer's-eye coverage. Low pct or many n/a kinds = we
        # tested little here (blind, or a genuinely tiny app); a low slop score then means little.
        "pct_applicable": cov.get("pct_applicable"),
        "na_kinds": len(cov.get("na_kinds") or []),
        # wall-clock per phase (measurement): which stacks are expensive to deploy vs grade
        "deploy_s": tm.get("deploy_s"), "grade_s": tm.get("grade_s"), "total_s": tm.get("total_s"),
        # slop normalized by how much we SAW: high surface + low ratio = clean; low surface = suspect
        "slop_per_surface": round(slop / size, 2) if (slop is not None and size) else None,
    }


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.mean(xs), 1) if xs else None


def group_parity(rows: list, key: str) -> dict:
    """Per-stack aggregates + TYPE parity. Parity for a surface type = of the DEPLOYED apps whose source
    says they HAVE it (expected), on how many did discovery actually OBSERVE it — i.e. the recall of that
    surface type for this stack. Low + clustered = a blind spot."""
    groups = defaultdict(list)
    for r in rows:
        groups[r[key]].append(r)
    out = {}
    for g, rs in groups.items():
        dep = [r for r in rs if r["deployed"] and r["obs_surface_size"] is not None]
        parity = {}
        for t in _TYPES:
            expected = [r for r in dep if r.get(f"exp_{t}")]                 # source says the surface exists
            observed = [r for r in expected if r.get(f"obs_{t}")]            # ...and discovery saw it
            parity[t] = (len(observed), len(expected))                       # (saw, should-have-seen)
        out[g] = {
            "n": len(rs), "deployed": sum(r["deployed"] for r in rs),
            "surface_avg": _avg([r["obs_surface_size"] for r in dep]),
            "coverage_avg": _avg([r["pct_applicable"] for r in dep]),   # avg % of battery that applied
            "findings_avg": _avg([r["findings"] for r in dep]),
            "slop_avg": _avg([r["slop_score"] for r in dep]),
            "slop_per_surface_avg": _avg([r["slop_per_surface"] for r in dep]),
            "parity": parity,
        }
    return out


def blind_spots(rows: list, key: str) -> list:
    """Ranked (stack, type, missed, observed, expected) — missed = expected−observed = the number of apps
    where the source says a surface exists but we didn't see it. This IS prevalence × brokenness (how many
    apps of the stack have it × the fraction we miss), so the ranking is the fix-order."""
    gp = group_parity(rows, key)
    spots = []
    for g, agg in gp.items():
        for t, (obs, exp) in agg["parity"].items():
            if exp and obs < exp:
                spots.append({"stack": g, "type": t, "missed": exp - obs, "observed": obs, "expected": exp})
    return sorted(spots, key=lambda s: (-s["missed"], -s["expected"]))


_CSV_COLS = ["repo", "app_kind", "web_gradeable", "deployed", "framework", "routing", "api_style", "stack",
             "n_features", "obs_routes", "obs_forms", "obs_inputs", "obs_endpoints",
             "obs_endpoints_reached", "obs_endpoints_dead", "obs_surface_size",
             "obs_login", "obs_upload", "obs_api", "exp_login", "exp_upload", "exp_search",
             "exp_api", "exp_views", "pct_applicable", "na_kinds", "deploy_s", "grade_s", "total_s",
             "slop_score", "findings", "slop_per_surface"]


def main():
    ap = argparse.ArgumentParser(description="Cross-stack parity dashboard from deploy_and_grade records.")
    ap.add_argument("results", help="the JSONL from deploy_and_grade --record")
    ap.add_argument("--by", default="routing", choices=["routing", "framework", "api_style"],
                    help="group key (default routing — the discovery-relevant axis)")
    ap.add_argument("--csv", metavar="FILE", help="write the per-app rows to FILE (the ledger) and exit")
    ap.add_argument("--json", action="store_true", help="emit machine-readable groups + blind spots")
    args = ap.parse_args()

    rows = [_row(r) for r in load(args.results)]
    if not rows:
        sys.exit("no records")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_COLS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {len(rows)} rows -> {args.csv}")
        return

    # parity/blind-spots are only meaningful for apps the black-box HTTP grader can actually assess —
    # a mobile/CLI/notebook scoring low isn't a blind spot, it's out of scope. Split them out.
    web = [r for r in rows if r["web_gradeable"]]
    nonweb = [r for r in rows if not r["web_gradeable"]]
    gp = group_parity(web, args.by)
    spots = blind_spots(web, args.by)

    if args.json:
        kinds = Counter(r["app_kind"] for r in rows)
        print(json.dumps({"n_apps": len(rows), "web_gradeable": len(web),
                          "app_kinds": dict(kinds), "group_by": args.by,
                          "groups": gp, "blind_spots": spots}, indent=2))
        return

    print(f"\n═══ cross-stack parity — {len(rows)} apps ({len(web)} web-gradeable), grouped by {args.by} ═══")

    # APP-KIND distribution — how much of the field is even a web app? (out-of-scope ≠ blind spot)
    print("\nAPP-KIND DISTRIBUTION  (only web apps are gradeable; the rest are out of scope, not blind spots)")
    for kind, n in Counter(r["app_kind"] for r in rows).most_common():
        tag = "" if kind in ("web-app", "web-api", "static-site", "?") else "   ← not web-gradeable"
        print(f"  {kind:14} {n:>3}{tag}")
    if nonweb:
        print(f"  → {len(nonweb)}/{len(rows)} ({len(nonweb)/len(rows)*100:.0f}%) are NOT web apps — "
              f"excluded from the parity below")

    # stack DISTRIBUTION (which stacks dominate — the head to cover first)
    print("\nSTACK DISTRIBUTION  (cover the head)")
    for g, agg in sorted(gp.items(), key=lambda kv: -kv[1]["n"]):
        print(f"  {g:16} {agg['n']:>3} apps  ({agg['deployed']} deployed)")

    # per-stack observed surface + test COVERAGE + TYPE parity. cov% = avg share of the battery that
    # applied; a low cov% (lots of n/a) means a low slop score is uninformative, not necessarily clean.
    print(f"\nOBSERVED SURFACE & TYPE PARITY  (per {args.by}; parity = saw / source-says-exists)")
    print(f"  {'stack':16} {'dep':>4} {'surf':>5} {'cov%':>5} {'find':>5} {'slop':>5}   "
          + "  ".join(f"{t:>9}" for t in _TYPES))
    for g, agg in sorted(gp.items(), key=lambda kv: -kv[1]["n"]):
        par = "  ".join(
            (f"{o}/{e}".rjust(9) if e else "   —".rjust(9)) for o, e in
            (agg["parity"][t] for t in _TYPES))
        print(f"  {g:16} {agg['deployed']:>4} {str(agg['surface_avg']):>5} "
              f"{str(agg['coverage_avg']):>5} {str(agg['findings_avg']):>5} "
              f"{str(agg['slop_avg']):>5}   {par}")

    # blind-spot ranking (prevalence × brokenness = # apps where we missed a surface the source implies)
    print("\nBLIND SPOTS  (fix order — apps where the source says a surface exists but we didn't see it)")
    if not spots:
        print("  (none — observed surface matches expected across every stack, or no expected labels)")
    for s in spots[:12]:
        print(f"  {s['stack']:16} {s['type']:8} missed {s['missed']}/{s['expected']} apps "
              f"(saw {s['observed']})")
    print(f"\n  → per-app ledger: scripts/parity.py {args.results} --csv rows.csv\n")


if __name__ == "__main__":
    main()
