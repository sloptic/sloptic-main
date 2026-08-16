#!/usr/bin/env python3
"""List every probe in the catalog with its metadata + penalty (its "score"), for export.

    uv run python scripts/list_probes.py            # aligned table (+ per-bundle totals)
    uv run python scripts/list_probes.py --csv      # CSV to stdout  (redirect to a file)
    uv run python scripts/list_probes.py --json     # JSON to stdout
    uv run python scripts/list_probes.py --catalog DIR   # a different catalog dir

The catalog is the source of truth (catalog/**/*.yaml); this just reflects it, so it never drifts.
"""
import argparse
import csv
import json
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))   # so `sloptic` imports when run as scripts/list_probes.py

from sloptic.aggregate import compute_slop_score  # noqa: E402
from sloptic.catalog import load_catalog  # noqa: E402
from sloptic.probes import describe  # noqa: E402
from sloptic.reportcard import card_copy  # noqa: E402
from sloptic.schema import Outcome  # noqa: E402


def _check(p) -> str:
    """The detection primitive: the predicate name, or the declarative slop_if matcher(s)."""
    if "predicate" in p.probe:
        return p.probe["predicate"]
    matchers = [c if isinstance(c, str) else next(iter(c)) for c in p.slop_if]
    return "slop_if:" + ",".join(matchers) if matchers else "(declarative)"


# Predicates whose REAL penalty is computed at grade time (via evidence["penalty_override"]), so the catalog
# nominal is misleading. Keyed on predicate -> human formula; the PEN cell shows "*" and a footnote gives the
# formula. (report_only probes are handled separately -> a flat 0.)
_COMPUTED_PENALTY = {
    "lighthouse_perf_score": "max(0, 90 - N), N = Lighthouse perf score (0-100)",
    "a11y_violations_present": "sum of per-rule axe severities (can exceed the nominal)",
    "a11y_hard_fails": "sum of per-rule severities of the static a11y hard-fails",
}


def _rows(catalog):
    for p in sorted(catalog, key=lambda x: (x.bundle, x.category, x.id)):
        # report_only probes FIRE as diagnostics but are forced to penalty 0 (they contribute nothing to the
        # score -- e.g. the per-audit Lighthouse probes, since perf is scored once on the overall headline).
        # Show their EFFECTIVE penalty (0) + an [off-score] marker so the table isn't read as if they still score.
        report_only = bool(p.probe.get("report_only"))
        pen_note = "" if report_only else _COMPUTED_PENALTY.get(p.probe.get("predicate"), "")
        yield {
            "id": p.id,
            "bundle": p.bundle,
            "category": p.category,
            "penalty": 0 if report_only else p.penalty,   # nominal; see penalty_note for computed-at-grade-time
            "penalty_note": pen_note,
            "pool": p.pool,
            "evidence_model": p.evidence_model,
            "variant_group": p.variant_group_id or "",
            "requires": ";".join(p.applicability.requires),
            "check": _check(p),
            "why": ("[off-score] " + describe(p)) if report_only else describe(p),
        }


def _worst_case(probes) -> int:
    """The damped score if EVERY one of these probes fired once — the real scorer, so variant-group
    (fires once at max) and per-category diminishing-returns (0.6**i) dampers are applied exactly as in
    a live grade. The realistic ceiling for a maximally-bad app, vs the naive raw penalty sum."""
    fired = [Outcome(probe_id=p.id, bundle=p.bundle, category=p.category, outcome="slop_detected",
                     penalty=(0 if p.probe.get("report_only") else p.penalty),   # off-score probes add nothing
                     variant_group_id=p.variant_group_id) for p in probes]
    return compute_slop_score(fired)


# (dict key, column header, width) for the human table
_COLS = [("id", "ID", 18), ("bundle", "BUNDLE", 11), ("category", "CATEGORY", 18),
         ("penalty", "PEN", 3), ("pool", "POOL", 6), ("evidence_model", "MODEL", 8),
         ("check", "CHECK", 24), ("why", "WHY", 62)]


def main() -> None:
    ap = argparse.ArgumentParser(description="List every catalog probe with its metadata + penalty.")
    ap.add_argument("--catalog", default=str(_ROOT / "catalog"), help="catalog dir (default: ./catalog)")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--csv", action="store_true", help="emit CSV")
    fmt.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("-v", "--verbose", action="store_true",   # composes with --csv/--json, or stands alone
                    help="show the team REPORT-CARD copy (expected / indicates / remediation) per probe")
    args = ap.parse_args()

    catalog = load_catalog(args.catalog)
    data = list(_rows(catalog))
    if args.verbose:   # fold the report-card copy into every record (json/csv columns; human blocks below)
        for r in data:
            r["card_expected"], r["card_indicates"], r["card_remediation"] = card_copy(r["id"], r["why"])

    if args.json:
        print(json.dumps(data, indent=2))
        return
    if args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(data[0].keys()))
        w.writeheader()
        w.writerows(data)
        return
    if args.verbose:   # human: a report-card block per probe instead of the table
        for r in data:
            print(f"\n{r['id']}  [{r['bundle']}/{r['category']}]  penalty "
                  + (f"* ({r['penalty_note']})" if r.get("penalty_note") else str(r["penalty"]))
                  + (f"  ·  {r['variant_group']}" if r["variant_group"] else ""))
            print(f"  EXPECTED:    {r['card_expected']}")
            print(f"  INDICATES:   {r['card_indicates']}")
            print(f"  REMEDIATION: {r['card_remediation']}")
        print(f"\n{len(catalog)} probes.")
        return

    header = "  ".join(h.ljust(w) for _, h, w in _COLS)
    print(header)
    print("-" * len(header))
    notes = {}
    for r in data:
        if r.get("penalty_note"):
            notes[r["check"]] = r["penalty_note"]
        cells = []
        for k, _, w in _COLS:
            v = "*" if (k == "penalty" and r.get("penalty_note")) else str(r[k])   # computed at grade time
            cells.append(v[:w].ljust(w))
        print("  ".join(cells))
    print("-" * len(header))
    for pred, note in sorted(notes.items()):
        print(f"  * {pred}: real penalty = {note}")

    print("-" * len(header))
    raw = sum(p.penalty for p in catalog)
    worst = _worst_case(catalog)
    print(f"  {len(catalog)} probes · raw sum {raw} · WORST-CASE {worst}  "
          f"(every probe fires once; variant-group + category dampers applied)")
    print(f"  {'BUNDLE':<12} {'PROBES':>6} {'RAW':>6} {'WORST-CASE':>11}")
    for b in sorted({p.bundle for p in catalog}):
        bp = [p for p in catalog if p.bundle == b]
        print(f"  {b:<12} {len(bp):>6} {sum(p.penalty for p in bp):>6} {_worst_case(bp):>11}")


if __name__ == "__main__":
    main()
