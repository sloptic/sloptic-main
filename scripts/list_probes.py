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
sys.path.insert(0, str(_ROOT))   # so `hacklet_runner` imports when run as scripts/list_probes.py

from hacklet_runner.aggregate import compute_slop_score  # noqa: E402
from hacklet_runner.catalog import load_catalog  # noqa: E402
from hacklet_runner.probes import describe  # noqa: E402
from hacklet_runner.schema import Outcome  # noqa: E402


def _check(p) -> str:
    """The detection primitive: the predicate name, or the declarative slop_if matcher(s)."""
    if "predicate" in p.probe:
        return p.probe["predicate"]
    matchers = [c if isinstance(c, str) else next(iter(c)) for c in p.slop_if]
    return "slop_if:" + ",".join(matchers) if matchers else "(declarative)"


def _rows(catalog):
    for p in sorted(catalog, key=lambda x: (x.bundle, x.category, x.id)):
        yield {
            "id": p.id,
            "bundle": p.bundle,
            "category": p.category,
            "penalty": p.penalty,
            "pool": p.pool,
            "evidence_model": p.evidence_model,
            "variant_group": p.variant_group_id or "",
            "requires": ";".join(p.applicability.requires),
            "check": _check(p),
            "why": describe(p),
        }


def _worst_case(probes) -> int:
    """The damped score if EVERY one of these probes fired once — the real scorer, so variant-group
    (fires once at max) and per-category diminishing-returns (0.6**i) dampers are applied exactly as in
    a live grade. The realistic ceiling for a maximally-bad app, vs the naive raw penalty sum."""
    fired = [Outcome(probe_id=p.id, bundle=p.bundle, category=p.category, outcome="slop_detected",
                     penalty=p.penalty, variant_group_id=p.variant_group_id) for p in probes]
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
    args = ap.parse_args()

    catalog = load_catalog(args.catalog)
    data = list(_rows(catalog))

    if args.json:
        print(json.dumps(data, indent=2))
        return
    if args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(data[0].keys()))
        w.writeheader()
        w.writerows(data)
        return

    header = "  ".join(h.ljust(w) for _, h, w in _COLS)
    print(header)
    print("-" * len(header))
    for r in data:
        print("  ".join(str(r[k])[:w].ljust(w) for k, _, w in _COLS))

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
