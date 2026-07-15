"""Generate a team-facing DURABILITY REPORT CARD from a grade record — the explainability layer a mandatory
credential needs: each finding as expected / actual / what-it-indicates / how-to-fix, so a team that fails
the fuzzer knows exactly where and how to improve.

    uv run python scripts/report_card.py results.jsonl --app https://theirapp.vercel.app
    uv run python scripts/report_card.py results.jsonl --app theirapp --html card.html   # publishable page
    uv run python scripts/report_card.py results.jsonl --app theirapp --organizer         # reveal hidden checks
    uv run python scripts/report_card.py results.jsonl --all --html-dir cards/            # one card per app

PUBLIC findings render in full (teams learn + fix real durability); HIDDEN-pool findings (HackLet League's
anti-gaming set) are an opaque count in the team card and only itemized under --organizer. The catalog is the
pool source of truth, so marking a probe `pool: hidden` withholds it from team cards automatically."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from hacklet_runner.reportcard import build_card, to_html, to_markdown  # noqa: E402


def _load(results_path: str) -> list[dict]:
    recs = []
    for line in pathlib.Path(results_path).read_text().splitlines():
        line = line.strip()
        if line:
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return recs


def _key(rec: dict) -> str:
    return rec.get("url") or rec.get("repo") or rec.get("project") or ""


def _dedupe_latest(recs: list[dict]) -> list[dict]:
    """One record per target — the latest wins (matches stats.py semantics)."""
    by_key = {}
    for r in recs:
        by_key[_key(r)] = r
    return list(by_key.values())


def _match(recs: list[dict], needle: str) -> dict | None:
    """Find the record whose url/project/repo contains `needle` (case-insensitive substring)."""
    n = needle.lower()
    scored = [r for r in recs if r.get("slop_score") is not None or r.get("findings")]
    for pool in (scored, recs):                       # prefer a graded record over a bare stub
        for r in pool:
            if n in (_key(r) + " " + str(r.get("project", ""))).lower():
                return r
    return None


def _slug(rec: dict) -> str:
    base = rec.get("project") or _key(rec) or "app"
    return re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-")[:60] or "app"


def main():
    ap = argparse.ArgumentParser(description="Generate a durability report card from a grade record.")
    ap.add_argument("results", help="the run's JSONL results file")
    ap.add_argument("--app", help="grade one app: substring of its URL / project name")
    ap.add_argument("--all", action="store_true", help="a card for every graded app (use with --html-dir)")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML card to FILE (else markdown to stdout)")
    ap.add_argument("--html-dir", metavar="DIR", help="(--all) write one HTML card per app into DIR")
    ap.add_argument("--organizer", action="store_true", help="reveal HIDDEN-pool findings in full (organizer view)")
    ap.add_argument("--catalog", default=str(_ROOT / "catalog"), help="catalog dir for the pool map (default ./catalog)")
    args = ap.parse_args()

    recs = _dedupe_latest(_load(args.results))
    if not recs:
        sys.exit("no records in " + args.results)

    if args.all:
        graded = [r for r in recs if (r.get("findings") or r.get("slop_score") is not None)]
        out_dir = pathlib.Path(args.html_dir or "cards")
        out_dir.mkdir(parents=True, exist_ok=True)
        for r in graded:
            card = build_card(r, catalog_root=args.catalog, organizer=args.organizer)
            (out_dir / f"{_slug(r)}.html").write_text(to_html(card))
        print(f"wrote {len(graded)} card(s) to {out_dir}/")
        return

    if not args.app:
        ap.error("need --app <substring> (or --all with --html-dir)")
    rec = _match(recs, args.app)
    if rec is None:
        sys.exit(f"no app matching {args.app!r} in {args.results}")

    card = build_card(rec, catalog_root=args.catalog, organizer=args.organizer)
    if args.html:
        pathlib.Path(args.html).write_text(to_html(card))
        print(f"wrote {args.html}")
    else:
        print(to_markdown(card))


if __name__ == "__main__":
    main()
