#!/usr/bin/env python3
"""Grab hackathon project GitHub repos from Devpost, the input list for scripts/deploy_and_grade.py.

The client itself now lives in `sloptic.devpost` (the package, so the hosted service can import it too);
this file is the CLI around it and owns only the two policies a command line has: where the ingest cache
lives by default, and how `--limit` is spread across several hackathons.

Two modes, toggled by flag:
  --hackathon SLUG   scrape ONE hackathon (its Devpost subdomain, e.g. madhacks-fall-2025)
  --search QUERY     auto-pick hackathons from Devpost's open hackathons JSON API matching QUERY

    uv run python scripts/devpost_repos.py --hackathon madhacks-fall-2025 --limit 15
    uv run python scripts/devpost_repos.py --search flask --hackathons 5 --completed --limit 20
    # chain straight into deploy + grade:
    uv run python scripts/devpost_repos.py --search flask --completed \
      | while read repo; do uv run python scripts/deploy_and_grade.py "$repo"; done

Repos go to stdout (one per line, pipeable); progress goes to stderr. `--json` emits
{hackathon, project, repo, url, winner} records instead.
"""
import argparse
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.devpost import (  # noqa: E402
    IngestCache, hackathon_slugs, links_for, make_client, page_projects,
)


def _default_ingest_cache():
    """Same home as the plan/surface caches: $HL_CACHE_DIR (or ~/.cache/hacklet-plan), one shared JSONL."""
    base = os.environ.get("HL_CACHE_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "hacklet-plan")
    return os.path.join(base, "devpost-ingest.jsonl")


def _per_slug_budget(limit: int, n_slugs: int) -> int:
    """Spread --limit across N slugs so a MULTI-hackathon pull is BALANCED (the diversity goal), not front-
    loaded onto the first slug. Ceil-divide so the total still reaches ~limit; a single slug keeps the whole
    budget (and --search's auto-picked set gets balanced too, which beats the old take-all-from-slug-1)."""
    return limit if n_slugs <= 1 else -(-limit // n_slugs)


def main():
    ap = argparse.ArgumentParser(description="Grab hackathon project GitHub repos from Devpost.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hackathon", metavar="SLUG", nargs="+",
                      help="one or more hackathon subdomain slugs (space-separated), pooled into one run")
    mode.add_argument("--search", metavar="QUERY", help="auto-pick hackathons matching QUERY via the API")
    ap.add_argument("--hackathons", type=int, default=5, help="(--search) how many hackathons (default 5)")
    ap.add_argument("--completed", action="store_true",
                    help="(--search) only ended / winners-announced hackathons (real submissions)")
    ap.add_argument("--limit", type=int, default=25,
                    help="max repos to output — pages are fetched automatically until this is met (default 25)")
    ap.add_argument("--max-pages", type=int, default=25, dest="max_pages",
                    help="safety cap on gallery pages fetched per hackathon (~24 projects/page; default 25)")
    ap.add_argument("--json", action="store_true",
                    help="emit {hackathon, project, repo, url, winner} JSON records (feeds a batch driver)")
    ap.add_argument("--ingest-cache", metavar="FILE", dest="ingest_cache", default=None,
                    help="JSONL memo of gallery + project fetches, appended as each resolves — a re-run of an "
                         "already-scraped hackathon does ~zero network (default: $HL_CACHE_DIR or "
                         "~/.cache/hacklet-plan, /devpost-ingest.jsonl). Completed hackathons never change, so "
                         "cached entries never expire; only successful fetches are stored.")
    ap.add_argument("--no-ingest-cache", action="store_true", dest="no_ingest_cache",
                    help="disable the ingest cache — fetch every gallery page and project fresh.")
    args = ap.parse_args()

    cache = None if args.no_ingest_cache else IngestCache(args.ingest_cache or _default_ingest_cache())
    with make_client() as c:
        slugs = (args.hackathon if args.hackathon
                 else hackathon_slugs(c, args.search, args.hackathons, args.completed))
        if not slugs:
            sys.exit("no hackathons matched")
        per_slug = _per_slug_budget(args.limit, len(slugs))   # balance --limit across slugs (diversity)
        sys.stderr.write(f"hackathons ({len(slugs)}): {', '.join(slugs)}"
                         + (f"  · ~{per_slug}/slug" if len(slugs) > 1 else "") + "\n")
        records, seen, seen_urls = [], set(), set()
        for slug in slugs:
            if len(records) >= args.limit:
                break
            got, page = 0, 1
            while len(records) < args.limit and got < per_slug and page <= args.max_pages:
                page_cached = cache is not None and cache.seen_page(slug, page)
                hits = page_projects(c, slug, page, cache)
                if not hits:                      # empty page -> gallery exhausted
                    break
                for project_url, winner in hits:
                    if len(records) >= args.limit or got >= per_slug:
                        break
                    link_cached = cache is not None and cache.seen_project(project_url)
                    repo, url = links_for(c, project_url, cache)
                    dup = (repo and repo in seen) or (url and url in seen_urls)
                    if dup or not (repo or url):   # already have it, or nothing gradeable -> skip
                        if not link_cached:
                            time.sleep(0.2)        # politeness delay throttles NETWORK only; cache hits are free
                        continue
                    if repo:
                        seen.add(repo)
                    if url:
                        seen_urls.add(url)
                    got += 1
                    records.append({"hackathon": slug, "project": project_url, "repo": repo,
                                    "url": url, "winner": winner})   # winner: True=badge found; False=none
                    if not args.json:
                        print(f"{repo or '(no repo)'}   url={url or '-'}", flush=True)
                    if not link_cached:
                        time.sleep(0.2)
                page += 1
                if not page_cached:
                    time.sleep(0.3)
            sys.stderr.write(f"  {slug}: {got} submissions (through page {page - 1})\n")
        if args.json:
            print(json.dumps(records, indent=2))
        if cache is not None and cache.path:
            sys.stderr.write(f"ingest cache: {cache.hits} fetch(es) served from {cache.path}\n")
        sys.stderr.write(f"\n{len(records)} submissions ({sum(bool(r['repo']) for r in records)} with repo, "
                         f"{sum(bool(r['url']) for r in records)} with url).\n")


if __name__ == "__main__":
    main()
