#!/usr/bin/env python3
"""Grab hackathon project GitHub repos from Devpost — the input list for scripts/deploy_and_grade.py.

Two modes, toggled by flag:
  --hackathon SLUG   scrape ONE hackathon (its Devpost subdomain, e.g. madhacks-fall-2025)
  --search QUERY     auto-pick hackathons from Devpost's open hackathons JSON API matching QUERY

    uv run python scripts/devpost_repos.py --hackathon madhacks-fall-2025 --limit 15
    uv run python scripts/devpost_repos.py --search flask --hackathons 5 --completed --limit 20
    # chain straight into deploy + grade:
    uv run python scripts/devpost_repos.py --search flask --completed \
      | while read repo; do uv run python scripts/deploy_and_grade.py "$repo"; done

Repos go to stdout (one per line — pipeable); progress goes to stderr. `--json` emits
{hackathon, project, repo} records instead.

How it works (verified 2026): Devpost's hackathons API (`/api/hackathons`) is open JSON. The GLOBAL
software gallery is AWS-WAF-blocked, but each hackathon's OWN submissions pages
(`<slug>.devpost.com/submissions/search?page=N`) are plain server-rendered HTML with no WAF — so this
needs only httpx + a browser UA (no key, no Playwright). A project's real repo lives in the page's
`app-links` block (embedded vendor scripts like newrelic sit outside it, so they're excluded).
"""
import argparse
import json
import os
import pathlib
import re
import sys
import time

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.scope import off_target  # noqa: E402  (the ONE authoritative off-target deny-list)
from hacklet_runner.jsonl import append_jsonl  # noqa: E402  (atomic, resumable append — shared w/ results writer)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
_HACK_API = "https://devpost.com/api/hackathons"
_SUBS = "https://{slug}.devpost.com/submissions/search?page={page}"
_PROJ = re.compile(r"https://devpost\.com/software/[a-z0-9][a-z0-9-]*")
_SLUG = re.compile(r"https?://([a-z0-9][a-z0-9-]*)\.devpost\.com")
_GH = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_APP_LINKS = re.compile(r'class="[^"]*app-links.*?</ul>', re.S)   # the submission's own links list
# Devpost embeds a vendor RUM script (New Relic) whose OWN source repo link sits in the page JS on
# EVERY project — never a submission's repo. Deny-list it so it can't be mistaken for the project.
_VENDOR_REPO = re.compile(r"github\.com/newrelic/", re.I)
_LINK = re.compile(r'href="(https?://[^"]+)"')   # every outbound link inside the app-links block
# a live-demo URL is a link that is NOT version control, a video, a slide/doc/design host, or social —
# i.e. the submission's "Try it out" deployment. Best heuristic; a stray portfolio link is possible noise.
_NOT_LIVE = re.compile(
    r"github\.com|gitlab\.com|bitbucket\.org|youtube\.com|youtu\.be|vimeo\.com|devpost\.com|"
    r"docs\.google|drive\.google|figma\.com|canva\.com|notion\.|loom\.com|dropbox\.com|slideshare|"
    r"pitch\.com|newrelic|medium\.com|linkedin\.com|twitter\.com|facebook\.com|x\.com/|t\.co/", re.I)


def _ck_page(slug, page):
    return f"page:{slug}:{page}"


def _ck_links(project_url):
    return f"links:{project_url}"


def _default_ingest_cache():
    """Same home as the plan/surface caches: $HL_CACHE_DIR (or ~/.cache/hacklet-plan), one shared JSONL."""
    base = os.environ.get("HL_CACHE_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "hacklet-plan")
    return os.path.join(base, "devpost-ingest.jsonl")


class IngestCache:
    """Persistent memo of the two expensive Devpost fetches — gallery-page enumeration (`page_projects`) and
    per-project link resolution (`links_for`) — so re-running an already-scraped hackathon does ~zero network.
    Keyed by the fetched identity (a completed hackathon's pages never change → entries never expire), stored
    as JSONL and appended the instant each item resolves, so an interrupted scrape keeps everything it pulled
    and the next run resumes from there. ONLY successful fetches are memoized: a network failure is never
    cached, so a transient blip retries next run instead of poisoning the cache with a false 'empty' page."""

    def __init__(self, path):
        self.path = pathlib.Path(path) if path else None
        self.mem, self.hits = {}, 0
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                with open(self.path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            self.mem[rec["k"]] = rec["v"]
                        except (json.JSONDecodeError, KeyError, TypeError):
                            continue

    def has(self, key):
        return key in self.mem

    def get(self, key):
        self.hits += 1
        return self.mem[key]

    def put(self, key, val):
        self.mem[key] = val
        if self.path:
            append_jsonl(self.path, {"k": key, "v": val})


def _get(client, url, **kw):
    try:
        return client.get(url, headers={"User-Agent": UA}, timeout=25, **kw)
    except httpx.HTTPError:
        return None


def hackathon_slugs(client, query, count, completed):
    """Subdomain slugs of hackathons matching `query` (newest first), optionally only ended ones."""
    slugs, page = [], 1
    while len(slugs) < count and page <= 25:
        r = _get(client, _HACK_API, params={"search": query, "page": page})
        if not r or r.status_code != 200:
            break
        hacks = r.json().get("hackathons", [])
        if not hacks:
            break
        for h in hacks:
            if completed and not h.get("winners_announced") and h.get("open_state") != "ended":
                continue
            m = _SLUG.match(h.get("url", ""))
            if m and m.group(1) not in slugs:
                slugs.append(m.group(1))
                if len(slugs) >= count:
                    break
        page += 1
    return slugs


_GALLERY_SPLIT = re.compile(r'(?=class="[^"]*gallery-item)')


def page_projects(client, slug, page, cache=None):
    """(project_url, winner) for ONE submissions gallery page (Devpost serves ~24/page); [] when the page
    is empty (gallery exhausted) or unreachable. `winner` is BEST-EFFORT from a 'winner' marker in the
    gallery entry — Devpost only badges winners post-judging and often on a separate view, so it's
    frequently False; override per app with deploy_and_grade --meta if you have the real result.
    A `cache` (IngestCache) short-circuits an already-seen page; only a real 200 is stored (a failed fetch
    returns [] UNCACHED so it retries next run — never memoize a blip as 'gallery exhausted')."""
    ck = _ck_page(slug, page)
    if cache is not None and cache.has(ck):
        return [tuple(x) for x in cache.get(ck)]        # JSON stored each (url, winner) pair as a list
    r = _get(client, _SUBS.format(slug=slug, page=page))
    if not r or r.status_code != 200:
        return []                                       # transient/unreachable -> do NOT cache
    out, seen = [], set()
    for block in _GALLERY_SPLIT.split(r.text)[1:]:
        m = _PROJ.search(block)
        if m and m.group(0) not in seen:
            seen.add(m.group(0))
            out.append((m.group(0), bool(re.search(r"\bwinner\b", block, re.I))))
    if cache is not None:
        cache.put(ck, out)                              # a genuine 200 (even empty = gallery end) is cacheable
    return out


def links_for(client, project_url, cache=None):
    """(repo, live_url) from the submission's OWN app-links block. repo = first non-vendor GitHub link;
    live_url = first link that is neither version control, a video, a slide/doc/design host, nor social —
    Devpost's "Try it out" deployment. We do NOT fall back to a whole-page scan: a project that links no
    repo still has Devpost's embedded vendor URL (github.com/newrelic/..., in the RUM script on every page)
    in its markup, and grabbing that would clone+deploy the wrong thing. Either field may be None; a
    submission with neither is skipped by the caller.
    A `cache` (IngestCache) short-circuits an already-resolved project. A genuine 200 is cached even when it
    yields (None, None) (the project truly links nothing gradeable — don't re-fetch it); a FAILED fetch is
    NOT cached, so it retries next run."""
    ck = _ck_links(project_url)
    if cache is not None and cache.has(ck):
        return tuple(cache.get(ck))                     # (repo, url), stored as a 2-list
    r = _get(client, project_url)
    if not r or r.status_code != 200:
        return None, None                               # transient/unreachable -> do NOT cache
    block = _APP_LINKS.search(r.text)
    if not block:
        result = (None, None)                           # genuine: this project links nothing gradeable
    else:
        hrefs = list(dict.fromkeys(_LINK.findall(block.group(0))))
        repo = url = None
        for h in hrefs:
            m = _GH.match(h)
            if m and not _VENDOR_REPO.search(h):
                repo = repo or m.group(0).rstrip('.,);"\'')   # just github.com/user/repo, not any /tree/... suffix
            elif not _NOT_LIVE.search(h) and not off_target(h):   # off_target = the authoritative safety deny-list
                url = url or h.rstrip('.,);"\'')               # the live "Try it out" demo (full URL)
        result = (repo, url)
    if cache is not None:
        cache.put(ck, list(result))
    return result


def repo_for(client, project_url):
    """The submission's declared GitHub repo (see links_for). Retained for callers/tests wanting only it."""
    return links_for(client, project_url)[0]


def main():
    ap = argparse.ArgumentParser(description="Grab hackathon project GitHub repos from Devpost.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hackathon", metavar="SLUG", help="one hackathon subdomain slug")
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
    with httpx.Client(follow_redirects=True) as c:
        slugs = ([args.hackathon] if args.hackathon
                 else hackathon_slugs(c, args.search, args.hackathons, args.completed))
        if not slugs:
            sys.exit("no hackathons matched")
        sys.stderr.write(f"hackathons ({len(slugs)}): {', '.join(slugs)}\n")
        records, seen, seen_urls = [], set(), set()
        for slug in slugs:
            if len(records) >= args.limit:
                break
            got, page = 0, 1
            while len(records) < args.limit and page <= args.max_pages:
                page_cached = cache is not None and cache.has(_ck_page(slug, page))
                hits = page_projects(c, slug, page, cache)
                if not hits:                      # empty page -> gallery exhausted
                    break
                for project_url, winner in hits:
                    if len(records) >= args.limit:
                        break
                    link_cached = cache is not None and cache.has(_ck_links(project_url))
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
