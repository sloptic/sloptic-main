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
import re
import sys
import time

import httpx

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


def page_projects(client, slug, page):
    """(project_url, winner) for ONE submissions gallery page (Devpost serves ~24/page); [] when the page
    is empty (gallery exhausted) or unreachable. `winner` is BEST-EFFORT from a 'winner' marker in the
    gallery entry — Devpost only badges winners post-judging and often on a separate view, so it's
    frequently False; override per app with deploy_and_grade --meta if you have the real result."""
    r = _get(client, _SUBS.format(slug=slug, page=page))
    if not r or r.status_code != 200:
        return []
    out, seen = [], set()
    for block in _GALLERY_SPLIT.split(r.text)[1:]:
        m = _PROJ.search(block)
        if m and m.group(0) not in seen:
            seen.add(m.group(0))
            out.append((m.group(0), bool(re.search(r"\bwinner\b", block, re.I))))
    return out


def links_for(client, project_url):
    """(repo, live_url) from the submission's OWN app-links block. repo = first non-vendor GitHub link;
    live_url = first link that is neither version control, a video, a slide/doc/design host, nor social —
    Devpost's "Try it out" deployment. We do NOT fall back to a whole-page scan: a project that links no
    repo still has Devpost's embedded vendor URL (github.com/newrelic/..., in the RUM script on every page)
    in its markup, and grabbing that would clone+deploy the wrong thing. Either field may be None; a
    submission with neither is skipped by the caller."""
    r = _get(client, project_url)
    if not r or r.status_code != 200:
        return None, None
    block = _APP_LINKS.search(r.text)
    if not block:
        return None, None
    hrefs = list(dict.fromkeys(_LINK.findall(block.group(0))))
    repo = url = None
    for h in hrefs:
        m = _GH.match(h)
        if m and not _VENDOR_REPO.search(h):
            repo = repo or m.group(0).rstrip('.,);"\'')   # just github.com/user/repo, not any /tree/... suffix
        elif not _NOT_LIVE.search(h):
            url = url or h.rstrip('.,);"\'')               # the live "Try it out" demo (full URL)
    return repo, url


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
    args = ap.parse_args()

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
                hits = page_projects(c, slug, page)
                if not hits:                      # empty page -> gallery exhausted
                    break
                for project_url, winner in hits:
                    if len(records) >= args.limit:
                        break
                    repo, url = links_for(c, project_url)
                    dup = (repo and repo in seen) or (url and url in seen_urls)
                    if dup or not (repo or url):   # already have it, or nothing gradeable -> skip
                        time.sleep(0.2)
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
                    time.sleep(0.2)
                page += 1
                time.sleep(0.3)
            sys.stderr.write(f"  {slug}: {got} submissions (through page {page - 1})\n")
        if args.json:
            print(json.dumps(records, indent=2))
        sys.stderr.write(f"\n{len(records)} submissions ({sum(bool(r['repo']) for r in records)} with repo, "
                         f"{sum(bool(r['url']) for r in records)} with url).\n")


if __name__ == "__main__":
    main()
