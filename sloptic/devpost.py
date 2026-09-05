"""Devpost client: event pages, gallery submissions, and event metadata, behind one WAF aware fetch.

Two consumers share this module. The corpus scraper (`scripts/devpost_repos.py`) walks a hackathon's
submission gallery for repos and live URLs. Organizer verification reads an event's own pages to see whether
the organizer published a token we handed them. The second consumer is why every fetch here is tri-state.

Devpost fronts its subdomains with an AWS WAF that rate limits per client, and it answers a limited client
with 202, 403, 405, 429 or 503, sometimes with a zero byte body. A client that folds those into the same
value a 404 returns will eventually read a WAF page as proof that a token is absent, which turns "we could
not check" into "not verified" and revokes a credential the organizer earned. So a fetch returns `Fetch`
with a status, never a bare None, and absence is narrow: **only 404 and 410 mean the page is not there.**
Every other unhappy answer, a WAF status, a transport error, a 5xx, an empty 200 body, a challenge page, or
a redirect off the pinned host, is `blocked`, which means conclude nothing and try again later.

The host is pinned in here rather than in each caller. Every event URL is built from a validated slug as
exactly `<slug>.devpost.com`, and the host that actually answered is compared against that after redirects,
so the substring test against "devpost.com" that `evil-devpost.com` and `devpost.com.attacker.net` both pass
never gets a chance to be written.

Verification reads hrefs, never page text. `event_links` hands back the `<a href>` values it found and the
page each came from, and the comparison stays with the caller, so the secret never crosses this boundary and
the caller can use `hmac.compare_digest`. There is deliberately no "does this page contain X" helper: a token
quoted anywhere on the page, a participant pasting it into a discussion, is not the organizer publishing it,
and extracting hrefs is what keeps the two apart.

The iterators (`submissions`) raise `Blocked` instead of returning a status, because a generator that just
stops on a block hands back a short list that looks exactly like a complete one.

Verified live 2026-09-01: the hackathons API is open JSON, event pages are server rendered HTML fetchable
with httpx and a full Chrome UA (a bare `Mozilla/5.0` is 403'd), a missing event or page is a real 404, and
the API's `search` matches TITLES rather than slugs, so `event_meta` searches the slug with its hyphens
turned into spaces (10 of 10 sampled corpus slugs then resolve on the first page).
"""
from __future__ import annotations

import html as _htmllib
import json
import os
import pathlib
import re
import sys
import time
from typing import Iterator, Literal, NamedTuple

import httpx

from .jsonl import append_jsonl
from .net import is_bot_challenge
from .scope import off_target          # the ONE authoritative off-target deny-list

__all__ = [
    "Blocked", "Fetch", "IngestCache", "Link", "Links", "Meta", "Status",
    "anchor_hrefs", "event_links", "event_meta", "event_page", "hackathon_slugs", "links_for",
    "make_client", "page_projects", "pinned_host", "repo_for", "submissions",
]

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
_HACK_API = "https://devpost.com/api/hackathons"
_API_HOST = "devpost.com"
_SUBS = "https://{slug}.devpost.com/submissions/search?page={page}"
_EVENT_PATHS = {"rules": "/rules", "overview": "/"}
_PROJ = re.compile(r"https://devpost\.com/software/[a-z0-9][a-z0-9-]*")
_SLUG_FROM_URL = re.compile(r"https?://([a-z0-9][a-z0-9-]*)\.devpost\.com")
_GH = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_APP_LINKS = re.compile(r'class="[^"]*app-links.*?</ul>', re.S)   # the submission's own links list
# Devpost embeds a vendor RUM script (New Relic) whose OWN source repo link sits in the page JS on
# EVERY project page, never a submission's repo. Deny-list it so it can't be mistaken for the project.
_VENDOR_REPO = re.compile(r"github\.com/newrelic/", re.I)
# every <a href> on a page, quoted either way or bare. Anchors only: a stylesheet <link href> is not
# something an organizer published, and neither is a token pasted into prose.
_A_HREF = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.I | re.S)
_GALLERY_SPLIT = re.compile(r'(?=class="[^"]*gallery-item)')
# a live-demo URL is a link that is NOT version control, a video, a slide/doc/design host, or social,
# i.e. the submission's "Try it out" deployment. Best heuristic; a stray portfolio link is possible noise.
_NOT_LIVE = re.compile(
    r"github\.com|gitlab\.com|bitbucket\.org|youtube\.com|youtu\.be|vimeo\.com|devpost\.com|"
    r"docs\.google|drive\.google|figma\.com|canva\.com|notion\.|loom\.com|dropbox\.com|slideshare|"
    r"pitch\.com|newrelic|medium\.com|linkedin\.com|twitter\.com|facebook\.com|x\.com/|t\.co/", re.I)
# a DNS label: what can legally sit in front of .devpost.com. No dots, so no slug can smuggle a second host.
_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Devpost's AWS-WAF answers a rate-limited client several ways, NONE of them an empty page: 403/429/503,
# and (observed on the Dell under fan-out load) a 202 or 405 CAPTCHA/Challenge with a 0-byte body.
_BLOCK_STATUS = frozenset({202, 403, 405, 429, 503})
_ABSENT_STATUS = frozenset({404, 410})
_CACHED = "served from the ingest cache"
_DEBUG = bool(os.environ.get("DEVPOST_DEBUG"))   # DEVPOST_DEBUG=1 -> log every status/size

Status = Literal["ok", "not_found", "blocked"]


class Blocked(Exception):
    """A fetch could not be completed, so whatever the caller is enumerating is INCOMPLETE.

    Raised only by the iterators, where a status field has nowhere to live. Catching this and continuing is
    fine; catching it and treating the partial yield as the whole gallery is the bug this exists to prevent.
    """


class Fetch(NamedTuple):
    """One settled fetch. `status` is the only thing a caller may branch on.

    ok        the page was read from the pinned host; `html` is its body.
    not_found the host answered 404 or 410. This is the ONLY value that means "it is not there."
    blocked   we could not check. A WAF status, a transport failure, a 5xx, an empty body, a challenge
              page, or an answer from a host other than the pinned one. `html` is None. Try again later.
    """
    status: Status
    html: str | None
    detail: str          # what was actually seen, for the audit trail. Never parse it, only record it.


class Link(NamedTuple):
    """One `<a href>` value, and which event page it was found on."""
    href: str
    page: str            # "rules" or "overview"
    text: str = ""       # the anchor's own display text, for showing the organizer what to look for


class Links(NamedTuple):
    """The links found across an event's pages, with the completeness of the list stated up front.

    The verification rule, and the reason `status` and `links` travel together:

    * a match in `links` PROVES publication whatever the status is, because every link here came from a
      page we actually read off the pinned host;
    * no match proves absence ONLY when `status` is "ok", which means every requested page was read;
    * "blocked" means at least one page could not be read, so the list is short by an unknown amount and
      the honest answer to the organizer is "could not check", never "not verified".
    """
    status: Status
    links: list[Link]
    detail: str



class Meta(NamedTuple):
    """An event's record from the public hackathons API.

    `event` is the API's own dict. The fields verification cares about:

    * `submission_period_dates`, display text like "Sep 19 - 21, 2025". It carries no timezone and is not
      a timestamp, so treat any parse of it as advisory and never as a deadline you enforce to the minute.
    * `open_state`, one of "open", "upcoming", "ended". With `winners_announced`, this is the machine
      readable answer to "is the submission window still running", which is the check worth gating on.
    * `invite_only` and `submission_gallery_url`.
    """
    status: Status
    event: dict | None
    detail: str


def make_client() -> httpx.Client:
    """A client shaped the way Devpost expects: redirects followed, full Chrome UA (a short one is 403'd).

    Callers that make several calls should pass one of these through, so the WAF sees one connection reusing
    its rate window rather than a burst of new ones.
    """
    return httpx.Client(follow_redirects=True, headers={"User-Agent": UA})


def pinned_host(slug: str) -> str:
    """The one host an event's pages may be served from, `<slug>.devpost.com`, built rather than matched.

    Lowercases first, because DNS is case insensitive and an organizer typing "MadHacks-2025" means the same
    host. Then validates against a single DNS label, so a slug carrying a dot, a slash, an @ or a colon is
    rejected outright and cannot compose a different host. Raises ValueError, which is deliberate: nothing
    was fetched and nothing is uncertain, so this is not one of the three fetch outcomes.
    """
    if not isinstance(slug, str):
        raise ValueError(f"slug must be a string, got {type(slug).__name__}")
    s = slug.strip().lower()
    if not _SLUG_RE.match(s):
        raise ValueError(f"not a Devpost event slug: {slug!r} (expected one DNS label, a-z 0-9 and hyphens)")
    return f"{s}.devpost.com"


def _host_of(url: str) -> str | None:
    """The host of a URL, lowercased. None when it does not parse or carries no host."""
    try:
        return (httpx.URL(url).host or "").lower() or None
    except (ValueError, TypeError):
        return None


def _final_host(r) -> str | None:
    """The host that actually answered, after every redirect. None when the response cannot say."""
    u = getattr(r, "url", None)
    return _host_of(str(u)) if u is not None else None


def _get_detail(client, url, tries=5, **kw):
    """GET with backoff on a transient WAF block (202/403/405/429/503) or a transport error.

    Returns `(response, note)`. The response comes back even when it is a FINAL block, so the caller can
    tell a WAF challenge from a 404 instead of silently reading one as the other; `response` is None only
    when no answer ever arrived, and `note` says which of the two happened.
    """
    delay, r, note = 1.5, None, ""
    for i in range(tries):
        try:
            r = client.get(url, headers={"User-Agent": UA}, timeout=25, **kw)
        except httpx.HTTPError as e:                   # RST / SSL / timeout: the WAF drops connections too
            note = f"transport error after {i + 1} of {tries} attempts, {type(e).__name__}: {e}"
            if _DEBUG:
                sys.stderr.write(f"  [debug] _get {note}  url={url}\n")
            r = None
            if i < tries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            return None, note
        if r.status_code not in _BLOCK_STATUS:
            return r, f"answered on attempt {i + 1}"
        if _DEBUG:
            sys.stderr.write(f"  [debug] _get block HTTP {r.status_code} (try {i + 1}/{tries})  url={url}\n")
        if i < tries - 1:
            time.sleep(delay)
            delay *= 2                # backoff 1.5s, 3s, 6s, 12s: rides out a transient rate window
    return r, f"still blocked after {tries} attempts"   # hand the block back, never None


def _fetch_pinned(client, url, host: str, tries=5, **kw) -> Fetch:
    """One GET, pinned to `host`, mapped onto the three outcomes.

    Everything that is not a readable 200 from the pinned host is `blocked` except a literal 404 or 410,
    which is the single narrow definition of absence this module allows.
    """
    r, note = _get_detail(client, url, tries=tries, **kw)
    if r is None:
        return Fetch("blocked", None, f"{url}: {note}")
    where = f"{url}: HTTP {r.status_code}"
    if r.status_code in _ABSENT_STATUS:
        return Fetch("not_found", None, f"{where}, no such page")
    if r.status_code != 200:
        why = "WAF block" if r.status_code in _BLOCK_STATUS else "unexpected status"
        return Fetch("blocked", None, f"{where}, {why} ({note}), read as could not check")
    final = _final_host(r)
    if final is None:
        return Fetch("blocked", None, f"{where}, but the final URL was unreadable so the host went unpinned")
    if final != host:
        return Fetch("blocked", None, f"{where}, answered by {final} rather than the pinned {host}")
    try:
        body = r.text
    except (httpx.HTTPError, ValueError, UnicodeError) as e:
        return Fetch("blocked", None, f"{where}, body unreadable, {type(e).__name__}")
    if not body.strip():
        return Fetch("blocked", None, f"{where}, empty body (the WAF serves zero byte challenges)")
    if is_bot_challenge(r):
        return Fetch("blocked", None, f"{where}, a bot challenge page rather than content")
    return Fetch("ok", body, f"{where}, {len(body)} bytes from {final}")


def anchor_hrefs(html: str) -> list[str]:
    """Every `<a href>` value in `html`, entity decoded, in document order, deduplicated.

    Values come back exactly as the author wrote them, with no urljoin, so a caller comparing against a URL
    it issued compares the same bytes. Anchors only, which is the point: a token in a paragraph, a script,
    or a comment is somebody quoting it, and only a link is the organizer publishing it.
    """
    out = []
    for m in _A_HREF.finditer(html or ""):
        raw = next((g for g in m.groups() if g is not None), "")
        href = _htmllib.unescape(raw).strip()
        if href:
            out.append(href)
    return list(dict.fromkeys(out))


def anchor_pairs(html: str) -> list[tuple[str, str]]:
    """(href, display text) for every `<a>` in `html`, entity decoded, in document order,
    deduplicated by href. Same anchors as anchor_hrefs, plus the anchor's own visible words, so a
    verification slip can show the organizer the link they published. The display text is metadata
    for display only: the token match stays on the href, exactly where it always was.
    """
    pairs: dict[str, str] = {}
    for m in re.finditer(r"<a\b[^>]*?\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))[^>]*>(.*?)</a>",
                         html or "", re.I | re.S):
        raw = next((g for g in m.groups()[:3] if g is not None), "")
        href = _htmllib.unescape(raw).strip()
        if not href or href in pairs:
            continue
        text = re.sub(r"<[^>]+>", " ", m.group(4))
        text = " ".join(_htmllib.unescape(text).split())
        pairs[href] = text
    return list(pairs.items())


def event_page(slug: str, page: str = "overview", *, client=None) -> Fetch:
    """Fetch one of an event's own pages, `rules` or `overview`, from the pinned host.

    The page name is a key into a fixed table rather than a path, so no caller can steer this at a URL of
    its choosing. A missing `/rules` is a real 404 and comes back `not_found`; plenty of events never fill
    it in, which is why verification scans both pages instead of trusting either alone.
    """
    if page not in _EVENT_PATHS:
        raise ValueError(f"unknown event page {page!r} (expected one of {sorted(_EVENT_PATHS)})")
    host = pinned_host(slug)
    url = f"https://{host}{_EVENT_PATHS[page]}"
    if client is not None:
        return _fetch_pinned(client, url, host)
    with make_client() as c:
        return _fetch_pinned(c, url, host)


def event_links(slug: str, *, client=None, pages=("rules", "overview")) -> Links:
    """Every `<a href>` an event published on its own pages, tagged with the page it came from.

    Read `Links` for the rule that makes this safe to act on. In short: a hit is a hit whatever the status,
    a miss only means anything when the status is "ok", and one blocked page makes the whole list "blocked"
    even if the other page read fine, because a token could have been sitting on the page we did not get.

    The comparison is yours. Nothing here takes the token, so it never has to be handled, logged, or
    compared without `hmac.compare_digest`.
    """
    if not pages:
        raise ValueError("event_links needs at least one page to scan")

    def _scan(c) -> Links:
        found, details, statuses = [], [], []
        for page in pages:
            f = event_page(slug, page, client=c)
            statuses.append(f.status)
            details.append(f"{page}: {f.detail}")
            if f.status == "ok":
                found.extend(Link(h, page, text) for h, text in anchor_pairs(f.html))
        status: Status = ("blocked" if "blocked" in statuses
                          else "not_found" if statuses and all(s == "not_found" for s in statuses)
                          else "ok")
        return Links(status, found, "; ".join(details))

    if client is not None:
        return _scan(client)
    with make_client() as c:
        return _scan(c)


def _api_page(client, query: str, page: int) -> tuple[Status, list, str]:
    """One page of the public hackathons API, with a non JSON body treated as a block rather than as empty."""
    f = _fetch_pinned(client, _HACK_API, _API_HOST, params={"search": query, "page": page})
    if f.status != "ok":
        return f.status, [], f.detail
    try:
        data = json.loads(f.html)
    except (json.JSONDecodeError, TypeError, ValueError):
        return "blocked", [], f"{f.detail}, but the body was not JSON"
    hacks = data.get("hackathons") if isinstance(data, dict) else None
    if not isinstance(hacks, list):
        return "blocked", [], f"{f.detail}, but the payload carried no hackathons list"
    return "ok", hacks, f.detail


def event_meta(slug: str, *, client=None, max_pages: int = 3) -> Meta:
    """The event's record from `devpost.com/api/hackathons`, matched on the exact pinned host.

    The API searches titles, not slugs, so the query is the slug with its hyphens turned into spaces, which
    resolved every corpus slug sampled on the first page. Candidates are then matched on host equality
    against `<slug>.devpost.com`, so a similarly titled event can never be mistaken for this one.

    A miss is not automatically an absence. When the search turns up no record, the event's own page is
    fetched as corroboration: a 404 there means the event really does not exist (`not_found`), while a live
    page means the search simply did not surface it, which happens when a title shares no words with its
    slug, and that comes back `blocked`, because "we could not read the metadata" is the truth and "no such
    event" would not be. A miss says nothing about the event's privacy: invite only events are indexed too.
    """
    host = pinned_host(slug)
    query = host.split(".", 1)[0].replace("-", " ")

    def _lookup(c) -> Meta:
        detail = ""
        for page in range(1, max_pages + 1):
            status, hacks, detail = _api_page(c, query, page)
            if status != "ok":
                return Meta(status, None, f"hackathons API: {detail}")
            for h in hacks:
                if isinstance(h, dict) and _host_of(h.get("url", "") or "") == host:
                    return Meta("ok", h, f"hackathons API page {page}: {detail}")
            if not hacks:
                break
        probe = event_page(slug, "overview", client=c)
        if probe.status == "not_found":
            return Meta("not_found", None, f"no event at {host} and none in the API for {query!r}; {probe.detail}")
        if probe.status == "blocked":
            return Meta("blocked", None, f"not in the API for {query!r} and its page could not be read; {probe.detail}")
        return Meta("blocked", None,
                    f"{host} is live but the API's title search did not surface it for {query!r} within "
                    f"{max_pages} pages, so its metadata is unavailable rather than absent")

    if client is not None:
        return _lookup(client)
    with make_client() as c:
        return _lookup(c)


# ── the submission gallery ─────────────────────────────────────────────────────────────────────────────
def _ck_page(slug, page):
    return f"page:{slug}:{page}"


def _ck_links(project_url):
    return f"links:{project_url}"


def _ck_hrefs(project_url):
    return f"hrefs:{project_url}"


class IngestCache:
    """Persistent memo of the two expensive Devpost fetches, gallery-page enumeration and per-project link
    resolution, so re-running an already-scraped hackathon does ~zero network. Keyed by the fetched identity
    (a completed hackathon's pages never change, so entries never expire), stored as JSONL and appended the
    instant each item resolves, so an interrupted scrape keeps everything it pulled and the next run resumes
    from there. ONLY successful fetches are memoized: a block or a network failure is never cached, so a
    transient one retries next run instead of poisoning the cache with a false 'empty'.

    Three key spaces: `page:` for a gallery page, `hrefs:` for a project's raw app-links hrefs, and `links:`
    for the derived (repo, live URL) pair that older caches wrote. `links:` is read but no longer written,
    so an existing cache keeps hitting while new fetches store the richer form.
    """

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

    def seen_page(self, slug, page) -> bool:
        """Whether this gallery page is already memoized, so a caller can skip its politeness delay."""
        return self.has(_ck_page(slug, page))

    def seen_project(self, project_url) -> bool:
        """Whether this project's links are memoized, under either the new or the legacy key space."""
        return self.has(_ck_hrefs(project_url)) or self.has(_ck_links(project_url))


def _gallery_items(html: str) -> list[tuple[str, bool]]:
    """(project_url, winner) for each gallery entry in one submissions page's markup."""
    out, seen = [], set()
    for block in _GALLERY_SPLIT.split(html)[1:]:
        m = _PROJ.search(block)
        if m and m.group(0) not in seen:
            seen.add(m.group(0))
            out.append((m.group(0), bool(re.search(r"\bwinner\b", block, re.I))))
    return out


def _gallery(client, slug, page, cache=None) -> tuple[Status, list[tuple[str, bool]], str]:
    """One gallery page, tri-state. An empty 200 is a real end of gallery and IS cached; a block is not."""
    ck = _ck_page(slug, page)
    if cache is not None and cache.has(ck):
        return "ok", [tuple(x) for x in cache.get(ck)], _CACHED
    f = _fetch_pinned(client, _SUBS.format(slug=slug, page=page), pinned_host(slug))
    if f.status != "ok":
        return f.status, [], f.detail
    items = _gallery_items(f.html)
    if _DEBUG:
        sys.stderr.write(f"  [debug] {slug} p{page}: {f.detail} parsed={len(items)}"
                         f"{'  <-- 200 but 0 items (interstitial?)' if not items else ''}\n")
    if cache is not None:
        cache.put(ck, items)
    return "ok", items, f.detail


def _project_hrefs(client, project_url, cache=None) -> tuple[Status, list[str], str]:
    """The raw hrefs inside a submission's OWN app-links block, tri-state.

    We do NOT fall back to a whole-page scan: a project that links no repo still carries Devpost's embedded
    vendor URL (github.com/newrelic/..., in the RUM script on every page), and grabbing that would clone and
    deploy the wrong thing.
    """
    ck = _ck_hrefs(project_url)
    if cache is not None and cache.has(ck):
        return "ok", list(cache.get(ck)), _CACHED
    f = _fetch_pinned(client, project_url, _API_HOST)
    if f.status != "ok":
        return f.status, [], f.detail
    block = _APP_LINKS.search(f.html)
    hrefs = anchor_hrefs(block.group(0)) if block else []      # no block: the project links nothing
    if cache is not None:
        cache.put(ck, hrefs)
    return "ok", hrefs, f.detail


def hackathon_slugs(client, query, count, completed):
    """Subdomain slugs of hackathons matching `query` (newest first), optionally only ended ones.

    Stops on a block and says so on stderr, so a short list is never mistaken for the whole result set.
    """
    slugs, page = [], 1
    while len(slugs) < count and page <= 25:
        status, hacks, detail = _api_page(client, query, page)
        if status != "ok":
            sys.stderr.write(f"  ⚠ hackathon search stopped at page {page}, {status}: {detail}\n")
            break
        if not hacks:
            break
        for h in hacks:
            if completed and not h.get("winners_announced") and h.get("open_state") != "ended":
                continue
            m = _SLUG_FROM_URL.match(h.get("url", ""))
            if m and m.group(1) not in slugs:
                slugs.append(m.group(1))
                if len(slugs) >= count:
                    break
        page += 1
    return slugs


def page_projects(client, slug, page, cache=None):
    """(project_url, winner) for ONE submissions gallery page (Devpost serves ~24/page); [] when the page is
    empty (gallery exhausted) or unreachable. `winner` is BEST-EFFORT from a 'winner' marker in the gallery
    entry: Devpost only badges winners post-judging and often on a separate view, so it is frequently False.

    The scraper's shape, which flattens a block to [] after warning loudly about it. Anything that must not
    confuse a block with an empty gallery should call `submissions`, which raises instead.
    """
    status, items, detail = _gallery(client, slug, page, cache)
    if status == "blocked":
        sys.stderr.write(f"  ⚠ {slug} page {page}: Devpost WAF-blocked after retries, this client is being "
                         f"rate-limited, NOT an empty gallery. Yields 0 here; fetch from a less-loaded "
                         f"client, slow down (raise the politeness delay), or wait for the window. {detail}\n")
    return items


def links_for(client, project_url, cache=None):
    """(repo, live_url) from the submission's OWN app-links block. repo = first non-vendor GitHub link;
    live_url = first link that is neither version control, a video, a slide/doc/design host, nor social,
    which is Devpost's "Try it out" deployment. Either may be None; a submission with neither is skipped by
    the caller.

    Returns (None, None) for a block as well as for a project that links nothing, which is the scraper's
    tolerance (an uncached miss simply retries next run) and NOT a contract to build verification on.
    """
    ck = _ck_links(project_url)
    if cache is not None and cache.has(ck):
        return tuple(cache.get(ck))                     # legacy entries, written before hrefs: existed
    status, hrefs, _ = _project_hrefs(client, project_url, cache)
    if status != "ok":
        return None, None
    repo = url = None
    for h in hrefs:
        m = _GH.match(h)
        if m and not _VENDOR_REPO.search(h):
            repo = repo or m.group(0).rstrip('.,);"\'')   # just github.com/user/repo, not any /tree/... suffix
        elif not _NOT_LIVE.search(h) and not off_target(h):   # off_target = the authoritative safety deny-list
            url = url or h.rstrip('.,);"\'')              # the live "Try it out" demo (full URL)
    return repo, url


def repo_for(client, project_url):
    """The submission's declared GitHub repo (see `links_for`). Retained for callers wanting only it."""
    return links_for(client, project_url)[0]


def submissions(slug: str, *, client=None, cache=None, max_pages: int = 25,
                delay: float = 0.2) -> Iterator[tuple[str, list[str]]]:
    """Yield `(project_url, hrefs)` for each submission in an event's gallery, page by page.

    `hrefs` are the raw app-links values, undissected, so the caller decides what a repo or a demo is.

    Raises `Blocked` the moment a gallery or project page comes back blocked, rather than ending the loop:
    a generator has nowhere to put a status, and stopping early would hand back a partial gallery that looks
    exactly like a complete one. Whatever was already yielded stays valid; the enumeration does not.
    """
    pinned_host(slug)          # reject a bad slug now, not on the caller's first next()

    def _walk(c):
        for page in range(1, max_pages + 1):
            status, items, detail = _gallery(c, slug, page, cache)
            if status == "blocked":
                raise Blocked(f"{slug} gallery page {page}: {detail}")
            if status == "not_found" or not items:
                return                                   # a real end of gallery
            for project_url, _winner in items:
                p_status, hrefs, p_detail = _project_hrefs(c, project_url, cache)
                if p_status == "blocked":
                    raise Blocked(f"{project_url}: {p_detail}")
                yield project_url, hrefs                  # a 404 project yields [], a genuine absence
                if delay and p_detail != _CACHED:
                    time.sleep(delay)                     # throttle NETWORK only; cache hits are free

    def _iter():
        if client is not None:
            yield from _walk(client)
        else:
            with make_client() as c:
                yield from _walk(c)

    return _iter()
