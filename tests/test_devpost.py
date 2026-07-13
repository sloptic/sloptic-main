"""devpost_repos.repo_for must return a submission's OWN repo, never Devpost's embedded vendor URL
(github.com/newrelic/newrelic-browser-agent, present in the RUM script on every project page). Pure —
a stub client feeds canned HTML, no network.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from devpost_repos import IngestCache, links_for, page_projects, repo_for  # noqa: E402

_VENDOR = '<script>d("https://github.com/newrelic/newrelic-browser-agent")</script>'   # on EVERY page


class _Stub:
    def __init__(self, text, status=200):
        self._text, self._status = text, status

    def get(self, url, **kw):
        return type("R", (), {"status_code": self._status, "text": self._text})()


def _page(html):
    return repo_for(_Stub(_VENDOR + html), "https://devpost.com/software/x")


def _links(html):
    return links_for(_Stub(_VENDOR + html), "https://devpost.com/software/x")


def test_links_for_extracts_repo_and_live_url_together():
    # the demo link is the live URL — not the repo, not the video
    repo, url = _links('<ul class="app-links">'
                       '<li><a href="https://github.com/alice/proj">GitHub</a></li>'
                       '<li><a href="https://alice-proj.vercel.app">Try it</a></li>'
                       '<li><a href="https://youtu.be/xyz">Video</a></li></ul>')
    assert repo == "https://github.com/alice/proj" and url == "https://alice-proj.vercel.app"


def test_links_for_url_only_submission_has_no_repo():
    repo, url = _links('<ul class="app-links"><li><a href="https://cool.netlify.app">demo</a></li></ul>')
    assert repo is None and url == "https://cool.netlify.app"


def test_links_for_repo_href_with_a_path_is_trimmed_to_user_repo():
    # a deep-link (…/tree/main) must reduce to the cloneable github.com/user/repo, not the full path
    repo, _ = _links('<ul class="app-links"><li>'
                     '<a href="https://github.com/alice/proj/tree/main/src">code</a></li></ul>')
    assert repo == "https://github.com/alice/proj"


def test_links_for_real_devpost_software_urls_markup():
    # the ACTUAL Devpost shape (verified live): a div.app-links section wrapping <ul data-role=
    # "software-urls"> whose <a> carry target/title/rel attrs — both repo and demo must extract
    repo, url = _links(
        '<div class="app-links section"><h2>Try it out</h2>'
        '<ul data-role="software-urls" class="no-bullet">'
        '<li><a target="_blank" title="x" rel="nofollow" href="https://github.com/team/proj">'
        '<i class="ss-icon ss-link"></i><span>github.com</span></a></li>'
        '<li><a target="_blank" rel="nofollow" href="https://proj.vercel.app"><span>demo</span></a></li>'
        '</ul></div>')
    assert repo == "https://github.com/team/proj" and url == "https://proj.vercel.app"


def test_real_repo_from_app_links_block_not_the_vendor_url():
    repo = _page('<ul class="app-links"><li><a href="https://github.com/alice/proj">GitHub</a></li></ul>')
    assert repo == "https://github.com/alice/proj"


def test_no_app_links_block_returns_none_not_the_vendor_url():
    # p-block's shape: author linked no repo, so the only github link is the vendor's -> must be None
    assert _page("<body>no links here</body>") is None


def test_app_links_block_without_github_returns_none():
    # neuralpets' shape: an app-links list, but it only links a demo, not a repo
    assert _page('<ul class="app-links"><li><a href="https://demo.example.com">Try it</a></li></ul>') is None


def test_vendor_url_inside_app_links_block_is_filtered():
    # defense-in-depth: even if the vendor URL lands in the block, it's denied
    assert _page('<ul class="app-links"><li>'
                 '<a href="https://github.com/newrelic/newrelic-browser-agent">x</a></li></ul>') is None


def test_multiclass_app_links_ul_still_matches():
    repo = _page('<ul class="grid app-links mt-2"><li><a href="https://github.com/bob/thing">gh</a></li></ul>')
    assert repo == "https://github.com/bob/thing"


# ── ingest cache: a completed hackathon's fetches are memoized, so a re-run does ~zero network ──
class _Counting:
    """A client that counts real fetches and returns fixed 200 markup — proves the cache skips the network."""
    def __init__(self, text):
        self._text, self.n = text, 0

    def get(self, url, **kw):
        self.n += 1
        return type("R", (), {"status_code": 200, "text": self._text})()


def test_ingest_cache_memoizes_links_and_survives_reload(tmp_path):
    # the core resumability claim: resolve once (1 fetch), re-resolve from cache (0), then a FRESH cache object
    # reading the same file still hits (persisted to disk) — an interrupted scrape resumes without re-fetching.
    c = _Counting('<ul class="app-links"><li><a href="https://github.com/a/b">gh</a></li></ul>')
    cache = IngestCache(tmp_path / "ing.jsonl")
    r1 = links_for(c, "https://devpost.com/software/x", cache)
    r2 = links_for(c, "https://devpost.com/software/x", cache)
    assert r1 == r2 == ("https://github.com/a/b", None)
    assert c.n == 1                                        # second call served from memory -> no new fetch
    reloaded = IngestCache(tmp_path / "ing.jsonl")         # simulate a subsequent process
    assert links_for(c, "https://devpost.com/software/x", reloaded) == r1
    assert c.n == 1                                        # still no new fetch: the entry persisted to the file


def test_ingest_cache_never_memoizes_a_failed_fetch(tmp_path):
    # no-poisoning claim: a transient failure must NOT be cached as an (empty) result — it retries next run.
    class _Flaky:
        def __init__(self):
            self.n = 0

        def get(self, url, **kw):
            self.n += 1
            ok = self.n > 1                               # first fetch fails (500), then recovers (200)
            text = '<ul class="app-links"><li><a href="https://github.com/a/b">gh</a></li></ul>' if ok else ""
            return type("R", (), {"status_code": 200 if ok else 500, "text": text})()

    c, cache = _Flaky(), IngestCache(tmp_path / "ing.jsonl")
    assert links_for(c, "https://devpost.com/software/x", cache) == (None, None)   # 500 -> uncached
    assert links_for(c, "https://devpost.com/software/x", cache) == ("https://github.com/a/b", None)
    assert c.n == 2                                        # it re-fetched rather than serving a poisoned blank


def test_ingest_cache_memoizes_gallery_pages(tmp_path):
    # the gallery-enumeration half caches too (and round-trips the (url, winner) tuple through JSON).
    c = _Counting('<div class="gallery-item">https://devpost.com/software/proj-one winner</div>')
    cache = IngestCache(tmp_path / "ing.jsonl")
    p1 = page_projects(c, "hack", 1, cache)
    p2 = page_projects(c, "hack", 1, cache)
    assert p1 == p2 == [("https://devpost.com/software/proj-one", True)]
    assert c.n == 1                                        # page 1 served from cache the second time


def test_per_slug_budget_balances_a_multi_hackathon_pull():
    from devpost_repos import _per_slug_budget
    assert _per_slug_budget(30, 1) == 30       # single slug -> whole budget (unchanged behavior)
    assert _per_slug_budget(30, 3) == 10       # 3 slugs -> 10 each, balanced for diversity (not 30/0/0)
    assert _per_slug_budget(25, 5) == 5        # --search's default shape, now balanced too
    assert _per_slug_budget(10, 3) == 4        # ceil so the total still reaches ~the limit (4*3=12 >= 10)
