"""sloptic.devpost: the tri-state fetch, the pinned host, href-only link extraction, and the gallery walk.

The load-bearing claim under test is that a WAF block NEVER looks like an absence. Organizer verification
reads "not_found" as "the organizer did not publish the token" and "blocked" as "try again later", so any
path that collapses the two revokes a credential somebody earned. Pure: a routed stub client feeds canned
responses, no network.
"""
import json
import pathlib
import sys

import httpx
import pytest

from sloptic.devpost import (
    Blocked, IngestCache, anchor_hrefs, event_links, event_meta, event_page, links_for,
    page_projects, pinned_host, repo_for, submissions,
)

_VENDOR = '<script>d("https://github.com/newrelic/newrelic-browser-agent")</script>'   # on EVERY page


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Skip the retry waits; every block path here retries five times before it settles."""
    import sloptic.devpost as dp
    monkeypatch.setattr(dp.time, "sleep", lambda *_a: None)


class _Client:
    """Routes a URL substring to a canned answer and counts fetches.

    A route value is (status, text), or (status, text, final_url) to model a redirect landing somewhere
    else, or an Exception instance to raise as a transport failure.
    """

    def __init__(self, routes, default=(404, "no such page")):
        self.routes, self.default, self.n = routes, default, 0

    def get(self, url, **kw):
        self.n += 1
        full = str(url)
        if kw.get("params"):
            full += "?" + "&".join(f"{k}={v}" for k, v in kw["params"].items())
        answer = next((v for k, v in self.routes.items() if k in full), self.default)
        if isinstance(answer, Exception):
            raise answer
        status, text, final = (answer + (None,))[:3] if len(answer) == 2 else answer
        return httpx.Response(status, text=text, request=httpx.Request("GET", final or full))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _one(status, text, final=None):
    return _Client({"": (status, text, final)} if final else {"": (status, text)})


# ── the host pin ───────────────────────────────────────────────────────────────────────────────────────
def test_pinned_host_is_built_not_matched():
    assert pinned_host("madhacks-fall-2025") == "madhacks-fall-2025.devpost.com"
    assert pinned_host("  MadHacks-2025 ") == "madhacks-2025.devpost.com"   # DNS is case insensitive


@pytest.mark.parametrize("slug", [
    "evil-devpost.com",              # the substring test's classic pass
    "devpost.com.attacker.net",
    "a.b",
    "x/y",
    "x?y",
    "user@host",
    "",
    "-leading",
    "trailing-",
    "a" * 64,
])
def test_pinned_host_rejects_anything_that_is_not_one_label(slug):
    with pytest.raises(ValueError):
        pinned_host(slug)


def test_event_page_rejects_an_arbitrary_path():
    with pytest.raises(ValueError):
        event_page("some-event", "../../admin")


# ── the tri-state fetch: only 404 and 410 are absence ──────────────────────────────────────────────────
@pytest.mark.parametrize("status", [202, 403, 405, 429, 503])
def test_waf_statuses_are_blocked_never_not_found(status):
    f = event_page("ev", "rules", client=_one(status, ""))
    assert f.status == "blocked" and f.html is None and str(status) in f.detail


@pytest.mark.parametrize("status", [404, 410])
def test_only_a_real_absence_is_not_found(status):
    assert event_page("ev", "rules", client=_one(status, "gone")).status == "not_found"


@pytest.mark.parametrize("status,text", [(500, "boom"), (502, "bad gateway"), (301, "moved")])
def test_other_unhappy_statuses_are_blocked(status, text):
    assert event_page("ev", "rules", client=_one(status, text)).status == "blocked"


def test_a_transport_error_is_blocked_not_absent():
    f = event_page("ev", "rules", client=_one(200, "x").__class__({"": httpx.ConnectError("reset")}))
    assert f.status == "blocked" and "ConnectError" in f.detail


def test_an_empty_200_body_is_blocked():
    # the WAF's zero byte challenge answers 200 sometimes; an empty page is not an empty rules page
    assert event_page("ev", "rules", client=_one(200, "   ")).status == "blocked"


def test_a_challenge_page_served_as_200_is_blocked():
    f = event_page("ev", "rules", client=_one(200, "<html>captcha.awswaf.com</html>"))
    assert f.status == "blocked" and "challenge" in f.detail


def test_a_redirect_off_the_pinned_host_is_blocked():
    # a 200 that came from somewhere else is not this event's page, whatever it says
    f = event_page("ev", "rules", client=_one(200, "<a href='/x'>x</a>", "https://evil-devpost.com/rules"))
    assert f.status == "blocked" and "evil-devpost.com" in f.detail


def test_a_good_page_is_ok_and_carries_its_body():
    f = event_page("ev", "overview", client=_one(200, "<html>hi</html>"))
    assert f.status == "ok" and f.html == "<html>hi</html>" and "200" in f.detail


# ── href extraction: a link, never a mention ───────────────────────────────────────────────────────────
def test_anchor_hrefs_takes_anchors_only_and_decodes_entities():
    hrefs = anchor_hrefs(
        '<link rel="stylesheet" href="https://cdn.example/app.css">'
        '<p>our token is https://sloptic.org/v/abc123, paste it</p>'
        "<!-- <a href='https://sloptic.org/v/commented'>x</a> is still an anchor -->"
        '<a class="btn" href="https://sloptic.org/v/abc123?a=1&amp;b=2">verify</a>'
        "<a href='https://single.example/q'>q</a>"
        '<a href=https://bare.example/z>z</a>'
        '<a href="">empty</a>')
    assert "https://cdn.example/app.css" not in hrefs          # a stylesheet is not published by anyone
    assert "https://sloptic.org/v/abc123" not in hrefs         # quoted in prose, not linked
    assert "https://sloptic.org/v/abc123?a=1&b=2" in hrefs     # entity decoded, byte comparable
    assert "https://single.example/q" in hrefs and "https://bare.example/z" in hrefs
    assert "" not in hrefs


def test_anchor_hrefs_deduplicates_and_keeps_document_order():
    assert anchor_hrefs('<a href="/a">1</a><a href="/b">2</a><a href="/a">3</a>') == ["/a", "/b"]


# ── event_links: the completeness contract ─────────────────────────────────────────────────────────────
def _links_client(rules, overview):
    return _Client({"/rules": rules, "": overview})


def test_event_links_tags_each_href_with_the_page_it_came_from():
    got = event_links("ev", client=_links_client(
        (200, '<a href="https://sloptic.org/v/tok">verify</a>'),
        (200, '<a href="https://example.org/sponsor">sponsor</a>')))
    assert got.status == "ok"
    # each link carries its page and, now, the anchor's own display text
    pairs = [(l.href, l.page, l.text) for l in got.links]
    assert ("https://sloptic.org/v/tok", "rules", "verify") in pairs
    assert ("https://example.org/sponsor", "overview", "sponsor") in pairs


def test_a_missing_rules_page_still_leaves_the_list_complete():
    # plenty of events never fill /rules in; a 404 there is a genuine absence of links, not a gap
    got = event_links("ev", client=_links_client((404, "nope"), (200, '<a href="https://x.test/t">t</a>')))
    assert got.status == "ok" and [link.href for link in got.links] == ["https://x.test/t"]


def test_one_blocked_page_makes_the_whole_list_incomplete():
    # the token could have been on the page we did not get, so absence proves nothing here
    got = event_links("ev", client=_links_client((403, ""), (200, '<a href="https://x.test/t">t</a>')))
    assert got.status == "blocked"
    assert [link.href for link in got.links] == ["https://x.test/t"]   # what we DID read still counts


def test_an_event_with_no_pages_at_all_is_not_found():
    assert event_links("ev", client=_links_client((404, ""), (404, ""))).status == "not_found"


def test_event_links_never_offers_a_contains_helper():
    import sloptic.devpost as dp
    assert not [n for n in dir(dp) if "contain" in n.lower()]


# ── event_meta ─────────────────────────────────────────────────────────────────────────────────────────
def _api(*events, page2=()):
    return {"api/hackathons?search=cs girlies wellness hackathon&page=1": (200, json.dumps({"hackathons": list(events)})),
            "api/hackathons": (200, json.dumps({"hackathons": list(page2)}))}


_REAL = {"title": "CS Girlies Annual Hackathon", "url": "https://cs-girlies-wellness-hackathon.devpost.com/",
         "open_state": "ended", "invite_only": False, "submission_period_dates": "Mar 07 - 09, 2026",
         "submission_gallery_url": "https://cs-girlies-wellness-hackathon.devpost.com/project-gallery"}
_DECOY = {"title": "CS Girlies November Hackathon", "url": "https://cs-girlies-november.devpost.com/"}


def test_event_meta_matches_the_exact_host_not_a_similar_title():
    m = event_meta("cs-girlies-wellness-hackathon", client=_Client(_api(_DECOY, _REAL)))
    assert m.status == "ok"
    assert m.event["submission_period_dates"] == "Mar 07 - 09, 2026"
    assert m.event["open_state"] == "ended" and m.event["invite_only"] is False
    assert m.event["submission_gallery_url"].endswith("/project-gallery")


def test_event_meta_ignores_a_decoy_and_reports_the_absence_only_with_corroboration():
    # nothing in the API and no event page either: this event really does not exist
    routes = dict(_api(_DECOY))
    routes["cs-girlies-wellness-hackathon.devpost.com"] = (404, "nope")
    assert event_meta("cs-girlies-wellness-hackathon", client=_Client(routes)).status == "not_found"


def test_a_live_event_the_search_missed_is_blocked_not_absent():
    # the API searches titles, so an event whose title shares no words with its slug can go unsurfaced
    # while its page serves fine. Reporting that as "no such event" would be a fabricated absence.
    routes = dict(_api(_DECOY))
    routes["cs-girlies-wellness-hackathon.devpost.com"] = (200, "<html>the event</html>")
    m = event_meta("cs-girlies-wellness-hackathon", client=_Client(routes))
    assert m.status == "blocked" and "did not surface" in m.detail


def test_a_blocked_api_is_blocked_meta():
    assert event_meta("ev", client=_one(429, "")).status == "blocked"


def test_a_non_json_api_body_is_blocked_not_empty():
    assert event_meta("ev", client=_one(200, "<html>challenge</html>")).status == "blocked"


# ── the gallery ────────────────────────────────────────────────────────────────────────────────────────
_GALLERY = '<div class="gallery-item">https://devpost.com/software/proj-one winner</div>'


def _page(html):
    return repo_for(_one(200, _VENDOR + html), "https://devpost.com/software/x")


def _links(html):
    return links_for(_one(200, _VENDOR + html), "https://devpost.com/software/x")


def test_links_for_extracts_repo_and_live_url_together():
    # the demo link is the live URL, not the repo, not the video
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
    # "software-urls" whose <a> carry target/title/rel attrs; both repo and demo must extract
    repo, url = _links(
        '<div class="app-links section"><h2>Try it out</h2>'
        '<ul data-role="software-urls" class="no-bullet">'
        '<li><a target="_blank" title="x" rel="nofollow" href="https://github.com/team/proj">'
        '<i class="ss-icon ss-link"></i><span>github.com</span></a></li>'
        '<li><a target="_blank" rel="nofollow" href="https://proj.vercel.app"><span>demo</span></a></li>'
        '</ul></div>')
    assert repo == "https://github.com/team/proj" and url == "https://proj.vercel.app"


def test_real_repo_from_app_links_block_not_the_vendor_url():
    assert _page('<ul class="app-links"><li><a href="https://github.com/alice/proj">GitHub</a></li></ul>') \
        == "https://github.com/alice/proj"


def test_no_app_links_block_returns_none_not_the_vendor_url():
    # p-block's shape: the author linked no repo, so the only github link is the vendor's -> must be None
    assert _page("<body>no links here</body>") is None


def test_app_links_block_without_github_returns_none():
    # neuralpets' shape: an app-links list, but it only links a demo, not a repo
    assert _page('<ul class="app-links"><li><a href="https://demo.example.com">Try it</a></li></ul>') is None


def test_vendor_url_inside_app_links_block_is_filtered():
    assert _page('<ul class="app-links"><li>'
                 '<a href="https://github.com/newrelic/newrelic-browser-agent">x</a></li></ul>') is None


def test_multiclass_app_links_ul_still_matches():
    assert _page('<ul class="grid app-links mt-2"><li><a href="https://github.com/bob/thing">gh</a></li></ul>') \
        == "https://github.com/bob/thing"


def test_waf_block_warns_and_is_not_read_as_empty(capsys):
    # a 403 must NOT be silently read as an empty gallery: page_projects retries, then warns loudly and
    # returns [] UNCACHED, so a re-run retries instead of memoizing 'no projects'.
    assert page_projects(_one(403, "blocked"), "waf-slug", 1) == []
    err = capsys.readouterr().err
    assert "WAF-blocked" in err and "waf-slug" in err


def test_empty_gallery_200_is_cacheable_not_a_block(tmp_path):
    cache = IngestCache(str(tmp_path / "c.jsonl"))
    assert page_projects(_one(200, "<html>no items</html>"), "empty-slug", 9, cache) == []
    assert cache.has("page:empty-slug:9")            # an empty 200 IS cached; a 403 would not be


@pytest.mark.parametrize("status", [202, 405])
def test_waf_202_and_405_captcha_are_blocks_not_empty_galleries(status, capsys):
    # AWS-WAF's CAPTCHA answers a rate-limited client with a 0-byte 202 or 405, not a 403
    assert page_projects(_one(status, ""), f"waf{status}", 1) == []
    assert "WAF-blocked" in capsys.readouterr().err


# ── submissions: an iterator that refuses to look complete when it is not ──────────────────────────────
def _sub_client(**over):
    routes = {"submissions/search?page=1": (200, _GALLERY),
              "submissions/search?page=2": (200, "<html>end</html>"),
              "software/proj-one": (200, _VENDOR + '<ul class="app-links">'
                                        '<li><a href="https://github.com/a/b">gh</a></li>'
                                        '<li><a href="https://demo.test">demo</a></li></ul>')}
    routes.update(over)
    return _Client(routes)


def test_submissions_yields_the_raw_app_links():
    got = list(submissions("ev", client=_sub_client(), delay=0))
    assert got == [("https://devpost.com/software/proj-one", ["https://github.com/a/b", "https://demo.test"])]


def test_submissions_raises_when_a_gallery_page_is_blocked():
    # ending the loop instead would hand back a short gallery that looks exactly like a complete one
    with pytest.raises(Blocked):
        list(submissions("ev", client=_sub_client(**{"submissions/search?page=2": (503, "")}), delay=0))


def test_submissions_raises_when_a_project_page_is_blocked():
    with pytest.raises(Blocked):
        list(submissions("ev", client=_sub_client(**{"software/proj-one": (429, "")}), delay=0))


def test_submissions_treats_a_404_project_as_an_empty_link_list():
    got = list(submissions("ev", client=_sub_client(**{"software/proj-one": (404, "gone")}), delay=0))
    assert got == [("https://devpost.com/software/proj-one", [])]


# ── ingest cache: a completed hackathon's fetches are memoized ─────────────────────────────────────────
def test_ingest_cache_memoizes_links_and_survives_reload(tmp_path):
    # the core resumability claim: resolve once (1 fetch), re-resolve from cache (0), then a FRESH cache
    # object reading the same file still hits, so an interrupted scrape resumes without re-fetching.
    c = _one(200, '<ul class="app-links"><li><a href="https://github.com/a/b">gh</a></li></ul>')
    cache = IngestCache(tmp_path / "ing.jsonl")
    r1 = links_for(c, "https://devpost.com/software/x", cache)
    r2 = links_for(c, "https://devpost.com/software/x", cache)
    assert r1 == r2 == ("https://github.com/a/b", None)
    assert c.n == 1                                        # served from memory -> no new fetch
    reloaded = IngestCache(tmp_path / "ing.jsonl")         # a subsequent process
    assert links_for(c, "https://devpost.com/software/x", reloaded) == r1
    assert c.n == 1                                        # the entry persisted to the file


def test_a_legacy_links_cache_entry_is_still_honoured(tmp_path):
    # caches written before the hrefs: key space existed must keep hitting, not re-fetch the whole corpus
    path = tmp_path / "ing.jsonl"
    path.write_text(json.dumps({"k": "links:https://devpost.com/software/x",
                                "v": ["https://github.com/old/entry", None]}) + "\n")
    c = _one(200, "<html>should not be fetched</html>")
    assert links_for(c, "https://devpost.com/software/x", IngestCache(path)) == ("https://github.com/old/entry", None)
    assert c.n == 0


def test_ingest_cache_never_memoizes_a_blocked_fetch(tmp_path):
    # no-poisoning: a WAF block must NOT be cached as an (empty) result; it retries next run
    class _Flaky:
        def __init__(self):
            self.n = 0

        def get(self, url, **kw):
            self.n += 1
            ok = self.n > 5                                # blocked through every retry, then recovers
            body = '<ul class="app-links"><li><a href="https://github.com/a/b">gh</a></li></ul>' if ok else ""
            return httpx.Response(200 if ok else 403, text=body, request=httpx.Request("GET", url))

    c, cache = _Flaky(), IngestCache(tmp_path / "ing.jsonl")
    assert links_for(c, "https://devpost.com/software/x", cache) == (None, None)   # blocked -> uncached
    assert links_for(c, "https://devpost.com/software/x", cache) == ("https://github.com/a/b", None)
    assert not any(k.startswith("hrefs:") for k in cache.mem) or c.n == 6


def test_ingest_cache_memoizes_gallery_pages(tmp_path):
    c = _one(200, _GALLERY)
    cache = IngestCache(tmp_path / "ing.jsonl")
    p1 = page_projects(c, "hack", 1, cache)
    p2 = page_projects(c, "hack", 1, cache)
    assert p1 == p2 == [("https://devpost.com/software/proj-one", True)]
    assert c.n == 1


def test_per_slug_budget_balances_a_multi_hackathon_pull():
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    from devpost_repos import _per_slug_budget
    assert _per_slug_budget(30, 1) == 30       # single slug -> whole budget (unchanged behavior)
    assert _per_slug_budget(30, 3) == 10       # 3 slugs -> 10 each, balanced for diversity (not 30/0/0)
    assert _per_slug_budget(25, 5) == 5        # --search's default shape, now balanced too
    assert _per_slug_budget(10, 3) == 4        # ceil so the total still reaches ~the limit (4*3=12 >= 10)


def test_submissions_rejects_a_bad_slug_before_the_first_step():
    # a generator that validates lazily hands the caller a ValueError from inside their loop
    with pytest.raises(ValueError):
        submissions("evil-devpost.com")


def test_event_links_refuses_to_call_an_empty_scan_complete():
    with pytest.raises(ValueError):
        event_links("ev", client=_one(200, "x"), pages=())
