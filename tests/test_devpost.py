"""devpost_repos.repo_for must return a submission's OWN repo, never Devpost's embedded vendor URL
(github.com/newrelic/newrelic-browser-agent, present in the RUM script on every project page). Pure —
a stub client feeds canned HTML, no network.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from devpost_repos import repo_for  # noqa: E402

_VENDOR = '<script>d("https://github.com/newrelic/newrelic-browser-agent")</script>'   # on EVERY page


class _Stub:
    def __init__(self, text, status=200):
        self._text, self._status = text, status

    def get(self, url, **kw):
        return type("R", (), {"status_code": self._status, "text": self._text})()


def _page(html):
    return repo_for(_Stub(_VENDOR + html), "https://devpost.com/software/x")


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
