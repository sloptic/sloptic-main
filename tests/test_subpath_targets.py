"""A sub-path app's well-known paths must be probed UNDER it, not at the origin.

The client is origin-bound by design (a path-bearing base_url breaks httpx's relative-redirect resolution),
and `landing_path` was only applied to the homepage sentinel. So a probe declaring `target: /.env` or
`/.git/config` resolved against the HOST and reported clean on the app.

Measured on GapBench: `/.git/config` 404s at the apex while the scenario serves it at
`/site/git-exposed/.git/config`, so every path-guessing exposure probe tested nothing across 31 scenarios and
came back "miss". The same applies to any app at `user.github.io/project/`, which the Devpost corpus contains.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.pipeline import _expand  # noqa: E402
from sloptic.probes import _at  # noqa: E402
from sloptic.schema import Form, Probe, Profile  # noqa: E402


def _probe(target):
    return Probe(id="t", bundle="security", penalty=1, probe={"target": target})


def _sub(landing="/site/git-exposed"):
    return Profile(base_url="https://host", landing_path=landing,
                   routes=["/site/git-exposed/", "/site/git-exposed/inbox"],
                   forms=[Form(action="/site/git-exposed/login", method="post", fields=["u", "p"])])


def _root():
    return Profile(base_url="https://host", landing_path="/", routes=["/", "/inbox"],
                   forms=[Form(action="/login", method="post", fields=["u", "p"])])


def test_a_literal_well_known_path_is_probed_under_the_app_root():
    for declared, expected in (("/.env", "/site/git-exposed/.env"),
                               ("/.git/config", "/site/git-exposed/.git/config"),
                               ("/.aws/credentials", "/site/git-exposed/.aws/credentials")):
        (label, _fetch), = _expand(_probe(declared), _sub())
        assert label == expected, declared


def test_the_homepage_sentinel_still_maps_to_the_landing_page():
    (label, _f), = _expand(_probe("/"), _sub())
    assert label == "/site/git-exposed"


def test_a_root_served_app_is_completely_unaffected():
    # the whole normal corpus: landing_path "/" must leave every target exactly as declared
    for declared in ("/", "/.env", "/.git/config", "/crash", "/slow"):
        (label, _f), = _expand(_probe(declared), _root())
        assert label == ("/" if declared == "/" else declared), declared


def test_discovered_surface_is_never_rebased():
    # routes and forms already carry full paths from discovery; prefixing them again would double the prefix
    routes = _expand(_probe("routes"), _sub())
    assert [lbl for lbl, _f in routes] == ["/site/git-exposed/", "/site/git-exposed/inbox"]
    forms = _expand(_probe("forms"), _sub())
    assert [lbl for lbl, _f in forms] == ["/site/git-exposed/login"]


def test_at_helper_rebases_constructed_fetches_and_no_ops_at_root():
    sub = type("C", (), {"profile": _sub()})()
    assert _at(sub, "/") == "/site/git-exposed"
    assert _at(sub, "/.git/config") == "/site/git-exposed/.git/config"
    assert _at(sub, "hl-probe-404") == "/site/git-exposed/hl-probe-404"   # relative form too
    root = type("C", (), {"profile": _root()})()
    for path in ("/", "/.env", "hl-probe-404"):
        assert _at(root, path) == path
    # tolerant of a ctx with no profile at all (stub ctxs in unit tests)
    assert _at(type("C", (), {})(), "/.env") == "/.env"
