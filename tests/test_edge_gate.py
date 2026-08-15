"""v2.0: the hosting-layer probes (sec-ratelimit-001 rate-limiting, perf-load-001 load burst) go N/A on a
managed-edge host, where those protections are the VENDOR's (inherited), not the team's -- and where sending
the burst trips the platform's WAF. They stay LIVE on a self-hosted PaaS (railway/render/fly) and unknown/own
hosts, where the app owns its own rate-limiting + capacity."""
from sloptic.catalog import default_catalog_dir, load_catalog
from sloptic.pipeline import _applicable
from sloptic.platform_id import classify, edge_managed
from sloptic.schema import Profile

_GATED = ("sec-ratelimit-001", "perf-load-001")
_CAT = {p.id: p for p in load_catalog(default_catalog_dir())}


def test_edge_managed_hosts_vs_self_hosted():
    for plat in ({"host_platform": "vercel", "edge": None}, {"host_platform": "netlify", "edge": None},
                 {"host_platform": "cloudflare-pages", "edge": None}, {"host_platform": "firebase", "edge": None},
                 {"host_platform": "base44", "edge": None},             # a BaaS platform: it owns auth + scaling
                 {"host_platform": "unknown", "edge": "cloudflare"}):   # any WAF-CDN-fronted origin
        assert edge_managed(plat) is True, plat
    for plat in ({"host_platform": "railway", "edge": None}, {"host_platform": "render", "edge": None},
                 {"host_platform": "fly", "edge": None}, {"host_platform": "unknown", "edge": None}):
        assert edge_managed(plat) is False, plat


def test_classify_flags_vercel_from_headers():
    assert edge_managed(classify("https://app.vercel.app", {"x-vercel-id": "abc"}, None)) is True
    assert edge_managed(classify("https://app.up.railway.app", {}, None)) is False


def test_classify_flags_base44_as_managed_by_suffix():
    # base44's /api/auth/login is the platform's endpoint (identical across every base44 app), so its
    # rate-limiting is the vendor's -> the hosting-layer probes go N/A, like firebase.
    plat = classify("https://cheerful-mind-match-flow.base44.app", {}, None)
    assert plat["host_platform"] == "base44" and edge_managed(plat) is True


def test_gate_makes_the_two_probes_na_on_managed_edge_only():
    managed = Profile(base_url="x", capabilities={"at_least_one_http_endpoint_exists": True, "not_edge_managed": False})
    selfhost = Profile(base_url="x", capabilities={"at_least_one_http_endpoint_exists": True, "not_edge_managed": True})
    for pid in _GATED:
        assert _applicable(_CAT[pid], managed) is False, f"{pid} must be N/A on a managed-edge host"
        assert _applicable(_CAT[pid], selfhost) is True, f"{pid} must stay live self-hosted"


def test_a_missing_capability_gates_off_by_default():
    # a profile from an OLD cached run without the flag -> the probes go N/A (fail-safe: don't send a burst we
    # can't confirm is safe), never a crash.
    legacy = Profile(base_url="x", capabilities={"at_least_one_http_endpoint_exists": True})
    for pid in _GATED:
        assert _applicable(_CAT[pid], legacy) is False
