"""Cold-start-serving free-tier hosts (Render et al.) get a long READ timeout on the reachability check so a
spinning-up app isn't written off as dead_url — 30% of v17's Render 'dead' apps were merely cold (HTTP 200
after 20-31s). Connect stays short so a genuinely-down host still fails fast; other hosts keep the base timeout."""
import pathlib
import sys

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from deploy_and_grade import _reach_timeout  # noqa: E402


def test_cold_start_hosts_get_a_long_read_short_connect():
    for u in ("https://x.onrender.com/", "https://y.up.railway.app/", "https://z.fly.dev/",
              "https://w.koyeb.app/", "https://v.cyclic.app/"):
        t = _reach_timeout(u, 10.0)
        assert isinstance(t, httpx.Timeout), u
        assert t.read == 45.0 and t.connect <= 10.0, u


def test_non_cold_start_hosts_keep_the_base_timeout():
    for u in ("https://a.vercel.app/", "https://b.netlify.app/", "https://c.github.io/",
              "https://d.streamlit.app/", "https://e.example.com/"):
        assert _reach_timeout(u, 10.0) == 10.0, u


def test_bare_and_nested_subdomain_both_match():
    assert isinstance(_reach_timeout("https://onrender.com/", 10.0), httpx.Timeout)          # bare host
    assert isinstance(_reach_timeout("https://deep.sub.onrender.com/x", 10.0), httpx.Timeout)  # nested sub + path
    # a host that merely CONTAINS the suffix as a non-boundary substring must NOT match
    assert _reach_timeout("https://notonrender.com.evil.io/", 10.0) == 10.0
