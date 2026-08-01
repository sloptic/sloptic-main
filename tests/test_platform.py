"""platform_id — the off-score host-platform + AI-builder classifier. Header beats suffix (survives a custom
domain); builder comes from served markup, never the host; a fronting CDN is reported as edge, not as the
origin platform; an unattributable custom domain stays 'unknown' rather than guessing."""
from sloptic.platform_id import classify, classify_live


def test_vercel_by_header_on_custom_domain():
    # a custom domain hides the suffix, but the platform header leaks through -> still attributed
    p = classify("https://app.mystartup.com", {"x-vercel-id": "iad1::abc", "server": "Vercel"}, "<html></html>")
    assert p["host_platform"] == "vercel" and p["builder"] is None


def test_vercel_by_suffix():
    assert classify("https://foo.vercel.app", {}, "")["host_platform"] == "vercel"


def test_netlify_by_header():
    assert classify("https://x.com", {"x-nf-request-id": "abc"}, "")["host_platform"] == "netlify"


def test_railway_and_render_by_suffix():
    assert classify("https://api-foo.up.railway.app", {}, "")["host_platform"] == "railway"
    assert classify("https://svc.onrender.com", {}, "")["host_platform"] == "render"


def test_github_pages_by_server_header():
    assert classify("https://user.example.org", {"server": "GitHub.com"}, "")["host_platform"] == "github-pages"


def test_cloudflare_edge_masks_origin():
    # cf-ray means Cloudflare is FRONTING the origin, not that the origin is CF Pages -> edge set, host unknown
    p = classify("https://app.example.com", {"cf-ray": "8a::x", "server": "cloudflare"}, "")
    assert p["edge"] == "cloudflare" and p["host_platform"] == "unknown"


def test_cloudflare_pages_origin_by_suffix():
    p = classify("https://proj.pages.dev", {"cf-ray": "8a::x"}, "")
    assert p["host_platform"] == "cloudflare-pages" and p["edge"] == "cloudflare"


def test_lovable_builder_from_markup_on_any_host():
    # the thesis case: a Lovable-built app deployed to a Vercel custom domain -> builder=lovable, host=vercel
    html = '<head><script src="https://cdn.gpteng.co/gptengineer.js"></script></head>'
    p = classify("https://cool.mydomain.com", {"x-vercel-id": "iad1::z"}, html)
    assert p["builder"] == "lovable" and p["host_platform"] == "vercel"


def test_lovable_by_own_suffix_sets_both():
    p = classify("https://myapp.lovable.app", {}, "")
    assert p["builder"] == "lovable" and p["host_platform"] == "lovable"


def test_bolt_builder_from_markup():
    assert classify("https://x.netlify.app", {}, "<html>built with bolt.new</html>")["builder"] == "bolt"


def test_unknown_custom_domain_is_not_guessed():
    p = classify("https://acme.io", {"server": "nginx"}, "<html>plain</html>")
    assert p["host_platform"] == "unknown" and p["builder"] is None and p["edge"] is None


def test_https_flag_and_host():
    p = classify("http://foo.vercel.app", {}, "")
    assert p["https"] is False and p["host"] == "foo.vercel.app"


def test_classify_live_never_raises_on_dead_origin():
    import httpx

    class _Dead:
        def get(self, url):
            raise httpx.ConnectError("down")
    p = classify_live(_Dead(), "https://foo.vercel.app")   # falls back to URL-only classification
    assert p["host_platform"] == "vercel"
