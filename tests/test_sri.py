"""Subresource Integrity (SRI) -- a cross-origin <script>/<stylesheet> without an integrity= hash is an
unguarded supply-chain risk. Same-origin and relative resources need no SRI; images are out of scope; a page
that carries integrity on every third-party resource is clean; a page with no third-party resource is N/A."""
import http.server
import threading

import pytest

from sloptic.probes import _sri_scan, subresource_integrity_missing
from sloptic.schema import Profile

_ORIGIN = "https://app.example.com/"


def test_cross_origin_script_without_integrity_is_a_gap():
    gaps, total = _sri_scan('<script src="https://cdn.jsdelivr.net/npm/x.js"></script>', _ORIGIN)
    assert total == 1 and gaps == ["https://cdn.jsdelivr.net/npm/x.js"]


def test_cross_origin_script_with_integrity_is_clean():
    html = '<script src="https://cdn.jsdelivr.net/npm/x.js" integrity="sha384-abc" crossorigin></script>'
    gaps, total = _sri_scan(html, _ORIGIN)
    assert total == 1 and gaps == []


def test_same_origin_and_relative_scripts_need_no_sri():
    html = ('<script src="/app.js"></script>'
            '<script src="https://app.example.com/main.js"></script>'
            '<script src="bundle.js"></script>')
    gaps, total = _sri_scan(html, _ORIGIN)
    assert total == 0 and gaps == []


def test_cross_origin_stylesheet_and_modulepreload_are_in_scope():
    html = ('<link rel="stylesheet" href="https://cdn.other.io/theme.css">'
            '<link rel="modulepreload" href="https://cdn.other.io/m.js">')
    gaps, total = _sri_scan(html, _ORIGIN)
    assert total == 2 and set(gaps) == {"https://cdn.other.io/theme.css", "https://cdn.other.io/m.js"}


def test_protocol_relative_cross_origin_is_in_scope():
    gaps, total = _sri_scan('<script src="//cdn.other.io/a.js"></script>', _ORIGIN)
    assert total == 1 and gaps == ["https://cdn.other.io/a.js"]


def test_images_and_canonical_link_are_out_of_scope():
    html = '<img src="https://cdn.other.io/pic.png"><link rel="canonical" href="https://other.io/x">'
    gaps, total = _sri_scan(html, _ORIGIN)
    assert total == 0 and gaps == []


def test_sri_inapplicable_font_css_and_tag_loaders_are_excluded_by_dominance():
    # Google Fonts serves per-UA CSS -> a pinned hash BREAKS it, so requiring SRI is not the better practice (FP)
    gaps, total = _sri_scan('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">', _ORIGIN)
    assert total == 0 and gaps == []                 # not counted -> nothing SRI-applicable to protect
    # a tag/loader endpoint publishes no stable hash and bootstraps further scripts -> likewise excluded
    g2, t2 = _sri_scan('<script src="https://www.googletagmanager.com/gtag/js?id=X"></script>', _ORIGIN)
    assert t2 == 0 and g2 == []


def test_builder_injected_asset_hosts_are_wrong_owner_and_excluded():
    # the platform wrote these tags; the participant can't add integrity= to a tag they didn't author -> FP
    for src in ("https://cdn.gpteng.co/gptengineer.js",
                "https://framerusercontent.com/x.js",
                "https://static.parastorage.com/services/y.js"):
        gaps, total = _sri_scan(f'<script src="{src}"></script>', _ORIGIN)
        assert total == 0 and gaps == [], src


def test_first_party_sibling_subdomain_needs_no_sri():
    # same registrable domain (clerk.app.example.com ~ app.example.com) -> app-controlled, not a third-party CDN
    gaps, total = _sri_scan('<script src="https://clerk.app.example.com/npm/clerk.js"></script>', _ORIGIN)
    assert total == 0 and gaps == []


def test_different_multitenant_subdomain_is_still_third_party():
    # foo.vercel.app != bar.vercel.app (multi-tenant suffix, PSL-aware) -> another tenant IS cross-origin
    gaps, total = _sri_scan('<script src="https://other.vercel.app/x.js"></script>', "https://myapp.vercel.app/")
    assert total == 1 and gaps == ["https://other.vercel.app/x.js"]


def test_non_executing_preload_dropped_but_script_preload_kept():
    html = ('<link rel="preload" as="font" href="https://cdn.other.io/f.woff2">'
            '<link rel="preload" as="image" href="https://cdn.other.io/pic.png">'
            '<link rel="preload" as="script" href="https://cdn.other.io/late.js">')
    gaps, total = _sri_scan(html, _ORIGIN)
    assert total == 1 and gaps == ["https://cdn.other.io/late.js"]


# ---- the probe end to end ---------------------------------------------------------------------------

_PAGES = {
    "/gap": '<html><head><script src="https://cdn.jsdelivr.net/npm/x.js"></script></head></html>',
    "/clean": '<html><head><script src="https://cdn.jsdelivr.net/npm/x.js" integrity="sha384-abc"></script></head></html>',
    "/na": '<html><head><script src="/app.js"></script></head><body>hi</body></html>',
}


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = _PAGES.get(self.path.split("?")[0], "<html><body>ok</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": None, "evidence": {}})()


def _probe(target):
    return type("P", (), {"probe": {"target": target}})()


def test_fires_on_cross_origin_script_without_integrity(app):
    ctx = _ctx(app)
    assert subresource_integrity_missing(ctx, _probe("/gap")) is True
    assert ctx.evidence["sri_missing"] == ["https://cdn.jsdelivr.net/npm/x.js"]


def test_clean_when_integrity_present(app):
    assert subresource_integrity_missing(_ctx(app), _probe("/clean")) is False


def test_na_when_no_cross_origin_subresource(app):
    assert subresource_integrity_missing(_ctx(app), _probe("/na")) is None
