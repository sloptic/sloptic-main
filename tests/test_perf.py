"""Performance rubric — objective primitives + tiered thresholds. Unit-tests the math; integration-
tests each primitive against inline servers (slow / heavy / chatty vs fast / light)."""
import http.server
import threading
from urllib.parse import urlparse

import pytest

from hacklet_runner import perf
from hacklet_runner.probes import perf_load_time, perf_page_weight, perf_request_count, perf_ttfb


def test_percentile_interpolates():
    assert perf._pctl([1, 2, 3, 4, 5], 0.9) == pytest.approx(4.6)
    assert perf._pctl([], 0.9) == 0.0


def test_computed_load_time_is_deterministic():
    # 12 Mbps, 50ms RTT: 3MB -> 3e6*8/12e6 = 2.0s transfer; + 0.2 ttfb + 4 reqs*0.05 = 2.4s
    assert perf.computed_load_time(0.2, 3_000_000, 4) == pytest.approx(2.4, abs=0.01)


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        import time
        p = urlparse(self.path).path
        if p == "/slow":
            time.sleep(0.9); body = b"<html>ok</html>"
        elif p == "/heavy":
            body = b"<html>" + b"a" * 2_100_000 + b"</html>"           # >2MB (profile), <10MB (ceiling)
        elif p == "/huge":
            body = b"<html>" + b"a" * 11_000_000 + b"</html>"          # >10MB ceiling; load-time > 5s
        elif p == "/chatty":
            body = (b"<html>" + b"".join(b"<img src='/i%d.png'>" % i for i in range(60)) + b"</html>")
        elif p == "/cachebusted":
            # 60 round trips to ONE path, versioned by query — how every bundler ships assets. Counting
            # distinct PATHS collapses this to 1 and the page reads tidy.
            body = (b"<html>" + b"".join(b"<img src='/dot.png?v=%d'>" % i for i in range(60)) + b"</html>")
        else:
            body = b"<html><img src='/logo.png'>fast light page</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
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
    return type("C", (), {"base_url": url, "profile": None, "headers": None, "client": None,
                          "evidence": {}})()   # predicates record measured values here (as the real _Ctx does)


def _probe(**kw):
    return type("P", (), {"probe": kw})()


def test_ttfb_profile_fires_but_ceiling_stays_clean(app):
    ctx = _ctx(app)
    assert perf_ttfb(ctx, _probe(target="/slow", tier="profile")) is True    # 0.9s > 0.8 profile
    assert perf_ttfb(ctx, _probe(target="/slow", tier="ceiling")) is False   # 0.9s < 3.0 ceiling
    assert perf_ttfb(ctx, _probe(target="/fast", tier="profile")) is False


def test_page_weight_tiers(app):
    ctx = _ctx(app)
    assert perf_page_weight(ctx, _probe(target="/heavy", tier="profile")) is True    # >2MB
    assert perf_page_weight(ctx, _probe(target="/heavy", tier="ceiling")) is False   # <10MB
    assert perf_page_weight(ctx, _probe(target="/huge", tier="ceiling")) is True     # >10MB
    assert perf_page_weight(ctx, _probe(target="/fast", tier="profile")) is False


def test_request_count(app):
    ctx = _ctx(app)
    assert perf_request_count(ctx, _probe(target="/chatty")) is True   # 61 > 50
    assert perf_request_count(ctx, _probe(target="/fast")) is False    # 2


def test_load_time_ceiling(app):
    ctx = _ctx(app)
    assert perf_load_time(ctx, _probe(target="/huge")) is True    # 11MB transfer -> >5s on the profile
    assert perf_load_time(ctx, _probe(target="/fast")) is False


def test_a_cache_busted_page_is_counted_as_the_round_trips_it_actually_makes(app):
    """Measured on supavulnbase's perf-003 fixture: 60 statically-referenced `dot.png?v=N` links counted as
    ONE request against a threshold of 50, so perf-requests-001 read clean on a page built to fail it.

    _page_weight stripped the query before de-duplicating, but `dot.png?v=11` and `dot.png?v=12` are two
    round trips and two cache entries — and a cache-busting query string is precisely how bundlers version
    assets, so this was not a fixture quirk but the mainstream case."""
    ctx = _ctx(app)
    assert perf_request_count(ctx, _probe(target="/cachebusted")) is True
    assert ctx.evidence["requests"] > perf.REQUESTS_PROFILE
    assert ctx.evidence["requests"] >= 60, "cache-busted URLs collapsed again: %r" % ctx.evidence

    clean = _ctx(app)
    assert perf_request_count(clean, _probe(target="/")) is False   # one asset -> still tidy


def test_content_encoding_identity_is_not_compression():
    """`identity` is HTTP's explicit token for "no transformation applied" (RFC 9110 8.4.1), so the header's
    PRESENCE is not evidence of compression — its VALUE is.

    Measured on supavulnbase's perf-001 fixture: 124,879 bytes of text/plain served with
    `content-encoding: identity` even when we send `Accept-Encoding: gzip, deflate, br`. Their verify.sh
    asserts it is uncompressed and passes; we saw the header existed and reported clean."""
    import gzip as _gzip

    import httpx

    from hacklet_runner.probes import response_uncompressed

    def _plain(headers, size=5000):
        return httpx.Response(200, headers={"content-type": "text/plain", **headers},
                              content=b"x" * size, request=httpx.Request("GET", "http://x/"))

    assert response_uncompressed(_plain({"content-encoding": "identity"}), 512) is True
    assert response_uncompressed(_plain({}), 512) is True                       # absent -> uncompressed
    assert response_uncompressed(_plain({"content-encoding": ""}), 512) is True   # empty -> uncompressed
    # the size gate still applies: a tiny body is correct to leave alone
    assert response_uncompressed(_plain({"content-encoding": "identity"}, size=100), 512) is False

    # genuinely compressed still reads clean. Encoded for real, because httpx decodes on .content and a
    # fake gzip header over plain bytes raises DecodingError rather than exercising the branch.
    body = _gzip.compress(b"x" * 5000)
    real = httpx.Response(200, headers={"content-type": "text/plain", "content-encoding": "gzip"},
                          content=body, request=httpx.Request("GET", "http://x/"))
    assert response_uncompressed(real, 512) is False

    # casing/whitespace must not defeat the check — the branch is reached before any body access
    class _Hdrs(dict):
        def get(self, k, d=""):
            return super().get(k.lower(), d)

    class _Fake:
        status_code = 200
        def __init__(self, enc):
            self.headers = _Hdrs({"content-type": "text/plain", "content-encoding": enc})
            self.content = b"x" * 5000

    for enc in ("GZIP", " gzip ", "br", "deflate", "zstd"):
        assert response_uncompressed(_Fake(enc), 512) is False, enc
    assert response_uncompressed(_Fake("IDENTITY"), 512) is True
