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
