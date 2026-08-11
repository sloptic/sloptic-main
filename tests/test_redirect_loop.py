"""Redirect loops -- a route that redirects endlessly (self-loop, A<->B cycle, or a chain over the browser cap)
so a visitor gets ERR_TOO_MANY_REDIRECTS instead of the page. A route that redirects and then resolves is fine."""
import http.server
import threading
from urllib.parse import urlparse

import pytest

from sloptic.probes import redirect_loop
from sloptic.schema import Profile


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _html(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/loopself":
            self._redirect("/loopself")                       # a route that redirects to itself
        elif p == "/loopa":
            self._redirect("/loopb")
        elif p == "/loopb":
            self._redirect("/loopa")                          # A <-> B cycle
        elif p == "/goodredirect":
            self._redirect("/ok")                             # redirects ONCE, then resolves -> fine
        elif p == "/ok":
            self._html("<h1>ok</h1>")
        elif p == "/hub":
            self._html('<a href="/loopself">x</a> <a href="/ok">y</a>')   # links a looping route
        elif p == "/clean":
            self._html('<a href="/ok">y</a> <a href="/goodredirect">z</a>')  # links only resolving routes
        else:
            self._html("<h1>home</h1>")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _probe(target):
    return type("P", (), {"probe": {"target": target, "max_hops": 20, "max_attempts": 40}})()


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": None, "evidence": {}})()


def test_fires_on_self_loop(app):
    ctx = _ctx(app)
    assert redirect_loop(ctx, _probe("/loopself")) is True
    assert ctx.evidence["loop"] is True and ctx.evidence["reason"] == "redirect cycle"


def test_fires_on_a_to_b_cycle(app):
    assert redirect_loop(_ctx(app), _probe("/loopa")) is True


def test_fires_on_a_looping_linked_route(app):
    # the entry page resolves, but a same-origin route it LINKS loops -> caught via the crawl
    ctx = _ctx(app)
    assert redirect_loop(ctx, _probe("/hub")) is True
    assert ctx.evidence["entry"] == "/loopself"


def test_clean_on_a_redirect_that_resolves(app):
    assert redirect_loop(_ctx(app), _probe("/goodredirect")) is False


def test_clean_when_all_linked_routes_resolve(app):
    assert redirect_loop(_ctx(app), _probe("/clean")) is False


def test_na_when_origin_unreachable():
    # nothing answered -> reachable stays False -> can't-assess, not a (false) clean
    ctx = _ctx("http://127.0.0.1:1")   # port 1: connection refused
    assert redirect_loop(ctx, _probe("/x")) is None
