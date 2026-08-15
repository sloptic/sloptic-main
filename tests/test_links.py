"""Broken links — an internal <a href> that lands on a 4xx is a dead end. Fires only on a same-origin
4xx; a followed redirect that resolves, a 5xx (crash-resistance's domain), and an external link are all
NOT broken. N/A when the page has no internal links."""
import http.server
import threading

import pytest

from sloptic.probes import broken_links

_MODE_LINK = {
    "dead": '<a href="/gone">x</a>',
    "ok": '<a href="/good2">x</a>',
    "redirect": '<a href="/moved">x</a>',
    "server": '<a href="/boom">x</a>',
    "external": '<a href="http://example.invalid/gone">x</a>',
    "template": '<a href="/${s.url}">x</a>',                 # uninterpolated template literal -> not a link
    "cdncgi": '<a href="/cdn-cgi/l/email-protection#abc">x</a>',  # Cloudflare-injected -> not the app's link
    "entity": '<a href="/api?role=x&amp;id=y">x</a>',        # &amp; IS & to a browser -> decodes to a valid URL
    "forbidden": '<a href="/gated">x</a>',                   # 403 access-control -> gated, not a dead end
}


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _w(self, code, body, ctype="text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/":
                if mode == "none":
                    return self._w(200, b"<html><body><p>no links here</p></body></html>")
                body = ('<html><body><a href="/good">home</a>' + _MODE_LINK[mode] + "</body></html>").encode()
                return self._w(200, body)
            if p in ("/good", "/good2"):
                return self._w(200, b"ok")
            if p == "/moved":
                self.send_response(302)
                self.send_header("Location", "/good")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if p == "/boom":
                return self._w(500, b"server error", "text/plain")
            if p == "/api":
                # 400 if the &amp; was NOT decoded (a literal `amp;` param leaks in); 200 on the real URL
                return self._w(400 if "amp;" in self.path else 200, b"ok")
            if p == "/gated":
                return self._w(403, b"forbidden", "text/plain")
            return self._w(404, b"not found", "text/plain")   # /gone + anything unknown
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(mode):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(mode))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {"target": "/", "max_attempts": 40}


def _ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()


def test_broken_links_fires_on_dead_internal_link(server):
    assert broken_links(_ctx(server("dead")), _Probe()) is True


@pytest.mark.parametrize("mode", ["ok", "redirect", "server", "external"])
def test_broken_links_clean_when_not_a_4xx_dead_end(server, mode):
    # resolves / followed-redirect-resolves / 5xx (crash-resistance's job) / external -> not broken
    assert broken_links(_ctx(server(mode)), _Probe()) is False


@pytest.mark.parametrize("mode", ["template", "cdncgi", "entity", "forbidden"])
def test_broken_links_ignores_artifacts_and_access_control(server, mode):
    # v18 FP classes: an uninterpolated /${...} template literal + a Cloudflare /cdn-cgi/ injected link are not
    # the app's links (skipped in extraction); an &amp; href decodes to a valid URL (200); a 403 is access-control
    # (the page exists, gated), not a dead end. All -> clean. Each would fire without the fix.
    assert broken_links(_ctx(server(mode)), _Probe()) is False


def test_broken_links_na_when_no_internal_links(server):
    assert broken_links(_ctx(server("none")), _Probe()) is None
