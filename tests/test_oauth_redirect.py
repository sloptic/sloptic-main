"""OAuth redirect_uri at localhost -- the app hands the browser an authorization URL whose redirect_uri points
at localhost / a private IP / an unset env var, so sign-in is dead in prod. Fires only when that host differs
from the app's own origin (a localhost dev target using a localhost callback is correct, not slop)."""
import http.server
import threading
from urllib.parse import quote, urlparse

import pytest

from sloptic.probes import _oauth_redirect_uri, oauth_redirect_localhost
from sloptic.schema import Profile

_CFG = {"redirect_uri": "", "oauth": True}


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _html(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/auth/google" and _CFG["oauth"]:
            self.send_response(302)
            self.send_header("Location",
                             "https://accounts.google.com/o/oauth2/auth?client_id=abc&response_type=code"
                             "&redirect_uri=" + quote(_CFG["redirect_uri"], safe=""))
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif p == "/":
            self._html('<a href="/auth/google">Sign in with Google</a>' if _CFG["oauth"] else "<h1>home</h1>")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"target": "/", "max_attempts": 30}


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": None, "evidence": {}})()


# ---- the pure extractor -----------------------------------------------------------------------------

def test_extractor_pulls_redirect_uri_from_an_authorization_url():
    u = ("https://accounts.google.com/o/oauth2/auth?client_id=abc&response_type=code"
         "&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb")
    assert _oauth_redirect_uri(u) == "http://localhost:3000/cb"


def test_extractor_handles_html_escaped_ampersands():
    u = "https://x/oauth2/authorize?client_id=a&amp;redirect_uri=http%3A%2F%2Flocalhost%2Fcb&amp;response_type=code"
    assert _oauth_redirect_uri(u) == "http://localhost/cb"


def test_extractor_ignores_a_redirect_that_is_not_oauth():
    # a plain in-app ?redirect_uri= with no client_id / response_type / provider host is not an OAuth flow
    assert _oauth_redirect_uri("https://site.com/go?redirect_uri=http://localhost/x") is None


# ---- the probe --------------------------------------------------------------------------------------

def test_fires_on_localhost_redirect_uri(app):
    _CFG.update(oauth=True, redirect_uri="http://localhost:3000/callback")
    ctx = _ctx(app)
    assert oauth_redirect_localhost(ctx, _Probe()) is True
    assert ctx.evidence["oauth_redirect_uri"] == "http://localhost:3000/callback"


def test_fires_on_unset_env_redirect_uri(app):
    _CFG.update(oauth=True, redirect_uri="https://undefined/callback")
    assert oauth_redirect_localhost(_ctx(app), _Probe()) is True


def test_clean_when_redirect_uri_is_a_public_host(app):
    _CFG.update(oauth=True, redirect_uri="https://myapp.example.com/callback")
    assert oauth_redirect_localhost(_ctx(app), _Probe()) is False


def test_clean_when_redirect_uri_matches_the_local_origin(app):
    # grading a localhost dev target whose callback is that SAME localhost origin -> correct, not slop
    _CFG.update(oauth=True, redirect_uri=app + "/callback")
    assert oauth_redirect_localhost(_ctx(app), _Probe()) is False


def test_na_when_no_oauth_flow(app):
    _CFG.update(oauth=False, redirect_uri="")
    assert oauth_redirect_localhost(_ctx(app), _Probe()) is None
