"""A per-path WAF block (Cloudflare's 1020 "Attention Required" served on a sensitive path like /.env while the
app itself stays fully reachable) must NOT halt the grade or flag it as a bot challenge -- only an APP-WIDE
interstitial should. This mirrors the existing Vercel `deny` carve-out, but the CF 1020 page carries no
distinguishing header, so the discriminator is a re-fetch of the origin: reachable -> per-path block -> keep
grading; challenged/unreachable -> app-wide -> halt (fail closed, never a false clean).
"""
import http.server
import pathlib
import threading

import httpx
import pytest

from sloptic import net
from sloptic.pipeline import _app_wide_challenge


# ---- unit: onset reset -------------------------------------------------------------------------------------

def test_reset_challenge_onset_clears_a_recorded_block():
    net.start_trace(False)                                  # fresh onset holder for this grade
    net._challenge_onset.get().record("sec-exposure-001")   # a probe hit a challenge marker
    assert net.challenge_onset() == "sec-exposure-001"
    net.reset_challenge_onset()                             # pipeline confirmed it was a per-path block
    assert net.challenge_onset() is None
    net.reset_challenge_onset()                             # idempotent: safe when nothing is recorded
    assert net.challenge_onset() is None


# ---- unit: the app-wide-vs-per-path discriminator ----------------------------------------------------------

class _Resp:
    def __init__(self, text, headers=None):
        self.text = text
        self.headers = headers or {"content-type": "text/html"}


class _Client:
    """Minimal stand-in: _app_wide_challenge only ever calls client.get(origin)."""
    def __init__(self, resp=None, exc=None):
        self._resp, self._exc = resp, exc

    def get(self, url):
        if self._exc:
            raise self._exc
        return self._resp


def test_app_wide_challenge_false_when_origin_still_serves_the_app():
    # origin re-fetch returns the real app -> the challenge was a per-path block -> do NOT halt
    client = _Client(resp=_Resp("<html><body><h1>Welcome</h1></body></html>"))
    assert _app_wide_challenge(client, "http://x") is False


def test_app_wide_challenge_true_when_origin_is_also_1020_blocked():
    # origin re-fetch is ALSO a Cloudflare 1020 block -> app-wide -> halt (no false clean)
    client = _Client(resp=_Resp("<html><title>Attention Required! | Cloudflare</title>"
                                "Sorry, you have been blocked. Ray ID: abc</html>"))
    assert _app_wide_challenge(client, "http://x") is True


def test_app_wide_challenge_fails_closed_when_origin_unreachable():
    # can't confirm reachability -> treat as app-wide (halt), never risk grading a blocked app as clean
    assert _app_wide_challenge(_Client(exc=httpx.ConnectError("down")), "http://x") is True


# ---- integration: a per-path /.env block does not halt the grade -------------------------------------------

_REQUESTED: list = []


class _PerPathBlock(http.server.BaseHTTPRequestHandler):
    """A reachable app whose edge WAF blocks only sensitive paths (/.env, /.git) with a CF 1020 page."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        _REQUESTED.append(self.path)
        if ".env" in self.path or "/.git" in self.path:
            body = (b"<html><head><title>Attention Required! | Cloudflare</title></head>"
                    b"<body>Sorry, you have been blocked. Cloudflare Ray ID: 8abc123</body></html>")
            self.send_response(403)
        else:
            body = (b"<html><head><title>Real App</title></head><body><h1>Welcome</h1>"
                    b"<a href='/about'>about</a><form action='/q'><input name='q'></form></body></html>")
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def perpath_url():
    _REQUESTED.clear()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PerPathBlock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_pipeline_grades_through_a_per_path_waf_block(perpath_url):
    from sloptic.catalog import load_catalog
    from sloptic.deploy import RemoteDeployer
    from sloptic.pipeline import run
    full = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
    catalog = [p for p in full if p.id.startswith("sec-exposure")]   # these fetch /.env, /.git, ...
    report = run(RemoteDeployer(perpath_url), catalog)

    # a sensitive path WAS probed (the CF 1020 tripped the onset watch) ...
    assert any(".env" in p for p in _REQUESTED), _REQUESTED
    # ... yet the origin stayed reachable, so the grade is neither halted nor flagged.
    assert report.bot_challenge is False
    assert report.challenge_stage == ""
    assert report.blocked_probes == []
    # the exposure probe's own outcome is KEPT (before the fix it was dropped as a "post-onset" outcome).
    assert "sec-exposure-001" in {o.probe_id for o in report.outcomes}
