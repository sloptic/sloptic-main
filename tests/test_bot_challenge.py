"""Bot-challenge guard: a WAF/challenge/sleeping-app interstitial served IN PLACE OF the app must be detected
(is_bot_challenge) and WITHHELD (the pipeline flags bot_challenge and skips the gauntlet), so it never draws
false findings from the interstitial's HTML nor reports false cleans from the surface it hides. Conservative:
a real 403/error page is NOT a challenge, so a genuine grade is never withheld."""
import http.server
import pathlib
import threading

import pytest

from sloptic.net import is_bot_challenge


class _Resp:
    def __init__(self, headers, text=""):
        self.headers = headers
        self.text = text


def test_detects_cloudflare_mitigation_header():
    assert is_bot_challenge(_Resp({"cf-mitigated": "challenge", "content-type": "text/html"}, "x")) is True


def test_detects_known_interstitial_markers():
    for marker in ("Just a moment...", "Checking your browser", "Verifying you are human",
                   "This app has gone to sleep", "Get this app back up"):
        assert is_bot_challenge(_Resp({"content-type": "text/html"}, f"<html>{marker}</html>")) is True, marker


def test_clean_page_is_not_a_challenge():
    assert is_bot_challenge(_Resp({"content-type": "text/html"}, "<html><body>Welcome</body></html>")) is False


def test_real_403_is_not_flagged():
    # a genuine Forbidden page (no challenge marker) must NOT be treated as a challenge -> never withhold a real grade
    assert is_bot_challenge(_Resp({"content-type": "text/html"}, "<h1>403 Forbidden</h1>")) is False


def test_non_html_is_skipped():
    # a JSON body that happens to contain a marker string is not an interstitial
    assert is_bot_challenge(_Resp({"content-type": "application/json"}, '{"msg":"just a moment"}')) is False


class _Challenge(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = b"<html><head><title>Just a moment...</title></head><body>Checking your browser...</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture
def challenge_url():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Challenge)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_pipeline_withholds_grade_on_a_challenge(challenge_url):
    from sloptic.catalog import load_catalog
    from sloptic.deploy import RemoteDeployer
    from sloptic.pipeline import run
    catalog = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
    report = run(RemoteDeployer(challenge_url), catalog)
    assert report.bot_challenge is True     # detected + flagged -> the record is excluded from the corpus stats
    assert report.outcomes == []            # the gauntlet was withheld, not run on the interstitial
    assert report.slop_score == 0           # not a false clean and not false slop: no grade at all
