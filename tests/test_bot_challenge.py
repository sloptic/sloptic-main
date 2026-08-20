"""Bot-challenge guard: a WAF/challenge/sleeping-app interstitial served IN PLACE OF the app must be detected
(is_bot_challenge) and WITHHELD (the pipeline flags bot_challenge and skips the gauntlet), so it never draws
false findings from the interstitial's HTML nor reports false cleans from the surface it hides. Conservative:
a real 403/error page is NOT a challenge, so a genuine grade is never withheld."""
import http.server
import pathlib
import threading

import pytest

from sloptic import net
from sloptic.net import is_bot_challenge


class _R:
    def __init__(self, status, body="", headers=None):
        self.status_code = status
        self.text = body
        self.headers = headers or {"content-type": "text/html"}

    def read(self):
        return None


_CHAL = "<html>Just a moment... verifying your browser</html>"   # a WAF challenge page (markers)


def test_challenge_onset_is_body_confirmed_not_a_plain_403():
    net.start_trace(False)                                   # resets onset
    net.set_trace_probe("sec-headers-001")
    net._watch_challenge(_R(200, "ok"))                      # a 200 is not a trip
    assert net.challenge_onset() is None
    net._watch_challenge(_R(403, "<h1>403 Forbidden</h1>"))  # a PLAIN auth 403 -> not a challenge, no onset
    assert net.challenge_onset() is None
    net.set_trace_probe("sec-ratelimit-001")
    net._watch_challenge(_R(403, _CHAL))                     # a 403 CHALLENGE page -> onset
    assert net.challenge_onset() == "sec-ratelimit-001"
    net.set_trace_probe("perf-load-001")
    net._watch_challenge(_R(403, _CHAL))                     # FIRST only -> not overwritten
    assert net.challenge_onset() == "sec-ratelimit-001"
    net.start_trace(False)
    assert net.challenge_onset() is None                    # reset per grade


def test_challenge_onset_also_catches_cf_mitigated_header():
    net.start_trace(False)
    net.set_trace_probe("sec-sqli-004")
    net._watch_challenge(_R(200, "ok", {"cf-mitigated": "challenge"}))
    assert net.challenge_onset() == "sec-sqli-004"
    net.start_trace(False)


def test_challenge_onset_also_catches_vercel_mitigated_header():
    # Vercel Attack Challenge Mode signals via x-vercel-mitigated (429), often with a non-HTML body -> the
    # header alone must mark onset, no body read needed (same as cf-mitigated).
    net.start_trace(False)
    net.set_trace_probe("sec-xss-001")
    net._watch_challenge(_R(429, "", {"x-vercel-mitigated": "challenge"}))
    assert net.challenge_onset() == "sec-xss-001"
    net.start_trace(False)


def test_request_counts_tally_per_probe():
    net.start_trace(False)
    net.set_trace_probe("sec-cmdi-001")
    for _ in range(3):
        net._watch_challenge(_R(200, "ok"))
    net.set_trace_probe("sec-headers-001")
    net._watch_challenge(_R(200, "ok"))
    assert net.request_counts() == {"sec-cmdi-001": 3, "sec-headers-001": 1}


def test_make_client_presents_a_real_browser_user_agent_by_default():
    # a `python-httpx` UA is exactly what WAF/bot mitigations challenge; the client must look like a real Chrome.
    with net.make_client("http://x.test") as c:
        ua = c.headers.get("user-agent", "")
        assert "Chrome/" in ua and "python-httpx" not in ua
        assert c.headers.get("accept-language")


def test_make_client_lets_a_caller_user_agent_override():
    with net.make_client("http://x.test", headers={"user-agent": "custom/1"}) as c:
        assert c.headers.get("user-agent") == "custom/1"   # explicit --header wins, case-insensitively, no dup


def test_default_user_agent_env_override(monkeypatch):
    monkeypatch.setenv("SLOPTIC_USER_AGENT", "Mozilla/5.0 pinned-test")
    net._UA_CACHE = None
    try:
        assert net.default_user_agent() == "Mozilla/5.0 pinned-test"
    finally:
        net._UA_CACHE = None   # don't leak the pinned value into other tests (it is process-cached)


class _Resp:
    def __init__(self, headers, text=""):
        self.headers = headers
        self.text = text


def test_detects_cloudflare_mitigation_header():
    assert is_bot_challenge(_Resp({"cf-mitigated": "challenge", "content-type": "text/html"}, "x")) is True


def test_detects_vercel_mitigation_header():
    # Vercel Attack Challenge Mode: x-vercel-mitigated / x-vercel-challenge-token (429/403), body often NOT html,
    # so the header must win BEFORE the content-type gate (which would otherwise skip a JSON/empty challenge body).
    assert is_bot_challenge(_Resp({"x-vercel-mitigated": "challenge"}, "")) is True
    assert is_bot_challenge(_Resp({"x-vercel-challenge-token": "abc",
                                   "content-type": "application/json"}, "{}")) is True


def test_detects_known_interstitial_markers():
    for marker in ("Just a moment...", "Checking your browser", "Verifying you are human",
                   "This app has gone to sleep", "Get this app back up",
                   "We're verifying your browser: Vercel Security Checkpoint",   # Vercel Attack Challenge Mode
                   "Request unsuccessful. Incapsula incident ID: 1234",          # Imperva/Incapsula
                   "Sucuri WebSite Firewall - Access Denied",                    # Sucuri
                   "Our systems have detected unusual traffic",                  # Google/reCAPTCHA rate-limit
                   '<div id="px-captcha"></div>',                                # PerimeterX
                   '<iframe src="https://geo.captcha-delivery.com/...">',        # DataDome
                   '<script src="https://ca9c7d43.captcha.awswaf.com/...">'):    # AWS WAF
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
    assert report.bot_challenge is True     # detected + flagged
    assert report.challenge_stage == "entry"   # challenge from the FIRST fetch -> ungradeable -> withheld (not "late")
    assert report.outcomes == []            # the gauntlet was withheld, not run on the interstitial
    assert report.slop_score == 0           # not a false clean and not false slop: no grade at all
    # transparency: nothing ran, so the WHOLE battery is blocked and EVERY axis is incomplete -> a score of 0
    # here must never read as "clean". A severe probe is explicitly on the blocked list, not silently absent.
    assert set(report.blocked_probes) == {p.id for p in catalog}
    assert set(report.incomplete_axes) == {"security", "qa", "performance"}
    assert "sec-cmdi-001" in report.blocked_probes


def test_blocked_helper_maps_probes_to_their_axes():
    from sloptic.catalog import load_catalog
    from sloptic.pipeline import _blocked
    catalog = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
    tail = [p for p in catalog if p.id in ("sec-cmdi-001", "sec-ssti-001", "qa-crash-010")]
    ids, axes = _blocked(tail)
    assert set(ids) == {"sec-cmdi-001", "sec-ssti-001", "qa-crash-010"}
    assert set(axes) == {"security", "qa"}   # the bundles those blocked probes belong to
    assert _blocked([]) == ([], [])          # a fully-completed grade blocks nothing
