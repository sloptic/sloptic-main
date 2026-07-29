"""Error-based SQLi needs BOTH payload breadth and signature breadth; we shipped one of each.

Measured against GapBench's `sqli-raw` scenario — "user search builds SQL by string concatenation and reflects
errors back to the client" — which our five SQLi probes graded clean:

    ?username=1     -> {"query":"... username = '1'","rows":[...]}          baseline, fine
    ?username=1'    -> {"query":"... username = '1''","rows":[...]}         no error, rows returned
    ?username='     -> {"error":"unterminated string at character 35"}      only the BARE quote errors

Two independent misses, and fixing either alone leaves the probe silent:

  * PAYLOAD. `_tech_error` sent exactly one payload, "1'". A value-shaped input can be coerced, cast or
    length-checked before it reaches SQL where a lone quote is not, so the bare quote is a genuinely different
    probe rather than a variant of the same one.
  * SIGNATURE. `_SQL_ERROR` named drivers and exception classes (psycopg2, sqlalchemy.exc, PG::Error,
    SQLSTATE[) — the shape of a leaked stack trace. A JSON API doing `catch (e) { res.json({error: e.message})}`
    returns only the ENGINE's sentence with no class name anywhere, and slipped through.

(That target is a lenient emulation — a real engine errors on `'1''` too, since it leaves a literal open. The
breadth is worth having on its own terms: one payload for a whole technique is the narrowness the SQLi variant
group exists to avoid.)
"""
import http.server
import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from sloptic.probes import _SQL_ERROR, api_sqli
from sloptic.schema import Endpoint, Profile

_ROWS = json.dumps({"rows": [{"username": "admin"}]}).encode()


def _handler(bare_quote_errors: bool):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            if u.path != "/api/users":            # a nonexistent sibling 404s -> a REAL endpoint, not a phantom
                self.send_response(404); self.end_headers(); self.wfile.write(b"no"); return
            v = parse_qs(u.query).get("username", [""])[0]
            body = _ROWS
            # the sqli-raw shape: the value-form payload is shrugged off, the BARE quote errors
            if bare_quote_errors and v == "'":
                body = json.dumps({"error": "unterminated string at character 35"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


class _Probe:
    probe = {"max_attempts": 80, "time_delay": 1}


class _Ctx:
    def __init__(self, base_url, profile):
        self.base_url, self.profile, self.headers, self.client, self.evidence = base_url, profile, None, None, {}


def _serve(bare_quote_errors):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(bare_quote_errors))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def vulnerable():
    srv = _serve(True)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def clean():
    srv = _serve(False)
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def _profile(host):
    return Profile(base_url=host, endpoints=[
        Endpoint(path="/api/users", method="get", raw_path="/api/users", query_params=["username"])])


# ---------------------------------------------------------------- payload breadth

def test_a_bare_quote_is_tried_when_the_value_form_is_shrugged_off(vulnerable):
    """THE regression. With only "1'" this endpoint grades clean and a real SQL injection ships undetected."""
    ctx = _Ctx(vulnerable, _profile(vulnerable))
    assert api_sqli(ctx, _Probe()) is True
    assert ctx.evidence["via"] == "error"


def test_the_repro_names_the_payload_that_ACTUALLY_matched(vulnerable):
    """With more than one candidate payload, naming the wrong one hands the auditor a request that does not
    reproduce — worse than no repro, because it reads as a refutation of the finding."""
    ctx = _Ctx(vulnerable, _profile(vulnerable))
    api_sqli(ctx, _Probe())
    url = ctx.evidence["repro"]["url"]
    assert url.endswith("username=%27"), url


def test_an_endpoint_that_errors_on_neither_payload_stays_clean(clean):
    """Precision guard: trying more payloads must not manufacture a finding on a parameterized endpoint."""
    ctx = _Ctx(clean, _profile(clean))
    assert api_sqli(ctx, _Probe()) is False


# ---------------------------------------------------------------- signature breadth

def test_bare_engine_messages_match_not_just_leaked_driver_classes():
    for s in ('{"error":"unterminated string at character 35"}',   # the measured GapBench response
              'syntax error at or near "1"',                        # PostgreSQL's canonical syntax error
              'near "foo": syntax error'):                          # SQLite's phrasing of the same
        assert _SQL_ERROR.search(s), s


def test_a_json_parse_error_is_not_mistaken_for_a_database_one():
    """The false positive the widening deliberately avoids: injecting a quote into a JSON body makes parsers
    say "Unterminated string in JSON at position N", which an app may echo. Matching bare `unterminated
    string` would have bought that FP for nothing."""
    assert not _SQL_ERROR.search("Unterminated string in JSON at position 12")
    assert not _SQL_ERROR.search("we fixed a syntax error in the readme")
