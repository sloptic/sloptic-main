"""CWE-943 filter injection: user input reaching a data-store FILTER expression.

The BaaS-era analogue of SQL injection. Measured on supavulnbase's {basePath}/api/projects/search, which
interpolates `q` straight into a PostgREST filter:

    q=Build          -> 200 {"count":0}
    q=Build,other    -> 400 {"error":"failed to parse logic tree
                             ((title.ilike.%Build,other%,tagline.ilike.%Build,other%))"}
    q=*              -> 200 {"count":7}    every row, because * lands inside the ilike pattern

EVIDENCE, NOT HEURISTIC. The payload is a comma and a benign token, so a response containing
`title.ilike.%` can only be the APP's own filter template — reflecting our input cannot produce it. Same rule
that makes sec-lfi-001 precise: it matches /etc/passwd's root line, never the path we asked for.

Two precision rules under test here:
  * a benign baseline must come back WITHOUT the signature, so an app that always answers with a parse error
    (a strict validator, a chatty framework) cannot false-fire;
  * the wildcard differential is CORROBORATION ONLY and never fires alone — a search that deliberately treats
    `*` as match-all is a design choice, and firing on it would penalise a feature.
"""
import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import _FILTER_GRAMMAR, filter_injection  # noqa: E402
from hacklet_runner.schema import Endpoint, Profile  # noqa: E402

_ROWS = [{"id": i, "title": "Project %d" % i} for i in range(7)]


def _serve(mode):
    """mode: 'vulnerable' leaks the filter template on a comma; 'safe' parameterises; 'always_errors' answers
    with filter grammar even on a benign term; 'wildcard_only' honours * but never leaks grammar."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = (urllib.parse.parse_qs(u.query).get("q") or [""])[0]
            if u.path != "/api/search":
                return self._json(404, {"e": "no"})
            if mode == "always_errors":
                return self._json(400, {"error": "failed to parse logic tree ((title.ilike.%%%s%%))" % q})
            if mode == "vulnerable" and "," in q:
                return self._json(400, {"error": 'failed to parse logic tree '
                                                 '((title.ilike.%%%s%%,tagline.ilike.%%%s%%))' % (q, q)})
            if q == "*" and mode in ("vulnerable", "wildcard_only"):
                return self._json(200, {"query": q, "count": len(_ROWS), "results": _ROWS})
            return self._json(200, {"query": q, "count": 0, "results": []})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(mode, params=("q",), path="/api/search", kind="search"):
    srv = _serve(mode)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, routes=["/"],
                   endpoints=[Endpoint(path=path, raw_path=path, method="get",
                                       query_params=list(params), kind=kind)])
    ctx = _Ctx(base, make_client(base, None, timeout=8.0, follow_redirects=True), prof, None)
    try:
        return filter_injection(ctx, type("P", (), {"probe": {}})()), dict(ctx.evidence)
    finally:
        ctx.client.close()
        srv.shutdown()


# ---------------------------------------------------------------- the signature

def test_the_signature_matches_what_only_the_flaw_can_emit():
    for leak in ('failed to parse logic tree ((title.ilike.%x%))',
                 'title.ilike.%probe%', 'id.eq.3', 'or(title.ilike.%a%,body.ilike.%a%)',
                 'unexpected "," expecting letter'):
        assert _FILTER_GRAMMAR.search(leak), leak


def test_the_signature_does_not_match_ordinary_prose_or_our_own_payload():
    for benign in ('{"query":"hlfiprobe,hlfi","count":0,"results":[]}',
                   '{"error":"Bad Request"}', '{"error":"invalid input syntax"}',
                   'Search failed. Please try again.', '{"results":[{"title":"a.b.c"}]}'):
        assert not _FILTER_GRAMMAR.search(benign), benign


# ---------------------------------------------------------------- must fire

def test_a_filter_that_leaks_its_template_on_a_comma_fires():
    hit, ev = _run("vulnerable")
    assert hit is True
    assert ev["endpoint"] == "/api/search" and ev["param"] == "q"
    assert "logic tree" in ev["matched"]
    assert "filter grammar disclosed" in ev["repro"]["matched"]


def test_the_wildcard_differential_is_recorded_as_corroboration():
    _hit, ev = _run("vulnerable")
    assert ev["wildcard_rows"] == 7 and ev["baseline_rows"] == 0


# ---------------------------------------------------------------- must stay silent

def test_a_parameterised_search_reads_clean():
    hit, ev = _run("safe")
    assert hit is False and ev["injectable"] is False and ev["params_tested"] == 1


def test_an_app_that_always_answers_with_filter_grammar_cannot_false_fire():
    """The baseline gate. A strict validator or chatty framework that echoes filter syntax on every request
    carries no signal, and firing on it would report every such app as injectable."""
    verdict, ev = _run("always_errors")
    assert verdict is None and "clean baseline" in ev["na_reason"]


def test_a_deliberate_wildcard_search_is_a_feature_not_a_finding():
    """* returning every row is how plenty of search boxes are designed. Without the grammar leak there is no
    evidence the value reached the filter expression, so this must stay silent."""
    hit, ev = _run("wildcard_only")
    assert hit is False and ev["injectable"] is False


def test_no_query_parameter_is_na_not_clean():
    verdict, ev = _run("safe", params=())
    assert verdict is None and "no GET endpoint with a query parameter" in ev["na_reason"]


# ---------------------------------------------------------------- targeting

def test_search_endpoints_are_tried_first():
    from hacklet_runner.probes import _filter_targets
    prof = Profile(base_url="http://x", endpoints=[
        Endpoint(path="/api/other", raw_path="/api/other", method="get", query_params=["page"]),
        Endpoint(path="/api/search", raw_path="/api/search", method="get", query_params=["q"], kind="search"),
    ])
    assert _filter_targets(prof)[0] == ("/api/search", "q")


def test_post_endpoints_are_not_targets():
    prof = Profile(base_url="http://x", endpoints=[
        Endpoint(path="/api/create", raw_path="/api/create", method="post", query_params=["q"])])
    from hacklet_runner.probes import _filter_targets
    assert _filter_targets(prof) == []
