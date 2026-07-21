"""API-injection path: OpenAPI-driven discovery + error-based SQLi over the discovered surface.
Uses the stdlib `jsonapi` reference (a form-less API that publishes a spec) so the JSON-API recall
path is locked in CI, not just validated against live third-party apps."""
import pathlib

import httpx
import pytest

from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import SubprocessDeployer
from hacklet_runner.discovery import discover
from hacklet_runner.pipeline import run
from hacklet_runner.probes import api_sqli, response_leaks_credentials
from hacklet_runner.schema import Endpoint, Profile

CATALOG = pathlib.Path(__file__).resolve().parent.parent / "catalog"

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFS = ROOT / "references"


@pytest.fixture
def jsonapi():
    d = SubprocessDeployer(str(REFS / "jsonapi" / "app.py"))
    url = d.deploy().base_url
    yield url
    d.teardown()


class _Ctx:
    """Minimal pipeline context: api_sqli reads base_url, profile.endpoints, headers, and records into
    evidence (as the real _Ctx does)."""
    def __init__(self, base_url, profile):
        self.base_url = base_url
        self.profile = profile
        self.headers = None
        self.client = None
        self.evidence = {}

    def register(self, suffix=""):   # mirrors pipeline._Ctx.register (browser fallback off in unit tests)
        from hacklet_runner import auth
        return auth.register_account(self.base_url, self.profile, suffix=suffix)


class _Probe:
    probe = {"max_attempts": 80, "time_delay": 1}   # short delay keeps the time-based test fast


def test_discovers_api_endpoints_from_spec(jsonapi):
    p = discover(jsonapi)
    raws = {e.raw_path for e in p.endpoints}
    assert "/api/items/{id}" in raws and "/api/notes" in raws
    assert p.capabilities["any_endpoint_accepts_text_input"] is True


def test_api_sqli_fires_on_injectable_endpoint(jsonapi):
    p = discover(jsonapi)
    assert api_sqli(_Ctx(jsonapi, p), _Probe()) is True


def test_api_sqli_clean_on_parameterized_endpoint_only(jsonapi):
    # only the safe endpoint in scope -> the quote never errors -> clean (differential precision)
    safe = Profile(base_url=jsonapi, endpoints=[
        Endpoint(path="/api/notes", method="get", query_params=["q"], raw_path="/api/notes")])
    assert api_sqli(_Ctx(jsonapi, safe), _Probe()) is False


def test_api_sqli_na_when_no_endpoints(jsonapi):
    assert api_sqli(_Ctx(jsonapi, Profile(base_url=jsonapi, endpoints=[])), _Probe()) is None


def test_sqli_targets_folds_forms_and_common_params():
    from hacklet_runner.probes import _COMMON_PARAMS, _sqli_targets
    from hacklet_runner.schema import Form
    prof = Profile(
        base_url="http://x",
        endpoints=[Endpoint(path="/api/search", method="get", raw_path="/api/search"),   # searchable, param-less
                   Endpoint(path="/api/health", method="get", raw_path="/api/health")],   # not searchable
        forms=[Form(action="/vulnerabilities/sqli/", method="get", fields=["id"])])
    t = _sqli_targets(prof)
    assert next(e for e in t if e.raw_path == "/api/search").query_params == list(_COMMON_PARAMS)
    assert next(e for e in t if e.raw_path == "/api/health").query_params == []  # left alone
    form_ep = next(e for e in t if e.raw_path == "/vulnerabilities/sqli/")
    assert form_ep.method == "get" and form_ep.query_params == ["id"]  # GET form -> query-param endpoint


def test_api_sqli_common_param_guessing_on_searchable_get(jsonapi):
    # a param-less searchable GET (declares NO params) -> common-param guessing finds the injectable ?q=
    prof = Profile(base_url=jsonapi, endpoints=[
        Endpoint(path="/api/search", method="get", raw_path="/api/search")])
    assert api_sqli(_Ctx(jsonapi, prof), _Probe()) is True


def _only(jsonapi, path):
    return _Ctx(jsonapi, Profile(base_url=jsonapi,
                                 endpoints=[Endpoint(path=path, method="get", raw_path=path)]))


def test_sqli_boolean_technique(jsonapi):
    # /api/bsearch leaks NO error; injection only shows as a result-set size change (true vs false)
    assert api_sqli(_only(jsonapi, "/api/bsearch"), _Probe()) is True


def test_union_technique_retired_from_score(jsonapi):
    # UNION is CUT: its oracle (a concatenated marker in the body) is unsalvageable on an LLM corpus — the app
    # quotes the marker back as generated content. /api/usearch, which ONLY answers a union, is now clean.
    assert api_sqli(_only(jsonapi, "/api/usearch"), _Probe()) is False


def test_time_technique_is_advisory_not_scored(jsonapi):
    # TIME is advisory/off-score: /api/tsearch (blind, sleep-only) must NOT score, but records the advisory
    # for human review — a proxy's latency is not the app's SQL, so it never enters the slop number.
    ctx = _only(jsonapi, "/api/tsearch")
    assert api_sqli(ctx, _Probe()) is not True                     # never scored
    assert "time-based" in (ctx.evidence.get("advisory") or "")    # but flagged for review
    assert ctx.evidence.get("advisory_repro", {}).get("url")       # with a replayable request


def test_time_advisory_needs_dose_scaling_not_bare_latency(monkeypatch):
    # multi-dose: a FIXED-latency endpoint (ignores the sleep argument — a slow upstream/proxy) shows no
    # scaling between SLEEP(d) and SLEEP(3d) -> no advisory; a real sleep that TRACKS the argument does.
    # Uses a fake clock so the test is fast + deterministic (no real sleeping).
    import re as _re
    from hacklet_runner import probes
    clock = {"t": 0.0}
    monkeypatch.setattr(probes.time, "perf_counter", lambda: clock["t"])
    reqfn = lambda v: v                                                        # the "request" IS the payload  # noqa: E731

    def fixed(c, m, payload):
        clock["t"] += 0.3                                                      # fixed latency, ignores the arg
    monkeypatch.setattr(probes, "_do", fixed)
    assert probes._tech_time(None, "GET", reqfn, delay=1) is False             # no scaling -> not injectable

    def scaling(c, m, payload):
        mt = _re.search(r"\((\d+)\)", payload)                                 # latency TRACKS the sleep argument
        clock["t"] += int(mt.group(1)) if mt else 0
    monkeypatch.setattr(probes, "_do", scaling)
    assert probes._tech_time(None, "GET", reqfn, delay=1) is True              # SLEEP(3)-SLEEP(1)=2 >= 1.4 -> fires


def test_boolean_noise_floor_suppresses_content_reflective(monkeypatch):
    # the AI-app FP: two DIFFERENT benign values already diverge (an LLM/TTS/proxy varies output with input),
    # so the noise-floor gate must suppress BEFORE the true/false comparison -> no boolean fire.
    from hacklet_runner import probes
    monkeypatch.setattr(probes, "_do",
        lambda c, m, v: httpx.Response(200, text="x" * (500 if v == probes._SQLI_NOISE_B else 40)))
    assert probes._tech_boolean(None, "GET", lambda v: v) is False   # benign noise diverges -> confounded -> suppress


def test_boolean_fires_on_stable_endpoint_with_true_false_split(monkeypatch):
    # a real SQL result set: benign values are stable, the always-TRUE payload opens the gate to a large
    # result while FALSE stays small, and the split reproduces -> boolean fires.
    from hacklet_runner import probes
    monkeypatch.setattr(probes, "_do",
        lambda c, m, v: httpx.Response(200, text="x" * (900 if v == probes._SQLI_TRUE else 40)))
    assert probes._tech_boolean(None, "GET", lambda v: v) is True


def test_upstream_error_regex_matches_the_proxy_fp_bodies():
    # the two proxy FPs (the-angle NewsAPI 429, oversightusa OpenStates 504) must be suppressed by naming an
    # upstream vendor error; a real DB result must NOT match.
    from hacklet_runner.probes import _UPSTREAM_ERROR
    assert _UPSTREAM_ERROR.search("NewsAPI 429 — You have made too many requests recently")
    assert _UPSTREAM_ERROR.search("OpenStates API error: 504 - Gateway Time-out")
    assert not _UPSTREAM_ERROR.search('{"results": [{"id": 1, "name": "widget"}]}')


def test_sqli_evidence_records_the_specific_technique(jsonapi):
    # auditability: a fire records WHICH scored technique fired (error vs boolean); an ERROR fire carries the
    # leaked DB-error signature so an audit is reproducible. (union is cut; time is advisory, tested above.)
    err = _only(jsonapi, "/api/search")             # error-leaking endpoint (a lone quote -> sqlite3 error)
    assert api_sqli(err, _Probe()) is True
    assert err.evidence["via"] == "error" and "sqlite3.OperationalError" in (err.evidence.get("sql_error") or "")

    b = _only(jsonapi, "/api/bsearch")              # blind boolean endpoint (no error leaked)
    assert api_sqli(b, _Probe()) is True
    assert b.evidence["via"] == "boolean" and not b.evidence.get("sql_error")


def test_sqli_clean_on_parameterized_reflecting_endpoint(jsonapi):
    # /api/notes reflects q but is parameterized; equal-length true/false payloads -> no divergence,
    # no error, no marker, no delay -> every technique stays clean (precision on a reflecting API)
    prof = Profile(base_url=jsonapi, endpoints=[
        Endpoint(path="/api/notes", method="get", query_params=["q"], raw_path="/api/notes")])
    assert api_sqli(_Ctx(jsonapi, prof), _Probe()) is False


# --- excessive data exposure (response_leaks_credentials) ---

def _resp(text, status=200, ctype="application/json"):
    return httpx.Response(status, text=text, headers={"content-type": ctype})


def test_credential_leak_fires_on_password_field_and_hash():
    assert response_leaks_credentials(_resp('{"user":"a","password":"hunter2"}')) is True
    assert response_leaks_credentials(_resp('{"pw":"$2b$12$' + "a" * 53 + '"}')) is True  # bcrypt hash


def test_credential_leak_precision_no_false_positives():
    # access/refresh tokens ARE the auth flow, not a leak
    assert response_leaks_credentials(_resp('{"access_token":"eyJhbGci.abc.def","token_type":"bearer"}')) is False
    # masked / empty values are not a leak
    assert response_leaks_credentials(_resp('{"password":"****"}')) is False
    assert response_leaks_credentials(_resp('{"password":""}')) is False
    # the served OpenAPI spec naming a password field in its schema is not a data leak
    assert response_leaks_credentials(_resp('{"openapi":"3.0.0","paths":{"x":{"password":"string"}}}')) is False
    # non-200 (e.g. a 401 body that happens to mention a password) is not a leak
    assert response_leaks_credentials(_resp('{"password":"secret"}', status=401)) is False
    # a JS bundle's Angular password-toggle (hide?"password":"text") is code, not a data leak
    js = 'x("type",n.hide?"password":"text"),l(2)'
    assert response_leaks_credentials(_resp(js, ctype="application/javascript")) is False


def test_data_exposure_probe_fires_on_leaky_endpoint():
    report = run(SubprocessDeployer(str(REFS / "jsonapi" / "app.py")), load_catalog(CATALOG))
    assert report.by_id["sec-exposure-005"] == "slop_detected"  # /api/dump leaks passwords


# --- API BOLA / horizontal IDOR (api_bola) ---

def test_bola_pairs_matches_create_to_read():
    from hacklet_runner.probes import _bola_pairs
    eps = [
        Endpoint(path="/api/orders", method="post", body_fields=["item", "secret"], raw_path="/api/orders"),
        Endpoint(path="/api/orders/1", method="get", path_params=["id"], raw_path="/api/orders/{id}"),
        Endpoint(path="/api/notes", method="get", query_params=["q"], raw_path="/api/notes"),  # unpaired
    ]
    pairs = _bola_pairs(eps)
    assert len(pairs) == 1
    c, r, param, id_field = pairs[0]
    assert (c.raw_path, r.raw_path, param, id_field) == ("/api/orders", "/api/orders/{id}", "id", None)


def test_bola_probe_fires_on_cross_user_object_read():
    # A creates an order with a canary secret; B reads it back -> broken object-level auth
    report = run(SubprocessDeployer(str(REFS / "jsonapi" / "app.py")), load_catalog(CATALOG))
    assert report.by_id["sec-idor-002"] == "slop_detected"


# --- data-integrity round-trip (data_integrity_roundtrip) ---

def _drafts_pair():
    return [Endpoint(path="/api/drafts", method="post", body_fields=["title", "body"], raw_path="/api/drafts"),
            Endpoint(path="/api/drafts/1", method="get", path_params=["id"], raw_path="/api/drafts/{id}")]


def _orders_pair():
    return [Endpoint(path="/api/orders", method="post", body_fields=["item", "secret"], raw_path="/api/orders"),
            Endpoint(path="/api/orders/1", method="get", path_params=["id"], raw_path="/api/orders/{id}")]


def test_data_integrity_fires_on_non_durable_write(jsonapi):
    from hacklet_runner.probes import data_integrity_roundtrip
    ctx = _Ctx(jsonapi, Profile(base_url=jsonapi, endpoints=_drafts_pair()))
    assert data_integrity_roundtrip(ctx, _Probe()) is True   # POST 201 + id, but GET /api/drafts/{id} 404s
    assert ctx.evidence["read_status"] == 404 and ctx.evidence["durable"] is False


def test_data_integrity_clean_on_durable_pair(jsonapi):
    from hacklet_runner.probes import data_integrity_roundtrip
    ctx = _Ctx(jsonapi, Profile(base_url=jsonapi, endpoints=_orders_pair()))
    assert data_integrity_roundtrip(ctx, _Probe()) is False  # /api/orders create round-trips correctly


def test_data_integrity_na_when_no_create_read_pair(jsonapi):
    from hacklet_runner.probes import data_integrity_roundtrip
    ctx = _Ctx(jsonapi, Profile(base_url=jsonapi, endpoints=[]))
    assert data_integrity_roundtrip(ctx, _Probe()) is None


def test_api_bola_na_with_a_single_provided_session():
    # Option B guard: a --header session is ONE identity, so A and B are the SAME user — B "reading A's object"
    # would be a false BOLA. The pair is valid (secret field), so N/A here can only come from the provided guard.
    from hacklet_runner.probes import api_bola
    from hacklet_runner.auth import Account

    def _provided(suffix=""):
        return Account(username="p", password="", client=httpx.Client(base_url="http://x"),
                       register_response=httpx.Response(200, request=httpx.Request("GET", "http://x")),
                       provided=True)
    ctx = type("C", (), {"base_url": "http://x", "headers": None, "evidence": {},
                         "profile": Profile(base_url="http://x", endpoints=_orders_pair()),
                         "register": lambda self, suffix="": _provided(suffix)})()
    assert api_bola(ctx, _Probe()) is None


def test_data_integrity_probe_fires_end_to_end():
    report = run(SubprocessDeployer(str(REFS / "jsonapi" / "app.py")), load_catalog(CATALOG))
    assert report.by_id["qa-integrity-001"] == "slop_detected"


# --- content-type correctness (content_type_mismatch) ---

def test_declared_type_contradiction_detects_json_as_html():
    from hacklet_runner.probes import _declared_type_contradicted as m
    assert m("text/html; charset=utf-8", '{"ok": true}') == "json-body-served-as-text/html"
    assert m("application/json", "<!doctype html><html></html>") == "html-body-served-as-application/json"


def test_declared_type_contradiction_no_false_positives():
    from hacklet_runner.probes import _declared_type_contradicted as m
    assert m("application/json", '{"ok": true}') is None            # JSON as JSON
    assert m("text/html; charset=utf-8", "<!doctype html><p>hi") is None  # HTML as HTML
    assert m("text/plain", "just some plain text") is None          # plain text, no JSON/HTML shape
    assert m("text/html", "") is None                               # empty body -> can't classify
    assert m("text/html", "not json { but starts wrong") is None    # looks like { but isn't valid JSON


def test_content_type_mismatch_fires_on_mistyped_endpoint(jsonapi):
    from hacklet_runner.net import make_client
    from hacklet_runner.probes import content_type_mismatch
    ctx = _Ctx(jsonapi, Profile(base_url=jsonapi, endpoints=discover(jsonapi).endpoints))
    ctx.client = make_client(jsonapi, None, timeout=10.0, follow_redirects=True)
    assert content_type_mismatch(ctx, _CtypeProbe()) is True   # /api/mistyped: JSON body, text/html header
    assert ctx.evidence["endpoint"] == "/api/mistyped"


def test_content_type_mismatch_clean_on_correctly_typed_endpoints(jsonapi):
    from hacklet_runner.net import make_client
    from hacklet_runner.probes import content_type_mismatch
    correct = [Endpoint(path="/api/notes", method="get", query_params=["q"], raw_path="/api/notes"),
               Endpoint(path="/api/dump", method="get", raw_path="/api/dump")]
    ctx = _Ctx(jsonapi, Profile(base_url=jsonapi, endpoints=correct))
    ctx.client = make_client(jsonapi, None, timeout=10.0, follow_redirects=True)
    # target defaults to "/" (jsonapi 404s with a JSON error body under application/json) -> also clean
    assert content_type_mismatch(ctx, _CtypeProbe()) is False


class _CtypeProbe:
    probe = {"target": "/api/notes"}   # a known-good JSON endpoint as the homepage stand-in
