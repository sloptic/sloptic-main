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


def test_sqli_union_technique(jsonapi):
    # /api/usearch: a UNION-concatenated marker executes (appears only if the SQL ran)
    assert api_sqli(_only(jsonapi, "/api/usearch"), _Probe()) is True


def test_sqli_time_technique(jsonapi):
    # /api/tsearch: fully blind — only a SLEEP payload's measurable delay reveals it
    assert api_sqli(_only(jsonapi, "/api/tsearch"), _Probe()) is True


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
