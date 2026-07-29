"""A create that corrects itself, so the create+read families stop reading N/A on typed APIs.

Four blockers, each found by asking why data-integrity stayed dark on OopsSec, and each a CONVENTION rather
than a quirk of that app:

1. A create does not always live AT its collection. REST purists POST to /api/cart; plenty of real apps POST to
   /api/cart/add, /api/todos/create, /api/posts/new. Reading the list back at the CREATE path fetched the action
   endpoint instead of the collection, so nothing could ever be verified.
2. A marker string in every field is rejected by any TYPED api. Measured:
       {"productId":"hldm..","quantity":"hldm.."} -> 400 {"details":[{"path":"quantity","code":"invalid_type"}]}
       {"productId":<real id>,"quantity":1}       -> 200 {"success":true}
   The app names the offending field in its own rejection, so the create corrects itself instead of guessing.
3. A reference field needs a REAL id, taken from the sibling collection it names (`productId` -> /api/products).
4. A fresh account's collection is legitimately EMPTY, and requiring a non-empty array of objects threw the
   before-snapshot away on exactly the apps this is meant to test.

The oracle is "did the collection change", not "is the marker present", because a fully-typed create leaves no
marker to look for. Comparing whole bodies rather than counts also survives a MERGING create: adding the same
product twice bumps quantity on one line instead of adding a row, and a count check would read that correct
behaviour as data loss.
"""
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

from sloptic import probes  # noqa: E402
from sloptic.schema import Endpoint  # noqa: E402

_PRODUCTS = [{"id": "p-real-1", "name": "Sourdough"}, {"id": "p-real-2", "name": "Cold Brew"}]


# ---------------------------------------------------------------- collection resolution

def test_an_action_suffixed_create_resolves_to_its_parent_collection():
    for path, want in (("/api/cart/add", "/api/cart"), ("/api/todos/create", "/api/todos"),
                       ("/api/posts/new", "/api/posts"), ("/api/rows/insert", "/api/rows"),
                       ("/api/notes/save", "/api/notes"), ("/api/forms/submit", "/api/forms")):
        assert probes._create_collection(path) == want, path


def test_a_rest_style_create_is_its_own_collection():
    for path in ("/api/cart", "/api/products", "/api/v1/orders"):
        assert probes._create_collection(path) == path


def test_a_trailing_slash_and_query_are_normalised():
    assert probes._create_collection("/api/cart/add/?x=1") == "/api/cart"


# ---------------------------------------------------------------- collection parsing

def _json_resp(body):
    return httpx.Response(200, json=body, headers={"content-type": "application/json"})


def test_an_unconventionally_named_wrapper_list_is_found():
    # OopsSec answers /api/cart with {"cartItems":[...],"total":0}; "cartItems" is in no convention list
    objs = probes._json_objects(_json_resp({"cartItems": [{"id": 1}], "total": 0}))
    assert objs == [{"id": 1}]


def test_a_scalar_list_is_not_mistaken_for_a_collection():
    # requiring dicts is what keeps {"tags":["a","b"]} from being read as the resource collection
    assert probes._json_objects(_json_resp({"tags": ["a", "b"], "total": 0})) is None


def test_a_conventional_wrapper_still_wins():
    objs = probes._json_objects(_json_resp({"items": [{"id": 1}], "other": [{"id": 2}]}))
    assert objs == [{"id": 1}]


def test_an_empty_collection_is_a_legitimate_state_for_the_comparison_gate():
    # _json_objects may not classify it, but the round-trip's own gate only needs 200 + JSON
    assert probes._is_json_ok(_json_resp({"cartItems": []})) is True
    assert probes._is_json_ok(httpx.Response(200, text="<html>", headers={"content-type": "text/html"})) is False
    assert probes._is_json_ok(httpx.Response(401, json={"error": "no"})) is False


# ---------------------------------------------------------------- type coercion ladder

def test_the_coercion_ladder_walks_string_number_bool_date():
    assert probes._coerce_next("marker") == 1
    assert probes._coerce_next(1) is True
    assert probes._coerce_next(True) == "2026-01-01T00:00:00Z"
    assert probes._coerce_next("2026-01-01T00:00:00Z") == 1     # a string retries as a number


def test_refused_field_names_are_read_from_every_validation_shape():
    for body, want in (({"details": [{"path": "quantity"}]}, ["quantity"]),
                       ({"issues": [{"path": ["body", "amount"]}]}, ["amount"]),
                       ({"detail": [{"loc": ["body", "email"]}]}, ["email"]),
                       ({"errors": [{"param": "code"}]}, ["code"]),
                       ({"errors": {"email": ["blank"]}}, ["email"])):
        assert probes._schema_refused_fields(_json_resp(body)) == want


# ---------------------------------------------------------------- end to end

def _serve(require_number_quantity=True, durable=True):
    """A typed API in the OopsSec shape: /api/cart/add needs a real productId and a NUMERIC quantity, and the
    collection lives at the parent /api/cart wrapped under an unconventional key."""
    cart: list = []

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
            path = self.path.split("?")[0]
            if path == "/api/products":
                return self._json(200, _PRODUCTS)
            if path == "/api/cart":
                return self._json(200, {"cartItems": list(cart), "total": len(cart)})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path.split("?")[0] != "/api/cart/add":
                return self._json(404, {"error": "not found"})
            raw = self.rfile.read(int(self.headers.get("content-length") or 0) or 0)
            body = json.loads(raw or b"{}")
            if require_number_quantity and not isinstance(body.get("quantity"), int):
                return self._json(400, {"error": "Invalid input",
                                        "details": [{"path": "quantity", "code": "invalid_type"}]})
            if body.get("productId") not in {p["id"] for p in _PRODUCTS}:
                return self._json(400, {"error": "Invalid input",
                                        "details": [{"path": "productId", "code": "invalid_type"}]})
            if durable:
                cart.append({"id": "line-1", **body})
            return self._json(200, {"success": True})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _eps():
    return [Endpoint(path="/api/products", raw_path="/api/products", method="get"),
            Endpoint(path="/api/cart", raw_path="/api/cart", method="get"),
            Endpoint(path="/api/cart/add", raw_path="/api/cart/add", method="post",
                     body_fields=["productId", "quantity"])]


def test_a_reference_field_is_seeded_from_the_sibling_collection():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(base_url=base, timeout=8.0) as c:
            assert probes._reference_id(c, "productId", _eps()) in {"p-real-1", "p-real-2"}
            assert probes._reference_id(c, "nonsenseId", _eps()) is None
    finally:
        srv.shutdown()


def test_the_create_corrects_itself_until_the_server_accepts():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        eps = _eps()
        create = eps[-1]
        with httpx.Client(base_url=base, timeout=8.0) as c:
            resp, body = probes._accepted_create(c, create, "hldmMARK", eps)
        assert resp.status_code == 200
        assert body["productId"] in {"p-real-1", "p-real-2"}   # seeded, never a marker
        assert body["quantity"] == 1                            # coerced string -> number
    finally:
        srv.shutdown()


def test_a_create_the_server_never_accepts_stops_instead_of_looping():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        # a field the server refuses forever and that no coercion satisfies
        create = Endpoint(path="/api/cart/add", raw_path="/api/cart/add", method="post",
                          body_fields=["productId"])
        with httpx.Client(base_url=base, timeout=8.0) as c:
            resp, _body = probes._accepted_create(c, create, "hldmMARK", [])   # no sibling to seed from
        assert resp.status_code == 400
    finally:
        srv.shutdown()
