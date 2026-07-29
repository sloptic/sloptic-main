"""Ask an endpoint to reject a body, and it names its own fields.

Mining took OopsSec from 13 endpoints to 24 and the re-grade was BYTE-IDENTICAL, because a path with no
parameters is nearly useless to an injection probe: sqli/xss/ssti had nothing to inject into. Modern TS APIs
answer a malformed body by naming their required fields, so the app hands over its own schema for one request.

Measured on OopsSec (Next.js + Zod), POST with an empty body:
    /api/support          -> {"details":[{"path":"email"},{"path":"title"}]}
    /api/cart/add         -> productId, quantity
    /api/gift-cards/redeem-> code
The auth-gated ones only answer with a session, which is why this runs with the crawl's credentials.

A WRONG field name costs one wasted injection attempt and can never produce a false finding, so the precision
bar here is low by nature. What must not happen is mistaking an HTML error page or a success body for a schema.
"""
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

from sloptic.discovery import _schema_discovery, _schema_fields  # noqa: E402
from sloptic.schema import Endpoint  # noqa: E402


def _resp(body, ctype="application/json"):
    return httpx.Response(400, json=body, headers={"content-type": ctype}) if not isinstance(body, str) \
        else httpx.Response(400, content=body, headers={"content-type": ctype})


# ---------------------------------------------------------------- the parsers

def test_zod_with_a_string_path():
    # the shape OopsSec actually returns
    got = _schema_fields(_resp({"error": "Invalid input",
                                "details": [{"path": "email", "code": "invalid_type"},
                                            {"path": "title", "code": "invalid_type"}]}))
    assert got == ["email", "title"]


def test_zod_with_an_array_path():
    # Zod v3's own issues[] shape, where path is a list and the LEAF is the field
    got = _schema_fields(_resp({"issues": [{"path": ["user", "email"], "message": "Required"},
                                           {"path": ["password"], "message": "Required"}]}))
    assert got == ["email", "password"]


def test_pydantic_and_fastapi_loc():
    got = _schema_fields(_resp({"detail": [{"loc": ["body", "email"], "msg": "field required"},
                                           {"loc": ["body", "amount"], "msg": "field required"}]}))
    assert got == ["email", "amount"]


def test_express_validator_param():
    got = _schema_fields(_resp({"errors": [{"msg": "Invalid", "param": "email", "location": "body"}]}))
    assert got == ["email"]


def test_rails_style_errors_object():
    got = _schema_fields(_resp({"errors": {"email": ["can't be blank"], "name": ["is too short"]}}))
    assert got == ["email", "name"]


def test_a_plain_required_sentence():
    assert _schema_fields(_resp({"error": "productId is required"})) == ["productId"]
    assert _schema_fields(_resp({"message": "'code' is required"})) == ["code"]


def test_wrapper_words_are_not_field_names():
    # ["body","email"] must yield email, and a bare {"loc":["body"]} must yield nothing
    assert _schema_fields(_resp({"detail": [{"loc": ["body"]}]})) == []
    assert _schema_fields(_resp({"errors": [{"param": "data"}]})) == []


def test_an_html_error_page_names_nothing():
    assert _schema_fields(_resp("<html><body>400 Bad Request</body></html>", "text/html")) == []


def test_a_non_json_content_type_is_ignored_even_if_the_body_looks_like_json():
    assert _schema_fields(_resp('{"details":[{"path":"email"}]}', "text/plain")) == []


def test_duplicates_collapse_and_order_is_stable():
    got = _schema_fields(_resp({"details": [{"path": "email"}, {"path": "email"}, {"path": "code"}]}))
    assert got == ["email", "code"]


# ---------------------------------------------------------------- end to end

def _serve():
    """POST /api/cart/add names its fields; /api/public succeeds; /api/opaque returns an HTML error."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            path = self.path.split("?")[0]
            if path == "/api/cart/add":
                code, ctype, body = 400, "application/json", json.dumps(
                    {"error": "Invalid input", "details": [{"path": "productId"}, {"path": "quantity"}]})
            elif path == "/api/public":
                code, ctype, body = 200, "application/json", json.dumps({"ok": True})
            else:
                code, ctype, body = 400, "text/html", "<html>bad request</html>"
            b = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _ep(path, method="post", **kw):
    return Endpoint(path=path, raw_path=path, method=method, **kw)


def test_a_parameterless_write_endpoint_gains_its_fields():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        eps = [_ep("/api/cart/add"), _ep("/api/public"), _ep("/api/opaque")]
        filled = _schema_discovery(base, None, eps)
        assert filled == 1
        assert eps[0].body_fields == ["productId", "quantity"]
        assert eps[1].body_fields == [] and eps[2].body_fields == []
    finally:
        srv.shutdown()


def test_an_endpoint_that_already_has_parameters_is_left_alone():
    # discovery observed these for real; a synthesized guess must never overwrite ground truth
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        known = _ep("/api/cart/add", body_fields=["sku"])
        query = _ep("/api/cart/add", query_params=["q"])
        assert _schema_discovery(base, None, [known, query]) == 0
        assert known.body_fields == ["sku"] and query.query_params == ["q"]
    finally:
        srv.shutdown()


def test_get_only_endpoints_are_not_posted_to():
    # a GET collection is an IDOR target, not an injection target; POSTing to it would be a stray write
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert _schema_discovery(base, None, [_ep("/api/cart/add", method="get")]) == 0
    finally:
        srv.shutdown()


def test_no_write_endpoints_means_no_requests():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert _schema_discovery(base, None, []) == 0
    finally:
        srv.shutdown()
