"""A collection's search sibling is concatenated in the client, so no bundle literal exists to mine.

Measured on OopsSec: mining found `/api/products`; the injectable endpoint is `/api/products/search?q=`, where
`q=test'` returns 500 and api_sqli fires instantly when handed the path. The app's own manifest names the
challenge `product-search-sql-injection`. One suffix guess reaches it, and neither the crawl nor bundle mining
ever could — the client builds it as `fetch("/api/products/search?q=" + term)`.

THE PARAMETER MUST BE PROVEN, NOT GUESSED, and my first attempt got this wrong. A length differential between
the bare call and a nonsense term cannot work: on OopsSec both `/api/products/search` and `?q=test` answer
`{"products":[]}` — identical bytes. The fix is to search for a term the collection itself just returned, so a
match proves the endpoint actually searched on that param rather than merely tolerating it. Same self-as-oracle
move `_conventional_pairs` uses for ids.

Registering six speculative param names instead would multiply every injection probe's request count by six for
five names the app ignores.
"""
import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.discovery import _collection_token, _search_endpoints  # noqa: E402
from sloptic.schema import Endpoint  # noqa: E402

_ITEMS = [{"id": "p1", "name": "Artisan Sourdough Bread", "price": 5.49},
          {"id": "p2", "name": "Cold Brew Concentrate", "price": 9.99}]


def _serve(search_param="q", search_path="/api/products/search", collection_shape="list",
           collection_path="/api/products"):
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
            q = urllib.parse.parse_qs(u.query)
            if u.path == collection_path:
                return self._json(200, _ITEMS if collection_shape == "list" else {"products": _ITEMS})
            if u.path == search_path:
                term = (q.get(search_param) or [""])[0]
                hits = [i for i in _ITEMS if term and term.lower() in i["name"].lower()]
                return self._json(200, {"products": hits})     # EMPTY for a nonsense term, always 200
            return self._json(404, {"error": "not found"})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(**kw):
    srv = _serve(**kw)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        eps = [Endpoint(path="/api/products", raw_path="/api/products", method="get")]
        return _search_endpoints(base, None, eps)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- the token

def test_a_token_is_taken_from_the_collections_own_data():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        import httpx
        with httpx.Client(base_url=base, timeout=8.0) as c:
            assert _collection_token(c, "/api/products") in ("Artisan", "Sourdough", "Bread")
    finally:
        srv.shutdown()


def test_a_wrapped_collection_is_also_read():
    srv = _serve(collection_shape="wrapped")
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        import httpx
        with httpx.Client(base_url=base, timeout=8.0) as c:
            assert _collection_token(c, "/api/products") is not None
    finally:
        srv.shutdown()


def test_a_collection_with_nothing_searchable_yields_no_token():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        import httpx
        with httpx.Client(base_url=base, timeout=8.0) as c:
            assert _collection_token(c, "/api/nope") is None
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- discovery

def test_the_search_sibling_is_found_with_its_real_param():
    got = _run()
    assert len(got) == 1
    e = got[0]
    assert e.path == "/api/products/search" and e.query_params == ["q"]
    assert e.kind == "search" and e.method == "get" and e.origin == "mined"
    assert e.raw_path == "/api/products/search?q="


def test_a_non_default_param_name_is_found_too():
    # the whole point of proving rather than assuming: this app searches on `term`, not `q`
    got = _run(search_param="term")
    assert got and got[0].query_params == ["term"]


def test_a_different_suffix_is_found():
    got = _run(search_path="/api/products/find")
    assert got and got[0].path == "/api/products/find"


def test_an_app_with_no_search_sibling_registers_nothing():
    # every suffix 404s; guessing must not leave a phantom endpoint behind
    assert _run(search_path="/api/products/nonexistent") == []


def test_a_param_that_is_merely_ACCEPTED_is_not_registered():
    """The precision rule. An endpoint that answers 200 to any query string but never filters has not proven a
    searchable param, and registering one would point every injection probe at a parameter the app ignores."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            body = json.dumps(_ITEMS if u.path == "/api/products" else {"products": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        eps = [Endpoint(path="/api/products", raw_path="/api/products", method="get")]
        assert _search_endpoints(base, None, eps) == []
    finally:
        srv.shutdown()


def test_an_endpoint_already_known_is_not_re_registered():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        eps = [Endpoint(path="/api/products", raw_path="/api/products", method="get"),
               Endpoint(path="/api/products/search", raw_path="/api/products/search", method="get")]
        assert _search_endpoints(base, None, eps) == []
    finally:
        srv.shutdown()


def test_only_top_level_api_collections_are_probed():
    # /api/products/cmrz.../reviews is an item sub-resource, not a collection to hang /search off
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        deep = [Endpoint(path="/api/products/p1/reviews", raw_path="/api/products/p1/reviews", method="get")]
        assert _search_endpoints(base, None, deep) == []
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- sub-path deployments

def test_a_sub_path_app_is_not_invisible():
    """The bug this file's own feature shipped with, caught by a fixture serving both variants.

    The collection shape test was `path.startswith("/api/") and path.count("/") == 2`, which on a sub-path
    deployment sees /app/api/projects -- neither condition holds -- so search discovery rejected EVERY
    collection and the whole feature was dead on any app not served at the origin. Measured on supavulnbase,
    whose /app/api/projects/search?q= is the location its manifest gives for the PostgREST injection finding.
    """
    from sloptic.discovery import _relative_to, _under
    assert _relative_to("/app", "/app/api/projects") == "/api/projects"
    assert _relative_to("/", "/api/projects") == "/api/projects"
    # and a bundle literal is APP-relative, so verifying it at the origin 404s an endpoint that exists
    assert _under("/app", "/api/feedback") == "/app/api/feedback"
    assert _under("/", "/api/feedback") == "/api/feedback"
    assert _under("/app", "/app/api/feedback") == "/app/api/feedback"    # idempotent


def test_a_collection_found_only_as_a_ROUTE_still_counts():
    """A crawl that sees /api/projects records it as a route, not an endpoint. Looking only at `endpoints`
    skipped the single collection supavulnbase exposes, so the search sibling was never guessed."""
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        got = _search_endpoints(base, None, [], routes=["/api/products"])   # no endpoints at all
        assert got and got[0].path == "/api/products/search" and got[0].query_params == ["q"]
    finally:
        srv.shutdown()


def test_a_sub_path_collection_yields_a_sub_path_sibling():
    srv = _serve(search_path="/app/api/products/search", collection_path="/app/api/products")
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        got = _search_endpoints(base, None, [], app_root="/app", routes=["/app/api/products"])
        assert got and got[0].path == "/app/api/products/search"
    finally:
        srv.shutdown()
