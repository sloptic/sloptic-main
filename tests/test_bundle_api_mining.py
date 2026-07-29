"""Mine API path literals out of code-split bundles, then let the SERVER decide which are real.

A framework-routed SPA keeps its whole write surface in per-route chunks that only load when you reach that
route, so an anonymous render observes a fraction of it. Measured on OopsSec Store (Next.js App Router): the
crawl found 13 endpoints; mining the chunks it discovered found 11 more, including /api/wishlists. Without
them, 27 of that app's 35 declared vulnerabilities sat in classes whose probes ran against nothing.

The proof that this is a REACH problem and not a detector problem: handed /api/products/search?q=, api_sqli
fires immediately via boolean differential. It had simply never been shown the endpoint.

A string in a bundle is a CLAIM, so verification is the whole design: 404 drops it, 405 means it exists but is
POST-only (the write surface), 401/403 means it exists behind auth. Without that step, mining manufactures
phantom endpoints, inflates endpoints_dead on every app, and spends the probe budget on nothing.
"""
import http.server
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.discovery import _mine_api_literals, _mined_api_endpoints  # noqa: E402
from sloptic.schema import Endpoint  # noqa: E402

_BUNDLE = """
  var e=await fetch("/api/wishlists");let t=await fetch("/api/orders",{method:"POST"});
  fetch("/api/gift-cards/redeem",{method:"POST"});n("/api/uploads/");
  o.src="/_next/static/chunks/app/page-abc.js";p("/img/api-logo.svg");
  q(`/api/orders/${id}`);r("/api/cart/items/"+id);s("/graphql");
  u("/static/config.json");v("/api/ghost-route");
"""


# ---------------------------------------------------------------- the literal miner

def test_api_paths_are_mined_from_a_bundle():
    got = _mine_api_literals(_BUNDLE)
    for want in ("/api/wishlists", "/api/orders", "/api/gift-cards/redeem", "/graphql"):
        assert want in got, want


def test_a_trailing_slash_collapses_to_the_collection():
    # /api/uploads/ and /api/cart/items/ are collection prefixes an id hangs off
    got = _mine_api_literals(_BUNDLE)
    assert "/api/uploads" in got and "/api/uploads/" not in got
    assert "/api/cart/items" in got


def test_an_interpolated_template_is_not_an_endpoint():
    # `/api/orders/${id}` fetched verbatim 404s, and reading that as "absent" is worse than not guessing
    got = _mine_api_literals(_BUNDLE)
    assert not any("$" in g or "{" in g for g in got)
    assert "/api/orders/${id}" not in got


def test_assets_and_framework_noise_are_not_endpoints():
    got = _mine_api_literals(_BUNDLE)
    assert not any(g.endswith((".js", ".json", ".svg")) for g in got)
    assert "/static/config" not in got          # first segment is not API-ish
    assert not any(g.startswith("/_next") for g in got)


def test_the_api_segment_must_be_first():
    # /img/api-logo.svg contains "api" but is an image; anchoring at segment one is what separates them
    assert "/img/api-logo" not in _mine_api_literals(_BUNDLE)
    assert _mine_api_literals('x("/assets/v1/sprite")') == set()


def test_an_empty_or_binary_bundle_mines_nothing():
    for blob in ("", None, "\x00\x01\x02"):
        assert _mine_api_literals(blob) == set()


# ---------------------------------------------------------------- verification

def _serve():
    """/api/wishlists is auth-gated, /api/orders is POST-only, /api/ghost-route does not exist."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            code = {"/api/wishlists": 401, "/api/orders": 405, "/api/gift-cards/redeem": 405,
                    "/api/cart/items": 200, "/graphql": 400, "/api/uploads": 404}.get(path, 404)
            body = b"{}" if path != "/bundle.js" else _BUNDLE.encode()
            if path == "/bundle.js":
                code = 200
            self.send_response(code)
            self.send_header("Content-Type", "application/javascript" if path == "/bundle.js" else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _mine(existing=()):
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        eps = _mined_api_endpoints(base, None, ["/", "/bundle.js"], list(existing))
        return {e.path: e for e in eps}
    finally:
        srv.shutdown()


def test_a_404_candidate_is_dropped():
    # THE precision rule: the bundle names it, the server does not serve it
    got = _mine()
    assert "/api/ghost-route" not in got
    assert "/api/uploads" not in got


def test_a_405_is_registered_as_a_write_endpoint():
    # "exists, wrong verb" is the point: an app's writes are what the injection/integrity/race probes need
    got = _mine()
    assert got["/api/orders"].method == "post" and got["/api/orders"].baseline_status == 405
    assert got["/api/gift-cards/redeem"].method == "post"


def test_an_auth_gated_endpoint_is_kept():
    # 401 proves existence just as well as 200; this is the IDOR target that was dark on OopsSec
    e = _mine().get("/api/wishlists")
    assert e is not None and e.method == "get" and e.baseline_status == 401


def test_the_baseline_status_is_recorded_for_the_health_gate():
    got = _mine()
    assert all(e.baseline_status is not None for e in got.values())
    assert got["/api/cart/items"].baseline_status == 200


def test_mined_endpoints_are_tagged_for_off_score_telemetry():
    # origin separates mined reach from crawl/observed reach, the same way "perceived" does for the LLM
    assert all(e.origin == "mined" for e in _mine().values())


def test_an_endpoint_the_crawl_already_has_is_not_duplicated():
    existing = [Endpoint(path="/api/wishlists", raw_path="/api/wishlists", method="get")]
    assert "/api/wishlists" not in _mine(existing)


def test_no_js_route_means_no_requests_and_no_endpoints():
    srv = _serve()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert _mined_api_endpoints(base, None, ["/", "/about"], []) == []
    finally:
        srv.shutdown()
