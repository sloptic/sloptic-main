"""Ask for the conventional API names, because some endpoints are referenced by NOTHING.

Measured on supavulnbase: `feedback` appears in ZERO of 16 reachable chunks and in no page HTML, yet
POST {basePath}/api/feedback answers 405 and names its own fields in a Zod error. That is the fixture's
tmpl-001, and its declared discovery mechanism (`schema-error`) presumes you already hold the path. OopsSec's
/wishlists is the same shape: a live 200 page linked from nowhere. No crawl and no bundle mine can reach an
unreferenced route, so the only move left is to ask for the names — exactly what we already do for FILE paths
(.env, .git/config) and never did for API paths.

Yield measured BEFORE building it, 32 candidates:
    supavulnbase  /api/feedback 405   /api/projects 200
    OopsSec       /api/support 405  /api/admin 401  /api/user 401  /api/orders 401  /api/files 400

Verification is shared with bundle mining (_verify_api_path) so the two cannot drift: a wrong guess costs one
404 and never leaves a phantom endpoint behind.
"""
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

from hacklet_runner.discovery import _conventional_api_endpoints, _verify_api_path  # noqa: E402
from hacklet_runner.schema import Endpoint  # noqa: E402


def _serve(table):
    """`table` maps a path to a status code; everything else 404s."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            code = table.get(path, 404)
            b = json.dumps({"p": path}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- the shared verifier

def test_the_status_taxonomy_is_the_detector():
    srv = _serve({"/api/feedback": 405, "/api/admin": 401, "/api/users": 200, "/api/nope": 404,
                  "/api/broken": 500})
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(base_url=base, timeout=6.0) as c:
            assert _verify_api_path(c, "/api/feedback", set()).method == "post"   # 405 = exists, wrong verb
            assert _verify_api_path(c, "/api/admin", set()).method == "get"       # 401 = exists, gated
            assert _verify_api_path(c, "/api/users", set()).method == "get"
            assert _verify_api_path(c, "/api/nope", set()) is None                # 404 = not served
            assert _verify_api_path(c, "/api/broken", set()).baseline_status == 500
    finally:
        srv.shutdown()


def test_an_endpoint_already_known_is_not_re_verified():
    srv = _serve({"/api/users": 200})
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(base_url=base, timeout=6.0) as c:
            assert _verify_api_path(c, "/api/users", {("get", "/api/users")}) is None
            assert _verify_api_path(c, "/api/users", {("post", "/api/users")}) is None
    finally:
        srv.shutdown()


def test_an_unreachable_host_is_none_not_an_exception():
    with httpx.Client(base_url="http://127.0.0.1:1", timeout=2.0) as c:
        assert _verify_api_path(c, "/api/users", set()) is None


# ---------------------------------------------------------------- the conventional probe

def _run(table, app_root="/", existing=(), api_seen=True):
    srv = _serve(table)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        return {e.path: e for e in _conventional_api_endpoints(base, None, list(existing), app_root, api_seen)}
    finally:
        srv.shutdown()


def test_an_unreferenced_write_endpoint_is_found():
    # THE case this exists for: nothing in the app links or names /api/feedback
    got = _run({"/api/feedback": 405})
    assert "/api/feedback" in got and got["/api/feedback"].method == "post"
    assert got["/api/feedback"].origin == "conventional"


def test_auth_gated_and_open_endpoints_are_both_kept():
    got = _run({"/api/admin": 401, "/api/orders": 403, "/api/projects": 200})
    assert set(got) == {"/api/admin", "/api/orders", "/api/projects"}


def test_an_app_with_no_conventional_endpoints_registers_nothing():
    assert _run({}) == {}


def test_a_sub_path_app_is_probed_under_its_own_root():
    got = _run({"/app/api/feedback": 405}, app_root="/app")
    assert "/app/api/feedback" in got
    # and the origin-relative path must NOT be probed as if it were the app root
    assert "/api/feedback" not in got


def test_a_static_site_pays_nothing():
    """The gate: without any sign of an API, 27 requests on a brochure site buy nothing. api_seen is set from
    a rendered SPA or any /api/ path already observed."""
    assert _conventional_api_endpoints("http://127.0.0.1:1", None, [], "/", False) == []


def test_an_endpoint_the_crawl_already_found_is_not_duplicated():
    existing = [Endpoint(path="/api/projects", raw_path="/api/projects", method="get")]
    got = _run({"/api/projects": 200, "/api/feedback": 405}, existing=existing)
    assert "/api/projects" not in got and "/api/feedback" in got


def test_the_candidate_list_covers_the_names_the_fixtures_actually_use():
    from hacklet_runner.discovery import _CONVENTIONAL_API
    for measured in ("feedback", "projects", "support", "admin", "user", "orders", "files"):
        assert measured in _CONVENTIONAL_API, measured
