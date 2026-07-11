"""Discovery tests — the crawl must build the right surface map (routes + structured forms) from
the reference apps. No Docker: a reference app is hosted via SubprocessDeployer and crawled.
"""
import pathlib

import pytest

from hacklet_runner.deploy import SubprocessDeployer
from hacklet_runner.discovery import (
    _ACTION, _FIELD, _FORM, _LINK, _SRC, _parse_forms, _same_origin_path, discover,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFS = ROOT / "references"


@pytest.fixture
def serve():
    deployers = []

    def _serve(app: str) -> str:
        d = SubprocessDeployer(str(REFS / app / "app.py"))
        deployers.append(d)
        return d.deploy().base_url

    yield _serve
    for d in deployers:
        d.teardown()


def test_discovers_routes_and_login_form(serve):
    profile = discover(serve("vulnerable"))
    assert {"/", "/login", "/search", "/crash", "/heavy", "/config.js", "/register"} <= set(profile.routes)
    logins = [f for f in profile.forms if f.action == "/login"]
    assert logins, "should discover the /login form"
    assert logins[0].method == "post"
    assert set(logins[0].fields) == {"username", "password"}
    searches = [f for f in profile.forms if f.action == "/search"]
    assert searches and searches[0].method == "get" and searches[0].fields == ["q"]
    registers = [f for f in profile.forms if f.action == "/register"]
    assert registers and "password" in registers[0].fields
    assert profile.capabilities["any_endpoint_accepts_text_input"] is True
    assert profile.capabilities["any_form_has_password"] is True
    assert {"/login", "/search", "/register"} <= set(profile.form_endpoints)  # back-compat property


def test_self_submitting_form_resolves_to_current_page():
    # action="#" (DVWA, many CMS forms) submits back to the current page, not a dead fragment
    html = '<form action="#" method="get"><input name="id"><input type="submit" name="Submit"></form>'
    forms = _parse_forms(_FORM.findall(html), "http://x", "/vulnerabilities/sqli/")
    assert len(forms) == 1
    assert forms[0].action == "/vulnerabilities/sqli/" and forms[0].fields == ["id", "Submit"]


def test_logout_links_are_excluded_from_the_crawl():
    # following a logout link would destroy the runner's own authenticated session
    for href in ("/logout.php", "logout", "/auth/sign-out", "/user_logout", "/logoff"):
        assert _same_origin_path(href, "http://x", "/") is None, href
    # ordinary links (incl. lookalikes that merely contain 'log') are kept
    assert _same_origin_path("/dashboard", "http://x", "/") == "/dashboard"
    assert _same_origin_path("/blog/post", "http://x", "/") == "/blog/post"


def test_template_literal_artifacts_are_excluded_from_the_crawl():
    # un-rendered client-side templates leaked into markup are ghost routes, not real endpoints
    for href in ("/api/${apiBase}/items", "/{{userId}}/profile", "/list/{{i}}", "/x/`tpl`/y"):
        assert _same_origin_path(href, "http://x", "/") is None, href
    # a real route that merely contains a dollar sign or braces-free path is kept
    assert _same_origin_path("/api/v1/items", "http://x", "/") == "/api/v1/items"
    assert _same_origin_path("/prices$", "http://x", "/") == "/prices$"  # lone $, not a ${...} artifact


def test_attribute_regexes_ignore_data_attrs():
    # data-* attributes must not be mistaken for href/name/action (no leading boundary -> phantoms).
    assert _LINK.findall('<a href="/real">x</a>') == ["/real"]
    assert _LINK.findall('<div data-href="/phantom"></div>') == []
    assert _FIELD.findall('<input data-name="phantom" name="real">') == ["real"]
    assert _FIELD.findall('<input data-name="phantom" type="text">') == []
    assert _ACTION.findall('<form data-action="/x" action="/real">') == ["/real"]


def test_src_extraction_spans_tags():
    assert _SRC.findall('<img src="/api/avatar/5"><iframe src="/embed"><script src="/app.js">') == \
        ["/api/avatar/5", "/embed", "/app.js"]
    assert _SRC.findall('<img data-src="/lazy">') == []  # data-src guarded (no leading boundary)


def test_minimal_has_no_forms(serve):
    profile = discover(serve("minimal"))
    assert profile.routes == ["/"]  # no links, no forms
    assert profile.forms == []
    assert profile.capabilities["any_endpoint_accepts_text_input"] is False
    assert profile.capabilities["any_form_has_password"] is False


def test_hardened_same_surface_as_vulnerable(serve):
    profile = discover(serve("hardened"))
    assert {"/", "/login", "/search", "/crash", "/heavy"} <= set(profile.routes)
    assert any(
        f.action == "/login" and set(f.fields) == {"username", "password"} for f in profile.forms
    )


import http.server        # noqa: E402
import threading          # noqa: E402


def _serve_two_page():
    # "/" has no form (like bWAPP's login/portal redirect); "/deep" carries the real form
    pages = {"/": b"<html><body>home, nothing here</body></html>",
             "/deep": b'<html><body><form action="/deep" method="get"><input name="q"></form></body></html>'}

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = pages.get(self.path.split("?")[0], b"not found")
            self.send_response(200 if body != b"not found" else 404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_path_bearing_target_crawls_the_entry_page_and_binds_to_origin():
    srv = _serve_two_page()
    try:
        origin = "http://127.0.0.1:%d" % srv.server_address[1]
        # a bare-origin target sees only "/" (no form there)
        assert discover(origin).forms == []
        # a --target pointing at /deep must discover THAT page's form, and normalize base_url to the origin
        prof = discover(origin + "/deep")
        assert prof.base_url == origin  # bound to origin (not the path) so probes build base_url+"/path"
        assert any(f.action == "/deep" and f.fields == ["q"] for f in prof.forms)
    finally:
        srv.shutdown()


# --- which routes get browser-rendered for forms (pure filter, no browser) ----------------------
from hacklet_runner.discovery import _formless_form, _renderable_route  # noqa: E402


def test_renderable_route_filters_static_assets():
    assert _renderable_route("/login") and _renderable_route("/api/broadcast")
    assert not _renderable_route("/assets/index-abc.js")
    assert not _renderable_route("/logo.png") and not _renderable_route("/data.json")


# --- formless inputs: SPA fetch()-submit controls with no <form> wrapper (pure parser, no browser) ----
def test_formless_file_input_becomes_multipart_upload_target():
    # a bare <input type=file> + <button>, NO <form> (phish-school's uploader); id= is the sole identifier
    f = _formless_form('<div><input type="file" id="file-upload" accept=".png">'
                       '<button>Analyze</button></div>', "/detector")
    assert f is not None
    assert f.action == "/detector" and f.method == "post"           # upload -> POST to the page itself
    assert f.enctype == "multipart/form-data" and f.file_fields == ["file-upload"]


def test_formless_login_flips_to_post_with_password():
    f = _formless_form('<input name="email"><input name="password" type="password">'
                       '<button>Sign in</button>', "/login")
    assert f is not None and f.method == "post" and set(f.fields) == {"email", "password"}


def test_formless_search_is_get():
    # a loose text/search box with no password/file -> GET (folds into query-param injection)
    f = _formless_form('<input name="q" type="search"><button>Go</button>', "/results")
    assert f is not None and f.method == "get" and f.fields == ["q"]


def test_formless_ignores_inputs_inside_a_real_form():
    # inputs wrapped in <form> are handled by _parse_forms; synthesizing here too would double-count
    assert _formless_form('<form action="/x"><input name="a"></form>', "/") is None


def test_formless_skips_noninjectable_and_nameless():
    # submit/hidden/checkbox carry no injectable free text; a nameless+idless input is unaddressable
    assert _formless_form('<input type="submit" value="go"><input type="hidden" name="csrf" value="x">'
                          '<input type="checkbox" name="agree"><input type="text">', "/") is None


# --- name inference for anonymous SPA inputs (no name/id — React-controlled) ---------------------
from hacklet_runner.discovery import _infer_name, _scan_form_inputs  # noqa: E402


def test_infer_name_from_semantic_type():
    # phish-school's login: <input type=email>/<input type=password> with no name/id -> inferred
    assert _infer_name(' type="email"', None) == "email"
    assert _infer_name(' type="password"', None) == "password"
    assert _infer_name(' type="text"', None) is None       # a bare text box gives no field-name hint


def test_infer_name_prefers_autocomplete_then_label_then_placeholder():
    assert _infer_name(' autocomplete="username"', None) == "username"
    assert _infer_name(' autocomplete="current-password"', None) == "password"
    assert _infer_name(' type="text"', "Full Name") == "full"          # <label> text -> first word
    assert _infer_name(' type="text" placeholder="Search notes"', None) == "search"


def test_scan_infers_anonymous_login_and_keeps_hidden_in_a_form():
    # a real <form> keeps its CSRF/hidden field (needed to submit) AND infers the anonymous credential inputs
    fields, files, has_pw = _scan_form_inputs(
        '<input type="hidden" name="csrf"><label>Email</label><input type="email">'
        '<input type="password"><button type="submit">Go</button>')
    assert fields == ["csrf", "email", "password"] and has_pw and files == []


def test_scan_associates_nearest_label():
    fields, _, _ = _scan_form_inputs('<label>Username</label><input type="text">'
                                     '<label>Bio</label><textarea></textarea>')
    assert fields == ["username", "bio"]


# --- observed-surface fingerprint (the parity denominator) --------------------------------------
from hacklet_runner.discovery import surface_metrics  # noqa: E402


def test_surface_metrics_fingerprints_discovered_surface(serve):
    s = surface_metrics(discover(serve("vulnerable")))
    assert s["has_login"] is True and s["forms"] >= 2 and s["inputs"] >= 2
    assert s["surface_size"] == s["routes"] + s["inputs"] + s["endpoints"]   # composite is the sum


def test_surface_metrics_low_on_a_form_less_landing_page(serve):
    # the 'blind-or-trivial' end: minimal app (one route, no forms/api) -> tiny surface, no categorical hits
    s = surface_metrics(discover(serve("minimal")))
    assert s["forms"] == 0 and s["surface_size"] == 1        # just the "/" route
    assert s["has_login"] is False and s["has_upload"] is False and s["has_api"] is False


# --- api-only feature seeding + vendor-path stripping -------------------------------------------
from hacklet_runner.discovery import _VENDOR_PATH, _endpoints_from_features  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402


def test_endpoints_from_features_seeds_api_surface():
    eps = _endpoints_from_features([
        {"kind": "crud-read", "path": "/api/x/{id}/", "method": "get"},   # templated -> path_params
        {"kind": "search", "path": "/api/s/", "method": "get"},           # search -> query params
        {"kind": "other", "path": "not-a-path"},                          # not a "/path" -> skipped
    ])
    assert len(eps) == 2
    tid = next(e for e in eps if e.raw_path == "/api/x/{id}/")
    assert tid.path == "/api/x/1/" and tid.path_params == ["id"]          # {id} concretized + captured
    assert next(e for e in eps if e.raw_path == "/api/s/").query_params == ["q", "search", "query"]


def test_surface_metrics_recognizes_api_login_upload_endpoints():
    from hacklet_runner.schema import Endpoint
    # an api-only app's login/upload are ENDPOINTS (feature kind or a login/upload-named path), not forms —
    # has_login/has_upload must see them, else parity falsely reports a blind spot (sapling)
    eps = [Endpoint(path="/api/login", raw_path="/api/login", method="post", kind="auth"),
           Endpoint(path="/api/documents", raw_path="/api/documents", method="post", kind="upload")]
    s = surface_metrics(Profile(base_url="http://t", routes=["/"], forms=[], capabilities={}, endpoints=eps))
    assert s["has_login"] is True and s["has_upload"] is True
    # and path-based, for a crawled/mined endpoint with no feature kind
    e = [Endpoint(path="/api/v2/signin", raw_path="/api/v2/signin", method="post")]
    assert surface_metrics(Profile(base_url="http://t", routes=["/"], forms=[], capabilities={},
                                   endpoints=e))["has_login"] is True


def test_surface_metrics_counts_only_healthy_endpoints():
    from hacklet_runner.schema import Endpoint
    eps = [Endpoint(path="/api/a", raw_path="/api/a", baseline_status=200),   # healthy
           Endpoint(path="/api/b", raw_path="/api/b", baseline_status=500),   # env-var-dead
           Endpoint(path="/api/c", raw_path="/api/c", baseline_status=None)]  # untested -> counts as healthy
    p = Profile(base_url="http://t", routes=["/"], forms=[], capabilities={}, endpoints=eps)
    s = surface_metrics(p)
    assert s["endpoints"] == 2 and s["endpoints_reached"] == 3 and s["endpoints_dead"] == 1
    assert s["surface_size"] == 1 + 2      # 1 route + 2 healthy endpoints (dead one excluded)


def test_surface_metrics_excludes_bundled_vendor_paths():
    # a Potree/three.js app serving 60+ /libs files must not inflate the surface denominator
    p = Profile(base_url="http://t", routes=["/", "/dashboard", "/potree/libs/three.js",
                                             "/node_modules/x.js"], forms=[], capabilities={}, endpoints=[])
    s = surface_metrics(p)
    assert s["routes"] == 2 and s["routes_all"] == 4 and s["surface_size"] == 2
    assert bool(_VENDOR_PATH.search("/libs/d3.min.js")) and not _VENDOR_PATH.search("/api/v1/tracts/")
