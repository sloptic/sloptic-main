"""Discovery tests — the crawl must build the right surface map (routes + structured forms) from
the reference apps. No Docker: a reference app is hosted via SubprocessDeployer and crawled.
"""
import pathlib

import pytest

from hacklet_runner.deploy import SubprocessDeployer
from hacklet_runner.discovery import (
    _ACTION, _FIELD, _FORM, _LINK, _SRC, _parse_forms, _same_origin_path, discover, merge_perceived,
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
from hacklet_runner.schema import Endpoint, Form, Profile  # noqa: E402


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


def test_endpoints_from_features_uses_source_declared_params_and_body_fields():
    # build #2: the LLM names each endpoint's ACTUAL query params + body fields from the source, so
    # injection points at the real input surface a crawler can't see — not a generic guess. Untrusted-plan
    # sanitized, and the search fallback survives only when the LLM named nothing.
    from hacklet_runner.probes import _sqli_slots
    eps = _endpoints_from_features([
        {"kind": "crud-create", "path": "/projects", "method": "post",
         "body_fields": ["title", "description"]},                        # POST body -> SQLi body slots
        {"kind": "crud-read", "path": "/download", "method": "get", "params": ["file"]},  # non-search GET param (LFI)
        {"kind": "search", "path": "/api/search", "method": "get",
         "params": ["q", "q", "  ", 7, "limit"]},                         # dupes/blank/non-str sanitized out
        {"kind": "search", "path": "/api/s2", "method": "get"},           # search + no names -> fallback intact
    ])
    create = next(e for e in eps if e.raw_path == "/projects")
    assert create.method == "post" and create.body_fields == ["title", "description"] and create.query_params == []
    assert next(e for e in eps if e.raw_path == "/download").query_params == ["file"]   # the key win: a real, non-search target
    assert next(e for e in eps if e.raw_path == "/api/search").query_params == ["q", "limit"]  # deduped, blank + int dropped
    assert next(e for e in eps if e.raw_path == "/api/s2").query_params == ["q", "search", "query"]  # fallback preserved
    # and it actually reaches the injection battery: the source-named body field becomes a real SQLi slot
    assert ("body", "title") in _sqli_slots(create)


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


def test_dedup_merges_llm_params_onto_crawler_found_endpoint():
    from hacklet_runner.discovery import _dedup_merge_endpoints
    from hacklet_runner.schema import Endpoint
    # a crawler-found endpoint and an LLM feature for the SAME (method, raw_path): the LLM's source-named
    # body/query params must MERGE on (not be dropped by keep-first dedup), and origin must downgrade to
    # crawl (a crawl source found the path too -> not the pointer's UNIQUE contribution).
    out = _dedup_merge_endpoints([
        Endpoint(path="/api/x", raw_path="/api/x", method="get", query_params=["page"], origin="crawl"),
        Endpoint(path="/api/x", raw_path="/api/x", method="get", query_params=["q"], body_fields=["title"],
                 kind="search", origin="llm"),
    ])
    assert len(out) == 1
    assert out[0].query_params == ["page", "q"] and out[0].body_fields == ["title"]  # unioned; LLM params kept
    assert out[0].kind == "search" and out[0].origin == "crawl"                      # kind filled; not LLM-unique
    # LLM seen FIRST, a crawl source merges later -> origin still downgrades to crawl (order-independent)
    out2 = _dedup_merge_endpoints([
        Endpoint(path="/y", raw_path="/y", query_params=["a"], origin="llm"),
        Endpoint(path="/y", raw_path="/y", query_params=["b"], origin="crawl"),
    ])
    assert out2[0].origin == "crawl" and out2[0].query_params == ["a", "b"]
    # an endpoint ONLY the LLM named keeps origin llm (the pointer's genuine unique find)
    assert _dedup_merge_endpoints([Endpoint(path="/ghost", raw_path="/ghost", origin="llm")])[0].origin == "llm"


def test_catch_all_host_drops_phantom_endpoints_and_forms():
    import http.server
    import threading

    from hacklet_runner.discovery import discover
    _SHELL = (b"<html><body><h1>App</h1>"
              b"<form action='/login'><input name='email'><input name='password' type='password'></form>"
              b"<a href='/api/data?q=x'>data</a></body></html>")

    class _CatchAll(http.server.BaseHTTPRequestHandler):   # every path -> the SAME 200 shell (SPA/soft-404)
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(_SHELL)

        def log_message(self, *a):
            pass

    class _Real(http.server.BaseHTTPRequestHandler):       # real 404 for nonexistent; a real JSON endpoint
        def do_GET(self):
            if self.path.startswith("/api/data"):
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"items":[]}'); return
            if self.path in ("/", "/login"):
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
                self.wfile.write(_SHELL); return
            self.send_response(404); self.end_headers(); self.wfile.write(b"not found")

        def log_message(self, *a):
            pass

    def _serve(handler):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    ca = _serve(_CatchAll)
    real = _serve(_Real)
    try:
        p_ca = discover(f"http://127.0.0.1:{ca.server_address[1]}")
        assert p_ca.capabilities["catch_all"] is True          # nonexistent path returned the shell -> catch-all
        assert p_ca.endpoints == [] and p_ca.forms == []       # /api/data + /login echo the shell -> phantom, dropped
        p_real = discover(f"http://127.0.0.1:{real.server_address[1]}")
        assert p_real.capabilities["catch_all"] is False       # nonexistent path 404s -> real server
        assert any("/api/data" in e.path for e in p_real.endpoints)   # a real endpoint (distinct JSON) is KEPT
        assert any(f.action == "/login" for f in p_real.forms)        # and its real form
    finally:
        ca.shutdown(); real.shutdown()


def test_vendor_antibot_fields_excluded_from_injectable_surface():
    from hacklet_runner.discovery import _scan_form_inputs
    fields, _files, _pw = _scan_form_inputs(
        "<input name='email'><input name='cf-turnstile-response' type='hidden'>"
        "<input name='g-recaptcha-response'><input name='password' type='password'>")
    assert "email" in fields and "password" in fields                                      # real inputs kept
    assert "cf-turnstile-response" not in fields and "g-recaptcha-response" not in fields   # widget tokens dropped


def test_login_signup_triggers_credit_has_login_without_a_form():
    from hacklet_runner.discovery import _auth_triggers, surface_metrics
    # button/link CTAs, not inline password forms — the case the audit kept flagging as has_login=false
    assert _auth_triggers("<a href='/x'>Continue with Google</a><button>Sign up free</button>") == (True, True)
    assert _auth_triggers("<button>Get Started</button>") == (False, True)          # 'Get started' = signup CTA
    assert _auth_triggers("<button>Add to cart</button><a>Home</a>") == (False, False)   # no auth CTA -> no FP
    assert _auth_triggers("<button>Sign out</button>") == (False, False)            # sign OUT is not sign in
    # a Profile whose ONLY login/signup signal is the trigger cap (no form, no auth endpoint) -> credited
    m = surface_metrics(Profile(base_url="http://t", routes=["/"], forms=[], capabilities={},
                                endpoints=[]))
    assert m["has_login"] is False and m["has_signup"] is False                     # nothing -> both false
    m2 = surface_metrics(Profile(base_url="http://t", routes=["/"], forms=[], endpoints=[],
                                 capabilities={"login_trigger": True, "signup_trigger": True}))
    assert m2["has_login"] is True and m2["has_signup"] is True                     # CTA-only auth is now seen


def test_surface_metrics_reports_llm_pointer_precision():
    from hacklet_runner.schema import Endpoint
    # build #2 telemetry (off-score): of the endpoints ONLY the LLM seeded (origin llm), how many are real
    # (path exists) vs hallucinated (404). Crawler endpoints are excluded — this measures the POINTER.
    eps = [
        Endpoint(path="/api/search", raw_path="/api/search", query_params=["q"], baseline_status=200, origin="llm"),
        Endpoint(path="/download", raw_path="/download", query_params=["file"], baseline_status=401, origin="llm"),  # auth -> exists
        Endpoint(path="/ghost", raw_path="/ghost", baseline_status=404, origin="llm"),                            # 404 -> hallucinated
        Endpoint(path="/projects", raw_path="/projects", method="post", body_fields=["title", "body"],
                 baseline_status=200, origin="llm"),
        Endpoint(path="/crawled", raw_path="/crawled", query_params=["x"], baseline_status=200),                  # origin crawl -> excluded
    ]
    ptr = surface_metrics(Profile(base_url="http://t", routes=["/"], forms=[], capabilities={}, endpoints=eps))["pointer"]
    assert ptr["endpoints_seeded"] == 4              # 4 llm-origin (the crawled endpoint is not the pointer's)
    assert ptr["endpoints_reachable"] == 3           # 200 / 401 / 200 — the path exists (LLM was right)
    assert ptr["endpoints_hallucinated"] == 1        # /ghost 404 — a path that isn't there
    assert ptr["params_seeded"] == 4                 # q + file + (title, body); the ghost added none


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


# --- proactive discovery: merge an LLM perception of the rendered surface into the Profile ---------
def test_merge_perceived_adds_missed_forms_and_endpoints_tagged_perceived():
    prof = Profile(base_url="http://x", forms=[Form(action="/", method="get", fields=["q"])], endpoints=[])
    perceived = {
        "forms": [{"kind": "login", "action": "/api/login", "method": "post",
                   "fields": ["email", "password"], "file_fields": [], "label": "Sign in"}],
        "endpoints": [{"kind": "create", "path": "/api/boards", "method": "post",
                       "params": [], "body_fields": ["title"], "label": "New Board"}],
        "page_state": "working"}
    out = merge_perceived(prof, perceived)
    login = [f for f in out.forms if f.action == "/api/login"]
    assert login and login[0].fields == ["email", "password"] and login[0].origin == "perceived"  # wakes auth
    assert any(e.raw_path == "/api/boards" and e.body_fields == ["title"] and e.origin == "perceived"
               for e in out.endpoints)                                                        # injection target
    assert out.forms[0].action == "/"                             # the crawled form is untouched (floor preserved)


def test_merge_perceived_dedups_and_noops_on_empty():
    prof = Profile(base_url="http://x", forms=[Form(action="/login", method="post", fields=["email", "password"])])
    merge_perceived(prof, {"forms": [{"action": "/login", "method": "post",   # same form perceived again
                                      "fields": ["email", "password"]}], "endpoints": []})
    assert len(prof.forms) == 1                                   # deduped by (action, method, fields)
    assert merge_perceived(prof, None).forms == prof.forms        # None -> no-op: the crawl stays the floor


def test_merge_perceived_rejects_third_party_and_fieldless_forms():
    prof = Profile(base_url="http://x")
    merge_perceived(prof, {"forms": [
        {"action": "https://evil.com/x", "fields": ["a"]},        # not relative -> never post to a third party
        {"action": "/empty", "fields": [], "file_fields": []},    # no inputs -> not a probe target
    ], "endpoints": []})
    assert prof.forms == []


def _stub_render(base_url, paths, headers=None):
    return {p: "<html><body><h1>App</h1><button>Sign in</button></body></html>" for p in paths}


def test_discover_wires_perceive_into_the_profile(serve):
    # end-to-end wiring: discover() runs the injected perceive callback on the rendered pages and merges its
    # structured surface into the Profile (the crawl never sees /__perceived_* — only perception does).
    base = serve("vulnerable")

    def _perceive(doms, observed):
        assert doms and "routes" in observed             # got the rendered DOMs + what the crawl observed
        return {"forms": [{"kind": "login", "action": "/__perceived_login", "method": "post",
                           "fields": ["email", "password"]}],
                "endpoints": [{"kind": "create", "path": "/__perceived_api", "method": "post",
                               "body_fields": ["title"]}], "page_state": "working"}
    prof = discover(base, render=_stub_render, perceive=_perceive)
    assert any(f.action == "/__perceived_login" and f.origin == "perceived" for f in prof.forms)
    pe = [e for e in prof.endpoints if e.raw_path == "/__perceived_api" and e.origin == "perceived"]
    assert pe and pe[0].baseline_status is not None   # perceived endpoint is now BASELINED (was always None -> unjudged)


def test_discover_perceive_failure_degrades_to_the_deterministic_floor(serve):
    # graceful degradation: a perceive callback that raises (model down / bad output) must NOT break discovery
    base = serve("vulnerable")
    baseline = discover(base, render=_stub_render)                          # no perception

    def _boom(doms, observed):
        raise RuntimeError("model down")
    degraded = discover(base, render=_stub_render, perceive=_boom)          # perception raises -> swallowed
    assert [f.action for f in degraded.forms] == [f.action for f in baseline.forms]
    assert len(degraded.endpoints) == len(baseline.endpoints)              # identical to the pure crawl (the floor)


def test_surface_metrics_reports_the_perception_pointer():
    # off-score telemetry: perceived surface is measured SEPARATELY from the source-read #2 pointer, and
    # perceived endpoints split reachable/hallucinated via the frozen baseline (forms just count, having
    # survived phantom-suppression). This is the honesty number for a --proactive A/B.
    prof = Profile(base_url="http://x",
                   forms=[Form(action="/login", method="post", fields=["email", "password"], origin="perceived")],
                   endpoints=[
                       Endpoint(path="/api/real", raw_path="/api/real", method="post", body_fields=["t"],
                                baseline_status=200, origin="perceived"),
                       Endpoint(path="/api/ghost", raw_path="/api/ghost", baseline_status=404, origin="perceived"),
                       Endpoint(path="/api/src", raw_path="/api/src", baseline_status=200, origin="llm")])
    ptr = surface_metrics(prof)["pointer"]
    assert ptr["perceived_forms_seeded"] == 1 and ptr["perceived_form_actions"] == ["/login"]
    assert ptr["perceived_password_forms"] == 1        # the login carries a password field -> auth self-oracle surface
    assert ptr["perceived_endpoints_seeded"] == 2
    assert ptr["perceived_endpoints_reachable"] == 1 and ptr["perceived_endpoints_hallucinated"] == 1
    assert set(ptr["perceived_endpoint_paths"]) == {"/api/real", "/api/ghost"}   # the paths it added (not the llm one)
    assert ptr["perceived_ghost_paths"] == ["/api/ghost"]                        # only the 404 -> the invented path
    assert ptr["endpoints_seeded"] == 1        # the origin='llm' source-seed stays SEPARATE from perceived
