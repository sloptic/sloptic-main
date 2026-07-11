"""Browser-harness discovery — the rendered DOM exposes a client-rendered form a static crawl
misses. Requires a headless browser (system Chrome on the dev box); skipped where none is available.
"""
import pathlib

import pytest

from hacklet_runner import browser
from hacklet_runner.catalog import load_catalog
from hacklet_runner.deploy import SubprocessDeployer
from hacklet_runner.discovery import discover
from hacklet_runner.pipeline import run

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFS = ROOT / "references"
CATALOG = ROOT / "catalog"

pytestmark = pytest.mark.skipif(not browser.browser_available(), reason="no headless browser")


@pytest.fixture
def spa_url():
    d = SubprocessDeployer(str(REFS / "spa" / "app.py"))
    handle = d.deploy()
    try:
        yield handle.base_url
    finally:
        d.teardown()


def test_static_discovery_misses_spa_form(spa_url):
    # the form is built by JS, so it isn't in the static HTML source
    assert discover(spa_url).capabilities["any_form_has_password"] is False


def test_browser_discovery_finds_spa_form(spa_url):
    profile = discover(spa_url, render=browser.render_routes)
    assert profile.capabilities["any_form_has_password"] is True
    assert any(f.action == "/register" and "password" in f.fields for f in profile.forms)


def test_browser_discovery_finds_subroute_form(spa_url):
    # the login <form> is painted on /login (NOT the entry page) — only multi-route rendering reaches it,
    # and its inputs are anonymous (type=email/password, no name/id) so the field names must be INFERRED
    profile = discover(spa_url, render=browser.render_routes)
    login = [f for f in profile.forms if f.action == "/session"]
    assert login and set(login[0].fields) == {"email", "password"}
    assert profile.capabilities["any_form_has_password"] is True


def test_browser_discovery_finds_formless_inputs(spa_url):
    # /upload has a bare <input type=file> + <button> with NO <form> — the SPA fetch() upload pattern
    profile = discover(spa_url, render=browser.render_routes)
    up = [f for f in profile.forms if f.file_fields]
    assert up and up[0].action == "/upload" and up[0].enctype == "multipart/form-data"
    assert profile.capabilities["any_endpoint_accepts_text_input"] is True


def test_interaction_reveals_click_gated_login_and_upload():
    # the AfroSecured/SPA-login gap: controls that only MOUNT on click (React-style) are invisible to a
    # static render; the interacting render clicks reveal-triggers and surfaces login (password) + upload
    import http.server
    import threading

    from hacklet_runner.discovery import _scan_form_inputs
    page = (
        "<!doctype html><html><body><h1>SPA</h1>"
        "<button id='lb'>Log in</button><button id='ub'>Upload evidence</button>"
        "<div id='lm'></div><div id='um'></div><script>"
        "function mk(t,a){var e=document.createElement(t);for(var k in a)e.setAttribute(k,a[k]);return e;}"
        "document.getElementById('lb').onclick=function(){var f=mk('form',{action:'/login'});"
        "f.appendChild(mk('input',{name:'email'}));f.appendChild(mk('input',{name:'password',type:'password'}));"
        "document.getElementById('lm').appendChild(f);};"
        "document.getElementById('ub').onclick=function(){"
        "document.getElementById('um').appendChild(mk('input',{name:'doc',type:'file'}));};"
        "</script></body></html>").encode("ascii")

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(page)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        static = browser.render_routes(base, ["/"], interact=False)["/"]
        live = browser.render_routes(base, ["/"], interact=True)["/"]
        assert _scan_form_inputs(static)[2] is False           # static render is blind to the gated controls
        _, files, has_pw = _scan_form_inputs(live)
        assert has_pw is True and files == ["doc"]             # interaction surfaces login + upload
    finally:
        srv.shutdown()


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


def test_dom_xss_detects_sink(serve):
    # vulnerable /dom innerHTMLs the q param (the payload executes); hardened uses textContent (safe)
    assert browser.dom_xss_executes(serve("vulnerable"), ["/dom"]) is True
    assert browser.dom_xss_executes(serve("hardened"), ["/dom"]) is False


def test_cwv_detects_slow_paint(serve):
    # vulnerable /slow injects content late (high FCP); hardened has it in the initial HTML (fast)
    slow = browser.first_contentful_paint(serve("vulnerable") + "/slow")
    assert slow is not None and slow > 1000
    fast = browser.first_contentful_paint(serve("hardened") + "/slow")
    assert fast is not None and fast < 1000


# End-to-end: the browser probes through the FULL pipeline (browser capability gate + predicate +
# scoring), not just the helper primitives above. Closes the gap where run(..., render=...) — and so
# the browser_ok gate and the median-of-N slow_first_paint predicate — was never exercised.
_BROWSER_PROBES = ("sec-domxss-001", "perf-cwv-001", "qa-console-001", "qa-a11y-001")


def _browser_run(app: str):
    catalog = [p for p in load_catalog(CATALOG) if p.id in _BROWSER_PROBES]
    return run(SubprocessDeployer(str(REFS / app / "app.py")), catalog, render=browser.render_routes)


def test_browser_pipeline_fires_on_vulnerable():
    o = _browser_run("vulnerable").by_id
    assert o["sec-domxss-001"] == "slop_detected"  # /dom innerHTMLs q -> the injected payload executes
    assert o["perf-cwv-001"] == "slop_detected"    # /slow paints late -> median FCP over the gate
    assert o["qa-console-001"] == "slop_detected"  # homepage throws an uncaught JS error on load
    assert o["qa-a11y-001"] == "slop_detected"     # missing lang + unlabeled inputs


def test_browser_pipeline_clears_on_hardened():
    o = _browser_run("hardened").by_id
    assert o["sec-domxss-001"] == "clean"          # /dom uses textContent -> no execution
    assert o["perf-cwv-001"] == "clean"            # /slow content in initial HTML -> fast FCP
    assert o["qa-console-001"] == "clean"          # no uncaught errors on load
    assert o["qa-a11y-001"] == "clean"             # lang set + every input aria-labeled


# Full-cascade contrast — colors from a <style> block + inheritance (the p's background is inherited
# from body), which only a rendered browser resolves. The static inline-style probe cannot see this.
import http.server        # noqa: E402
import threading          # noqa: E402

_LOW_CONTRAST = ("<!doctype html><html lang=en><head><title>t</title>"
                 "<style>body{background:#808080} p{color:#8a8a8a}</style></head>"
                 "<body><p>hard to read text</p></body></html>")
_HIGH_CONTRAST = ("<!doctype html><html lang=en><head><title>t</title>"
                  "<style>body{background:#ffffff} p{color:#111111}</style></head>"
                  "<body><p>easy to read text</p></body></html>")


def _serve_html(body):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_contrast_detects_cascade_low_contrast():
    srv = _serve_html(_LOW_CONTRAST)
    try:
        assert browser.contrast_violations("http://127.0.0.1:%d/" % srv.server_address[1]) > 0
    finally:
        srv.shutdown()


def test_contrast_clean_on_high_contrast():
    srv = _serve_html(_HIGH_CONTRAST)
    try:
        assert browser.contrast_violations("http://127.0.0.1:%d/" % srv.server_address[1]) == 0
    finally:
        srv.shutdown()


# --- Core Web Vitals (perf-cwv-002 / slow_core_web_vitals) --------------------------------
from hacklet_runner.net import make_client        # noqa: E402
from hacklet_runner.probes import slow_core_web_vitals  # noqa: E402

# an 800ms synchronous busy-loop blocks the main thread on load -> Total Blocking Time well past 600ms
_CWV_POOR = ("<!doctype html><html lang=en><head><title>t</title></head><body><h1>slow</h1>"
             "<script>const t0=performance.now();while(performance.now()-t0<800){}</script></body></html>")
_CWV_CLEAN = "<!doctype html><html lang=en><head><title>t</title></head><body><h1>fast</h1></body></html>"


class _CwvProbe:
    probe = {"target": "/", "samples": 2}


def _cwv_ctx(url):
    return type("C", (), {"base_url": url, "headers": None, "client": make_client(url), "evidence": {}})()


def test_cwv_fires_on_poor_web_vitals():
    srv = _serve_html(_CWV_POOR)
    try:
        ctx = _cwv_ctx("http://127.0.0.1:%d/" % srv.server_address[1])
        assert slow_core_web_vitals(ctx, _CwvProbe()) is True
        assert "TBT" in ctx.evidence["failed"]        # main-thread block is the metric that trips
    finally:
        srv.shutdown()


def test_cwv_clean_on_fast_page():
    srv = _serve_html(_CWV_CLEAN)
    try:
        ctx = _cwv_ctx("http://127.0.0.1:%d/" % srv.server_address[1])
        assert slow_core_web_vitals(ctx, _CwvProbe()) is False
        assert ctx.evidence["failed"] == []
    finally:
        srv.shutdown()
