"""sec-redirect-001 must reach the OAuth parameter name, and must guess paths under the app root.

Measured on GapBench: the probe fired on the `open-redirect` scenario and read clean on `oauth-redirect`,
which is the SAME defect behind the standard OAuth parameter. `redirect_uri` was simply absent from the
param list, so the one param name that matters most on a real login flow was never sent.

The second half is the sub-path rule again: `_REDIRECT_ENDPOINTS` are CONSTRUCTED guesses, so on an app
served at /site/app they have to be asked for at /site/app/oauth/authorize, not at the origin's apex.
"""
import http.server
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import _REDIRECT_PARAMS, open_redirect  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402

_PROBE_HOST = "hacklet-redirect-probe.example"


def _serve(vuln_path, vuln_param):
    """Redirect to `vuln_param`'s value, but ONLY at `vuln_path` and only for that one param."""
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            hits.append(parsed.path)
            q = urllib.parse.parse_qs(parsed.query)
            dest = (q.get(vuln_param) or [None])[0]
            if parsed.path == vuln_path and dest:
                self.send_response(302)
                self.send_header("Location", dest)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>ok</html>")

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, hits


def _run(vuln_path, vuln_param, landing="/", routes=("/",)):
    srv, hits = _serve(vuln_path, vuln_param)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=8.0, follow_redirects=False),
               Profile(base_url=url, landing_path=landing, routes=list(routes)), None)
    try:
        return open_redirect(ctx, type("P", (), {"probe": {}})()), dict(ctx.evidence), hits
    finally:
        ctx.client.close()
        srv.shutdown()


def test_the_oauth_parameter_name_is_covered():
    # THE GapBench miss: an authorize endpoint that trusts redirect_uri
    hit, ev, _ = _run("/oauth/authorize", "redirect_uri", routes=["/", "/oauth/authorize"])
    assert hit is True
    assert ev["vulnerable"] is True and ev["endpoint"] == "/oauth/authorize"
    assert _PROBE_HOST in ev["repro"]["matched"]


def test_the_established_parameter_names_still_fire():
    for param in ("next", "url", "redirect", "return", "dest", "continue", "to", "r"):
        assert _run("/go", param, routes=["/", "/go"])[0] is True, param


def test_the_other_added_names_fire_too():
    for param in ("redirect_url", "returnTo", "return_url", "callback_url"):
        assert _run("/login", param, routes=["/", "/login"])[0] is True, param


def test_an_app_that_never_redirects_off_host_reads_clean():
    hit, ev, _ = _run("/nowhere", "next", routes=["/", "/oauth/authorize", "/login"])
    assert hit is False and ev["vulnerable"] is False


def test_a_same_host_redirect_is_not_an_open_redirect():
    # THE precision rule: an app that accepts the param but bounces you to its OWN /home is behaving
    # correctly. Only a Location whose host became our foreign probe host is a finding.
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "/home")     # ignores the attacker's value entirely
            self.end_headers()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=8.0, follow_redirects=False),
               Profile(base_url=url, landing_path="/", routes=["/", "/login", "/oauth/authorize"]), None)
    try:
        assert open_redirect(ctx, type("P", (), {"probe": {}})()) is False
        assert ctx.evidence["vulnerable"] is False
    finally:
        ctx.client.close()
        srv.shutdown()


def test_constructed_guesses_are_asked_for_under_the_app_root():
    # the sub-path rule: /oauth/authorize is a GUESS, so on a sub-path app it must be probed under it
    hit, ev, hits = _run("/site/app/oauth/authorize", "redirect_uri",
                         landing="/site/app", routes=["/site/app/"])
    assert hit is True and ev["endpoint"] == "/site/app/oauth/authorize"
    assert "/oauth/authorize" not in hits, "guessed the apex, which is a different app on a shared host"


def test_a_root_served_app_is_unaffected_by_the_rebasing():
    _hit, _ev, hits = _run("/nowhere", "next", landing="/", routes=["/"])
    assert "/oauth/authorize" in hits and "/sso" in hits


def test_redirect_uri_is_actually_in_the_param_list():
    # a one-word regression that costs an entire vulnerability class on every OAuth app
    assert "redirect_uri" in _REDIRECT_PARAMS
