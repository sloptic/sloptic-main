"""sec-exposure-007: sensitive files beyond the .env/.git/.aws trio.

Guessing the wrong filename is indistinguishable from safety. Measured on GapBench: `config-leak` serves
`config.json`, `terraform-state-leak` serves `terraform.tfstate`, `docker-config-leak` serves registry auth —
8 of 10 selected probes APPLIED on those scenarios and every one still read clean, because we only ever asked
for `.env`, `.git/*` and `.aws/credentials`.

The precision rule this pins: a path is never a finding on its own. A catch-all host answers 200 for
everything, and a public frontend `config.json` is entirely normal, so the BODY has to prove it. A config only
fires when the secret scanner finds a real secret inside.
"""
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import exposed_sensitive_file  # noqa: E402
from hacklet_runner.schema import Profile  # noqa: E402

_TFSTATE = json.dumps({"version": 4, "terraform_version": "1.7.2",
                       "resources": [{"type": "aws_db_instance", "instances": [{"attributes":
                                     {"password": "hunter2-real-db-password"}}]}]})
_SQL = "-- MySQL dump 10.13\nCREATE TABLE users (id INT, email TEXT);\nINSERT INTO users VALUES (1,'a@b.c');"
_DOCKER = json.dumps({"auths": {"registry.example.com": {"auth": "dXNlcjpwYXNzd29yZA=="}}})
_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
# a config that carries a REAL secret -> a finding. NB not AWS's documented AKIAIOSFODNN7EXAMPLE: the scanner
# rejects any value containing "example" as a placeholder, which is correct and cost me a test.
_CONFIG_SECRET = 'window.__CFG__ = {apiKey: "AKIAQ7Z3XK2LMNBVCXZA", dbPassword: "pR9x-Kt2vLm8QwEr"};'
# a public frontend config: base urls and flags, no credential -> must NOT fire
_CONFIG_PUBLIC = 'window.__CFG__ = {apiBase: "https://api.example.com", darkMode: true, version: "1.4.0"};'


def _serve(files, catch_all=False):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            body, ctype = files.get(path), "text/plain"
            if body is None and catch_all:
                body, ctype = "<!doctype html><html><body>app shell</body></html>", "text/html"
            if body is None:
                self.send_response(404); self.end_headers(); self.wfile.write(b"nope"); return
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(files, catch_all=False, landing="/"):
    srv = _serve(files, catch_all)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _Ctx(url, make_client(url, None, timeout=8.0, follow_redirects=True),
               Profile(base_url=url, landing_path=landing, routes=["/"]), None)
    try:
        return exposed_sensitive_file(ctx, type("P", (), {"probe": {}})()), dict(ctx.evidence)
    finally:
        ctx.client.close()
        srv.shutdown()


def test_fires_on_each_sensitive_file_class():
    for path, body in (("/terraform.tfstate", _TFSTATE), ("/dump.sql", _SQL),
                       ("/.dockercfg", _DOCKER), ("/id_rsa", _KEY),
                       ("/.npmrc", "//registry.npmjs.org/:_authToken=npm_realtokenvalue123")):
        verdict, ev = _run({path: body})
        assert verdict is True, path
        assert ev["path"] == path and ev["exposed"] is True
        assert ev["repro"]["url"].endswith(path)          # auditable: the exact request that proved it


def test_a_config_fires_only_when_it_carries_a_real_secret():
    hit, ev = _run({"/config.js": _CONFIG_SECRET})
    assert hit is True and ev["path"] == "/config.js"
    # THE precision rule: a public frontend config (base urls, flags, a version) is normal, not a leak
    clean, ev2 = _run({"/config.js": _CONFIG_PUBLIC})
    assert clean is False and ev2["exposed"] is False


def test_a_catch_all_host_serving_its_shell_everywhere_reads_clean():
    # every path answers 200 with the SPA shell. Existence must never be the evidence, or this host would
    # report every sensitive file at once.
    verdict, ev = _run({}, catch_all=True)
    assert verdict is False and ev["exposed"] is False


def test_a_wrong_content_type_or_html_body_is_not_a_file():
    assert _run({"/terraform.tfstate": "<html><body>not found</body></html>"})[0] is False
    assert _run({"/dump.sql": "welcome to our site, no sql here"})[0] is False


def test_nothing_served_reads_clean_not_na():
    verdict, ev = _run({"/": "hello"})
    assert verdict is False and ev["paths_checked"] > 10      # it looked, and found nothing


def test_a_sub_path_deployment_is_probed_under_its_own_root():
    # the bug that made this probe necessary in the first place: a sub-path app's files live under its landing
    # path, and probing the origin reports clean on an app that is leaking
    verdict, ev = _run({"/site/app/terraform.tfstate": _TFSTATE}, landing="/site/app")
    assert verdict is True and ev["path"] == "/terraform.tfstate"
    assert "/site/app/terraform.tfstate" in ev["repro"]["url"]


def test_a_path_discovery_already_found_is_left_to_the_routes_probes():
    # ONE leak must not be billed twice under two categories. /config.js on the vulnerable reference app is
    # already sec-secrets-001's finding (it scans discovered routes), and firing here as well moved the
    # calibration anchor from 664 to 673. What remains is precisely this probe's value: the files discovery
    # never sees.
    srv = _serve({"/config.js": _CONFIG_SECRET})
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        for routes, expected in ((["/", "/config.js"], False),   # discovered -> the routes probes own it
                                 (["/"], True)):                 # missed by discovery -> ours to find
            ctx = _Ctx(url, make_client(url, None, timeout=8.0, follow_redirects=True),
                       Profile(base_url=url, routes=routes), None)
            try:
                assert exposed_sensitive_file(ctx, type("P", (), {"probe": {}})()) is expected, routes
            finally:
                ctx.client.close()
    finally:
        srv.shutdown()
