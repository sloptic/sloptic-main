"""Path traversal / LFI — the filename param serves a system file (absolute / ../ / URL-encoded /
null-byte), detected by the file's content signature; a whitelisting app stays clean."""
import http.server
import threading
import urllib.parse
from urllib.parse import parse_qs, urlparse

import pytest

from hacklet_runner.probes import path_traversal
from hacklet_runner.schema import Endpoint, Profile

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _include(page: str) -> str:
    """Naive file include: decodes %-encoding, honors null-byte truncation, and 'reads' the file."""
    s = urllib.parse.unquote(page).split("\x00")[0]
    if "etc/passwd" in s:
        return _PASSWD
    if "win.ini" in s.lower():
        return "; for 16-bit app support\n[fonts]\n[extensions]\n"
    return "default content"


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        page = parse_qs(u.query).get("page", [""])[0]
        if u.path == "/vuln":                              # includes whatever the param points at
            self._send("<html>%s</html>" % _include(page))
        elif u.path == "/safe":                            # whitelist -> never reads an arbitrary file
            self._send("<html>%s</html>" % ("home page" if page in ("home", "about") else "not allowed"))
        elif u.path == "/jsbundle":                        # the app's OWN minified JS asset (never a system file)
            b = b'var x={root:1};t=":0:0:";p="root:x:0:0:root:/root:/bin/bash";fn=function(){return x.root};'
            self.send_response(200); self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        else:
            self._send("ok")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {"max_attempts": 200}


def _ctx(url, path):
    prof = Profile(base_url=url, endpoints=[Endpoint(path=path, method="get", query_params=["page"], raw_path=path)])
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def test_lfi_reads_system_file(app):
    assert path_traversal(_ctx(app, "/vuln"), _Probe()) is True


def test_lfi_clean_on_whitelisting_app(app):
    assert path_traversal(_ctx(app, "/safe"), _Probe()) is False


def test_lfi_na_when_no_surface(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert path_traversal(ctx, _Probe()) is None


def test_lfi_skips_apps_own_js_bundle(app):
    # a JS bundle that happens to contain a passwd-like string must NOT phantom-fire (the arcgis-core-*.js
    # regression: a real minified asset false-fired at penalty 40). Guarded by content-type (js/css skipped).
    assert path_traversal(_ctx(app, "/jsbundle"), _Probe()) is False


def test_lfi_signature_rejects_minified_noise():
    # the old `root:.*?:0:0:` matched unrelated tokens across ONE minified line; the tight form must not.
    from hacklet_runner.probes import _LFI_SIG
    assert _LFI_SIG.search('a.root:{x:1};q=":0:0:";m=[0,0,0];fn=function(){return root}') is None
    assert _LFI_SIG.search("root:x:0:0:root:/root:/bin/bash")        # real passwd still detected
    assert _LFI_SIG.search("root::0:0:root:/root:/bin/sh")           # empty-password variant too
