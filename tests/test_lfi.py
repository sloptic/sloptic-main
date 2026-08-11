"""Path traversal / LFI — the filename param serves a system file (absolute / ../ / URL-encoded /
null-byte), detected by the file's content signature; a whitelisting app stays clean."""
import http.server
import threading
import urllib.parse
from urllib.parse import parse_qs, urlparse

import pytest

from sloptic.probes import path_traversal
from sloptic.schema import Endpoint, Profile

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _include(page: str) -> str:
    """A real file include RESOLVES the path: only a traversal (../ or an absolute path or a php:// wrapper)
    escapes to a system file. A bare relative filename (etc/passwd) resolves locally and does NOT -- which is
    exactly the premise the paired canary leans on. (The old mock substring-matched, so it could not tell a
    traversal from a bare literal and behaved like a reflector.)"""
    s = urllib.parse.unquote(page).split("\x00")[0]
    traverses = ".." in s or s.startswith("/") or ":\\" in s or s.startswith("php://")
    if traverses and "etc/passwd" in s:
        return _PASSWD
    if traverses and "win.ini" in s.lower():
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
        elif u.path == "/reflect":                         # reflector / LLM-hallucinator: emits the passwd
            #  signature whenever it merely SEES the filename token, with NO real traversal -> the paired canary
            #  (the bare filename) reproduces it -> the fire is suppressed as not causally specific to traversal.
            self._send("<html>%s</html>" % (_PASSWD if "passwd" in page.lower() else "no match"))
        elif u.path == "/safe":                            # whitelist -> never reads an arbitrary file
            self._send("<html>%s</html>" % ("home page" if page in ("home", "about") else "not allowed"))
        elif u.path == "/jsbundle":                        # the app's OWN minified JS asset (never a system file)
            b = b'var x={root:1};t=":0:0:";p="root:x:0:0:root:/root:/bin/bash";fn=function(){return x.root};'
            self.send_response(200); self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        elif u.path.startswith("/api/"):                   # a catch-all: EVERY path under /api includes the param,
            #  so a nonexistent sibling answers identically -> the liveness gate must suppress the phantom.
            self._send("<html>%s</html>" % _include(page))
        else:
            self._send("ok")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _flaky_lfi_handler():
    """A real endpoint that returns the passwd content the FIRST time a traversal reaches it, then clean content
    thereafter -- a flaky include / an LLM in the path that hallucinates once. The detect send matches; the
    determinism-gate resend does not reproduce -> suppressed."""
    state = {"n": 0}

    class H(http.server.BaseHTTPRequestHandler):
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
            if u.path != "/flaky":
                self._send("ok")                 # distinct phantom -> the liveness gate sees a real endpoint
                return
            page = parse_qs(u.query).get("page", [""])[0]
            s = urllib.parse.unquote(page).split("\x00")[0]
            hit = (".." in s or s.startswith("/") or ":\\" in s or s.startswith("php://")) and "etc/passwd" in s
            if hit:
                state["n"] += 1
            self._send("<html>%s</html>" % (_PASSWD if hit and state["n"] == 1 else "default content"))
    return H


@pytest.fixture
def flaky():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _flaky_lfi_handler())
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


def test_lfi_suppresses_reflected_passwd(app):
    # /reflect returns the passwd signature for the bare filename too (reflection / hallucination, no traversal);
    # the paired canary must catch that the content is not caused by the ../ and suppress the fire.
    assert path_traversal(_ctx(app, "/reflect"), _Probe()) is False


def test_lfi_suppresses_nondeterministic_read(flaky):
    # v2.0 foundation #1: the file signature appears on the detect send but not on the identical resend (flaky
    # include / one-off hallucination), so it does not reproduce and must be treated as can't-assess, not a fire.
    assert path_traversal(_ctx(flaky, "/flaky"), _Probe()) is False


def test_lfi_gated_on_catch_all_phantom(app):
    # a catch-all host serves the file for every path, so a traversal payload would "fire" on an endpoint that
    # does not exist server-side. The liveness gate compares it to a nonexistent sibling under its own prefix;
    # they answer identically, so the phantom is suppressed before injection (this also stops an LLM-fabricated passwd).
    assert path_traversal(_ctx(app, "/api/read"), _Probe()) is None


def test_lfi_na_when_no_surface(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None, "client": None, "evidence": {}})()
    assert path_traversal(ctx, _Probe()) is None


def test_lfi_skips_apps_own_js_bundle(app):
    # a JS bundle that happens to contain a passwd-like string must NOT phantom-fire (the arcgis-core-*.js
    # regression: a real minified asset false-fired at penalty 40). Guarded by content-type (js/css skipped).
    assert path_traversal(_ctx(app, "/jsbundle"), _Probe()) is False


def test_lfi_signature_rejects_minified_noise():
    # the old `root:.*?:0:0:` matched unrelated tokens across ONE minified line; the tight form must not.
    from sloptic.probes import _LFI_SIG
    assert _LFI_SIG.search('a.root:{x:1};q=":0:0:";m=[0,0,0];fn=function(){return root}') is None
    assert _LFI_SIG.search("root:x:0:0:root:/root:/bin/bash")        # real passwd still detected
    assert _LFI_SIG.search("root::0:0:root:/root:/bin/sh")           # empty-password variant too
