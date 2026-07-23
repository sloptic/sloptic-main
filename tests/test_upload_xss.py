"""Stored XSS via file upload (sec-upload-002). An app that serves an uploaded .html/.svg back with an
EXECUTABLE content-type INLINE runs attacker script in its own origin. The probe fires ONLY on
inline-executable serving; an attachment / text-plain / octet-stream response is the app defending
itself -> clean. Precision-guard (fire vs each safe serving) + CI-lock (catalog wiring)."""
import http.server
import pathlib
import re
import threading

import pytest

from hacklet_runner.catalog import load_catalog
from hacklet_runner.probes import PREDICATES, _UPLOAD_XSS_MARK, upload_stored_xss
from hacklet_runner.schema import Form, Profile

_STORE = {}                     # basename -> raw uploaded bytes (the marker rides inside)
_MODE = {"how": "inline-html"}  # how the server serves stored files back (set per test)


def _basename(body: bytes) -> str:
    m = re.search(rb'filename="([^"]*)"', body)
    return (m.group(1).decode() if m else "").split("\x00")[0].split("/")[-1]


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _raw(self, b, ctype, disposition=None):
        b = b.encode() if isinstance(b, str) else b
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        name = _basename(raw)
        _STORE[name] = raw                       # store verbatim; the uploaded marker is embedded
        self._raw("saved to /f/%s" % name, "text/plain; charset=utf-8")

    def do_GET(self):
        if not self.path.startswith("/f/"):
            self._raw("ok", "text/plain")
            return
        data = _STORE.get(self.path[3:])
        if data is None:
            self._raw("not found", "text/plain")
            return
        how = _MODE["how"]                        # one serving policy for the whole server, set per test
        if how == "inline-html":
            self._raw(data, "text/html; charset=utf-8")
        elif how == "inline-svg":
            self._raw(data, "image/svg+xml")
        elif how == "attachment":
            self._raw(data, "text/html", disposition='attachment; filename="f"')
        elif how == "plain":
            self._raw(data, "text/plain; charset=utf-8")
        else:                                     # octet
            self._raw(data, "application/octet-stream")


@pytest.fixture
def app():
    _STORE.clear()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Probe:
    probe = {}


def _ctx(url, action="/upload"):
    form = Form(action=action, method="post", fields=["file"],
                enctype="multipart/form-data", file_fields=["file"])
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url, forms=[form]),
                          "headers": None, "client": None, "evidence": {}})()


def test_fires_when_uploaded_active_content_served_inline_html(app):
    _MODE["how"] = "inline-html"
    ctx = _ctx(app)
    assert upload_stored_xss(ctx, _Probe()) is True
    assert ctx.evidence.get("stored_xss") is True
    repro = ctx.evidence.get("repro")                 # (A) the deciding GET is captured, replayable in Burp
    assert repro and repro["method"] == "GET" and "hlxss" in repro["url"]


def test_fires_when_served_as_inline_svg(app):
    _MODE["how"] = "inline-svg"          # image/svg+xml opened top-level executes its <script>
    assert upload_stored_xss(_ctx(app), _Probe()) is True


def test_clean_when_forced_to_download(app):
    _MODE["how"] = "attachment"          # Content-Disposition: attachment -> never executes in-origin
    assert upload_stored_xss(_ctx(app), _Probe()) is False


def test_clean_when_served_text_plain(app):
    _MODE["how"] = "plain"
    assert upload_stored_xss(_ctx(app), _Probe()) is False


def test_clean_when_served_octet_stream(app):
    _MODE["how"] = "octet"               # application/octet-stream is inert
    assert upload_stored_xss(_ctx(app), _Probe()) is False


def test_na_without_upload_form(app):
    ctx = type("C", (), {"base_url": app, "profile": Profile(base_url=app), "headers": None,
                         "client": None, "evidence": {}})()
    assert upload_stored_xss(ctx, _Probe()) is None


def test_marker_is_distinct_from_the_rce_probe_marker():
    # the two upload probes must not cross-trigger on each other's payloads
    from hacklet_runner.probes import _UPLOAD_MARK
    assert _UPLOAD_XSS_MARK != _UPLOAD_MARK


def test_catalog_wires_sec_upload_002_to_a_registered_predicate():
    cat = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
    probe = next((p for p in cat if p.id == "sec-upload-002"), None)
    assert probe is not None, "sec-upload-002 missing from the catalog"
    assert probe.probe.get("predicate") in PREDICATES, "sec-upload-002 predicate not registered in PREDICATES"
    assert probe.penalty == 35
