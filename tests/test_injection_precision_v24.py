"""The three precision gates the v24 discovery-run audit earned (5 TP / 6 FP on the classics).

Each test pins the exact FP mechanism observed in multihacksv24.jsonl, and each has a recall twin so a gate
cannot silently become a suppression: mesh-3d (all payloads answered byte-identically), cognify (an LLM SSE
stream whose response size varied arbitrarily), and the flaky-edge-cache shape that passed three coin flips
at grade time.
"""
import httpx
import pytest

import http.server
import threading
from urllib.parse import urlparse

from sloptic.probes import _tech_boolean, csrf_missing, host_header_injection
from sloptic.schema import Form, Profile

_T = "1' OR '1'='1' -- "
_F = "1' OR '1'='2' -- "


# ── csrf: a cross-host redirect is a bounce, not an acceptance ──────────────────────────────────────────
class _Serve:
    def __init__(self, cls):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.srv, self.port = srv, srv.server_address[1]

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def stop(self):
        self.srv.shutdown()


def _send(self, code, body=b"ok", loc=None):
    self.send_response(code)
    if loc:
        self.send_header("Location", loc)
    self.send_header("Content-Type", "text/html")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)


def _csrf_ctx(url):
    return type("C", (), {"base_url": url, "headers": {"Cookie": "sid=abc"}, "evidence": {},
                          "profile": Profile(base_url=url, forms=[Form(action="/pay", method="post",
                                                                      fields=["amount"])]),
                          "client": None})()


def _base(handlers):
    return type("_H", (http.server.BaseHTTPRequestHandler,),
                {**handlers, "log_message": lambda *a: None})


def _run_csrf(cls):
    s = _Serve(cls)
    try:
        return csrf_missing(_csrf_ctx(s.url), type("P", (), {"probe": {}})())
    finally:
        s.stop()


def test_csrf_cross_host_redirect_is_a_bounce_not_an_acceptance():
    """The governancex FP: a cross-site POST answered 307 to the site's own canonical domain — nothing
    processed it, and the v24 corpus scored it 45."""
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        if urlparse(self.path).path == "/pay":
            self._send(307, loc="https://canonical.example/")
        else:
            self._send(404, b"nf")                    # a real app 404s unknown paths (liveness sentinel)
    def do_GET(self):
        self._send(200, b"page " + urlparse(self.path).path.encode())
    cls = _base({"_send": _send, "do_POST": do_POST, "do_GET": do_GET})
    assert _run_csrf(cls) is not True


def test_csrf_same_host_redirect_to_the_next_step_is_still_an_acceptance():
    """Recall twin: a same-host 302 that is NOT login/auth (the next wizard step) means the cross-site POST
    WAS processed — that is the real finding."""
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        if urlparse(self.path).path == "/pay":
            self._send(302, loc="/pay/next-step")     # the wizard's next step: the POST WAS processed
        else:
            self._send(404, b"nf")
    def do_GET(self):
        self._send(200, b"page " + urlparse(self.path).path.encode())
    cls = _base({"_send": _send, "do_POST": do_POST, "do_GET": do_GET})
    assert _run_csrf(cls) is True


def test_csrf_records_the_redirect_location_for_audit():
    """A 3xx fire without its Location is unauditable: the dayli record said only `status: 302`, and the
    same status is a login rejection without a session and a wizard acceptance with one."""
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        if urlparse(self.path).path == "/pay":
            self._send(302, loc="/pay/next-step")
        else:
            self._send(404, b"nf")
    def do_GET(self):
        self._send(200, b"page " + urlparse(self.path).path.encode())
    cls = _base({"_send": _send, "do_POST": do_POST, "do_GET": do_GET})
    s = _Serve(cls)
    try:
        ctx = _csrf_ctx(s.url)
        csrf_missing(ctx, type("P", (), {"probe": {}})())
        assert ctx.evidence.get("redirect_location") == "/pay/next-step"
    finally:
        s.stop()
