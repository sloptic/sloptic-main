"""--trace: net.start_trace + the make_client response hook record EVERY request, tagged with the probe now
running (net.set_trace_probe), so a clean/N/A probe's payloads+endpoints are inspectable — not just findings.
Disabled by default (no sink -> no hook -> zero overhead). Bounded so a fan-out probe can't grow it unbounded."""
import http.server
import threading

import pytest

from hacklet_runner import net
from hacklet_runner.net import make_client, set_trace_probe, start_trace


class _Echo(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _ok(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))   # drain the body so keep-alive is happy
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST = lambda self: self._ok()


@pytest.fixture(autouse=True)
def _reset_trace():
    # ContextVars persist within a process/thread; reset around every test so tracing never leaks between them
    start_trace(False)
    set_trace_probe("")
    yield
    start_trace(False)
    set_trace_probe("")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def test_records_every_request_tagged_by_probe(app):
    sink = start_trace(True)
    set_trace_probe("sec-demo-001")
    with make_client(app, None, timeout=5.0) as c:
        c.get("/api/items")
        c.post("/api/items", json={"x": 1})
    assert len(sink) == 2
    assert {e["probe"] for e in sink} == {"sec-demo-001"}
    assert {e["method"] for e in sink} == {"GET", "POST"}
    post = next(e for e in sink if e["method"] == "POST")
    assert '"x"' in (post["body"] or "") and post["status"] == 200 and "/api/items" in post["url"]


def test_probe_tag_switches_between_probes(app):
    sink = start_trace(True)
    set_trace_probe("probe-a")
    with make_client(app, None, timeout=5.0) as c:
        c.get("/a")
    set_trace_probe("probe-b")
    with make_client(app, None, timeout=5.0) as c:
        c.get("/b")
    by_probe = {e["probe"]: e["url"] for e in sink}
    assert by_probe["probe-a"].endswith("/a") and by_probe["probe-b"].endswith("/b")


def test_no_recording_when_trace_disabled(app):
    sink = start_trace(True)
    set_trace_probe("p")
    with make_client(app, None, timeout=5.0) as c:
        c.get("/one")
    assert len(sink) == 1
    start_trace(False)                       # disable -> the ContextVar sink is cleared
    with make_client(app, None, timeout=5.0) as c:
        c.get("/two")
    assert len(sink) == 1                     # the post-disable request was NOT recorded


def test_trace_is_bounded(app, monkeypatch):
    monkeypatch.setattr(net, "_TRACE_CAP", 3)
    sink = start_trace(True)
    set_trace_probe("flood")
    with make_client(app, None, timeout=5.0) as c:
        for _ in range(6):
            c.get("/x")
    assert len(sink) == 3                      # global backstop: capped, not unbounded


def test_per_probe_cap_keeps_later_probes_from_being_starved(app, monkeypatch):
    # the bug this fixes: a global cap let a fan-out probe eat the whole budget, zeroing every later probe
    monkeypatch.setattr(net, "_TRACE_PER_PROBE_CAP", 2)
    sink = start_trace(True)
    set_trace_probe("fanout")                  # a high-fan-out probe (cmdi/lfi) runs first
    with make_client(app, None, timeout=5.0) as c:
        for _ in range(6):
            c.get("/x")
    set_trace_probe("later")                   # a probe that runs AFTER it (e.g. sec-upload-002)
    with make_client(app, None, timeout=5.0) as c:
        for _ in range(3):
            c.get("/y")
    from collections import Counter
    counts = Counter(e["probe"] for e in sink)
    assert counts["fanout"] == 2               # the fan-out is capped to a sample
    assert counts["later"] == 2                # and the later probe is STILL recorded, not starved to 0


def test_body_is_truncated(app, monkeypatch):
    monkeypatch.setattr(net, "_TRACE_BODY_CAP", 16)
    sink = start_trace(True)
    set_trace_probe("big")
    with make_client(app, None, timeout=5.0) as c:
        c.post("/x", content=b"A" * 200)
    assert sink and "+" in sink[0]["body"] and len(sink[0]["body"]) < 60   # truncated with a "+N bytes" marker
