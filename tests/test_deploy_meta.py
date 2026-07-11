"""deploy_and_grade plumbing: a failed clone is a recordable signal (not a crash), and the LLM's
identification (kind/stack/features) is copied onto the record. No network/LLM/Docker."""
import http.server
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from deploy_and_grade import (  # noqa: E402
    CloneError, _dead_url_reason, _inject_build_cache, _record_plan_meta, _trigger_str, clone)


class _LivenessHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/gone":
            self.send_response(404); self.end_headers(); self.wfile.write(b"nope"); return
        self.send_response(200); self.end_headers()
        self.wfile.write(b"There isn't a GitHub Pages site here"
                         if self.path == "/placeholder" else b"<h1>hello app</h1>")

    def log_message(self, *a):
        pass


def test_dead_url_reason_classifies_live_404_and_placeholder():
    # --url liveness gate: a real page is gradeable (None); a 404 entry or a 200 placeholder shell is dead
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LivenessHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        assert _dead_url_reason(base + "/live") is None
        assert _dead_url_reason(base + "/gone") == "HTTP 404"
        assert _dead_url_reason(base + "/placeholder").startswith("host placeholder")
    finally:
        srv.shutdown()


def test_trigger_str_surfaces_the_payload_but_not_config_checks():
    # a payload-bearing finding shows WHAT triggered it; a config check (headers) has none -> no line
    assert _trigger_str({"via": "malformed-json", "target": "/api/chat", "payload": "{not valid json"}) \
        == "@/api/chat  payload={not valid json"
    assert "technique=error" in _trigger_str({"technique": "error", "where": "query", "param": "q"})
    assert _trigger_str({"status": 200, "elapsed_ms": 17}) == ""      # header/perf check -> no trigger line


def test_inject_build_cache_mounts_pip_and_strips_no_cache_dir():
    # the slow step (pip download) gets a persistent cache mount; --no-cache-dir (which defeats it) is dropped
    out = _inject_build_cache("FROM python:3.11-slim\nRUN pip install --no-cache-dir -r requirements.txt\n")
    assert "RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt" in out
    assert "--no-cache-dir" not in out


def test_inject_build_cache_mounts_npm_and_leaves_plain_runs_untouched():
    out = _inject_build_cache("RUN apt-get update && apt-get install -y ffmpeg\nRUN npm ci\n")
    assert "RUN apt-get update && apt-get install -y ffmpeg" in out          # non-install RUN untouched
    assert "RUN --mount=type=cache,target=/root/.npm npm ci" in out


def test_inject_build_cache_handles_continuation_and_is_idempotent():
    # pip on a CONTINUATION line still mounts the RUN token; a second pass must not double-inject
    df = "RUN set -eux && \\\n    pip3 install -r req.txt\n"
    once = _inject_build_cache(df)
    assert once.startswith("RUN --mount=type=cache,target=/root/.cache/pip set -eux && \\")
    assert "    pip3 install -r req.txt" in once                             # continuation preserved as-is
    assert _inject_build_cache(once) == once                                 # idempotent (guarded on --mount=)


def test_clone_raises_cloneerror_instead_of_crashing():
    # a bad repo must raise CloneError (caught + recorded in main), not an uncaught TimeoutExpired/SystemExit
    with pytest.raises(CloneError):
        clone("file:///nonexistent/hl-does-not-exist.git", timeout=20)


def test_record_plan_meta_copies_kind_stack_and_features():
    result = {}
    _record_plan_meta(result, {
        "app_kind": "mobile", "web_gradeable": False, "stack": "iOS SwiftUI app",
        "stack_profile": {"framework": "SwiftUI"}, "expected_surface": {"login": False},
        "features": [{"name": "scan", "kind": "other"}], "dockerfile": "IGNORED"})
    assert result["app_kind"] == "mobile" and result["web_gradeable"] is False
    assert result["features"] == [{"name": "scan", "kind": "other"}]
    assert result["stack_profile"] == {"framework": "SwiftUI"}
    assert "dockerfile" not in result       # only the identification fields ride onto the record
