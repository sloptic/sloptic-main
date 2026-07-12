"""deploy_and_grade plumbing: a failed clone is a recordable signal (not a crash), and the LLM's
identification (kind/stack/features) is copied onto the record. No network/LLM/Docker."""
import http.server
import pathlib
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from deploy_and_grade import (  # noqa: E402
    CloneError, _dead_shell_reason, _dead_url_reason, _inject_build_cache, _looks_like_client_404,
    _record_plan_meta, _surface_skeleton, _trigger_str, audit_coverage, clone)


def test_surface_skeleton_extracts_interactive_surface_not_scripts():
    dom = ('<html><body><h1>Scam Reporter</h1>'
           '<button>Add Evidence</button><a href="/login">Log in</a>'
           '<form action="/report"><input name="title"><input type="file" name="doc"></form>'
           '<script>var secret=1</script></body></html>')
    sk = _surface_skeleton(dom)
    assert "Add Evidence" in sk and "Log in" in sk           # button + link labels for the LLM to read
    assert "/report" in sk and "file:doc" in sk              # form action + the file input
    assert "Scam Reporter" in sk and "var secret" not in sk  # heading yes; script content excluded


def test_audit_coverage_is_best_effort_none_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert audit_coverage("buttons/links: ['Upload']", {"has_upload": False}) is None   # no key -> skip
    assert audit_coverage("", {}) is None                                               # empty -> nothing to audit


def test_looks_like_client_404_detects_spa_not_found_shell():
    # a SPA that answers 200 but RENDERS 'page not found' (the LifeLine case) — scripts stripped so an
    # inline route-name string can't false-match; a real rendered app is not flagged
    shell = ('<div id="root"><script>var r="/home"; function nf(){}</script>'
             '<h1>404</h1><p>Page Not Found</p><p>The page "" could not be found in this application.</p></div>')
    assert _looks_like_client_404(shell) is True
    real = '<div id="root"><h1>LifeLine</h1><nav>Home Settings</nav><main>Welcome back, log a vital</main></div>'
    assert _looks_like_client_404(real) is False


def test_dead_shell_reason_flags_placeholder_and_default_pages_but_not_a_real_app():
    assert _dead_shell_reason("<h1>Coming Soon</h1><p>we're building something great</p>").startswith("placeholder")
    assert _dead_shell_reason("<title>Welcome to nginx!</title><h1>Welcome to nginx!</h1>").startswith("placeholder")
    assert _dead_shell_reason("<div>404</div><p>Page Not Found</p>").startswith("client-side 404")
    assert _dead_shell_reason("<h1>Receipts</h1><p>Welcome back — upload a receipt to get started</p>") is None


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


def test_plan_cache_roundtrip_keyed_by_commit(tmp_path, monkeypatch):
    # computational reproducibility: a commit's SUCCESSFUL plan is frozen + reused verbatim, keyed by SHA
    import subprocess

    import deploy_and_grade as dg
    monkeypatch.setattr(dg, "_CACHE_DIR", tmp_path / "cache")
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True)
    (repo / "f").write_text("x")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
    sha = dg._git_sha(repo)
    assert sha and len(sha) == 40
    assert dg.load_cached_plan("gh/x", sha) is None                 # miss before store
    plan = {"dockerfile": "FROM scratch", "features": [{"name": "login"}], "stack": "flask"}
    dg.store_cached_plan("gh/x", sha, plan)
    assert dg.load_cached_plan("gh/x", sha) == plan                 # frozen: same commit -> the same plan
    assert dg.load_cached_plan("gh/x", "0" * 40) is None            # a different commit -> miss (keyed by SHA)
    assert dg.load_cached_plan("gh/x", None) is None                # local non-git path -> no cache


def test_profile_cache_roundtrip_keyed_by_commit(tmp_path, monkeypatch):
    # build 1b: a commit's discovered SURFACE is frozen + reconstructed as a Profile, keyed by SHA, and
    # lives in a DISTINCT file from the plan cache (so both coexist for the same commit)
    import subprocess

    import deploy_and_grade as dg
    from hacklet_runner.schema import Endpoint, Form, Profile
    monkeypatch.setattr(dg, "_CACHE_DIR", tmp_path / "cache")
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True)
    (repo / "f").write_text("x")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], check=True)
    sha = dg._git_sha(repo)
    assert dg.load_cached_profile("gh/x", sha) is None              # miss before store
    prof = Profile(base_url="http://x", routes=["/", "/login"],
                   forms=[Form(action="/login", method="post", fields=["u", "p"])],
                   capabilities={"has_forms": True},
                   endpoints=[Endpoint(path="/api/1", raw_path="/api/{id}", baseline_status=200, kind="search")])
    dg.store_cached_profile("gh/x", sha, prof)
    assert dg.load_cached_profile("gh/x", sha) == prof             # frozen: same commit -> the same surface
    assert dg.load_cached_profile("gh/x", "0" * 40) is None        # a different commit -> miss (keyed by SHA)
    assert dg.load_cached_profile("gh/x", None) is None            # local non-git path -> no cache
    dg.store_cached_plan("gh/x", sha, {"stack": "flask"})          # the plan + surface caches share a commit
    assert dg.load_cached_plan("gh/x", sha) == {"stack": "flask"}  # but are DISTINCT files (.json vs
    assert dg.load_cached_profile("gh/x", sha) == prof             # .surface.json) -> neither clobbers the other


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
