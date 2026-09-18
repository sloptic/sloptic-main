"""The 404-shell gate's RENDER layer: a title-only / unhydrated SPA entry is classified render_state 'empty'
and excluded from the curve, without a dead verdict.

A parked or broken SPA serves an index shell that its JS never fills, so HTTP-level checks see a 200 and the
grade collects only the header tax on the empty page (idea-forge-web scored exactly 12.5 this way, with 0
forms / 0 endpoints / 0 inputs). Only the RENDERED DOM separates it from a real one-page app: idea-forge-web
renders its <title> "Idea Forge" (10 visible chars) and nothing else, while envi-seven, a real one-page app,
renders 514 chars of real copy. This is a probabilistic shell CLASSIFICATION (a slow-hydrating real SPA can
render short too), so it excludes the record like a Streamlit canvas shell -- never a confident dead-url DNF.
"""
import http.server
import threading

import pytest

from sloptic.discovery import discover, _render_visible_text, _EMPTY_RENDER_MAX_CHARS
from sloptic.eligibility import is_shell_only


def _server(body: bytes):
    """Serve `body` at "/" and 404 every other path -- so a probed common path or the catch-all ghost does not
    spuriously look like real surface (the handler that answered 200 for everything planted phantom routes)."""
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.split("?")[0] != "/":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _render_returning(dom: str):
    """A fake browser render: returns `dom` for the entry path, and never sets a Streamlit render_state
    (leaving it None, the non-canvas case the empty-shell detection keys on)."""
    def _r(base_url, paths, headers=None, net_sink=None, script_sink=None, meta_sink=None, **kw):
        return {paths[0]: dom}
    return _r


# --- the discriminator: rendered visible text -------------------------------------------------------------

def test_render_visible_text_measures_only_painted_text():
    title_only = "<html><head><title>Idea Forge</title></head><body><div id=root></div></body></html>"
    assert _render_visible_text(title_only) == "Idea Forge"
    assert len(_render_visible_text(title_only)) < _EMPTY_RENDER_MAX_CHARS      # 10 chars -> fires
    real = ("<html><head><title>WasteWise+</title></head><body><h1>WasteWise+</h1>"
            "<p>Type any household item to learn its disposal.</p></body></html>")
    assert len(_render_visible_text(real)) >= _EMPTY_RENDER_MAX_CHARS           # real copy -> spared
    # <script>/<style> bodies never count as painted text (they would false-match as content)
    noisy = "<html><body><script>var x='lots and lots of code here that is not visible'</script>Hi</body></html>"
    assert _render_visible_text(noisy) == "Hi"


# --- the detection, driven through discover() -------------------------------------------------------------

def test_a_title_only_entry_is_classified_empty():
    srv, origin = _server(b"<html><head><title>Idea Forge</title></head><body></body></html>")
    try:
        prof = discover(origin, render=_render_returning(
            "<html><head><title>Idea Forge</title></head><body><div id=root></div></body></html>"))
        assert prof.render_state == "empty"
        assert is_shell_only({"observed_surface": {"render_state": prof.render_state}})
    finally:
        srv.shutdown()


def test_a_real_one_page_render_is_not_classified_empty():
    srv, origin = _server(b"<html><head><title>WasteWise</title></head><body></body></html>")
    try:
        prof = discover(origin, render=_render_returning(
            "<html><head><title>WasteWise+</title></head><body><h1>WasteWise+</h1>"
            "<p>Type any household item to learn its correct disposal and impact.</p></body></html>"))
        assert prof.render_state != "empty"       # 514-class real copy -> a normal grade, stays in the curve
        assert not is_shell_only({"observed_surface": {"render_state": prof.render_state}})
    finally:
        srv.shutdown()


def test_captured_surface_spares_a_short_render():
    # the guard: even a near-empty entry render is NOT classified empty if the crawl captured real surface
    # (a form here) -- that is an SSR/hybrid app with a thin homepage, not a parked shell.
    srv, origin = _server(
        b"<html><body><form action='/login' method='post'><input name='pw' type='password'>"
        b"<button type='submit'>Sign in</button></form></body></html>")
    try:
        prof = discover(origin, render=_render_returning(
            "<html><head><title>App</title></head><body></body></html>"))   # title-only render, but a form exists
        assert prof.render_state != "empty"
        assert prof.forms or prof.endpoints                                  # real surface was captured -> spared
    finally:
        srv.shutdown()


def test_empty_state_excludes_on_any_host_not_just_streamlit():
    # is_shell_only keys on the state, so 'empty' excludes regardless of platform (unlike the legacy
    # Streamlit-only fallback), and a 'rendered' grade still counts.
    assert is_shell_only({"platform": {"host_platform": "vercel"}, "observed_surface": {"render_state": "empty"}})
    assert not is_shell_only({"platform": {"host_platform": "vercel"}, "observed_surface": {"render_state": "rendered"}})
