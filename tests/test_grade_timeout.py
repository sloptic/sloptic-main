"""The grading phase is HARD-bounded: a pathological target (every route hangs the socket) must not be
able to stall a batch. Proves the SIGALRM cap in deploy_and_grade.grade() actually interrupts the hang.
"""
import http.server
import pathlib
import socketserver
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from deploy_and_grade import GradeTimeout, grade  # noqa: E402


class _Hang(http.server.BaseHTTPRequestHandler):
    """Health check ('/') answers fast so the app is 'up'; every other path hangs — the exact shape of
    the broken New-Relic test server (root 200, injector routes never respond)."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body = b"<!doctype html><html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            time.sleep(3600)   # the pathology: fan-out probes would each pay a full read timeout here


def test_grade_timeout_interrupts_a_hanging_target():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Hang)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        t0 = time.monotonic()
        try:
            grade(url, use_browser=False, timeout=3)
            raise AssertionError("grade() should have raised GradeTimeout on a hanging target")
        except GradeTimeout:
            elapsed = time.monotonic() - t0
        # bounded near the 3s budget — decisively less than the server's 3600s hang (i.e. it interrupted,
        # not waited out an individual probe timeout or the hang itself)
        assert 2.0 < elapsed < 20.0, elapsed
    finally:
        srv.shutdown()
