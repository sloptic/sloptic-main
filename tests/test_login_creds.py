"""--login: authenticate with team-provided demo/test credentials and return the session as replayable
headers. A JSON login endpoint (bearer OR cookie) and an HTML login form both work; wrong creds or no login
surface -> {} (so the caller falls back to self-register / unauth, never a phantom session)."""
import http.server
import json
import pathlib
import sys
import threading
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.auth import login_with_credentials  # noqa: E402

GOOD = ("demo@app.com", "s3cret")


def _make_app(kind):   # json-bearer | json-cookie | html-form | none
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body="", ctype="application/json", cookie=None):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            form = ("<form action='/login' method='post'><input name='email'>"
                    "<input type='password' name='password'></form>")
            self._send(200, form if kind == "html-form" else "<html></html>", "text/html")

        def _creds_ok(self, raw):
            try:
                body = json.loads(raw)
            except Exception:
                body = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            return (body.get("email") == GOOD[0] or body.get("username") == GOOD[0]) and body.get("password") == GOOD[1]

        def do_POST(self):
            path = urlparse(self.path).path
            ok = self._creds_ok(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"")
            if kind == "json-bearer" and path in ("/api/login", "/api/auth/login"):
                return self._send(200, json.dumps({"access_token": "tok-abcdef123456"})) if ok else self._send(401, "{}")
            if kind == "json-cookie" and path in ("/api/login", "/api/auth/login"):
                return self._send(200, "{}", cookie="session=sess-xyz; Path=/") if ok else self._send(401, "{}")
            if kind == "html-form" and path == "/login":
                return self._send(200, "{}", cookie="session=form-sess; Path=/") if ok else self._send(401, "no", "text/html")
            return self._send(404, "{}")
    return H


def _run(kind, email=GOOD[0], pw=GOOD[1]):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(kind))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        return login_with_credentials(url, email, pw)
    finally:
        srv.shutdown()


def test_json_bearer_login():
    assert _run("json-bearer").get("Authorization") == "Bearer tok-abcdef123456"


def test_json_cookie_login():
    assert "session=sess-xyz" in _run("json-cookie").get("Cookie", "")


def test_html_form_login():
    assert "session=form-sess" in _run("html-form").get("Cookie", "")


def test_wrong_creds_yields_no_session():
    assert _run("json-bearer", pw="wrong") == {}


def test_no_login_surface_yields_no_session():
    assert _run("none") == {}
