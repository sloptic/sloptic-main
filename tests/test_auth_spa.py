"""SPA registration (the Borrow-Tracker / Next.js shape): a React login form whose POST action is a
placeholder, and the REAL registration is a JSON API that (a) requires a display NAME and (b) auto-establishes
a session COOKIE. register_account must fall through to the JSON API, send `name`, and capture the register's
own session — instead of grading the login page and reading the whole authed surface as N/A."""
import http.server
import json
import secrets
import threading

from hacklet_runner.auth import _has_session, register_account
from hacklet_runner.schema import Form, Profile


class _SpaAuth(http.server.BaseHTTPRequestHandler):
    """GET / -> a React login form whose action is the page itself (no real handler). POST /api/auth/register
    -> 500 on a bare {email,password} (name required), 200 + Set-Cookie once `name` is present."""
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html", cookie=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, b"<html><body><form><input type='email' name='email'>"
                        b"<input type='password' name='password'><button type='submit'>Sign In</button>"
                        b"</form></body></html>")

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        if self.path == "/api/auth/register":
            try:
                data = json.loads(raw or b"{}")
            except Exception:
                data = {}
            if not data.get("name"):
                self._send(500)                          # name required -> a bare body 500s (the real bug)
                return
            self._send(200, b'{"user":{"id":"1"}}', "application/json",
                       cookie="borrow_session=sess-%s; Path=/; HttpOnly; SameSite=Lax" % secrets.token_hex(4))
            return
        self._send(200, b"<html>shell</html>")           # the form's placeholder action -> no session


def test_register_account_falls_through_to_json_api_and_captures_the_spa_session():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpaAuth)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    acct = None
    try:
        prof = Profile(base_url=base, forms=[Form(action="/", method="post", fields=["email", "password"])])
        acct = register_account(base, prof)              # no browser -> must succeed via JSON fallback + name
        assert _has_session(acct), "React form gave no session; JSON /api/auth/register + name should have"
        assert any("borrow_session" in c.name for c in acct.client.cookies.jar)
    finally:
        if acct is not None:
            acct.client.close()
        srv.shutdown()
