"""Hardened reference app (stdlib only). The clean anchor / false-positive guard.

Identical surface to references/vulnerable, defended correctly: parameterized SQL, escaped search
reflection, security headers set, generic errors (no stack traces), fast endpoints. Every probe
must read clean here.
"""
import gzip
import hashlib
import html
import http.server
import json
import os
import secrets
import sqlite3
import threading
import urllib.parse
import zlib

PORT = int(os.environ.get("PORT", "8080"))

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (name TEXT, pw TEXT)")
_db.execute("INSERT INTO users VALUES ('alice', 's3cret')")
_db.commit()

_SESSIONS = {}     # session token -> username
_NOTES = {}        # note id -> {"owner", "text"}
_NEXT_NOTE = [1]   # sequential note ids (mutable holder)
_LOCK = threading.Lock()
_HITS = {}         # shared dict for the /report load probe
_LOGIN_FAILS = {}  # username -> failed login count, for brute-force lockout


def _user_of(handler):
    for part in handler.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("session="):
            return _SESSIONS.get(part[len("session="):])
    return None


HOME = b"""<!doctype html><html lang="en"><head><title>demo app</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="A small demo application."></head><body>
<h1>demo app</h1>
<a href="/login">login</a> | <a href="/search">search</a> | <a href="/crash">crash</a> | <a href="/heavy">heavy</a> | <a href="/dom">dom</a>
<form action="/login" method="post">
  <input name="username" aria-label="username" placeholder="user">
  <input name="password" type="password" aria-label="password" placeholder="pw">
  <button type="submit">log in</button>
</form>
<form action="/search" method="get">
  <input name="q" aria-label="search query" placeholder="search">
  <button type="submit">search</button>
</form>
<form action="/register" method="post">
  <input name="username" aria-label="new username" placeholder="user">
  <input name="email" type="email" aria-label="email" placeholder="email">
  <input name="password" type="password" aria-label="new password" placeholder="pw">
  <button type="submit">register</button>
</form>
<form action="/notes" method="post">
  <input name="text" aria-label="note text" placeholder="note">
  <button type="submit">add note</button>
</form>
<script src="/config.js"></script>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", cookie=None, cache=None, etag=None):
        if isinstance(body, str):
            body = body.encode()
        encoding = None
        if "gzip" in self.headers.get("Accept-Encoding", "") and len(body) > 512:
            body = gzip.compress(body)  # compress sizeable responses -> no perf-compress slop
            encoding = "gzip"
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if encoding:
            self.send_header("Content-Encoding", encoding)
        if cache:                                 # static assets are cacheable + revalidatable
            self.send_header("Cache-Control", cache)
        if etag:
            self.send_header("ETag", etag)
        self.send_header("X-Content-Type-Options", "nosniff")  # security headers set
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            return self._send(200, HOME)
        if self.path == "/config.js":  # same surface, no secret in client code; ships a PATCHED jQuery
            # (>=3.5.0) so sec-deps-001 sees the lib but reads it CLEAN (version discrimination, not lib presence)
            body = b'/*! jQuery v3.6.0 | (c) OpenJS Foundation | jquery.org/license */\nconst CONFIG = { api: "/api" };\n'
            etag = '"%s"' % hashlib.md5(body).hexdigest()   # cacheable static asset with a real validator
            if self.headers.get("If-None-Match") == etag:   # honor revalidation -> cheap 304, no refetch
                return self._send(304, b"", "application/javascript", cache="public, max-age=3600", etag=etag)
            return self._send(200, body, "application/javascript", cache="public, max-age=3600", etag=etag)
        if self.path.startswith("/notes/"):
            try:
                note_id = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(404, "not found")
            note = _NOTES.get(note_id)
            if note is None:
                return self._send(404, "not found")
            if _user_of(self) == note["owner"]:  # hardened: owner only -> no IDOR
                return self._send(200, "note: " + html.escape(note["text"]))
            return self._send(403, "forbidden")
        if self.path == "/account":  # host-safe: the redirect is a fixed relative path, never from the Host header
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/login":  # GET renders the login form (POST authenticates) -> the nav link resolves
            return self._send(200, '<!doctype html><html lang="en"><head><title>log in</title></head><body>'
                              '<form action="/login" method="post">'
                              '<input name="username" aria-label="username">'
                              '<input name="password" type="password" aria-label="password">'
                              '<button type="submit">log in</button></form></body></html>')
        if self.path.startswith("/search"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
            return self._send(200, "<p>results for: " + html.escape(q) + "</p>")  # escaped
        if self.path == "/crash":
            return self._send(500, "Internal Server Error")  # generic, no stack trace
        if self.path.startswith("/heavy"):
            return self._send(200, "done")  # fast
        if self.path.startswith("/dom"):  # same surface, but textContent (no HTML parsing) -> safe
            return self._send(200, '<div id="out"></div><script>'
                              'document.getElementById("out").textContent = '
                              'new URLSearchParams(location.search).get("q") || "";</script>')
        if self.path == "/report":  # locked snapshot -> safe under concurrent load
            with _LOCK:
                _HITS[len(_HITS)] = 1
                snapshot = list(_HITS.values())
            return self._send(200, "report: " + str(sum(snapshot)))
        if self.path == "/slow":  # content in the initial HTML -> fast First Contentful Paint
            return self._send(200, '<div id="app"><h1>loaded</h1></div>')
        if self.path.startswith("/redirect"):  # validated redirect: same-origin relative paths only
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            dest = (q.get("next") or q.get("url") or [""])[0]
            if dest.startswith("/") and not dest.startswith("//"):
                self.send_response(302)
                self.send_header("Location", dest)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(400, "invalid redirect")
        return self._send(404, "not found")

    def do_POST(self):
        if self.path == "/register":
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            email = form.get("email", [""])[0]
            if email and "@" not in email:                    # SERVER-side enforcement of the declared type=email
                return self._send(400, "invalid email")       # (not client-JS only) -> qa-input-001 stays clean
            user = form.get("username", ["anon"])[0] or "anon"
            sid = secrets.token_hex(16)
            _SESSIONS[sid] = user
            return self._send(200, "account created",
                              cookie="session=" + sid + "; HttpOnly; SameSite=Lax; Secure; Path=/")
        if self.path == "/notes":  # create a note owned by the current session's user
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            user = _user_of(self)
            if not user:
                return self._send(401, "login required")
            with _LOCK:  # atomic id allocation -> no collision under concurrency
                note_id = _NEXT_NOTE[0]
                _NEXT_NOTE[0] += 1
            _NOTES[note_id] = {"owner": user, "text": form.get("text", [""])[0]}
            self.send_response(302)
            self.send_header("Location", "/notes/%d" % note_id)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            user = form.get("username", [""])[0]
            pw = form.get("password", [""])[0]
            with _LOCK:  # per-username brute-force lockout -> rate-limited after repeated failures
                if _LOGIN_FAILS.get(user, 0) >= 5:
                    return self._send(429, "too many attempts; try later")
            row = _db.execute(
                "SELECT name FROM users WHERE name=? AND pw=?", (user, pw)  # parameterized
            ).fetchone()
            if row:
                with _LOCK:
                    _LOGIN_FAILS.pop(user, None)  # reset on success
                return self._send(200, "welcome " + row[0])
            with _LOCK:
                _LOGIN_FAILS[user] = _LOGIN_FAILS.get(user, 0) + 1
            return self._send(401, "invalid credentials")
        if self.path == "/profile":
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            raw = form.get("age", [""])[0]
            if not raw.isdigit():
                return self._send(400, "invalid age")  # graceful, no crash
            return self._send(200, "age is " + raw)
        if self.path == "/api/items":  # validates -> graceful 400 on bad JSON / wrong type / missing key
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode()
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._send(400, "invalid json")
            if not isinstance(data, dict) or not isinstance(data.get("name"), str):
                return self._send(400, "invalid item")
            return self._send(200, "item: " + data["name"].upper())
        if self.path == "/ingest":  # decompresses a gzip request body but CAPS it -> rejects a zip bomb
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if "gzip" in self.headers.get("Content-Encoding", "").lower():
                dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                raw = dec.decompress(raw, 1_000_000)   # cap decompression at 1 MB
                if dec.unconsumed_tail:                 # more than the cap remained -> refuse to expand it
                    return self._send(413, "payload too large")
            try:
                json.loads(raw)
                return self._send(200, "ingested")
            except Exception:
                return self._send(400, "invalid json")
        return self._send(404, "not found")


if __name__ == "__main__":
    # Bind 0.0.0.0: reachable as a dev/CI subprocess AND via the published port inside the
    # DockerDeployer container (a 127.0.0.1 binding is unreachable through Docker's port forward).
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # concurrent, but locked
