"""Deliberately-vulnerable reference app (stdlib only). The slop_detected anchor.

Same surface as references/hardened, but: string-formatted SQL (injectable login), reflects
search input unescaped (XSS), no security headers, leaks stack traces, and a slow endpoint.
Trusted code we wrote, safe to run as a local subprocess; real submissions are untrusted and
only ever run in the sandboxed container.
"""
import gzip
import http.server
import json
import os
import sqlite3
import time
import traceback
import urllib.parse

PORT = int(os.environ.get("PORT", "8080"))

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (name TEXT, pw TEXT)")
_db.execute("INSERT INTO users VALUES ('alice', 's3cret')")
_db.commit()

_SESSIONS = {}     # session token -> username
_NOTES = {}        # note id -> {"owner", "text"}
_NEXT_NOTE = [1]   # sequential note ids (mutable holder)
_HITS = {}         # shared dict for the /report load probe (unsynchronized)


def _user_of(handler):
    for part in handler.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("session="):
            return _SESSIONS.get(part[len("session="):])
    return None


HOME = b"""<!doctype html><html><body>
<h1>demo app</h1>
<a href="/login">login</a> | <a href="/search">search</a> | <a href="/crash">crash</a> | <a href="/heavy">heavy</a> | <a href="/dom">dom</a>
<form action="/login" method="post">
  <input name="username" placeholder="user">
  <input name="password" type="password" placeholder="pw">
  <button type="submit">log in</button>
</form>
<form action="/search" method="get">
  <input name="q" placeholder="search">
  <button type="submit">search</button>
</form>
<form action="/register" method="post">
  <input name="username" placeholder="user">
  <input name="email" placeholder="email">
  <input name="password" type="password" placeholder="pw">
  <button type="submit">register</button>
</form>
<form action="/notes" method="post">
  <input name="text" placeholder="note">
  <button type="submit">add note</button>
</form>
<script src="/config.js"></script>
<script>hacklet_undefined_fn();</script>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html", cookie=None):  # no charset -> browsers must guess encoding
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")  # leaks the stack — disclosure slop
        origin = self.headers.get("Origin")
        if origin:  # reflects ANY origin + allows credentials -> CORS misconfiguration
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()  # note: no security headers
        self.wfile.write(body)

    def do_GET(self):
        try:
            urllib.parse.unquote(self.path, errors="strict")  # naive router strict-decodes the raw path
        except Exception:
            return self._send(500, "decode error")  # and 500s on malformed %-encoding (no 400 guard)
        if self.path == "/":
            return self._send(200, HOME)
        if self.path == "/config.js":  # leaks a (fake, non-placeholder) AWS key in client JS — classic slop
            return self._send(200, 'const AWS_KEY = "AKIAZ3PK7NBQWXYZ1234";\n', "application/javascript")
        if self.path == "/.env":  # secrets file served at the webroot — deployment slop
            return self._send(
                200, "DATABASE_URL=postgres://app:hunter2@db/app\nDJANGO_SECRET_KEY=insecure-dev-key\n",
                "text/plain",
            )
        if self.path == "/.git/config":  # exposed source repo
            return self._send(
                200, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme/app.git\n',
                "text/plain",
            )
        if self.path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if self.path == "/.aws/credentials":  # cloud creds served at the webroot — critical exposure
            return self._send(
                200, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", "text/plain")
        if self.path.startswith("/dom"):  # DOM-sink XSS: client JS innerHTMLs a URL param (unescaped)
            return self._send(200, '<div id="out"></div><script>'
                              'document.getElementById("out").innerHTML = '
                              'new URLSearchParams(location.search).get("q") || "";</script>')
        if self.path == "/report":  # unsynchronized shared dict -> 500s under concurrent load
            try:
                _HITS[len(_HITS)] = 1
                total = 0
                for k in _HITS:  # iterating the LIVE dict while peers add keys -> RuntimeError
                    total += _HITS[k]
                    time.sleep(0.005)
                return self._send(200, "report: " + str(total))
            except RuntimeError:
                return self._send(500, "concurrent modification")
        if self.path == "/slow":  # content injected late by client JS -> high First Contentful Paint
            return self._send(200, '<div id="app"></div><script>'
                              'setTimeout(function(){document.getElementById("app").innerHTML='
                              '"<h1>loaded</h1>";}, 1500);</script>')
        if self.path.startswith("/notes/"):
            try:
                note_id = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(404, "not found")
            note = _NOTES.get(note_id)
            if note is None:
                return self._send(404, "not found")
            if _user_of(self):  # vulnerable: ANY logged-in user, no owner check -> horizontal IDOR
                return self._send(200, "note: " + note["text"])
            return self._send(401, "login required")
        if self.path.startswith("/search"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
            return self._send(200, "<p>results for: " + q + "</p>")  # reflects raw -> XSS
        if self.path == "/crash":
            try:
                raise ValueError("kaboom while rendering report")
            except ValueError:
                # Flask debug=True shipped to prod: the full interactive Werkzeug debugger (source + an
                # RCE console), not merely a leaked trace. The traceback keeps qa-errhyg firing too.
                page = ("<!DOCTYPE html><html><head><title>ValueError: kaboom // Werkzeug Debugger"
                        "</title></head><body><h1 class=\"traceback\">Werkzeug Debugger</h1><pre>"
                        + traceback.format_exc() + "</pre></body></html>")
                return self._send(500, page)  # debug UI (sec-debug-001) + leaked trace (qa-errhyg)
        if self.path.startswith("/heavy"):
            time.sleep(1.5)  # slow: over the TTFB gate, but small enough to keep the suite fast
            return self._send(200, "done")
        if self.path == "/account":  # host-header injection: builds the redirect from the client's Host
            self.send_response(302)
            self.send_header("Location", "http://" + self.headers.get("Host", "localhost") + "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/redirect"):  # open redirect: reflects any destination, no validation
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            dest = (q.get("next") or q.get("url") or q.get("redirect") or q.get("return")
                    or q.get("dest") or [""])[0]
            if dest:
                self.send_response(302)
                self.send_header("Location", dest)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(400, "no destination")
        # soft-404: a missing STATIC ASSET falls through to a 200 index shell instead of a 404
        # (misconfigured catch-all) -> caches/crawlers/monitors treat a nonexistent URL as real content
        if self.path.split("?")[0].rsplit(".", 1)[-1].lower() in (
                "js", "css", "png", "jpg", "gif", "svg", "ico", "woff", "woff2"):
            return self._send(200, HOME, "text/html; charset=utf-8")
        return self._send(404, "not found")

    def do_POST(self):
        if self.path == "/register":
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            user = form.get("username", ["anon"])[0] or "anon"
            _SESSIONS[user] = user  # vulnerable: session token == username (guessable)
            return self._send(200, "account created", cookie="session=" + user)
        if self.path == "/notes":  # create a note owned by the current session's user
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            user = _user_of(self)
            if not user:
                return self._send(401, "login required")
            note_id = _NEXT_NOTE[0]
            time.sleep(0.1)  # widen the read-then-increment window -> ID collision under concurrency
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
            query = "SELECT name FROM users WHERE name='%s' AND pw='%s'" % (user, pw)  # injectable
            try:
                row = _db.execute(query).fetchone()
            except Exception:
                return self._send(500, traceback.format_exc())
            if row:
                return self._send(200, "welcome " + row[0])
            return self._send(401, "invalid credentials")
        if self.path == "/profile":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode())
                age = int(form["age"][0])  # KeyError if missing, ValueError if non-numeric
                return self._send(200, "age is " + str(age))
            except Exception:
                return self._send(500, traceback.format_exc())  # unhandled -> 500 + leaks trace
        if self.path == "/api/items":  # naive JSON: crashes (500) on bad JSON / wrong type / missing key
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode()
            try:
                data = json.loads(body)
                return self._send(200, "item: " + data["name"].upper())
            except Exception:
                return self._send(500, traceback.format_exc())
        if self.path == "/ingest":  # decompresses a gzip request body with NO size cap -> zip-bomb DoS
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if "gzip" in self.headers.get("Content-Encoding", "").lower():
                raw = gzip.decompress(raw)             # unbounded: a tiny bomb expands to GB unchecked
            try:
                json.loads(raw)
                return self._send(200, "ingested")
            except Exception:
                return self._send(400, "invalid json")
        return self._send(404, "not found")


if __name__ == "__main__":
    # Bind 0.0.0.0: reachable as a dev/CI subprocess AND via the published port inside the
    # DockerDeployer container (a 127.0.0.1 binding is unreachable through Docker's port forward).
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # concurrent -> races surface
