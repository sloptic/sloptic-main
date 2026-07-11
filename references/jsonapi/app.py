"""JSON-API reference (stdlib only): a form-less API that publishes an OpenAPI spec. Exercises the
spec-driven discovery + error-based SQLi path that references/vulnerable (HTML-form only) can't.

- GET  /openapi.json      the spec -> the discoverable API surface (no HTML to crawl)
- GET  /api/items/{id}    INJECTABLE: id is concatenated into SQL; a lone quote -> a leaked DB error
- GET  /api/notes?q=      SAFE: q is parameterized; a quote is inert data, never an error
- GET  /api/dump          LEAKY: returns user records including plaintext "password" fields (exposure)
- POST /api/register, /api/login   self-as-oracle auth (login returns {"token": <username>})
- POST /api/orders        create an order carrying a private "secret" (auth required)
- GET  /api/orders/{id}   BOLA: returns ANY authed caller's-or-not order incl. its secret (no owner check)
- POST /api/drafts        NON-DURABLE: returns 201 + an id but never persists -> the read-back always 404s
- GET  /api/drafts/{id}   the broken round-trip's read side (always 404, even for a just-"created" id)
- GET  /api/mistyped      a JSON body served with Content-Type: text/html (declared-type mismatch)

api_sqli fires on /api/items/{id}, clean on /api/notes; response_leaks_credentials fires on /api/dump;
api_bola fires on /api/orders/{id} (B reads A's order + secret); data_integrity_roundtrip fires on
/api/drafts (create-then-read loses the object); content_type_mismatch fires on /api/mistyped — all
clean on the safe/correct endpoints (/api/orders round-trips, the JSON endpoints declare application/json).
"""
import http.server
import json
import os
import re
import time
from urllib.parse import parse_qs, unquote, urlparse

PORT = int(os.environ.get("PORT", "8080"))

USERS = {}          # username -> password
ORDERS = {}         # id -> {owner, item, secret}
_STATE = {"next_id": 1}

_STR = {"type": "string"}
SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "jsonapi-ref", "version": "1.0"},
    "paths": {
        "/api/items/{id}": {
            "get": {"parameters": [
                {"in": "path", "name": "id", "required": True, "schema": _STR}]}
        },
        "/api/notes": {
            "get": {"parameters": [{"in": "query", "name": "q", "schema": _STR}]}
        },
        "/api/search": {"get": {}},   # searchable, declares NO params -> exercises common-param guessing
        "/api/bsearch": {"get": {}},  # BOOLEAN-based only (no error leaked; result set depends on truth)
        "/api/usearch": {"get": {}},  # UNION-based only (a concatenated marker executes)
        "/api/tsearch": {"get": {}},  # TIME-based only (a sleep payload delays the response)
        "/api/dump": {"get": {}},
        "/api/register": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"username": _STR, "email": _STR, "password": _STR}}}}}}},
        "/api/login": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"username": _STR, "password": _STR}}}}}}},
        "/api/orders": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"item": _STR, "secret": _STR}}}}}}},
        "/api/orders/{id}": {
            "get": {"parameters": [{"in": "path", "name": "id", "required": True, "schema": _STR}]}
        },
        "/api/drafts": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"title": _STR, "body": _STR}}}}}}},   # NON-DURABLE: create 201, read 404
        "/api/drafts/{id}": {
            "get": {"parameters": [{"in": "path", "name": "id", "required": True, "schema": _STR}]}
        },
        "/api/mistyped": {"get": {}},   # a JSON body served as text/html (Content-Type mismatch)
    },
}


def _send(h, code, ctype, body: bytes):
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/openapi.json":
            _send(self, 200, "application/json", json.dumps(SPEC).encode())
        elif u.path.startswith("/api/items/"):
            item_id = unquote(u.path[len("/api/items/"):])
            sql = "SELECT * FROM items WHERE id = '%s'" % item_id  # unparameterized -> injectable
            if "'" in item_id:  # a lone quote breaks the string literal -> the framework leaks a DB error
                body = ('sqlite3.OperationalError: unrecognized token near "\'"\n[SQL: %s]' % sql).encode()
                _send(self, 500, "text/html; charset=utf-8", body)
            else:
                _send(self, 200, "application/json", json.dumps({"id": item_id, "name": "item"}).encode())
        elif u.path == "/api/notes":
            q = parse_qs(u.query).get("q", [""])[0]  # parameterized: quote is data, never grammar
            _send(self, 200, "application/json", json.dumps({"query": q, "notes": []}).encode())
        elif u.path == "/api/search":
            q = parse_qs(u.query).get("q", [""])[0]  # ERROR-based: a lone quote leaks a DB error
            sql = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % q
            if "'" in q:
                body = ('sqlite3.OperationalError: unrecognized token\n[SQL: %s]' % sql).encode()
                _send(self, 500, "text/html; charset=utf-8", body)
            else:
                _send(self, 200, "application/json", json.dumps({"results": []}).encode())
        elif u.path == "/api/bsearch":
            q = parse_qs(u.query).get("q", [""])[0]  # BOOLEAN: always-true condition -> all rows
            rows = ["item"] * 50 if "'1'='1" in q else []   # no error on a lone quote; size tracks truth
            _send(self, 200, "application/json", json.dumps({"results": rows}).encode())
        elif u.path == "/api/usearch":
            q = parse_qs(u.query).get("q", [""])[0]  # UNION: a concatenation expression executes
            m = (re.search(r"'([^']*)'\|\|'([^']*)'\|\|'([^']*)'", q)
                 or re.search(r"CONCAT\('([^']*)','([^']*)','([^']*)'\)", q, re.I))
            row = "".join(m.groups()) if m else ""
            _send(self, 200, "application/json", json.dumps({"row": row, "results": []}).encode())
        elif u.path == "/api/tsearch":
            q = parse_qs(u.query).get("q", [""])[0]  # TIME: a sleep payload delays the response
            m = re.search(r"(?:SLEEP|pg_sleep)\((\d+)\)", q, re.IGNORECASE)
            if m:
                time.sleep(min(int(m.group(1)), 5))
            _send(self, 200, "application/json", json.dumps({"results": []}).encode())
        elif u.path == "/api/dump":  # excessive data exposure: returns password material to any caller
            users = [{"username": "alice", "email": "alice@x.com", "password": "hunter2"},
                     {"username": "bob", "email": "bob@x.com", "password": "s3cret!"}]
            _send(self, 200, "application/json", json.dumps({"users": users}).encode())
        elif u.path.startswith("/api/orders/"):
            if self._bearer() is None:  # auth-gated (so it's genuine BOLA, not a public endpoint)
                _send(self, 401, "application/json", b'{"error":"unauthorized"}')
                return
            order = ORDERS.get(unquote(u.path[len("/api/orders/"):]))
            if order is None:
                _send(self, 404, "application/json", b'{"error":"not found"}')
            else:  # BOLA: any authed caller reads any order incl. its secret — no owner check
                _send(self, 200, "application/json", json.dumps({"id": order["id"], **order}).encode())
        elif u.path.startswith("/api/drafts/"):
            # NON-DURABLE WRITE: the POST below hands back an id but never persists, so every read 404s
            _send(self, 404, "application/json", b'{"error":"not found"}')
        elif u.path == "/api/mistyped":  # a JSON body served with the wrong Content-Type (text/html)
            _send(self, 200, "text/html; charset=utf-8", json.dumps({"ok": True, "value": 42}).encode())
        else:
            _send(self, 404, "application/json", b'{"error":"not found"}')

    def _bearer(self):
        h = self.headers.get("Authorization", "")
        return h[7:] if h.startswith("Bearer ") and h[7:] in USERS else None

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}

    def do_POST(self):
        u = urlparse(self.path)
        body = self._json_body()
        if u.path == "/api/register":
            USERS[body.get("username", "")] = body.get("password", "")
            _send(self, 200, "application/json", b'{"status":"registered"}')
        elif u.path == "/api/login":
            user = body.get("username", "")
            if user in USERS and USERS[user] == body.get("password"):
                _send(self, 200, "application/json", json.dumps({"token": user}).encode())
            else:
                _send(self, 401, "application/json", b'{"error":"bad credentials"}')
        elif u.path == "/api/orders":
            owner = self._bearer()
            if owner is None:
                _send(self, 401, "application/json", b'{"error":"unauthorized"}')
                return
            oid = str(_STATE["next_id"])
            _STATE["next_id"] += 1
            ORDERS[oid] = {"id": oid, "owner": owner, "item": body.get("item", ""),
                           "secret": body.get("secret", "")}
            _send(self, 201, "application/json", json.dumps({"id": oid}).encode())
        elif u.path == "/api/drafts":  # returns a fresh id but NEVER stores it -> the read-back 404s
            oid = str(_STATE["next_id"])
            _STATE["next_id"] += 1
            _send(self, 201, "application/json", json.dumps({"id": oid}).encode())
        else:
            _send(self, 404, "application/json", b'{"error":"not found"}')


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
