"""Managed-backend exposure (Supabase/Firebase shipped without row-level security). The provider hosts
are external, so CI locks the pieces (mining + the read-with-public-key query) against local mocks, plus
the N/A path when no backend config is embedded (the firewalled Tier-A case)."""
import http.server
import json
import threading

import httpx
import pytest

from hacklet_runner import probes
from hacklet_runner.schema import Profile


def _serve(handler_body):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            code, ctype, body = handler_body(self.path)
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def serve():
    servers = []

    def _make(fn):
        srv = _serve(fn)
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


def test_mining_regexes():
    blob = ('const u="https://abcdefghij0123456789.supabase.co";'
            'const k="eyJ%s.eyJ%s.%s";'
            'firebase={databaseURL:"https://my-app-123.firebaseio.com"};' % ("a" * 20, "b" * 20, "c" * 20))
    assert probes._SUPABASE_URL.search(blob).group(1) == "abcdefghij0123456789"
    assert probes._FIREBASE_RTDB.search(blob).group(1) == "my-app-123.firebaseio.com"
    assert probes._JWT.search(blob)


def test_postgrest_tables_parses_definitions():
    r = httpx.Response(200, json={"definitions": {"users": {}, "orders": {}}, "paths": {}})
    assert set(probes._postgrest_tables(r)) == {"users", "orders"}


def test_supabase_readable_fires_when_rows_come_back(serve):
    def h(path):
        if path.startswith("/rest/v1/") and path != "/rest/v1/":
            return 200, "application/json", json.dumps([{"id": 1, "email": "a@x.com", "password": "p"}]).encode()
        return 200, "application/json", json.dumps({"definitions": {"users": {}}}).encode()
    base = serve(h)
    with httpx.Client(timeout=5) as c:
        hit = probes._supabase_readable(c, base, ["eyJanon"], [])   # root still exposes the list (self-hosted path)
    assert hit["table"] == "users" and hit["rows"] == 1 and "password" in hit["columns"]


def test_supabase_clean_when_rls_returns_no_rows(serve):
    def h(path):
        if path.startswith("/rest/v1/") and path != "/rest/v1/":
            return 200, "application/json", b"[]"                     # RLS on -> filtered to nothing
        return 200, "application/json", json.dumps({"definitions": {"users": {}}}).encode()
    base = serve(h)
    with httpx.Client(timeout=5) as c:
        assert probes._supabase_readable(c, base, ["eyJanon"], []) is None


def test_supabase_unreachable_is_na():
    with httpx.Client(timeout=1) as c:
        assert probes._supabase_readable(c, "http://127.0.0.1:1", ["eyJanon"], []) == "unreachable"


def test_supabase_tables_mined_from_bundle():
    # bundle-driven enumeration (the OpenAPI root is anon-blocked since Apr 2026): app-referenced .from()
    # and /rest/v1/ tables first (real signal), then the common-name fallback appended.
    blob = 'supabase.from("profiles").select();x.from(\'orders\');fetch("/rest/v1/api_keys?select=*")'
    t = probes._supabase_tables(blob)
    assert t[:3] == ["profiles", "orders", "api_keys"]
    assert "users" in t and len(t) <= 16


def test_supabase_sensitivity_gate_ignores_intentionally_public_table(serve):
    # a NON-sensitive, public-by-design table (a product catalog) readable to anon is NOT a finding — the
    # sensitivity gate is what stops an intentionally-public table from false-firing (rows-to-anon != leak).
    def h(path):
        if "/rest/v1/products" in path and path != "/rest/v1/":
            return 200, "application/json", json.dumps([{"id": 1, "name": "Widget", "price": 9}]).encode()
        return 403, "application/json", b'{"code":"42501","message":"permission denied"}'
    base = serve(h)
    with httpx.Client(timeout=5) as c:
        assert probes._supabase_readable(c, base, ["eyJanon"], ["products"]) is None


def test_supabase_fires_on_sensitive_bundle_table(serve):
    # a private-looking table (accounts, with PII columns) readable to anon -> RLS misconfiguration -> fires.
    # Non-target tables 42501 (no grant); the OpenAPI root is 403 (post-Apr-2026), so the table came from the bundle.
    def h(path):
        if "/rest/v1/accounts" in path and path != "/rest/v1/":
            return 200, "application/json", json.dumps([{"id": 1, "email": "a@x.com", "password_hash": "x"}]).encode()
        return 403, "application/json", b'{"code":"42501","message":"permission denied"}'
    base = serve(h)
    with httpx.Client(timeout=5) as c:
        hit = probes._supabase_readable(c, base, ["eyJanon"], ["accounts"])
    assert hit["table"] == "accounts" and "email" in hit["columns"]


def test_firebase_readable_fires_on_open_rtdb(serve):
    base = serve(lambda p: (200, "application/json", json.dumps({"users": {"1": {"email": "a@x.com"}}}).encode()))
    with httpx.Client(timeout=5) as c:
        data = probes._firebase_readable(c, base + "/.json")
    assert isinstance(data, dict) and "users" in data


def test_firebase_clean_on_permission_denied(serve):
    base = serve(lambda p: (200, "application/json", b"null"))   # locked RTDB returns null to anon
    with httpx.Client(timeout=5) as c:
        assert probes._firebase_readable(c, base + "/.json") is None


def test_firestore_config_detected_in_bundle():
    blob = ('firebase.initializeApp({apiKey:"AIza%s",projectId:"my-cool-app"});'
            'import{getFirestore}from"firebase/firestore";' % ("b" * 35))
    assert probes._FIREBASE_APIKEY.search(blob).group(0) == "AIza" + "b" * 35
    assert probes._FIREBASE_PROJECT.search(blob).group(1) == "my-cool-app"
    assert probes._FIRESTORE_SIGNAL.search(blob)


def test_firestore_collections_mined_from_bundle():
    # app-referenced collections first (the real signal), then the common-name fallback appended
    blob = 'const db=getFirestore(app);collection(db,"users");collection(db, "chat_rooms");x.collection("orders");'
    colls = probes._firestore_collections(blob)
    assert colls[:3] == ["users", "chat_rooms", "orders"]
    assert "messages" in colls and len(colls) <= 14


def test_firestore_readable_fires_on_open_collection(serve):
    def h(path):
        if "/documents/users" in path:   # this collection's rules are `allow read: if true`
            return 200, "application/json", json.dumps({"documents": [
                {"name": "projects/p/databases/(default)/documents/users/1",
                 "fields": {"email": {"stringValue": "a@x.com"}, "role": {"stringValue": "admin"}}}]}).encode()
        return 200, "application/json", b'{"documents": []}'
    base = serve(h)
    with httpx.Client(timeout=5) as c:
        hit = probes._firestore_readable(c, base, "my-proj", "AIzaKEY", ["posts", "users"])
    assert hit["collection"] == "users" and hit["documents"] == 1 and "email" in hit["fields"]


def test_firestore_clean_on_permission_denied(serve):
    base = serve(lambda p: (403, "application/json",
                            json.dumps({"error": {"code": 403, "status": "PERMISSION_DENIED"}}).encode()))
    with httpx.Client(timeout=5) as c:
        assert probes._firestore_readable(c, base, "my-proj", "AIzaKEY", ["users", "posts"]) is None


def test_firestore_unreachable_is_na():
    with httpx.Client(timeout=1) as c:
        assert probes._firestore_readable(c, "http://127.0.0.1:1", "p", "k", ["users"]) == "unreachable"


def _serve_authed(rules):
    """Local mock keyed off the Authorization Bearer token: rules(path, bearer) -> (code, body_bytes). For
    the authenticated-tier differential (anon vs a fresh JWT/idToken); handles GET + POST (signup)."""
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _do(self):
            bearer = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            code, body = rules(self.path, bearer)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _do
        do_POST = _do

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_supabase_authed_only_fires_on_authenticated_rls_bypass():
    # broken RLS: anon is denied ([]), but a FRESH authed user (created nothing) sees everyone's rows ->
    # `using (auth.role() = 'authenticated')` -> the IDOR equivalent. Sensitive table+columns -> fires.
    ANON, JWT = "eyJanon", "eyJfreshuser"

    def rules(path, bearer):
        if "/rest/v1/messages" in path:
            return (200, json.dumps([{"id": 1, "email": "a@x.com", "body": "private"}]).encode()) \
                if bearer == JWT else (200, b"[]")   # anon -> RLS blocks -> empty
        return 200, b"[]"
    srv = _serve_authed(rules)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=5) as c:
            hit = probes._supabase_authed_only(c, base, ANON, JWT, ["messages"])
        assert hit and hit["table"] == "messages" and "email" in hit["columns"]
    finally:
        srv.shutdown()


def test_supabase_authed_only_clean_on_correct_per_user_rls():
    # correct per-user policy: a FRESH user sees [] too (created nothing) -> not the authenticated-tier bug
    srv = _serve_authed(lambda path, bearer: (200, b"[]"))
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=5) as c:
            assert probes._supabase_authed_only(c, base, "eyJanon", "eyJfresh", ["messages"]) is None
    finally:
        srv.shutdown()


def test_supabase_authed_only_skips_anon_open_table():
    # anon ALSO sees the rows -> sec-backend-001's anon-open finding, NOT the authenticated tier -> clean here
    srv = _serve_authed(lambda path, bearer: (200, json.dumps([{"id": 1, "email": "a@x.com"}]).encode()))
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=5) as c:
            assert probes._supabase_authed_only(c, base, "eyJanon", "eyJfresh", ["users"]) is None
    finally:
        srv.shutdown()


def test_supabase_signup_jwt_when_autoconfirm_else_none():
    ok = _serve_authed(lambda path, bearer: (200, json.dumps({"access_token": "eyJnew"}).encode()))
    conf = _serve_authed(lambda path, bearer: (200, json.dumps({"user": {"id": "x"}, "session": None}).encode()))
    try:
        with httpx.Client(timeout=5) as c:
            assert probes._supabase_signup(c, "http://127.0.0.1:%d" % ok.server_address[1], "eyJanon") == "eyJnew"
            # confirmation required -> no access_token -> N/A (can't obtain an authed identity)
            assert probes._supabase_signup(c, "http://127.0.0.1:%d" % conf.server_address[1], "eyJanon") is None
    finally:
        ok.shutdown(); conf.shutdown()


def test_firebase_anon_token_obtained_or_none_when_disabled():
    ok = _serve_authed(lambda path, bearer: (200, json.dumps({"idToken": "fbTok", "localId": "anon1"}).encode()))
    off = _serve_authed(lambda path, bearer: (400, json.dumps({"error": {"message": "ADMIN_ONLY_OPERATION"}}).encode()))
    try:
        with httpx.Client(timeout=5) as c:
            assert probes._firebase_anon_token(c, "http://127.0.0.1:%d" % ok.server_address[1], "AIzaK") == "fbTok"
            assert probes._firebase_anon_token(c, "http://127.0.0.1:%d" % off.server_address[1], "AIzaK") is None
    finally:
        ok.shutdown(); off.shutdown()


def test_firestore_authed_only_fires_when_fresh_user_sees_docs():
    TOK = "fbTok"

    def rules(path, bearer):
        if "/documents/users" in path and bearer == TOK:   # anon (no bearer) sees nothing; authed sees data
            return 200, json.dumps({"documents": [
                {"name": "p/databases/(default)/documents/users/1",
                 "fields": {"email": {"stringValue": "a@x.com"}}}]}).encode()
        return 200, b"{}"
    srv = _serve_authed(rules)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=5) as c:
            hit = probes._firestore_authed_only(c, base, "proj", "AIzaK", TOK, ["posts", "users"])
        assert hit and hit["collection"] == "users" and "email" in hit["fields"]
    finally:
        srv.shutdown()


def test_authenticated_backend_na_when_no_config():
    ctx = type("C", (), {"client": httpx.Client(base_url="http://127.0.0.1:1"),
                         "profile": Profile(base_url="http://127.0.0.1:1", routes=["/"]), "evidence": {}})()
    assert probes.authenticated_backend_readable(ctx, type("P", (), {"probe": {}})()) is None


def test_predicate_na_when_no_backend_config():
    # a firewalled Tier-A app embeds no Supabase/Firebase config -> nothing to test -> N/A
    ctx = type("C", (), {"client": httpx.Client(base_url="http://127.0.0.1:1"),
                         "profile": Profile(base_url="http://127.0.0.1:1", routes=["/"]), "evidence": {}})()
    assert probes.exposed_backend_readable(ctx, type("P", (), {"probe": {}})()) is None
