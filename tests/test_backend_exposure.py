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
        hit = probes._supabase_readable(c, base, ["eyJanon"])
    assert hit["table"] == "users" and hit["rows"] == 1 and "password" in hit["columns"]


def test_supabase_clean_when_rls_returns_no_rows(serve):
    def h(path):
        if path.startswith("/rest/v1/") and path != "/rest/v1/":
            return 200, "application/json", b"[]"                     # RLS on -> filtered to nothing
        return 200, "application/json", json.dumps({"definitions": {"users": {}}}).encode()
    base = serve(h)
    with httpx.Client(timeout=5) as c:
        assert probes._supabase_readable(c, base, ["eyJanon"]) is None


def test_supabase_unreachable_is_na():
    with httpx.Client(timeout=1) as c:
        assert probes._supabase_readable(c, "http://127.0.0.1:1", ["eyJanon"]) == "unreachable"


def test_firebase_readable_fires_on_open_rtdb(serve):
    base = serve(lambda p: (200, "application/json", json.dumps({"users": {"1": {"email": "a@x.com"}}}).encode()))
    with httpx.Client(timeout=5) as c:
        data = probes._firebase_readable(c, base + "/.json")
    assert isinstance(data, dict) and "users" in data


def test_firebase_clean_on_permission_denied(serve):
    base = serve(lambda p: (200, "application/json", b"null"))   # locked RTDB returns null to anon
    with httpx.Client(timeout=5) as c:
        assert probes._firebase_readable(c, base + "/.json") is None


def test_predicate_na_when_no_backend_config():
    # a firewalled Tier-A app embeds no Supabase/Firebase config -> nothing to test -> N/A
    ctx = type("C", (), {"client": httpx.Client(base_url="http://127.0.0.1:1"),
                         "profile": Profile(base_url="http://127.0.0.1:1", routes=["/"]), "evidence": {}})()
    assert probes.exposed_backend_readable(ctx, type("P", (), {"probe": {}})()) is None
