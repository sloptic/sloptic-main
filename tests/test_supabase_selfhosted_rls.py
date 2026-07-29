"""Self-hosted Supabase, and anon WRITE as the RLS oracle.

Two findings from the supavulnbase fixture, whose Supabase gateway runs at http://localhost:8055 and whose
manifest attributes 8 of its 23 findings (7 EXCLUSIVELY) to reaching that gateway.

1. SUPPORT WAS BOUND TO THE HOSTED DOMAIN. `_SUPABASE_URL` only matched `*.supabase.co`, so a self-hosted
   gateway was invisible and the RLS probes never located a backend at all. Docker supabase/postgrest behind
   Kong is an ordinary shape. The host restriction is an SSRF GUARD though, so it is NARROWED, not removed: a
   bundle origin is followed only where the target already is (same host any port, or loopback-for-loopback),
   and it must then PROVE it is PostgREST behaviourally.

2. ANON READ IS THE WRONG ORACLE. An RLS-off table is often readable BY DESIGN (a build log's projects, a
   blog's posts), which is why the read path needs a sensitivity gate — and that gate misfires. Measured: it
   reported `profiles`, the fixture's own control for "correct owner-scoped RLS", while the three genuinely
   unpoliced tables went unnamed.

   Writability has no ambiguity: no legitimate app lets an anonymous stranger INSERT. And PostgREST answers
   without creating anything -- POST an EMPTY object and read the SQLSTATE.
       42501 / 401 / 403 -> RLS refused        -> secure (what every control answered)
       23502 / 23503 ... -> a CONSTRAINT refused it, so the insert already passed RLS -> FINDING
       PGRST204 / 42P01  -> schema mismatch / absent -> inconclusive, never a finding
   On the fixture: projects/updates/drafts -> 23502 (all three declared findings);
   profiles/payout_accounts/sponsor_leads -> 42501 (two are declared controls). Row counts unchanged.
"""
import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

from sloptic import probes  # noqa: E402

_ANON = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"


# ---------------------------------------------------------------- the SSRF guard

def test_a_foreign_internal_host_is_never_followed():
    # the guard that keeps a bundle string from turning the grader into an SSRF gadget on a real deployment
    assert probes._reachable_baas_origin("http://internal-db.corp", "https://app.example.com") is False
    assert probes._reachable_baas_origin("http://169.254.169.254", "https://app.example.com") is False
    assert probes._reachable_baas_origin("http://localhost:8055", "https://app.example.com") is False


def test_an_origin_the_target_is_already_on_is_allowed():
    assert probes._reachable_baas_origin("http://localhost:8055", "http://localhost:8090") is True
    assert probes._reachable_baas_origin("https://app.example.com:9000", "https://app.example.com") is True
    assert probes._reachable_baas_origin("http://127.0.0.1:8055", "http://localhost:8090") is True


def test_a_malformed_candidate_is_refused_not_crashed():
    for bad in ("", "not-a-url", "http://"):
        assert probes._reachable_baas_origin(bad, "http://localhost:8090") is False


# ---------------------------------------------------------------- the PostgREST signature

def _serve_gateway(server_header="kong/2.8.1", rls_open=("projects", "updates"), tables=None):
    """A PostgREST-shaped gateway. `rls_open` tables let an anon INSERT past RLS (and then fail NOT NULL);
    everything else answers 42501. No row is ever created, because the probe posts an empty body."""
    tables = tables or ["profiles", "projects", "updates", "payout_accounts"]

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if server_header:
                self.send_header("Server", server_header)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/rest/v1/":
                return self._json(200, {"swagger": "2.0",
                                        "paths": {"/" + t: {} for t in tables}})
            leaf = path.rsplit("/", 1)[-1]
            if leaf in tables:
                return self._json(200, [{"id": 1, "username": "ada", "bio": "hi"}])
            return self._json(404, {"code": "42P01", "message": "relation does not exist"})

        def do_POST(self):
            leaf = urllib.parse.urlparse(self.path).path.rsplit("/", 1)[-1]
            if leaf not in tables:
                return self._json(404, {"code": "42P01"})
            if leaf in rls_open:
                return self._json(400, {"code": "23502", "message": "null value in column violates not-null"})
            return self._json(401, {"code": "42501", "message": "new row violates row-level security policy"})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_a_gateway_proves_itself_postgrest_by_behaviour():
    srv = _serve_gateway()
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=6.0) as c:
            assert probes._looks_postgrest(c, origin) is True
    finally:
        srv.shutdown()


def test_a_plain_web_server_is_not_mistaken_for_a_gateway():
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "6")
            self.end_headers()
            self.wfile.write(b"<html>")

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with httpx.Client(timeout=6.0) as c:
            assert probes._looks_postgrest(c, "http://127.0.0.1:%d" % srv.server_address[1]) is False
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- anon write as the oracle

def test_an_anon_writable_table_is_a_finding():
    srv = _serve_gateway(rls_open=("projects",))
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=6.0) as c:
            hit = probes._supabase_anon_writable(c, origin, [_ANON], ["profiles", "projects"])
        assert hit and hit["table"] == "projects" and hit["sqlstate"] == "23502"
        assert "passed RLS" in hit["repro"]["matched"]
    finally:
        srv.shutdown()


def test_a_table_whose_rls_refuses_the_write_is_silent():
    # 42501 is what every one of the fixture's controls answered; firing here would flag correct code
    srv = _serve_gateway(rls_open=())
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=6.0) as c:
            assert probes._supabase_anon_writable(c, origin, [_ANON], ["profiles", "payout_accounts"]) is None
    finally:
        srv.shutdown()


def test_the_write_probe_enumerates_the_gateway_root_too():
    # bundle-mined names alone missed the unpoliced tables; the read path already enriched from the root
    srv = _serve_gateway(rls_open=("updates",))
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=6.0) as c:
            hit = probes._supabase_anon_writable(c, origin, [_ANON], [])   # nothing mined from the bundle
        assert hit and hit["table"] == "updates"
    finally:
        srv.shutdown()


def test_an_absent_table_is_inconclusive_never_a_finding():
    # 42P01 proves nothing about RLS. Every real table here refuses the write, so the only way this could
    # fire is by treating "table does not exist" as evidence.
    srv = _serve_gateway(rls_open=(), tables=["projects"])
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        with httpx.Client(timeout=6.0) as c:
            assert probes._supabase_anon_writable(c, origin, [_ANON], ["ghost_table"]) is None
    finally:
        srv.shutdown()


def test_only_integrity_and_data_sqlstates_prove_the_write_passed():
    ok = ("23502", "23503", "23514", "22P02", "22001")
    no = ("42501", "42P01", "PGRST204", "", "42703", "08006")
    assert all(probes._RLS_PASSED_SQLSTATE.match(c) for c in ok)
    assert not any(probes._RLS_PASSED_SQLSTATE.match(c) for c in no)
