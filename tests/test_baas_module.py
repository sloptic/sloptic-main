"""The shared managed-backend plumbing: gateway resolution, the SSRF guard, and BaaS registration.

It lives in its own module because `probes` imports `auth`, so `auth` cannot import `probes`, and both need to
resolve the app's data-plane gateway. Two copies of an SSRF guard is exactly the kind of duplication that drifts.

Why any of it exists: on a managed-backend app the auth API is NOT the app's. Measured on supavulnbase, every
app-side registration path 404s while POST <gateway>/auth/v1/signup with the PUBLIC anon key answers 200 with a
session. Without that session the crawl runs anonymous, where every route renders the same 31-byte shell — so
the authed routes, their per-route chunks, and the service_role key compiled into the dashboard chunk are all
invisible. With it, /app/dashboard renders 10679 bytes and sec-secrets-001 finds the key.
"""
import base64
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import baas  # noqa: E402


def _jwt(payload: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg(payload)}.sig-Tr0ub4dor"


_ANON = _jwt({"iss": "supabase", "role": "anon"})
_SERVICE = _jwt({"iss": "supabase", "role": "service_role"})


# ---------------------------------------------------------------- the SSRF guard

def test_only_an_origin_the_target_is_already_on_is_followed():
    assert baas.reachable_origin("http://localhost:8055", "http://localhost:8090") is True
    assert baas.reachable_origin("https://app.example.com:9000", "https://app.example.com") is True
    # a bundle string is attacker-influenced input; following it anywhere else is an SSRF gadget
    assert baas.reachable_origin("http://internal-db.corp", "https://app.example.com") is False
    assert baas.reachable_origin("http://169.254.169.254", "https://app.example.com") is False
    assert baas.reachable_origin("http://localhost:8055", "https://app.example.com") is False


def test_a_malformed_candidate_is_refused_not_crashed():
    for bad in ("", "not-a-url", "http://", None):
        assert baas.reachable_origin(bad or "", "http://localhost:8090") is False


# ---------------------------------------------------------------- key selection

def test_the_anon_key_is_selected_and_the_service_role_key_is_never_mistaken_for_it():
    """Both are JWTs of the same shape. Signing in with a service_role key would make every request omnipotent
    and every RLS check meaningless, so the role is read from the payload rather than guessed by position."""
    blob = 'createClient("https://x.supabase.co","%s");const admin="%s";' % (_ANON, _SERVICE)
    assert baas.anon_key(blob) == _ANON
    assert baas.anon_key('const k="%s"' % _SERVICE) is None
    assert baas.anon_key("no keys here") is None
    assert baas.anon_key("") is None


# ---------------------------------------------------------------- the session cookie

def test_the_cookie_name_follows_the_supabase_ssr_convention():
    assert baas.cookie_name("https://abcdefghijklmnop.supabase.co") == "sb-abcdefghijklmnop-auth-token"
    assert baas.cookie_name("http://localhost:8055") == "sb-localhost-auth-token"


def test_the_cookie_value_is_the_session_json_base64_wrapped():
    # measured on supavulnbase: this form and plain JSON both render the authed page (10679b vs 31b
    # anonymous), while a BARE access token gets the unauthenticated shell
    v = baas.cookie_value({"access_token": "tok", "refresh_token": "ref", "user": {"id": "u1"},
                           "ignored_extra": "dropped"})
    assert v.startswith("base64-")
    doc = json.loads(base64.b64decode(v[len("base64-"):]))
    assert doc["access_token"] == "tok" and doc["user"] == {"id": "u1"}
    assert "ignored_extra" not in doc


# ---------------------------------------------------------------- gateway + signup, end to end

def _serve():
    """A gateway that answers the PostgREST root and a GoTrue signup, plus an app page naming it."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json", server=None):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            if server:
                self.send_header("Server", server)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/rest/v1/":
                return self._send(200, json.dumps({"swagger": "2.0", "paths": {}}), server="kong/2.8.1")
            if path == "/app":
                port = self.server.server_address[1]
                return self._send(200, '<html><script src="/s.js"></script></html>', "text/html")
            if path == "/s.js":
                port = self.server.server_address[1]
                return self._send(200, 'createClient("http://127.0.0.1:%d","%s")' % (port, _ANON),
                                  "application/javascript")
            return self._send(404, json.dumps({"e": 1}))

        def do_POST(self):
            if self.path.split("?")[0] == "/auth/v1/signup":
                if not self.headers.get("apikey"):
                    return self._send(401, json.dumps({"message": "No API key found in request"}))
                return self._send(200, json.dumps({"access_token": "tok-abc", "refresh_token": "ref-abc",
                                                   "token_type": "bearer", "expires_in": 3600,
                                                   "user": {"id": "u1"}}))
            return self._send(404, json.dumps({"e": 1}))

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_the_blob_splits_origin_from_entry_path():
    """httpx.Client(base_url=".../app") + get("/app") resolves to /app/app -- the blob came back as 8552 bytes
    of shell with no gateway and no key, where the correct split yields the real bundle."""
    srv = _serve()
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        blob = baas.client_blob(origin + "/app")     # a path-bearing base_url, as callers pass it
        assert "createClient" in blob and _ANON in blob
    finally:
        srv.shutdown()


def test_a_self_hosted_gateway_is_resolved_and_signup_yields_a_session():
    srv = _serve()
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        blob = baas.client_blob(origin + "/app")
        gw = baas.resolve_gateway(blob, origin + "/app")
        assert gw == origin
        session = baas.signup(gw, baas.anon_key(blob))
        assert session and session["access_token"] == "tok-abc"
        assert session["_email"].endswith("@example.com") and session["_password"]
    finally:
        srv.shutdown()


def test_signup_without_a_key_yields_nothing():
    srv = _serve()
    origin = "http://127.0.0.1:%d" % srv.server_address[1]
    try:
        assert baas.signup(origin, "") is None
    finally:
        srv.shutdown()


def test_a_confirmation_required_signup_is_not_a_session():
    """GoTrue answers 200 with a user and NO access_token when email confirmation is on. Treating that as a
    session would authenticate every later probe as nobody and read the whole authed surface as clean."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            b = json.dumps({"id": "u1", "email": "x@example.com", "confirmation_sent_at": "now"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert baas.signup("http://127.0.0.1:%d" % srv.server_address[1], "k") is None
    finally:
        srv.shutdown()


def test_an_unreachable_gateway_is_none_not_an_exception():
    assert baas.signup("http://127.0.0.1:1", "k") is None
    assert baas.client_blob("http://127.0.0.1:1") == ""
    assert baas.resolve_gateway("", "http://127.0.0.1:1") is None
