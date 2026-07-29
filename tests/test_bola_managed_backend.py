"""sec-idor-004: broken per-user RLS on the app's managed backend (Supabase). We replay the app's OWN observed
/rest/v1 read as a SECOND registered user, with the app's OWN public apikey — testing the developer's RLS
config, never the vendor. A mock PostgREST backend in BROKEN mode (any user reads any row) must fire; SCOPED
(RLS: only your own row) must read clean; WORLD-READABLE (apikey alone returns the row) must read N/A (that's
the separate exposure finding, not per-user IDOR). A's unique username is the oracle; read-only."""
import base64
import http.server
import json
import pathlib
import re
import sys
import threading
from urllib.parse import urlparse

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.auth import Account  # noqa: E402
from sloptic.probes import bola_managed_backend  # noqa: E402

A_CANARY, B_CANARY = "hl_aaaa1111", "hl_bbbb2222"
_ROWS = {"1": {"id": "1", "username": A_CANARY}, "2": {"id": "2", "username": B_CANARY}}


def _jwt(sub):
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).rstrip(b"=").decode()
    return "eyJhbGciOiJub25lIn0." + p + ".sig"


def _sub(auth_header):
    try:
        seg = auth_header.split(" ", 1)[1].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))["sub"]
    except Exception:
        return None


def _make_backend(mode):   # mode: broken | scoped | public
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            u = urlparse(self.path)
            if not u.path.startswith("/rest/v1/profiles"):
                return self._j(404, {})
            if not self.headers.get("apikey"):
                return self._j(401, {})                       # PostgREST needs the anon apikey
            m = re.search(r"id=eq\.(\w+)", u.query)
            target = m.group(1) if m else None
            caller = _sub(self.headers.get("Authorization", ""))
            if mode == "public":
                rows = [_ROWS[target]] if target in _ROWS else []
            elif caller is None:
                rows = []                                     # RLS: no user context, no rows
            elif mode == "broken":
                rows = [_ROWS[target]] if target in _ROWS else []
            else:  # scoped
                rows = [_ROWS[target]] if (target == caller and target in _ROWS) else []
            return self._j(200, rows)

        def _j(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    return H


def _serve(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_backend(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Probe:
    probe = {}


def _account(sub, canary, backend, reads=True):
    c = httpx.Client(timeout=10.0)
    c.headers["Authorization"] = "Bearer " + _jwt(sub)
    # A's OWN observed read filters A's own id (id=eq.1) — exactly what the app's client fetched for A
    br = [{"url": f"{backend}/rest/v1/profiles?id=eq.1&select=*", "apikey": "anonkey"}] if reads else []
    return Account(username=canary, password="p", client=c,
                   register_response=httpx.Response(200, request=httpx.Request("GET", "http://x")),
                   backend_reads=br)


_LANE_ON = object()   # a non-None browser_register: deploy_and_grade sets one only under --browser-auth


def _ctx(backend, *, a_reads=True, canary=A_CANARY, a_auth=True, b_auth=True, browser_register=_LANE_ON):
    a = _account("1", canary, backend, reads=a_reads)
    b = _account("2", B_CANARY, backend, reads=False)
    if not a_auth:
        a.client.headers.pop("Authorization", None)
    if not b_auth:
        b.client.headers.pop("Authorization", None)
    accts = {"_a": a, "_b": b}
    return type("C", (), {"register": lambda self, suffix="": accts[suffix],
                          "evidence": {}, "base_url": "http://x",
                          "browser_register": browser_register})()


def _run(mode):
    srv = _serve(mode)
    try:
        return bola_managed_backend(_ctx(f"http://127.0.0.1:{srv.server_address[1]}"), _Probe())
    finally:
        srv.shutdown()


def test_fires_on_broken_rls():
    assert _run("broken") is True          # B reads A's row via the app's own read -> per-user RLS broken


def test_clean_when_rls_scopes_to_owner():
    assert _run("scoped") is False         # B gets [] for A's id -> RLS works


def test_na_when_world_readable():
    assert _run("public") is None          # apikey alone returns the row -> exposure finding, not per-user IDOR


# ---------------------------------------------------------------- N/A reasons must name the ACTUAL cause
# One message used to cover four causes and named only the first, blaming --browser-auth unconditionally. v12
# recorded it on 273 apps whose provenance says browser_auth was ON, i.e. it told the reader to enable a flag
# they had already enabled. Each cause points at a different next action, so each gets its own reason.

def _na(**kw):
    srv = _serve("scoped")
    try:
        ctx = _ctx("http://127.0.0.1:%d" % srv.server_address[1], **kw)
        return bola_managed_backend(ctx, _Probe()), dict(ctx.evidence)
    finally:
        srv.shutdown()


def test_no_reads_and_lane_OFF_names_the_flag():
    verdict, ev = _na(a_reads=False, browser_register=None)
    assert verdict is None
    assert "not enabled" in ev["na_reason"] and "--browser-auth" in ev["na_reason"]


def test_no_reads_but_lane_ON_must_NOT_blame_the_flag():
    """THE REGRESSION. The lane ran; telling the reader to switch it on is a dead end."""
    verdict, ev = _na(a_reads=False)
    assert verdict is None
    assert "--browser-auth" not in ev["na_reason"], ev["na_reason"]
    assert "observed no Supabase" in ev["na_reason"]


def test_reads_without_a_per_user_jwt_says_so():
    """A cookie/session app: the reads exist, but there is no second identity to replay them AS."""
    verdict, ev = _na(b_auth=False)
    assert verdict is None
    assert "no per-user bearer JWT for account B" in ev["na_reason"]


def test_reads_without_a_canary_says_the_oracle_is_missing():
    verdict, ev = _na(canary="")
    assert verdict is None
    assert "no unique username" in ev["na_reason"] and "oracle" in ev["na_reason"]


def test_the_four_causes_produce_four_DISTINCT_reasons():
    """The point of the fix: an aggregate over a corpus must be able to tell them apart."""
    reasons = {_na(a_reads=False, browser_register=None)[1]["na_reason"],
               _na(a_reads=False)[1]["na_reason"],
               _na(b_auth=False)[1]["na_reason"],
               _na(canary="")[1]["na_reason"]}
    assert len(reasons) == 4, reasons
