"""qa-integrity-002 (list round-trip) + qa-race-002 (concurrent JSON creates) — the SPA-shape data-integrity
and race probes for a JSON API with POST-create + GET-collection but NO read-by-{id} route. Silent data loss
(create 2xx but absent from its own list) fires integrity; non-atomic id allocation under concurrency fires
race; a durable, atomic API reads clean."""
import base64
import http.server
import json
import pathlib
import sys
import threading
import time
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import (  # noqa: E402
    api_bola_collection, data_integrity_list_roundtrip, race_resource_ids_api)
from sloptic.schema import Endpoint, Profile  # noqa: E402


def _jwt(sub):
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).rstrip(b"=").decode()
    return "eyJhbGciOiJub25lIn0." + p + ".sig"


def _make_app(mode):   # durable | lossy | atomic | racy
    users, items, ctr, lock = {}, [], {"n": 0}, threading.Lock()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _j(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            path = urlparse(self.path).path
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
            if path in ("/api/register", "/api/users"):
                with lock:
                    ctr["n"] += 1
                    uid = str(ctr["n"])
                users[body.get("username")] = {"id": uid}
                return self._j(201, {"id": uid})
            if path in ("/api/login", "/login"):
                u = users.get(body.get("username"))
                return self._j(200, {"access_token": _jwt(u["id"])}) if u else self._j(401, {})
            if path == "/api/items":
                if mode == "racy":
                    iid = str(int(time.time()))              # second-granularity id -> concurrent creates collide
                else:
                    with lock:
                        ctr["n"] += 1
                        iid = str(ctr["n"])                  # locked -> always unique
                if mode != "lossy":                          # durable/atomic/racy store; lossy drops the write
                    items.append({"id": iid, **body})
                return self._j(201, {"id": iid})
            if path == "/api/recommendation":               # a stateless RPC: 2xx, computes, persists nothing
                return self._j(200, {"score": 0.7})
            return self._j(404, {})

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/api/items":
                return self._j(200, {"items": items})
            if path == "/api/recommendation":               # sibling is a status/config OBJECT, not a collection
                return self._j(200, {"hasApiKey": False})
            return self._j(404, {})
    return H


def _serve(mode):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Probe:
    probe = {"bursts": 3, "min_collisions": 2}


def _ctx(url, endpoints=None):
    eps = endpoints if endpoints is not None else [
        Endpoint(path="/api/items", method="post", raw_path="/api/items", body_fields=["name"])]
    return _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
                Profile(base_url=url, forms=[], endpoints=eps), None)


def _run(pred, mode, endpoints=None):
    srv = _serve(mode)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _ctx(url, endpoints)
    try:
        return pred(ctx, _Probe())
    finally:
        ctx.client.close()
        srv.shutdown()


def test_integrity_fires_on_silent_data_loss():
    assert _run(data_integrity_list_roundtrip, "lossy") is True     # created 2xx but absent from its own list


def test_integrity_clean_when_durable():
    assert _run(data_integrity_list_roundtrip, "durable") is False   # created item present in the collection


def test_integrity_na_without_create_endpoint():
    assert _run(data_integrity_list_roundtrip, "durable", endpoints=[]) is None


def test_integrity_na_on_a_stateless_rpc_not_a_collection():
    # the v18 FP class (3 of 4 fires: encounter/recommendation/config): POST is 2xx but its sibling GET is a
    # status/config OBJECT, not a resource list -> nothing was ever persisted there -> N/A, not silent data loss.
    rpc = [Endpoint(path="/api/recommendation", method="post", raw_path="/api/recommendation",
                    body_fields=["task"])]
    assert _run(data_integrity_list_roundtrip, "durable", endpoints=rpc) is None


def test_integrity_na_on_an_auth_endpoint():
    # fahimni's /backend/auth.php fired here: a login POST has body fields but its 'collection' is not a public
    # data list. A password field (or an auth-verb path) excludes it from the create set -> N/A.
    auth = [Endpoint(path="/api/login", method="post", raw_path="/api/login",
                     body_fields=["username", "password"])]
    assert _run(data_integrity_list_roundtrip, "durable", endpoints=auth) is None


# ---- browser persist-confirm fallback: flips N/A -> confirmed-clean, NEVER fires loss (absence is ambiguous) --

def test_integrity_browser_confirm_flips_na_to_clean(monkeypatch):
    # httpx can't round-trip (no JSON create endpoint), but a browser drives the create and reads the canary back
    # from the client-rendered DOM -> the write persisted -> confirmed clean, via="browser".
    from sloptic import probes
    monkeypatch.setattr(probes.browser, "create_and_read_back",
                        lambda base, submit_value, locate, headers=None, timeout=12.0: "<li>%s</li>" % submit_value)
    srv = _serve("durable")
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _ctx(url, endpoints=[])
    ctx.profile.capabilities["browser"] = True
    try:
        assert data_integrity_list_roundtrip(ctx, _Probe()) is False
        assert ctx.evidence.get("via") == "browser" and ctx.evidence.get("durable") is True
    finally:
        ctx.client.close()
        srv.shutdown()


def test_integrity_browser_absence_stays_na_never_fires(monkeypatch):
    # the canary did NOT read back -> ambiguous (form not found / render lag), so we stay N/A and never fire a
    # false data-loss from the browser lane.
    from sloptic import probes
    monkeypatch.setattr(probes.browser, "create_and_read_back",
                        lambda base, submit_value, locate, headers=None, timeout=12.0: "<li>nothing</li>")
    srv = _serve("durable")
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _ctx(url, endpoints=[])
    ctx.profile.capabilities["browser"] = True
    try:
        assert data_integrity_list_roundtrip(ctx, _Probe()) is None
    finally:
        ctx.client.close()
        srv.shutdown()


# ---- IDOR browser cross-user fallback: reaches the SPA client-rendered feed the httpx collection scan can't ----

def _bola_ctx(monkeypatch, verdict):
    from sloptic import probes
    calls = {}
    def fake(base, submit_value, locate, a_headers, b_headers, timeout=12.0):
        calls["ran"] = True
        return verdict
    monkeypatch.setattr(probes.browser, "cross_user_read_back", fake)
    srv = _serve("durable")
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ctx = _ctx(url, endpoints=[])                 # no collection endpoint -> httpx path can't test
    ctx.profile.capabilities["browser"] = True
    return srv, ctx, calls


def test_bola_collection_browser_fallback_fires_cross_user(monkeypatch):
    srv, ctx, calls = _bola_ctx(monkeypatch, True)
    try:
        assert api_bola_collection(ctx, _Probe()) is True        # B saw A's gated created value
        assert calls.get("ran") and ctx.evidence.get("via") == "browser" and ctx.evidence.get("cross_user_read")
    finally:
        ctx.client.close()
        srv.shutdown()


def test_bola_collection_browser_fallback_clean_when_owner_scoped(monkeypatch):
    srv, ctx, calls = _bola_ctx(monkeypatch, False)
    try:
        assert api_bola_collection(ctx, _Probe()) is False       # A saw it, anon+B did not -> observed clean
        assert ctx.evidence.get("via") == "browser"
    finally:
        ctx.client.close()
        srv.shutdown()


def test_bola_collection_browser_fallback_na_when_create_unobservable(monkeypatch):
    srv, ctx, calls = _bola_ctx(monkeypatch, None)               # A's create never surfaced -> untestable
    try:
        assert api_bola_collection(ctx, _Probe()) is None        # honest N/A, never a false clean
    finally:
        ctx.client.close()
        srv.shutdown()


def test_race_fires_on_duplicate_ids_under_concurrency():
    assert _run(race_resource_ids_api, "racy") is True               # timestamp ids collide across concurrent creates


def test_race_clean_when_ids_are_atomic():
    assert _run(race_resource_ids_api, "atomic") is False            # locked counter -> unique ids -> no race


def test_race_na_without_create_endpoint():
    assert _run(race_resource_ids_api, "atomic", endpoints=[]) is None
