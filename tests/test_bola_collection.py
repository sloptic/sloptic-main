"""sec-idor-005: broken object-level authorization at the COLLECTION endpoint. A two-user JSON API whose
auth-gated list endpoint returns EVERY user's objects (broken) must fire; an owner-scoped list, a single-owner
shared catalog, and a publicly-readable list must not. Proven black-box: the endpoint is 401 unauthenticated
(the app declares it private) yet two unrelated fresh accounts receive >=2 owners' objects with an overlap."""
import base64
import http.server
import json
import pathlib
import re
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.catalog import load_catalog  # noqa: E402
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import PREDICATES, api_bola_collection  # noqa: E402
from hacklet_runner.schema import Endpoint, Profile  # noqa: E402


def _jwt(sub):
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).rstrip(b"=").decode()
    return "eyJhbGciOiJub25lIn0." + payload + ".sig"


def _sub(auth_header):
    try:
        seg = auth_header.split(" ", 1)[1].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))["sub"]
    except Exception:
        return None


def _make_app(mode):   # mode: broken | scoped | catalog | public
    users, items, ctr = {}, [{"id": "seed-1", "name": "s1", "owner_id": "owner-x"},
                             {"id": "seed-2", "name": "s2", "owner_id": "owner-y"}], {"n": 0}

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
                ctr["n"] += 1
                uid = str(ctr["n"])
                users[body.get("username")] = {"id": uid, "email": body.get("email")}
                items.append({"id": "own-" + uid, "name": "mine", "owner_id": uid})  # each user owns one item
                return self._j(201, {"id": uid})
            if path in ("/api/login", "/login"):
                u = users.get(body.get("username")) or next(
                    (x for x in users.values() if x["email"] == body.get("email")), None)
                return self._j(200, {"access_token": _jwt(u["id"])}) if u else self._j(401, {})
            return self._j(404, {})

        def do_GET(self):
            if urlparse(self.path).path != "/api/items":
                return self._j(404, {})
            if mode == "public":
                return self._j(200, {"items": items})           # 200 even unauthenticated -> intent-public
            caller = _sub(self.headers.get("Authorization", ""))
            if caller is None:
                return self._j(401, {})                          # gated: the app declares it private
            if mode == "broken":
                return self._j(200, {"items": items})            # ALL users' objects to any caller
            if mode == "catalog":
                return self._j(200, {"items": [{"id": "c1", "owner_id": "system"},
                                               {"id": "c2", "owner_id": "system"}]})  # one owner -> shared catalog
            return self._j(200, {"items": [i for i in items if i.get("owner_id") == caller]})  # scoped: own only
    return H


class _Probe:
    probe = {}


_LAST_EVIDENCE = {}


def _run(mode, endpoints=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(mode))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    eps = endpoints if endpoints is not None else [
        Endpoint(path="/api/items", method="post", raw_path="/api/items", body_fields=["name"])]  # GET derived from POST sibling
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
               Profile(base_url=url, forms=[], endpoints=eps), None)
    try:
        result = api_bola_collection(ctx, _Probe())
        _LAST_EVIDENCE.clear()
        _LAST_EVIDENCE.update(ctx.evidence)
        return result
    finally:
        ctx.client.close()
        srv.shutdown()


def test_fires_when_list_leaks_every_owner_to_a_stranger():
    assert _run("broken") is True            # auth-gated list returns >=2 owners' objects to two strangers
    repro = _LAST_EVIDENCE.get("repro")      # (A) the cross-user GET is captured, replayable in Burp
    assert repro and repro["method"] == "GET" and "/api/items" in repro["url"]


def test_clean_when_list_is_owner_scoped():
    assert _run("scoped") is False           # each account sees only its own item -> one owner -> not BOLA


def test_clean_when_shared_single_owner_catalog():
    assert _run("catalog") is False          # all objects one owner -> a shared catalog, not cross-user leakage


def test_na_when_list_is_public():
    assert _run("public") is None            # 200 unauthenticated -> the app intends it public -> not gated


def test_na_without_any_collection_endpoint():
    assert _run("broken", endpoints=[]) is None   # nothing non-templated to probe


def test_catalog_wires_sec_idor_005_to_a_registered_predicate():
    cat = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
    probe = next((p for p in cat if p.id == "sec-idor-005"), None)
    assert probe is not None, "sec-idor-005 missing from the catalog"
    assert probe.probe.get("predicate") in PREDICATES
    assert probe.penalty == 40
    assert probe.applicability.requires == ["has_auth_entrypoint"]
