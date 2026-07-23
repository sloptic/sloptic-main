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
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import data_integrity_list_roundtrip, race_resource_ids_api  # noqa: E402
from hacklet_runner.schema import Endpoint, Profile  # noqa: E402


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
            return self._j(404, {})

        def do_GET(self):
            if urlparse(self.path).path == "/api/items":
                return self._j(200, {"items": items})
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


def test_race_fires_on_duplicate_ids_under_concurrency():
    assert _run(race_resource_ids_api, "racy") is True               # timestamp ids collide across concurrent creates


def test_race_clean_when_ids_are_atomic():
    assert _run(race_resource_ids_api, "atomic") is False            # locked counter -> unique ids -> no race


def test_race_na_without_create_endpoint():
    assert _run(race_resource_ids_api, "atomic", endpoints=[]) is None
