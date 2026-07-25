"""Conventional create+read pair inference, so the authorization probes can run at all.

_bola_pairs needs BOTH halves already OBSERVED: a POST-with-body on the collection and a templated
`GET /coll/{id}`. A client-rendered app only issues those from a logged-in page the crawl may never reach, so
the pair goes undiscovered and IDOR/integrity/race read N/A. Measured: all five sec-idor probes NEVER APPLIED
across 1110 corpus apps, and on the OopsSec anchor whose POST /api/wishlists + GET /api/wishlists/{id} are
reachable the whole cluster sat dark.

The inference is evidence-gated, not a guess: the collection must return a JSON ARRAY OF OBJECTS CARRYING AN
ID, and the create body's fields come from those objects' OWN keys. A wrong inference costs one 404/405.
"""
import http.server
import json
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import probes  # noqa: E402
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.schema import Endpoint, Profile  # noqa: E402

_ROW = {"id": 1, "name": "widget", "ownerEmail": "a@b.c", "tags": ["x"], "createdAt": "2026-01-01"}
_BODIES = {
    # a real resource collection: array of objects, each with an id -> a pair is inferable
    "/api/items": [_ROW],
    # sibling collections under DIFFERENT resource ids: one SHAPE, so they must collapse to one pair
    "/api/shops/aaaaaaaaaaaaaaaaaaaa/items": [_ROW],
    "/api/shops/bbbbbbbbbbbbbbbbbbbb/items": [_ROW],
    # served as a list but with NO read-by-id route (the OopsSec reviews shape) -> must yield no pair
    "/api/products/aaaaaaaaaaaaaaaaaaaa/reviews": [{"id": 9, "content": "hi", "author": "z"}],
    "/api/status": {"ok": True},                       # an object, not a collection -> no pair
    "/api/tags": ["red", "blue"],                      # array of scalars -> no pair
    "/api/events": [{"name": "click", "at": 12}],      # objects with NO id -> nothing to read back by id
    "/api/logout": [{"id": 1, "name": "n"}],           # shaped like a collection but never write to it
}
# only these collections expose GET /<coll>/<id>; the rest are list-only
_HAS_READ_BY_ID = ("/api/items", "/api/shops/aaaaaaaaaaaaaaaaaaaa/items",
                   "/api/shops/bbbbbbbbbbbbbbbbbbbb/items", "/api/logout")


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        # read-by-id resolves only for _HAS_READ_BY_ID collections. A list-only collection is very common and
        # must NOT be mistaken for a broken round-trip.
        coll, _, last = path.rpartition("/")
        if coll in _HAS_READ_BY_ID and last:
            b = json.dumps(_ROW).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if path not in _BODIES:
            self.send_response(404); self.end_headers(); self.wfile.write(b"{}"); return
        b = json.dumps(_BODIES[path]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def _ctx(paths):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    eps = [Endpoint(path=p, method="get", raw_path=p) for p in paths]
    ctx = _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True),
               Profile(base_url=url, endpoints=eps), None)
    return ctx, srv


def _pairs(paths):
    ctx, srv = _ctx(paths)
    try:
        return [(c.raw_path, r.raw_path, c.body_fields) for c, r, _p, _i in probes._conventional_pairs(ctx)]
    finally:
        ctx.client.close()
        srv.shutdown()


def test_infers_the_pair_and_takes_body_fields_from_the_collections_own_objects():
    got = _pairs(["/api/items"])
    assert len(got) == 1
    coll, read, fields = got[0]
    assert coll == "/api/items" and read == "/api/items/{id}"
    assert "name" in fields and "ownerEmail" in fields          # the app's OWN keys, so BOLA can spot a private one
    assert "id" not in fields and "createdAt" not in fields     # server-assigned fields aren't create input
    assert "tags" not in fields                                 # nested list: not a scalar body field


def test_a_list_only_collection_yields_no_pair():
    # THE precision guard. OopsSec's reviews collection has no read-by-id, and without this check the
    # round-trip probe created a review (201), failed to read it back at the invented path (404), and reported
    # a 34-penalty data-integrity finding that was purely our own bad guess. No read-by-id is not a defect.
    # (/api/products/<id>/reviews is served as a list but has no /{reviewId} route in this mock.)
    assert _pairs(["/api/products/aaaaaaaaaaaaaaaaaaaa/reviews"]) == []


def test_sibling_collections_under_different_ids_collapse_to_one_shape():
    # a crawl that saw six products would otherwise spend the whole cap re-testing the same collection
    got = _pairs(["/api/shops/aaaaaaaaaaaaaaaaaaaa/items", "/api/shops/bbbbbbbbbbbbbbbbbbbb/items"])
    assert len(got) == 1, got


def test_non_collections_yield_nothing():
    assert _pairs(["/api/status"]) == []      # a scalar object is not a collection
    assert _pairs(["/api/tags"]) == []        # array of scalars: no per-object id
    assert _pairs(["/api/events"]) == []      # objects without an id: nothing to read back
    assert _pairs(["/api/missing"]) == []     # 404: a wrong inference costs one request, yields no pair


def test_action_endpoints_are_never_written_to():
    # shaped like a collection, but inferring a create on logout/checkout/pay is never worth it
    assert _pairs(["/api/logout"]) == []


def test_observed_pairs_win_and_are_not_duplicated():
    # discovery saw the real POST + templated GET: keep THOSE (their body/param names are real) and don't
    # add a conventional duplicate for the same collection
    ctx, srv = _ctx(["/api/items"])
    try:
        ctx.profile.endpoints += [
            Endpoint(path="/api/items", method="post", body_fields=["title"], raw_path="/api/items"),
            Endpoint(path="/api/items/1", method="get", path_params=["id"], raw_path="/api/items/{id}"),
        ]
        pairs = probes._create_read_pairs(ctx)
        assert len(pairs) == 1
        create, _read, _p, _i = pairs[0]
        assert create.body_fields == ["title"] and create.origin == "crawl"   # observed, not inferred
    finally:
        ctx.client.close()
        srv.shutdown()
