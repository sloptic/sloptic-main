"""sec-idor-003: horizontal IDOR on a user/account record (the canonical /user/123 -> /user/124 case). A
tiny two-user JSON API in BROKEN mode (any logged-in user reads any user by id) must fire; in SCOPED mode
(only your own record) must read clean; anon-readable or no-id-endpoint must read N/A. Proven by A's unique
registration username leaking into B's response — no planted secret, read-only."""
import base64
import http.server
import json
import pathlib
import re
import sys
import threading
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _Ctx  # noqa: E402
from hacklet_runner.probes import idor_user_record  # noqa: E402
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


def _make_app(broken, public=False):
    users, by_id, ctr = {}, {}, {"n": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _j(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_POST(self):
            path = urlparse(self.path).path
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
            if path in ("/api/register", "/api/users"):
                ctr["n"] += 1; uid = str(ctr["n"])
                u = {"id": uid, "email": body.get("email"), "username": body.get("username")}
                users[body.get("username")] = u; by_id[uid] = u
                return self._j(201, {"id": uid})
            if path in ("/api/login", "/login"):
                u = users.get(body.get("username")) or next(
                    (x for x in users.values() if x["email"] == body.get("email")), None)
                return self._j(200, {"access_token": _jwt(u["id"])}) if u else self._j(401, {})
            return self._j(404, {})

        def do_GET(self):
            m = re.match(r"^/api/users/([^/]+)$", urlparse(self.path).path)
            if not m:
                return self._j(404, {})
            target, caller = m.group(1), _sub(self.headers.get("Authorization", ""))
            if caller is None and not public:
                return self._j(401, {})                 # access-gated (anon can't read)
            if not broken and not public and target != caller:
                return self._j(403, {})                 # SCOPED: only your own record
            rec = by_id.get(target)
            return self._j(200, rec) if rec else self._j(404, {})
    return H


def _serve(broken, public=False):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_app(broken, public))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Probe:
    probe = {}


def _ctx(url):
    prof = Profile(base_url=url, forms=[], endpoints=[
        Endpoint(path="/api/users/1", method="get", path_params=["id"], raw_path="/api/users/{id}")])
    return _Ctx(url, make_client(url, None, timeout=10.0, follow_redirects=True), prof, None)


def _run(broken, public=False):
    srv = _serve(broken, public)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    ctx = _ctx(url)
    try:
        return idor_user_record(ctx, _Probe())
    finally:
        ctx.client.close(); srv.shutdown()


def test_fires_when_any_user_can_read_any_record():
    assert _run(broken=True) is True            # B reads A's own account record by id -> horizontal IDOR


def test_clean_when_records_are_scoped_to_owner():
    assert _run(broken=False) is False          # B gets 403 on A's id -> access control works


def test_na_when_record_is_public():
    assert _run(broken=False, public=True) is None   # anon can read it too -> not access-gated -> not IDOR
