"""sec-ssrf-001 needs an IN-BAND detector, not only an out-of-band callback.

OAST proves SSRF by having the target's server reach our collaborator. That is the precise detector when it
works, and it structurally cannot work when the server fetches the URL but its egress never reaches us —
which is the normal state of a serverless function whose network access is filtered to the platform. Measured
on GapBench: 0-for-2 on `ssrf-image-proxy` and `gcp-metadata-ssrf`, because no callback could ever arrive.

The precision rule: the signature is content the METADATA SERVICE returns, never a substring of the URL we
sent. An app that merely echoes our payload back must read clean, so `computeMetadata` (which IS in the
request path) would have been exactly the wrong token to match on.
"""
import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import _SSRF_INBAND, _ssrf_inband  # noqa: E402
from sloptic.schema import Endpoint, Profile  # noqa: E402

_GCP = json.dumps({"project": {"numericProjectId": 883220117, "projectId": "acme-prod"},
                   "serviceAccounts": {"default": {"email": "sa@acme-prod.iam.gserviceaccount.com"}}})
_AWS = json.dumps({"accountId": "402118283301", "imageId": "ami-0abcd1234",
                   "instanceId": "i-0fe9a1b2c3", "region": "us-east-1"})
_AZURE = json.dumps({"compute": {"vmId": "9f1c-4a2e", "subscriptionId": "b7c1-22e9", "name": "web-01"}})


def _serve(body_for):
    """`body_for(fetched_url) -> str|None`: what the app returns when asked to fetch that URL."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            body = body_for((q.get("url") or [""])[0]) or "<html>nothing fetched</html>"
            b = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(body_for):
    srv = _serve(body_for)
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=url, routes=["/", "/proxy"],
                   endpoints=[Endpoint(path="/proxy", raw_path="/proxy", method="get", query_params=["url"])])
    ctx = _Ctx(url, make_client(url, None, timeout=8.0, follow_redirects=True), prof, None)
    targets = [("/proxy", "get", ["url"], ["url"])]
    try:
        return _ssrf_inband(ctx, targets)
    finally:
        ctx.client.close()
        srv.shutdown()


def test_each_cloud_metadata_service_is_recognised_from_its_own_response():
    for label, body in (("gcp", _GCP), ("aws", _AWS), ("azure", _AZURE)):
        ev = _run(lambda fetched, b=body: b if "169.254.169.254" in fetched else None)
        assert ev is not None, label
        assert ev["field"] == "url" and "169.254.169.254" in ev["fetched"]
        assert "cloud metadata response in body" in ev["repro"]["matched"]


def test_an_app_that_only_echoes_the_url_back_reads_clean():
    # THE precision rule. A proxy that refuses and reports what you asked for is not vulnerable, and every
    # signature is chosen so that echoing the request cannot satisfy it.
    ev = _run(lambda fetched: "refused to fetch " + fetched)
    assert ev is None


def test_no_signature_is_a_substring_of_its_own_request_url():
    # the invariant that keeps the test above true as the target list grows
    for url, sig in _SSRF_INBAND:
        assert sig.search(url) is None, url


def test_a_proxy_that_fetches_only_allowed_hosts_reads_clean():
    ev = _run(lambda fetched: _GCP if "images.example.com" in fetched else None)
    assert ev is None


def test_a_partial_json_shape_still_matches_one_alternative():
    # real metadata responses vary by api-version; matching any one documented key is enough
    ev = _run(lambda fetched: json.dumps({"vmId": "9f1c-4a2e"}))
    assert ev is not None and ev["fetched"].endswith("api-version=2021-02-01")
