"""A 429 is the HOST refusing us; its body says nothing about the app.

Measured on the v10 corpus sample: sec-secrets-001 AND sec-secrets-002 both vanished on two apps that still
ship an `openai-key` today. Both probes reproduce on current code against the live apps, and the recorded route
sets were byte-identical between runs — so the detectors were fine and the FETCH was not. The declarative
fan-out scanned whatever came back, found no secret in it, and recorded that as a CLEAN observation.

That is the same principle as everywhere else in this catalog: absence of a test is not a pass. A route we
could not read must not count as evidence that it is clean.

5xx is deliberately NOT treated this way. qa-crash-010 matches a 5xx as evidence the app crashed under a
malformed request, so skipping those would trade this false-clean for a different one.
"""
import http.server
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.net import make_client  # noqa: E402
from hacklet_runner.pipeline import _run_probe, _Ctx  # noqa: E402
from hacklet_runner.schema import Probe, Profile  # noqa: E402

_SECRET = "sk-proj-A1" + "b" * 40      # matches secretscan's openai-key pattern


def _serve(script):
    """`script` maps a path to a list of (status, body) served in order, so a retry can differ."""
    state = {k: 0 for k in script}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            seq = script.get(path)
            if not seq:
                status, body = 404, "nope"
            else:
                i = min(state[path], len(seq) - 1)
                state[path] += 1
                status, body = seq[i]
            b = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


_PROBE = Probe(id="sec-secrets-001", bundle="security", category="secrets-exposure", penalty=35,
               probe={"target": "routes"}, slop_if=["response_leaks_secret"])


def _run(script, routes):
    srv = _serve(script)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, landing_path="/", routes=list(routes))
    client = make_client(base, None, timeout=8.0, follow_redirects=True)
    ctx = _Ctx(base, client, prof, None)
    try:
        return _run_probe(_PROBE, ctx, client, prof)
    finally:
        client.close()
        srv.shutdown()


def test_a_secret_is_found_when_the_route_reads_normally():
    outs = _run({"/app.js": [(200, "const k='%s'" % _SECRET)]}, ["/app.js"])
    assert [o.outcome for o in outs] == ["slop_detected"]


def test_a_429_is_retried_and_the_secret_is_still_found():
    # the observed failure: one throttled request stood between us and a real finding
    outs = _run({"/app.js": [(429, "rate limited"), (200, "const k='%s'" % _SECRET)]}, ["/app.js"])
    assert [o.outcome for o in outs] == ["slop_detected"]


def test_a_route_that_stays_throttled_is_NOT_scored_as_clean():
    """THE bug. Scanning a 429 body finds no secret, and recording that as clean turns a rate limiter into a
    passing grade."""
    outs = _run({"/app.js": [(429, "rate limited"), (429, "rate limited")]}, ["/app.js"])
    assert [o.outcome for o in outs] == ["not_applicable"]


def test_a_throttled_route_does_not_make_its_SIBLINGS_look_clean():
    # the partial case, which is what actually happened: other routes read fine, the one carrying the secret
    # was throttled, and the probe reported clean off the siblings
    outs = _run({"/ok.js": [(200, "nothing here")],
                 "/app.js": [(429, "rate limited"), (429, "rate limited")]}, ["/ok.js", "/app.js"])
    assert [o.outcome for o in outs] == ["clean"]          # only the readable sibling is judged
    assert len(outs) == 1, "the throttled route must not contribute an outcome at all"


def test_a_5xx_is_still_judged_because_a_crash_is_evidence():
    """qa-crash-010 matches a 5xx as proof the app fell over. Skipping 5xx would trade one false-clean for
    another, so only 429 is treated as unreadable."""
    outs = _run({"/app.js": [(500, "const k='%s'" % _SECRET)]}, ["/app.js"])
    assert [o.outcome for o in outs] == ["slop_detected"]


def test_every_route_throttled_is_not_applicable_not_clean():
    outs = _run({"/a.js": [(429, "x"), (429, "x")], "/b.js": [(429, "x"), (429, "x")]}, ["/a.js", "/b.js"])
    assert [o.outcome for o in outs] == ["not_applicable"]
