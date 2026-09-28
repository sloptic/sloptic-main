"""The fan-out pools run inside the SUBMITTING thread's context.

Three grade mechanisms live in ContextVars and all three went blind inside a pool thread, where Python hands
you a fresh empty Context: the request tally (so the 150-request injection cap never fired in the fan-out it
exists to bound), the challenge onset (so a WAF wall tripped by a pooled probe was never recorded and the
post-onset trim never ran), and the egress origin scope (fixed separately by scope_bound). The pools now
submit through a copy of the submitting context. The shared-object holders — the tally dict, the onset
recorder — make worker writes visible back on the main thread.
"""
import contextvars

import httpx
import pytest

from sloptic import net, probes


def test_the_fan_out_pool_runs_in_the_submitting_context():
    """The base claim: a ContextVar set on the main thread is READABLE inside the pool's workers."""
    var = contextvars.ContextVar("hl_test_marker", default=None)
    seen = []

    def send(spec):
        seen.append(var.get())
        return spec, "ok"

    var.set("from-main")
    probes._fan_out_first(send, ["a", "b"], lambda s, r: r is not None)
    assert seen and seen[0] == "from-main"


def test_the_race_pool_carries_the_context_too():
    var = contextvars.ContextVar("hl_test_marker2", default=None)
    seen = []

    def work():
        seen.append(var.get())
        return 1

    var.set("from-main")
    probes._fanout(work, 3)
    assert seen == ["from-main"] * 3


def test_fan_out_requests_tally_against_the_probe_so_the_cap_fires():
    """The inert cap. The tally hook runs in the worker; before the fix its increments landed in a worker
   -local copy and `request_counts()` on the main thread never saw them, so the 150-request cap — written
    after a v21 ssti run hit 991 requests — never fired in the fan-out it exists to bound."""
    net.start_trace(False)                     # resets the tally + onset for this "grade"
    net.set_trace_probe("sec-sqli-001")

    def send(spec):
        net._watch_challenge(httpx.Response(200, text="ok", request=httpx.Request("GET", "http://t/")))
        return spec, None                      # never hits the oracle -> the pool walks the whole list

    # 160 specs: with the tally propagating, cap_check stops submission at the 150th request
    specs = [f"s{i}" for i in range(160)]
    probes._fan_out_first(send, specs, lambda s, r: r is not None,
                          cap_check=lambda: (net.request_counts() or {}).get("sec-sqli-001", 0) >= 150)
    counted = (net.request_counts() or {}).get("sec-sqli-001", 0)
    assert 0 < counted < 160                   # the tally saw the worker requests...
    assert counted >= 150                      # ...and the cap tripped before the list ran out
    # and the number is visible ON THE MAIN THREAD, which is where _request_capped reads it


def test_a_worker_confirmed_challenge_registers_the_onset():
    """The onset gap: a WAF wall tripped by a pooled probe never registered, so the pipeline's post-onset
    outcome trim did not fire. The shared recorder makes the worker's write visible to challenge_onset()."""
    net.start_trace(False)
    net.set_trace_probe("sec-exposure-007")    # the corpus's #1 challenge trigger, and it is pooled

    chal = httpx.Response(403, text="<html>captcha.awswaf.com</html>",
                          headers={"content-type": "text/html"},
                          request=httpx.Request("GET", "http://t/"))

    def send(spec):
        net._watch_challenge(chal)
        return spec, None

    assert net.challenge_onset() is None       # nothing yet
    probes._fan_out_first(send, ["a"], lambda s, r: r is not None)
    assert net.challenge_onset() == "sec-exposure-007"


def test_the_onset_is_first_writer_wins():
    net.start_trace(False)
    net.set_trace_probe("first-probe")
    chal = httpx.Response(403, text="<html>captcha.awswaf.com</html>",
                          headers={"content-type": "text/html"},
                          request=httpx.Request("GET", "http://t/"))
    net._watch_challenge(chal)
    net.set_trace_probe("second-probe")
    net._watch_challenge(chal)
    assert net.challenge_onset() == "first-probe"


def test_the_scope_still_holds_in_the_pool_beside_the_context_copy(monkeypatch):
    """scope_bound remains the explicit scope guarantee; the context copy carries the same scope. Both
    mechanisms agreeing is fine — a test pins that the copy did not REPLACE the guarantee with a loophole."""
    import socket
    from sloptic import egress

    # monkeypatch, NOT a raw assignment: this fake answers EVERY resolution with a public IP, and a raw
    # assignment would leak it into every later test in the suite — a POST to 127.0.0.1 would dial the
    # public IP, which silently drops packets, and the test would hang in connect forever (observed).
    monkeypatch.setattr(egress, "_real_getaddrinfo",
                        lambda h, p, *a, **k: [(2, 1, 6, "", ("93.184.216.34", p or 443))])

    def send(spec):
        try:
            socket.getaddrinfo(spec, 443)
            return spec, "delivered"
        except egress.EgressRefused:
            return spec, None

    with egress.origin_scope("https://target.test"):
        hit = probes._fan_out_first(send, ["victim.example"], lambda s, r: r is not None)
    assert hit is None                         # nothing delivered off origin, with BOTH mechanisms active


def test_concurrent_submits_each_get_their_own_context_copy():
    """Context.run is single-entry: workers reusing ONE shared Context object raise 'already entered' on
    concurrent submits, every send dies, and the probe silently reads clean (caught live: exposed-files /
    lfi / pipeline all went False in one run). Each submit must copy fresh."""
    delivered = []

    def send(spec):
        delivered.append(spec)
        return spec, "ok"

    specs = [f"s{i}" for i in range(40)]           # 40 concurrent submits against a pool of 8
    hit = probes._fan_out_first(send, specs, lambda s, r: r is not None, cap_check=None)
    assert hit is not None                         # a send actually COMPLETED (the shared-Context bug raised
                                                   # "already entered" in every concurrent worker -> hit None)
    assert len(delivered) >= 2                     # the pool delivered several, then short-circuited on the hit
