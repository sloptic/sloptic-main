"""precision.py classification: a fire on a non-working / catch-all / vendor-field target is flagged as a
likely false positive; a real fire on a clean working app is left alone."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from precision import analyze  # noqa: E402


def _f(pid, pen=10, bundle="security", evidence=None):
    return {"probe_id": pid, "penalty": pen, "bundle": bundle, "evidence": evidence or {}, "count": 1}


def _rec(repo, slop, findings, page_state=None):
    r = {"repo": repo, "slop_score": slop, "findings": findings}
    if page_state:
        r["coverage_audit"] = {"page_state": page_state}
    return r


def test_flags_phantom_and_gating_fps_but_keeps_real_fires():
    recs = [
        # broken app -> the WHOLE surface is hallucinated, so every finding is phantom (a gating gap)
        _rec("gh/broken", 80, [_f("sec-sqli-004", 40), _f("qa-a11y-001", 26, "qa")], page_state="broken"),
        # working catch-all (soft-404 probe fired) -> server-side fires suspect, header fire still real
        _rec("gh/catchall", 60, [_f("sec-csrf-001", 25), _f("qa-http-001", 8, "qa"), _f("sec-headers-002", 12)],
             page_state="working"),
        # working, no catch-all -> nothing flagged (real fires left alone)
        _rec("gh/clean", 30, [_f("sec-headers-002", 12), _f("qa-a11y-001", 26, "qa")], page_state="working"),
        # XSS "reflection" into a Cloudflare anti-bot field -> the vendor's, not the app's
        _rec("gh/vendor", 30, [_f("sec-xss-001", 30, evidence={"field": "cf-turnstile-response"})], page_state="working"),
    ]
    a = analyze(recs)
    flagged = {(repo, pid) for repo, pid, *_ in a["flagged"]}
    assert ("gh/broken", "sec-sqli-004") in flagged and ("gh/broken", "qa-a11y-001") in flagged  # non-working -> ALL
    assert ("gh/catchall", "sec-csrf-001") in flagged           # phantom-sensitive on a catch-all host
    assert ("gh/catchall", "sec-headers-002") not in flagged    # a missing header is real even on a catch-all
    assert ("gh/clean", "sec-headers-002") not in flagged and ("gh/clean", "qa-a11y-001") not in flagged  # clean untouched
    assert ("gh/vendor", "sec-xss-001") in flagged              # vendor anti-bot field reflection
    assert a["nonworking_apps"] == 1 and a["nonworking_slop"] == 80   # the 404 app's entire score is phantom
    assert a["catchall_apps"] == 1
    assert a["per_probe"]["sec-csrf-001"] == [1, 1]              # 1 fire, 1 suspect
    assert a["per_probe"]["sec-headers-002"][1] == 0            # never suspect (real everywhere)
