"""audit_coverage is HARD-capped: a slow/hung OpenRouter call is abandoned at the deadline (one call once
trickled 1486s past the soft httpx timeout), and a failed / malformed response never raises. httpx stubbed."""
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import deploy_and_grade as dg  # noqa: E402


def _resp(status, content):
    return type("R", (), {"status_code": status,
                          "json": lambda self=None: {"choices": [{"message": {"content": content}}]}})()


def test_audit_returns_parsed_json_on_a_fast_call(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    payload = {"missed": [], "page_state": "working", "notes": "ok"}
    monkeypatch.setattr(dg.httpx, "post", lambda *a, **k: _resp(200, json.dumps(payload)))
    assert dg.audit_coverage("headings: [Login]", {"routes": []}, timeout=5) == payload


def test_audit_hard_caps_a_slow_call(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")

    def _slow(*a, **k):
        time.sleep(3)                        # simulate a hung / trickling response
        return _resp(200, "{}")
    monkeypatch.setattr(dg.httpx, "post", _slow)
    t0 = time.monotonic()
    out = dg.audit_coverage("headings: [Login]", {"routes": []}, timeout=0.2)
    assert out is None                       # abandoned at the 0.2s deadline
    assert time.monotonic() - t0 < 2.0       # did NOT block for the full 3s call


def test_audit_never_raises_on_malformed_json(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    monkeypatch.setattr(dg.httpx, "post", lambda *a, **k: _resp(200, "not json at all"))
    assert dg.audit_coverage("headings: [Login]", {"routes": []}, timeout=5) is None


def test_audit_none_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert dg.audit_coverage("headings: [Login]", {"routes": []}) is None
