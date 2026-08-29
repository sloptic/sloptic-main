"""qa-errhyg-001 (leaks_error_detail): an induced error leaking a stack trace / DB error fires and now records
the MATCHED SNIPPET + a replayable repro (add-evidence), not just the leak type -- so the finding self-
adjudicates from the record instead of leaving a future audit to guess what leaked."""
import httpx

from sloptic import probes


def _resp(text, status=500):
    return httpx.Response(status, text=text, request=httpx.Request("GET", "https://app.com/crash"))


def _ctx():
    return type("C", (), {"evidence": {}})()


_P = type("P", (), {"probe": {}})


def test_stack_trace_leak_records_matched_snippet(monkeypatch):
    trace = 'Traceback (most recent call last):\n  File "app.py", line 42, in handler\n    raise ValueError("boom")'
    monkeypatch.setattr(probes, "_induce_error_responses", lambda ctx: [_resp(trace)])
    ctx = _ctx()
    assert probes.leaks_error_detail(ctx, _P()) is True
    assert ctx.evidence["leak"] == "stack-trace"
    assert "Traceback" in ctx.evidence["matched"]
    assert "stack trace" in ctx.evidence["repro"]["matched"]


def test_db_error_leak_records_matched_snippet(monkeypatch):
    body = 'near "SELCT": SQL syntax error at line 1'
    monkeypatch.setattr(probes, "_induce_error_responses", lambda ctx: [_resp(body)])
    ctx = _ctx()
    assert probes.leaks_error_detail(ctx, _P()) is True
    assert ctx.evidence["leak"] == "db-error"
    assert "SQL syntax" in ctx.evidence["matched"]


def test_clean_when_no_leak(monkeypatch):
    monkeypatch.setattr(probes, "_induce_error_responses", lambda ctx: [_resp("Something went wrong", 500)])
    ctx = _ctx()
    assert probes.leaks_error_detail(ctx, _P()) is False
    assert ctx.evidence["leak"] is None


def test_na_when_no_error_induced(monkeypatch):
    monkeypatch.setattr(probes, "_induce_error_responses", lambda ctx: [])
    ctx = _ctx()
    assert probes.leaks_error_detail(ctx, _P()) is None
