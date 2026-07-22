"""Reproducibility: every attack finding carries a `repro` block — the exact request (payload embedded)
an auditor pastes into Burp. Locks the helpers, the curl renderer, and that real fires populate it."""
import pathlib
import sys

import httpx

from hacklet_runner.probes import _repro, _repro_from_resp

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from stats import _curl  # noqa: E402


def test_repro_embeds_payload_and_filters_headers():
    r = _repro("POST", "https://x/api?q=1'", headers={"apikey": "sk", "user-agent": "x"},
               body='{"a":1}', status=500, ms=42, matched="sqlite3.OperationalError")
    assert r["method"] == "POST" and r["url"] == "https://x/api?q=1'"
    assert r["headers"] == {"apikey": "sk"}          # security-relevant kept, user-agent dropped
    assert r["body"] == '{"a":1}' and r["status"] == 500 and r["ms"] == 42


def test_repro_from_resp_captures_absolute_request():
    # a completed httpx response carries the resolved absolute request + status; repro lifts them verbatim
    resp = httpx.Response(200, request=httpx.Request("GET", "https://h/rest/v1/users?select=*",
                                                     headers={"apikey": "anon"}))
    r = _repro_from_resp(resp, matched="3 rows")
    assert r["url"] == "https://h/rest/v1/users?select=*" and r["headers"]["apikey"] == "anon"
    assert r["status"] == 200 and r["matched"] == "3 rows"


def test_repro_from_resp_survives_a_streaming_multipart_request():
    # a file-upload probe sends a multipart (files=) request; the send consumes the stream, so req.content
    # raises httpx.RequestNotRead — a StreamError, NOT an httpx.HTTPError, so it escaped the pipeline's fetch
    # guard and DNF'd the whole grade (179/1043 apps in the v6 corpus). _repro_from_resp must degrade, not raise.
    req = httpx.Request("POST", "https://h/upload",
                        files={"f": ("shell.php", b"<?php echo 1;", "application/octet-stream")}, data={"g": "h"})
    r = _repro_from_resp(httpx.Response(200, request=req), matched="uploaded webshell executed")
    assert r["method"] == "POST" and r["url"] == "https://h/upload"   # method/url/headers still captured
    assert "body" not in r                                            # unreadable stream body -> omitted, no crash
    assert r["status"] == 200 and r["matched"] == "uploaded webshell executed"


def test_curl_is_pasteable_and_shell_escapes_the_payload_quote():
    r = _repro("GET", "https://h/x?q=1%27", headers={"apikey": "k"}, matched="hit")
    c = _curl(r)
    assert c.startswith("curl -sS -i -X GET 'https://h/x?q=1%27'") and "-H 'apikey: k'" in c
    # a raw single quote (in a body) is shell-escaped so it can't break the command
    assert "--data 'a'\\''b'" in _curl(_repro("POST", "https://h/x", body="a'b"))


def test_sqli_fire_records_a_replayable_repro():
    from hacklet_runner.deploy import SubprocessDeployer
    from hacklet_runner.discovery import discover
    from hacklet_runner.probes import api_sqli

    d = SubprocessDeployer(str(pathlib.Path(__file__).resolve().parent.parent / "references" / "jsonapi" / "app.py"))
    url = d.deploy().base_url
    try:
        ctx = type("C", (), {"base_url": url, "profile": discover(url), "headers": None,
                             "client": None, "evidence": {}})()
        assert api_sqli(ctx, type("P", (), {"probe": {"max_attempts": 80, "time_delay": 1}})()) is True
        repro = ctx.evidence.get("repro")
        assert repro and repro["method"] == "GET"
        assert "1%27" in repro["url"]                 # the lone-quote payload is embedded in the request
        assert "sqlite3" in (repro.get("matched") or "")
    finally:
        d.teardown()
