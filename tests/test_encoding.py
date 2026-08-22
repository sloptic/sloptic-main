"""qa-input-002: international / multibyte input robustness. One inline app exposes each round-trip outcome --
UTF-8-clean echo, latin-1 mojibake, `?` substitution, correct HTML-entity encoding, a 500 on non-ASCII, and a
non-echoing field -- so the predicate's two rungs (corruption 32 / server-error 72) and its precision guards
(entity-encoding is clean, a broken ASCII baseline is N/A, a non-echo can't be judged) are each exercised."""
import http.server
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from sloptic.probes import _encoding_corrupted, international_input_breaks
from sloptic.schema import Endpoint, Form, Profile


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        has_unicode = any(ord(c) > 127 for c in q)
        if path == "/echo":                                      # UTF-8 clean round trip
            self._send("<p>%s</p>" % q)
        elif path == "/latin1":                                  # utf-8 bytes shown as latin-1 -> mojibake
            self._send("<p>%s</p>" % q.encode("utf-8").decode("latin-1"))
        elif path == "/qmark":                                   # non-ASCII replaced by '?' (latin1 column)
            self._send("<p>%s</p>" % "".join(c if ord(c) < 128 else "?" for c in q))
        elif path == "/entity":                                  # correct HTML-entity encoding -> NOT corruption
            self._send("<p>%s</p>" % q.encode("ascii", "xmlcharrefreplace").decode())
        elif path == "/crash":                                   # 500 on non-ASCII, 200 on ASCII
            self._send("boom", code=500) if has_unicode else self._send("<p>ok</p>")
        elif path == "/noecho":                                  # 200 but never echoes the value
            self._send("<p>thanks</p>")
        elif path == "/brokenascii":                             # 500 even on the ASCII baseline
            self._send("broken", code=500)
        else:
            self._send("<p>home</p>")


@pytest.fixture
def app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


class _Probe:
    probe = {"max_attempts": 60}


def _ctx(url, **profile_kw):
    prof = Profile(base_url=url, **profile_kw)
    return type("C", (), {"base_url": url, "profile": prof, "headers": None, "client": None, "evidence": {}})()


def _ep(path):
    return Endpoint(path=path, method="get", query_params=["q"], raw_path=path)


# ---- the detector, in isolation ---------------------------------------------------------------------------

def test_detector_clean_when_value_survives():
    assert _encoding_corrupted('<p>HLenc1 日本語</p>', "HLenc1", "日本語") is False


def test_detector_clean_on_html_entity_encoding():
    assert _encoding_corrupted('<p>HLenc1 &#26085;&#26412;</p>', "HLenc1", "日本") is False


def test_detector_fires_on_mojibake_and_qmark_and_fffd():
    assert _encoding_corrupted('<p>HLenc1 ' + "日".encode("utf-8").decode("latin-1") + '</p>', "HLenc1", "日") is True
    assert _encoding_corrupted('<p>HLenc1 ???</p>', "HLenc1", "日本語") is True
    assert _encoding_corrupted('<p>HLenc1 ��</p>', "HLenc1", "日本") is True


def test_detector_abstains_when_not_reflected_or_percent_encoded():
    assert _encoding_corrupted('<p>nothing here</p>', "HLenc1", "日") is None      # value not reflected
    assert _encoding_corrupted('<p>HLenc1 %E6%97%A5</p>', "HLenc1", "日") is None   # %-encoded, not corruption


def test_detector_abstains_when_value_stripped_even_if_template_has_latin1():
    # the value is stripped (delimiter immediately after the sentinel); a latin-1 char later in the TEMPLATE must
    # not be mistaken for mojibake of our value.
    assert _encoding_corrupted('<p>HLenc1</p><footer>café</footer>', "HLenc1", "日本") is None


# ---- the predicate, end to end ----------------------------------------------------------------------------

def test_clean_utf8_app_does_not_fire(app):
    assert international_input_breaks(_ctx(app, endpoints=[_ep("/echo")]), _Probe()) is False


def test_latin1_mojibake_fires_corruption(app):
    ctx = _ctx(app, endpoints=[_ep("/latin1")])
    assert international_input_breaks(ctx, _Probe()) is True
    assert ctx.evidence.get("corrupted") and ctx.evidence.get("kind") == "corruption"
    assert "server_error" not in ctx.evidence                    # corruption rung only -> 32, not 72


def test_qmark_substitution_fires_corruption(app):
    assert international_input_breaks(_ctx(app, endpoints=[_ep("/qmark")]), _Probe()) is True


def test_html_entity_encoding_is_clean(app):
    assert international_input_breaks(_ctx(app, endpoints=[_ep("/entity")]), _Probe()) is False


def test_500_on_unicode_fires_server_error(app):
    ctx = _ctx(app, endpoints=[_ep("/crash")])
    assert international_input_breaks(ctx, _Probe()) is True
    assert ctx.evidence.get("server_error") and ctx.evidence.get("kind") == "500"   # the 72 rung


def test_non_echoing_field_is_not_a_false_positive(app):
    assert international_input_breaks(_ctx(app, endpoints=[_ep("/noecho")]), _Probe()) is False


def test_broken_ascii_baseline_is_na(app):
    # the endpoint 500s even on ASCII -> broken regardless of encoding -> never blamed on it (N/A, not a fire)
    assert international_input_breaks(_ctx(app, endpoints=[_ep("/brokenascii")]), _Probe()) is None


def test_na_without_a_text_surface(app):
    assert international_input_breaks(_ctx(app), _Probe()) is None
