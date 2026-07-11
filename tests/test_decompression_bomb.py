"""Decompression-bomb resistance — an endpoint that decompresses gzip request bodies must cap the
expanded size. Fires when it decompresses uncapped, clean when it caps (413), N/A when it doesn't
decompress request bodies at all. The probe payload expands to ~50MB (safe), never a real OOM bomb."""
import gzip
import http.server
import json
import threading
import zlib

import pytest

from hacklet_runner.probes import decompression_bomb
from hacklet_runner.schema import Profile


def _handler(mode):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _end(self, code):
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            gz = "gzip" in self.headers.get("Content-Encoding", "").lower()
            if gz and mode != "nodecomp":                # nodecomp: ignore the encoding (safe, no bomb)
                if mode == "capped":
                    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    raw = d.decompress(raw, 1_000_000)
                    if d.unconsumed_tail:
                        return self._end(413)            # over the cap -> reject before expanding
                else:
                    raw = gzip.decompress(raw)           # uncapped -> a bomb expands unchecked
            try:
                json.loads(raw)
                self._end(200)
            except Exception:
                self._end(400)
    return _H


@pytest.fixture
def server():
    servers = []

    def _make(mode):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(mode))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return "http://127.0.0.1:%d" % srv.server_address[1]

    yield _make
    for s in servers:
        s.shutdown()


class _Probe:
    probe = {}


def _ctx(url):
    return type("C", (), {"base_url": url, "profile": Profile(base_url=url),
                          "headers": None, "client": None, "evidence": {}})()


def test_dos_fires_on_uncapped_decompression(server):
    assert decompression_bomb(_ctx(server("uncapped")), _Probe()) is True


def test_dos_clean_when_capped(server):
    assert decompression_bomb(_ctx(server("capped")), _Probe()) is False


def test_dos_na_when_no_decompression(server):
    assert decompression_bomb(_ctx(server("nodecomp")), _Probe()) is None
