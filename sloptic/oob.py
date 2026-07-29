"""Out-of-band interaction server ("collaborator") for SSRF / XXE detection.

The runner starts a listener the TARGET can reach and a probe injects a URL/entity pointing at it with
a unique token. If the target's SERVER fetches it (an SSRF, or an XXE external entity), the listener
records the token — confirmed out-of-band, no reflection needed, near-zero false positives (a unique
random URL is only requested if the server actually made the request). Candidate callback hosts cover a
same-host target (127.0.0.1 / LAN IP) and a Docker target (the docker0 gateway / host.docker.internal).
"""
from __future__ import annotations

import http.server
import socket
import threading


def _lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))          # no packet sent; just selects the default-route interface
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def callback_hosts() -> list[str]:
    """Addresses the target might reach the runner at, most-likely first."""
    hosts = ["127.0.0.1", "172.17.0.1", "host.docker.internal"]
    ip = _lan_ip()
    if ip and ip not in hosts:
        hosts.insert(1, ip)
    return hosts


class Collaborator:
    """A throwaway HTTP listener that records the path token of any request it receives."""

    def __init__(self):
        self.hits: set[str] = set()
        collab = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                collab.hits.add(self.path.strip("/").split("?")[0])
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_GET
            do_HEAD = do_GET

        self._srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _H)
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def url(self, host: str, token: str) -> str:
        return "http://%s:%d/%s" % (host, self.port, token)

    def received(self, token: str) -> bool:
        return token in self.hits

    def close(self):
        self._srv.shutdown()
