"""Minimal reference app (stdlib only). The not_applicable anchor.

A trivial app with no form, no DB, no extra endpoints — so surface-dependent probes (SQLi, XSS)
resolve to not_applicable rather than firing. It does set the security header, so the universal
header probe reads clean. Also exercises the Limited-Engagement floor.
"""
import http.server
import os

PORT = int(os.environ.get("PORT", "8080"))

HOME = b'<!doctype html><html lang="en"><head><title>minimal</title><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="A minimal page."></head><body><h1>minimal</h1><p>nothing to see here.</p></body></html>'


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            return self._send(200, HOME)
        return self._send(404, "not found")


if __name__ == "__main__":
    # Bind 0.0.0.0: reachable as a dev/CI subprocess AND via the published port inside the
    # DockerDeployer container (a 127.0.0.1 binding is unreachable through Docker's port forward).
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
