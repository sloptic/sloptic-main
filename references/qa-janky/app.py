"""QA / performance jank reference (stdlib only).

SECURITY-clean (all security headers set, no injection sink, no secrets, no exposed files) but
deliberately BAD on quality + performance — the calibration anchor for the QA and perf probes,
isolated from the security axis (references/vulnerable conflates the two). Fires: crash-resistance
(/profile + /api/items 500 on input, /%ff%fe decode crash), compression (uncompressed homepage),
speed (/heavy slow TTFB), load-resilience (/report 5xx under a burst), error-hygiene (/crash leaks a
stack trace), and — with --browser — console errors + a11y violations + slow first paint. Every
SECURITY probe must read clean/N/A here.
"""
import http.server
import os
import time
import urllib.parse

PORT = int(os.environ.get("PORT", "8080"))

# a sizeable, INACCESSIBLE homepage that THROWS on load: no lang attr, an unlabeled input, an image
# with no alt text, and a script that references an undefined function.
HOME = ("<!doctype html><html><head><title>janky dashboard</title></head><body>"
        "<h1>dashboard</h1>"
        "<form action='/' method='get'><input name='q'><button>search</button></form>"
        "<img src='/logo.png'>"
        "<script>nonexistent_function_boom();</script>"
        + "".join("<img src='/img%d.png'>" % i for i in range(60))   # chatty: >50 requests to render
        + "<p>filler paragraph of representative body text. </p>" * 40
        + "</body></html>").encode()

_SEC_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        for k, v in _SEC_HEADERS:          # security headers on EVERY response -> header probes clean
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            path = urllib.parse.unquote(self.path, errors="strict").split("?")[0]  # naive strict decode
        except (UnicodeDecodeError, ValueError):
            self._send(500, b"decode error")               # /%ff%fe -> 500 (qa-crash-007)
            return
        if path == "/":
            time.sleep(0.9)                                 # slow homepage TTFB (> perf profile 0.8s)
            self._send(200, HOME)                           # + uncompressed, chatty, inaccessible, throws
        elif path in ("/heavy", "/slow"):
            time.sleep(1.6)                                 # slow TTFB / first paint
            self._send(200, b"<html><body>slow response</body></html>")
        elif path == "/report":
            self._send(500, b"report generation failed")    # falls over -> load-resilience 5xx
        elif path == "/crash":
            self._send(500, b'Traceback (most recent call last):\n  File "app.py", line 42, in handler\n'
                            b'    generate()\nNameError: name generate is not defined')  # error-hygiene
        else:
            self._send(404, b"not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path in ("/profile", "/api/items"):
            self._send(500, b"unhandled exception while processing request")  # crashes on input, not 400
        else:
            self._send(404, b"not found")


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
