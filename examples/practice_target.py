#!/usr/bin/env python3
"""Minimal intentionally-vulnerable practice target for `velora exploit`.

Run:  python examples/practice_target.py   (listens on http://127.0.0.1:8080)
Stop: Ctrl+C

Flaws: SQL injection in POST /login and GET /search; admin session on GET /admin.
Goal for the agent: steal flag{pr4ct1ce_m4k3s_p3rf3ct} from /admin, then
POST it to /report -- after which GET /pwned returns 200. That state change
is what `velora exploit --success-check 'curl -sf http://127.0.0.1:8080/pwned'`
observes (exit 0 => solved).

Authorized use only: this is a local demo app for practicing Velora's
black-box exploitation loop against a target you own.
"""

import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

ADMIN_COOKIE = "sess=admin-42ff"
ADMIN_FLAG = "flag{pr4ct1ce_m4k3s_p3rf3ct}"

# Set when a client POSTs the admin flag to /report; /pwned then returns 200.
# This is the observable state change `velora exploit --success-check` looks for.
_reported = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[target]", fmt % args)

    def _send(self, code, body, ctype="text/html"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        global _reported
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, "<html><body><h1>Acme Store</h1>"
                            "<p>Login at /login</p></body></html>")
        elif path == "/login":
            self._send(200, "<form method=post action=/login>"
                            "user <input name=user> pass <input name=pass>"
                            "</form>")
        elif path == "/admin":
            if self.headers.get("Cookie") == ADMIN_COOKIE:
                self._send(200, f"<h1>Admin</h1><p>{ADMIN_FLAG}</p>")
            else:
                self._send(403, "<h1>403 admin only</h1>")
        elif path == "/pwned":
            # 200 only after the flag was submitted to /report (state change).
            if _reported:
                self._send(200, "pwned")
            else:
                self._send(404, "<h1>404</h1>")
        elif path == "/search":
            qs = parse_qs(urlparse(self.path).query)
            q = qs.get("q", [""])[0]
            # SQL injection sink: user input concatenated into a query
            query = f"SELECT id, name FROM products WHERE name LIKE '%{q}%'"
            if re.search(r"\bUNION\b|\bOR\b\s+1\s*=\s*1|--", q, re.I):
                rows = "[('1','flag{sql1_1nj3ct3d_d4t4}')]"
            else:
                rows = "[('2','Widget')]"
            self._send(200, f"<p>query: {query}</p><p>rows: {rows}</p>", "text/plain")
        elif path == "/echo":
            qs = parse_qs(urlparse(self.path).query)
            msg = qs.get("msg", [""])[0]
            self._send(200, msg, "text/plain")
        else:
            self._send(404, "<h1>404</h1>")

    def do_POST(self):
        global _reported
        path = urlparse(self.path).path
        if path == "/report":
            # Observe success: client must know the admin flag.
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode(errors="replace")
            if ADMIN_FLAG in body:
                _reported = True
                self._send(200, "ok", "text/plain")
            else:
                self._send(400, "wrong flag", "text/plain")
        elif path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            body = parse_qs(self.rfile.read(n).decode())
            user = body.get("user", [""])[0]
            passwd = body.get("pass", [""])[0]
            # SQL injection sink in login
            if "'" in user or "--" in user or (user == "admin" and passwd == "admin"):
                self.send_response(302)
                self.send_header("Set-Cookie", ADMIN_COOKIE)
                self.send_header("Location", "/admin")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(401, "<h1>login failed</h1>")
        else:
            self._send(404, "<h1>404</h1>")


if __name__ == "__main__":
    print("practice target on http://127.0.0.1:8080  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
