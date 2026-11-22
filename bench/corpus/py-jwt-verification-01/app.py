import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import tokens


def current_claims(headers):
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return None
    try:
        return tokens.decode(value[len("Bearer "):])
    except (tokens.TokenError, ValueError):
        return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        claims = current_claims(self.headers)
        if claims is None:
            status, payload = 401, {"error": "invalid token"}
        elif self.path == "/admin/report" and claims.get("role") != "admin":
            status, payload = 403, {"error": "admin role required"}
        else:
            status, payload = 200, {"subject": claims.get("sub"), "role": claims.get("role")}
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8106), Handler).serve_forever()
