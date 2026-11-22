import json
import math
from http.server import BaseHTTPRequestHandler, HTTPServer

ALLOWED_NAMES = {"pi": math.pi, "e": math.e, "sqrt": math.sqrt, "log": math.log}
MAX_BODY = 4096


def evaluate(expression):
    return eval(expression, {"__builtins__": {}}, dict(ALLOWED_NAMES))


def handle(raw):
    try:
        expression = str(json.loads(raw)["expression"])
        return 200, {"result": evaluate(expression)}
    except Exception:
        return 400, {"error": "invalid expression"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/evaluate":
            self.send_error(404)
            return
        length = min(int(self.headers.get("Content-Length", "0")), MAX_BODY)
        status, payload = handle(self.rfile.read(length))
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8108), Handler).serve_forever()
