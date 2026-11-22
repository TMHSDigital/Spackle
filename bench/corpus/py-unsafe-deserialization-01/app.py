import base64
import json
import pickle
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer

DEFAULT_PREFS = {"theme": "light", "page_size": 20}


def encode_prefs(prefs):
    return base64.urlsafe_b64encode(pickle.dumps(prefs)).decode()


def load_prefs(cookie_header):
    cookie = SimpleCookie()
    cookie.load(cookie_header or "")
    morsel = cookie.get("prefs")
    if morsel is None:
        return dict(DEFAULT_PREFS)
    raw = base64.urlsafe_b64decode(morsel.value)
    prefs = pickle.loads(raw)
    merged = dict(DEFAULT_PREFS)
    merged.update(prefs)
    return merged


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        prefs = load_prefs(self.headers.get("Cookie"))
        body = json.dumps(prefs).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", f"prefs={encode_prefs(prefs)}; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8103), Handler).serve_forever()
