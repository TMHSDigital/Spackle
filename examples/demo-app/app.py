import hashlib
import hmac
import html
import json
import os
import pickle
import secrets
import subprocess
import tempfile
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import db

SECRET_KEY = "fixture-s3cr3t-k3y-4Vt8Qz1Lm6Xp9Rw"
HOST = "127.0.0.1"
NOTES_DIR = os.path.join(tempfile.gettempdir(), "spackle-demo-notes")
CONN = None


def parse_query(path):
    parsed = urlparse(path)
    return parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}


def as_json(status, payload):
    return status, "application/json", json.dumps(payload).encode()


def make_token(user_id):
    sig = hmac.new(SECRET_KEY.encode(), str(user_id).encode(), hashlib.sha256).hexdigest()
    return f"{user_id}.{sig}"


def user_from_token(header):
    token = (header or "").removeprefix("Bearer ")
    user_id = token.partition(".")[0]
    if user_id.isdigit() and hmac.compare_digest(make_token(int(user_id)).encode(), token.encode()):
        return int(user_id)
    return None


def handle_login(body, user):
    creds = json.loads(body or b"{}")
    user_id = db.check_login(CONN, creds.get("username", ""), creds.get("password", ""))
    if user_id is None:
        return as_json(401, {"error": "bad credentials"})
    return as_json(200, {"token": make_token(user_id)})


def handle_search(params, user):
    q = params.get("q", "")
    rows = db.search_notes(CONN, q)
    items = "".join(f"<li>{html.escape(title)}</li>" for _, title in rows)
    page = f"<html><body><h1>Results for {q}</h1><ul>{items}</ul></body></html>"
    return 200, "text/html; charset=utf-8", page.encode()


def handle_note(params, user):
    if user is None:
        return as_json(401, {"error": "sign in required"})
    row = db.get_note(CONN, int(params.get("id", "0")))
    if row is None:
        return as_json(404, {"error": "note not found"})
    return as_json(200, {"id": row[0], "title": row[2], "body": row[3]})


def handle_ping(params, user):
    host = params.get("host", "127.0.0.1")
    proc = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True, timeout=10)
    return 200, "text/plain; charset=utf-8", proc.stdout.encode()


def handle_file(params, user):
    name = params.get("name", "welcome.txt")
    with open(os.path.join(NOTES_DIR, name), "rb") as fh:
        return 200, "text/plain; charset=utf-8", fh.read()


def handle_fetch(params, user):
    url = params.get("url", "")
    with urllib.request.urlopen(url, timeout=5) as resp:
        return 200, "text/plain; charset=utf-8", resp.read(65536)


def handle_import(body, user):
    if user is None:
        return as_json(401, {"error": "sign in required"})
    notes = pickle.loads(body)
    ids = [db.add_note(CONN, user, note["title"], note["body"]) for note in notes]
    return as_json(201, {"imported": ids})


GET_ROUTES = {
    "/search": handle_search,
    "/note": handle_note,
    "/ping": handle_ping,
    "/file": handle_file,
    "/fetch": handle_fetch,
}
POST_ROUTES = {"/login": handle_login, "/import": handle_import}


class Handler(BaseHTTPRequestHandler):
    def dispatch(self, routes, body=None):
        path, params = parse_query(self.path)
        handler = routes.get(path)
        if handler is None:
            self.respond(404, "text/plain; charset=utf-8", b"not found")
            return
        try:
            user = user_from_token(self.headers.get("Authorization"))
            status, ctype, payload = handler(params if body is None else body, user)
        except Exception:
            status, ctype, payload = 500, "text/plain; charset=utf-8", traceback.format_exc().encode()
        self.respond(status, ctype, payload)

    def respond(self, status, ctype, payload):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.dispatch(GET_ROUTES)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.dispatch(POST_ROUTES, self.rfile.read(length))


def main():
    global CONN
    os.makedirs(NOTES_DIR, exist_ok=True)
    with open(os.path.join(NOTES_DIR, "welcome.txt"), "w", encoding="utf-8") as fh:
        fh.write("Welcome to the notes demo.\n")
    passwords = {"alice": secrets.token_urlsafe(9), "bob": secrets.token_urlsafe(9)}
    CONN = db.connect()
    db.seed(CONN, passwords)
    for name, password in passwords.items():
        print(f"seeded user {name} with password {password}")
    port = int(os.environ.get("PORT", "8081"))
    print(f"notes demo listening on http://{HOST}:{port}")
    HTTPServer((HOST, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
