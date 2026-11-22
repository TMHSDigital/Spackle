import json
import re
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

EXPORT_ROOT = "/srv/exports"
PROJECT_ROOT = "/srv/projects"
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")


def load_settings(path="/etc/service/settings.yaml"):
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def search_users(conn, term, limit=20):
    pattern = f"%{term}%"
    cur = conn.execute(
        "SELECT id, display_name FROM users WHERE display_name LIKE ? LIMIT ?",
        (pattern, int(limit)),
    )
    return [{"id": row[0], "name": row[1]} for row in cur.fetchall()]


def export_project(name):
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("invalid project name")
    target = f"{EXPORT_ROOT}/{name}.tar.gz"
    subprocess.run(["tar", "-czf", target, "-C", PROJECT_ROOT, name], check=True, timeout=60)
    return target


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        status, payload = 404, {"error": "not found"}
        if parsed.path == "/users":
            conn = sqlite3.connect("service.db")
            try:
                payload = search_users(conn, params.get("q", [""])[0])
                status = 200
            finally:
                conn.close()
        elif parsed.path == "/export":
            try:
                export_project(params.get("project", [""])[0])
                status, payload = 200, {"status": "exported"}
            except (ValueError, subprocess.SubprocessError):
                status, payload = 400, {"error": "export failed"}
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8109), Handler).serve_forever()
