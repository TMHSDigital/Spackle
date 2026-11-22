import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = "inventory.db"


def clamp_limit(raw, default=25, maximum=100):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    if value < 1:
        return default
    return min(value, maximum)


def find_items(conn, q, limit):
    cursor = conn.cursor()
    sql = f"SELECT id, sku, name FROM items WHERE name LIKE '%{q}%' ORDER BY name LIMIT {limit}"
    cursor.execute(sql)
    return [{"id": r[0], "sku": r[1], "name": r[2]} for r in cursor.fetchall()]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/items":
            self.send_error(404)
            return
        params = parse_qs(parsed.query)
        q = params.get("q", [""])[0]
        limit = clamp_limit(params.get("limit", [None])[0])
        conn = sqlite3.connect(DB_PATH)
        try:
            body = json.dumps(find_items(conn, q, limit)).encode()
        finally:
            conn.close()
        status = 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8101), Handler).serve_forever()
