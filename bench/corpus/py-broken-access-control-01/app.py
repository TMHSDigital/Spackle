import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

import store


def serialize(invoice):
    return {"id": invoice.id, "amount": store.format_amount(invoice.amount_cents), "memo": invoice.memo}


def route(path, user_id):
    if path == "/invoices":
        return 200, [serialize(inv) for inv in store.invoices_for(user_id)]
    if path.startswith("/invoices/"):
        try:
            invoice_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            return 400, {"error": "invalid invoice id"}
        invoice = store.get_invoice(invoice_id)
        if invoice is None:
            return 404, {"error": "invoice not found"}
        return 200, serialize(invoice)
    return 404, {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        user_id = store.user_for_session(self.headers.get("X-Session", ""))
        if user_id is None:
            status, payload = 401, {"error": "sign in required"}
        else:
            status, payload = route(urlparse(self.path).path, user_id)
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8107), Handler).serve_forever()
