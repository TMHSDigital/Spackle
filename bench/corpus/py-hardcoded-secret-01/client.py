import json
import time
import urllib.error
import urllib.request

import config


def build_request(path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(config.API_BASE_URL + path, data=data)
    req.add_header("Authorization", "Bearer " + config.api_key)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", config.SERVICE_NAME)
    return req


def send(req):
    last_error = None
    for delay in config.retry_delays():
        try:
            with urllib.request.urlopen(req, timeout=config.REQUEST_TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.URLError as exc:
            last_error = exc
            time.sleep(delay)
    raise RuntimeError("billing API unavailable") from last_error


def fetch_invoices(page=1):
    return send(build_request(f"/invoices?page={int(page)}"))


def push_payment(invoice_id, amount_cents):
    return send(build_request("/payments", {"invoice": int(invoice_id), "amount": int(amount_cents)}))
