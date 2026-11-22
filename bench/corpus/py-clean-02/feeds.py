import hashlib
import hmac
import os
import re
import secrets
import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"feeds.example.com", "status.example.com"}
URL_PATTERN = re.compile(r"https://[a-z0-9.-]+(/[A-Za-z0-9._~/-]*)?(\?[A-Za-z0-9=&._-]*)?")
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()
_cache = {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def cache_key(url):
    return hashlib.md5(url.encode("utf-8"), usedforsecurity=False).hexdigest()


def new_session_id():
    return secrets.token_urlsafe(32)


def signature_valid(body, signature_hex):
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode(), signature_hex.encode())


def fetch_feed(url):
    if not URL_PATTERN.fullmatch(url):
        raise ValueError("unsupported url")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("destination not allowed")
    key = cache_key(url)
    if key not in _cache:
        with _opener.open(url, timeout=5) as resp:
            _cache[key] = resp.read(1 << 20)
    return _cache[key]


def handle_webhook(body, signature_hex):
    if not signature_valid(body, signature_hex):
        return 401, b"bad signature"
    return 200, fetch_feed(body.decode("utf-8").strip())
