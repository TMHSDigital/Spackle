import base64
import hashlib
import hmac
import json
import os
import time

SIGNING_KEY = os.environ["TOKEN_SIGNING_KEY"].encode()


class TokenError(Exception):
    pass


def b64decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(payload):
    header = b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64encode(json.dumps(payload).encode())
    mac = hmac.new(SIGNING_KEY, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64encode(mac)}"


def signature_matches(header, body, signature):
    expected = hmac.new(SIGNING_KEY, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return hmac.compare_digest(expected, b64decode(signature))


def decode(token):
    try:
        header, body, signature = token.split(".")
    except ValueError:
        raise TokenError("malformed token")
    signature_matches(header, body, signature)
    claims = json.loads(b64decode(body))
    if claims.get("exp", 0) < time.time():
        raise TokenError("token expired")
    return claims
