import hashlib
import hmac
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
"""


def connect(path="accounts.db"):
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    return conn


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def register(conn, email, password):
    if len(password) < 10:
        raise ValueError("password too short")
    conn.execute(
        "INSERT INTO accounts (email, password_hash) VALUES (?, ?)",
        (email.lower(), hash_password(password)),
    )
    conn.commit()


def authenticate(conn, email, password):
    row = conn.execute(
        "SELECT password_hash FROM accounts WHERE email = ?", (email.lower(),)
    ).fetchone()
    if row is None:
        return False
    return hmac.compare_digest(row[0], hash_password(password))
