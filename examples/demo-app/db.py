import hashlib
import hmac
import sqlite3

SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT, shared INTEGER);
"""

SEED_NOTES = [
    (1, "Groceries", "eggs, flour, coffee", 1),
    (1, "Door code", "the side door code is in the safe", 0),
    (2, "Trip ideas", "Lisbon in May", 1),
    (2, "Salary notes", "ask for a review in March", 0),
]


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def normalize_title(title):
    return " ".join(str(title).split())[:80]


def connect():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript(SCHEMA)
    return conn


def seed(conn, passwords):
    for username, password in passwords.items():
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
    conn.executemany("INSERT INTO notes (owner_id, title, body, shared) VALUES (?, ?, ?, ?)", SEED_NOTES)
    conn.commit()


def check_login(conn, username, password):
    row = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row and hmac.compare_digest(row[1], hash_password(password)):
        return row[0]
    return None


def search_notes(conn, q):
    sql = f"SELECT id, title FROM notes WHERE shared = 1 AND title LIKE '%{q}%'"
    return conn.execute(sql).fetchall()


def get_note(conn, note_id):
    return conn.execute("SELECT id, owner_id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()


def add_note(conn, owner_id, title, body):
    cur = conn.execute(
        "INSERT INTO notes (owner_id, title, body, shared) VALUES (?, ?, ?, 0)",
        (owner_id, normalize_title(title), str(body)),
    )
    conn.commit()
    return cur.lastrowid
