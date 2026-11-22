import secrets
from dataclasses import dataclass


@dataclass
class Invoice:
    id: int
    owner_id: int
    amount_cents: int
    memo: str


_INVOICES = {
    1001: Invoice(1001, 1, 12900, "Annual plan"),
    1002: Invoice(1002, 2, 4900, "Monthly plan"),
    1003: Invoice(1003, 2, 990, "Add-on seats"),
}
_SESSIONS = {}


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    _SESSIONS[token] = user_id
    return token


def user_for_session(token):
    return _SESSIONS.get(token)


def invoices_for(user_id):
    return [inv for inv in _INVOICES.values() if inv.owner_id == user_id]


def get_invoice(invoice_id):
    return _INVOICES.get(invoice_id)


def format_amount(cents):
    return f"{cents // 100}.{cents % 100:02d}"
