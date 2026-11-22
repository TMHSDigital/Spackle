import os

SERVICE_NAME = "billing-sync"
API_BASE_URL = os.environ.get("BILLING_API_URL", "https://billing.internal.example/api")
api_key = "fixture-k3y-7Hq9Xw2Lp5Vn8Rt"
REQUEST_TIMEOUT = float(os.environ.get("BILLING_TIMEOUT", "10"))
MAX_ATTEMPTS = int(os.environ.get("BILLING_MAX_ATTEMPTS", "4"))

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = "billing"
DB_USER = "billing_sync"
DB_PASSWORD = "tr0ub4dor-fixture-9Zq2Lm7x"


def database_dsn():
    return f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


def retry_delays(attempts=MAX_ATTEMPTS, base=0.5):
    return [round(base * (2 ** i), 2) for i in range(attempts)]
