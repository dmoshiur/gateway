"""Central configuration for the MFS Payment Gateway.

Every value can be overridden via environment variables so the same code runs
locally (SQLite) and in production (PostgreSQL + gunicorn behind TLS).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    # --- Flask ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-change-me")
    JSON_SORT_KEYS = False
    # Do not trust proxies in dev; behind nginx/heroku set X-Forwarded-* handling.
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "https")

    # --- Database ---
    # SQLite by default (zero-config). Point DATABASE_PATH at a real file in prod.
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "data" / "gateway.db"))

    # --- HMAC / request-signing security ---
    # Requests older than this many seconds are rejected (replay protection).
    HMAC_TIMESTAMP_WINDOW = int(os.environ.get("HMAC_TIMESTAMP_WINDOW", "300"))
    # Nonces are remembered for this many seconds to block exact replays.
    NONCE_TTL = int(os.environ.get("NONCE_TTL", "600"))
    # Hosted-checkout tokens (signed) expire after this many seconds.
    CHECKOUT_TOKEN_TTL = int(os.environ.get("CHECKOUT_TOKEN_TTL", "900"))
    # Amount matching tolerance (tk) — protects against float/format drift.
    AMOUNT_TOLERANCE = float(os.environ.get("AMOUNT_TOLERANCE", "0.001"))

    # --- Seed / first-boot demo data ---
    # WARNING: these are demo credentials. Override in production.
    SEED_ADMIN_USERNAME = os.environ.get("SEED_ADMIN_USERNAME", "admin")
    SEED_ADMIN_PASSWORD = os.environ.get("SEED_ADMIN_PASSWORD", "admin123")
    SEED_MERCHANT_NAME = os.environ.get("SEED_MERCHANT_NAME", "Demo Store Ltd.")
    SEED_MERCHANT_EMAIL = os.environ.get("SEED_MERCHANT_EMAIL", "merchant@demo.com")
    SEED_MERCHANT_PASSWORD = os.environ.get("SEED_MERCHANT_PASSWORD", "demo123")
    SEED_DEVICE_ID = os.environ.get("SEED_DEVICE_ID", "termux-demo-device")
    SEED_DEVICE_SECRET = os.environ.get("SEED_DEVICE_SECRET", "demo-device-secret")
