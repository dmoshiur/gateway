"""SQLite persistence layer for the gateway.

Designed to be swappable: every access goes through get_db() / query() /
execute() so the module can be replaced with a PostgreSQL adapter without
touching the route handlers.

Schema:
    admins        — superadmin logins (full system control)
    merchants     — merchant accounts (own API keys + devices + transactions)
    api_keys      — unlimited API keys per merchant (public key + HMAC secret)
    devices       — Termux/Android listener devices (device_id + HMAC secret)
    sms_logs      — every parsed MFS SMS (the source of truth for verification)
    transactions  — checkout / verify attempts (pending → verified / mismatch)
    nonces        — short-lived HMAC nonce store (replay protection)
"""
import os
import sqlite3
import threading
from datetime import datetime, timezone

from .config import Config

_local = threading.local()

# --------------------------------------------------------------------------- #
# Connection management
# --------------------------------------------------------------------------- #
def _connect():
    db_path = Config.DATABASE_PATH
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db():
    """Return a thread-local connection (created lazily)."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


def close_db(_e=None):
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
        _local.conn = None


def query(sql, params=(), one=False):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, params=()):
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'superadmin',
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS merchants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id  INTEGER NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,
    api_key      TEXT UNIQUE NOT NULL,
    api_secret   TEXT NOT NULL,
    is_active    INTEGER NOT NULL DEFAULT 1,
    last_used_at TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    device_id     TEXT UNIQUE NOT NULL,
    device_secret TEXT NOT NULL,
    merchant_id   INTEGER REFERENCES merchants(id) ON DELETE SET NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    last_seen_at  TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sms_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    provider       TEXT NOT NULL,
    provider_key   TEXT,
    sender_number  TEXT,
    amount         REAL,
    trx_id         TEXT,
    sms_timestamp  TEXT,
    direction      TEXT DEFAULT 'credit',
    status         TEXT DEFAULT 'new',   -- new | matched | ignored
    raw            TEXT,
    device_id      TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sms_trx ON sms_logs(trx_id);
CREATE INDEX IF NOT EXISTS idx_sms_provider_amount ON sms_logs(provider, amount);

CREATE TABLE IF NOT EXISTS transactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id    INTEGER REFERENCES merchants(id) ON DELETE SET NULL,
    api_key_id     INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
    trx_id         TEXT NOT NULL,
    amount         REAL,
    provider       TEXT,
    customer_phone TEXT,
    status         TEXT DEFAULT 'pending',  -- pending | verified | mismatch | expired
    sms_log_id     INTEGER REFERENCES sms_logs(id) ON DELETE SET NULL,
    gateway_note   TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_tx_trx ON transactions(trx_id);

CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
);
"""


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()


# --------------------------------------------------------------------------- #
# Seed / demo data (first boot only)
# --------------------------------------------------------------------------- #
def _rows(sql, params=()):
    return query(sql, params)


def seed():
    """Idempotently create demo accounts and sample SMS logs."""
    from werkzeug.security import generate_password_hash
    from .auth import generate_api_key, generate_device_credentials

    ts = now_iso()

    if _rows("SELECT id FROM admins LIMIT 1"):
        return  # already seeded

    admin_id = execute(
        "INSERT INTO admins (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (Config.SEED_ADMIN_USERNAME, generate_password_hash(Config.SEED_ADMIN_PASSWORD),
         "superadmin", ts),
    ).lastrowid

    merchant_id = execute(
        "INSERT INTO merchants (name, email, password_hash, is_active, created_at) VALUES (?,?,?,1,?)",
        (Config.SEED_MERCHANT_NAME, Config.SEED_MERCHANT_EMAIL,
         generate_password_hash(Config.SEED_MERCHANT_PASSWORD), ts),
    ).lastrowid

    # One API key for the demo merchant.
    pub, sec = generate_api_key()
    execute(
        "INSERT INTO api_keys (merchant_id, label, api_key, api_secret, is_active, created_at) VALUES (?,?,?,?,1,?)",
        (merchant_id, "Primary key", pub, sec, ts),
    )

    # One Termux device.
    execute(
        "INSERT INTO devices (name, device_id, device_secret, merchant_id, is_active, created_at) VALUES (?,?,?,?,1,?)",
        ("Demo Termux Device", Config.SEED_DEVICE_ID, Config.SEED_DEVICE_SECRET, merchant_id, ts),
    )

    # Sample SMS logs so the checkout can be tested immediately.
    _seed_sms_logs()

    print("[gateway] Seeded demo data:")
    print(f"  superadmin  -> {Config.SEED_ADMIN_USERNAME} / {Config.SEED_ADMIN_PASSWORD}")
    print(f"  merchant    -> {Config.SEED_MERCHANT_EMAIL} / {Config.SEED_MERCHANT_PASSWORD}")
    print(f"  device      -> id={Config.SEED_DEVICE_ID}")
    print(f"  demo api    -> key={pub}")


def _seed_sms_logs():
    samples = [
        ("bKash", "bkash", "01712345678", 500.0, "8JX4A2B3C4", "credit"),
        ("Nagad", "nagad", "01823456789", 250.5, "NAGAD123456", "credit"),
        ("Rocket", "rocket", "01934567890", 1000.0, "ROCKET2024", "credit"),
        ("Upay", "upay", "01645678901", 750.0, "UPAY998877", "credit"),
        ("Tap", "tap", "01556789012", 300.0, "TAP555321", "credit"),
    ]
    ts = now_iso()
    for provider, key, sender, amount, trx, direction in samples:
        execute(
            "INSERT INTO sms_logs (provider, provider_key, sender_number, amount, trx_id, direction, status, raw, created_at) "
            "VALUES (?,?,?,?,?,?,'new',?,?)",
            (provider, key, sender, amount, trx, direction,
             f"[demo] {provider} receive {amount} from {sender} TrxID {trx}", ts),
        )
