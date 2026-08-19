"""
SQLite data layer.

Single-writer friendly: WAL mode, one connection per Flask request via `g`.
All money values are integer paisa. All timestamps are UTC ISO-8601 strings.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

from .security import hash_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS merchants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',  -- active | suspended
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id  INTEGER NOT NULL REFERENCES merchants(id),
    key_id       TEXT UNIQUE NOT NULL,             -- pk_live_...
    secret       TEXT NOT NULL,                    -- sk_live_... (see README: at-rest note)
    label        TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active',   -- active | revoked
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT UNIQUE NOT NULL,             -- dev_...
    name         TEXT NOT NULL DEFAULT '',
    secret       TEXT NOT NULL,                    -- dsec_...
    status       TEXT NOT NULL DEFAULT 'active',   -- active | revoked
    last_seen_at TEXT,
    created_at   TEXT NOT NULL
);

-- Raw SMS-derived payment facts captured from Android devices.
CREATE TABLE IF NOT EXISTS sms_transactions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    provider           TEXT NOT NULL,
    sender             TEXT,
    amount_paisa       INTEGER NOT NULL,
    trxid              TEXT NOT NULL,
    device_id          TEXT,
    sms_timestamp      TEXT,
    raw_hash           TEXT,                        -- sha256 of raw SMS (privacy: raw body is NOT stored)
    status             TEXT NOT NULL DEFAULT 'unused',  -- unused | consumed | flagged
    matched_session_id TEXT,
    created_at         TEXT NOT NULL,
    UNIQUE(trxid COLLATE NOCASE)                    -- global replay protection
);

-- Merchant checkout orders.
CREATE TABLE IF NOT EXISTS payment_sessions (
    id             TEXT PRIMARY KEY,                -- ps_...
    merchant_id    INTEGER NOT NULL REFERENCES merchants(id),
    api_key_id     INTEGER REFERENCES api_keys(id),
    order_id       TEXT NOT NULL,
    amount_paisa   INTEGER NOT NULL,
    currency       TEXT NOT NULL DEFAULT 'BDT',
    customer_name  TEXT DEFAULT '',
    customer_email TEXT DEFAULT '',
    customer_phone TEXT DEFAULT '',
    success_url    TEXT NOT NULL DEFAULT '',
    cancel_url     TEXT NOT NULL DEFAULT '',
    callback_url   TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'pending', -- pending | paid | expired | cancelled
    provider       TEXT,
    payer_wallet   TEXT,
    trxid          TEXT,
    attempts       INTEGER NOT NULL DEFAULT 0,
    expires_at     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    paid_at        TEXT,
    UNIQUE(merchant_id, order_id)                   -- idempotent checkout creation
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    meta       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sms_status   ON sms_transactions(status);
CREATE INDEX IF NOT EXISTS idx_sms_created  ON sms_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_ps_merchant  ON payment_sessions(merchant_id);
CREATE INDEX IF NOT EXISTS idx_ps_status    ON payment_sessions(status);
"""

DEFAULT_SETTINGS = {
    "gateway_name": "MFS Gateway",
    "session_ttl_minutes": "15",
    "max_verify_attempts": "10",
    # Wallet numbers shown to buyers at checkout. Configure from Admin > Settings.
    "provider_wallets": json.dumps({
        "bkash":  {"number": "01700-000000", "type": "Personal", "enabled": True},
        "nagad":  {"number": "01800-000000", "type": "Personal", "enabled": True},
        "rocket": {"number": "01900-0000008", "type": "Agent",   "enabled": True},
        "upay":   {"number": "01600-000000", "type": "Personal", "enabled": True},
        "tap":    {"number": "01500-000000", "type": "Personal", "enabled": False},
        "meghna": {"number": "01300-000000", "type": "Personal", "enabled": False},
    }),
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, detect_types=0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def get_setting(db: sqlite3.Connection, key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def audit(db: sqlite3.Connection, actor: str, action: str, meta: str = "") -> None:
    db.execute(
        "INSERT INTO audit_logs(actor, action, meta, created_at) VALUES(?,?,?,?)",
        (actor, action, meta, utcnow_iso()),
    )


def init_db(app) -> None:
    """Create schema, seed the superadmin and default settings on first boot."""
    db_path = app.config["DATABASE"]
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)

        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (key, value)
            )

        if not conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            admin_user = os.environ.get("GATEWAY_ADMIN_USER", "admin")
            admin_pass = os.environ.get("GATEWAY_ADMIN_PASSWORD")
            if not admin_pass:
                admin_pass = secrets.token_urlsafe(9)
                app.logger.warning(
                    "\n" + "=" * 64 +
                    "\n  GENERATED SUPERADMIN CREDENTIALS (set GATEWAY_ADMIN_PASSWORD"
                    "\n  to override — change after first login):"
                    f"\n      username: {admin_user}\n      password: {admin_pass}"
                    "\n" + "=" * 64
                )
            conn.execute(
                "INSERT INTO admins(username, password_hash, created_at) VALUES(?,?,?)",
                (admin_user, hash_password(admin_pass), utcnow_iso()),
            )
            audit(conn, "system", "admin_seeded", admin_user)

        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Demo seeding (used by `python run.py --init-demo` and tools/demo_flow.py)
# ---------------------------------------------------------------------------

def ensure_demo_data(app) -> dict:
    """Create a demo merchant + API key + Termux device. Returns credentials."""
    from .security import generate_api_key_pair, generate_device_credentials

    conn = connect(app.config["DATABASE"])
    try:
        merchant = conn.execute(
            "SELECT * FROM merchants WHERE email=?", ("demo@merchant.test",)
        ).fetchone()
        if not merchant:
            conn.execute(
                "INSERT INTO merchants(email, name, password_hash, status, created_at)"
                " VALUES(?,?,?,?,?)",
                ("demo@merchant.test", "Demo Store BD", hash_password("demo12345"),
                 "active", utcnow_iso()),
            )
            merchant = conn.execute(
                "SELECT * FROM merchants WHERE email=?", ("demo@merchant.test",)
            ).fetchone()

        device = conn.execute(
            "SELECT * FROM devices WHERE device_id=?", ("dev_demo",)
        ).fetchone()
        if not device:
            conn.execute(
                "INSERT INTO devices(device_id, name, secret, status, created_at)"
                " VALUES(?,?,?,?,?)",
                ("dev_demo", "Demo Termux Phone", "dsec_" + secrets.token_urlsafe(18),
                 "active", utcnow_iso()),
            )
            device = conn.execute(
                "SELECT * FROM devices WHERE device_id=?", ("dev_demo",)
            ).fetchone()

        key = conn.execute(
            "SELECT * FROM api_keys WHERE merchant_id=? AND label='demo'",
            (merchant["id"],),
        ).fetchone()
        if not key:
            pk, sk = generate_api_key_pair()
            conn.execute(
                "INSERT INTO api_keys(merchant_id, key_id, secret, label, status,"
                " created_at) VALUES(?,?,?,?,?,?)",
                (merchant["id"], pk, sk, "demo", "active", utcnow_iso()),
            )
            key = conn.execute(
                "SELECT * FROM api_keys WHERE key_id=?", (pk,)
            ).fetchone()

        audit(conn, "system", "demo_seeded", f"merchant={merchant['email']}")
        conn.commit()
        return {
            "merchant_email": merchant["email"],
            "merchant_password": "demo12345",
            "api_key": key["key_id"],
            "api_secret": key["secret"],
            "device_id": device["device_id"],
            "device_secret": device["secret"],
        }
    finally:
        conn.close()
