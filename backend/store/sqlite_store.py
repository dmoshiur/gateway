"""SQLite backend — default, zero-infrastructure store."""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading

from ..security import hash_password
from . import DEFAULT_SETTINGS, DuplicateError, Store, utcnow_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS merchants (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
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
    key_id       TEXT UNIQUE NOT NULL,
    secret       TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    secret       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    last_seen_at TEXT,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sms_transactions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    provider           TEXT NOT NULL,
    sender             TEXT,
    amount_paisa       INTEGER NOT NULL,
    trxid              TEXT NOT NULL,
    device_id          TEXT,
    sms_timestamp      TEXT,
    raw_hash           TEXT,
    status             TEXT NOT NULL DEFAULT 'unused',
    matched_session_id TEXT,
    created_at         TEXT NOT NULL,
    UNIQUE(trxid COLLATE NOCASE)
);
CREATE TABLE IF NOT EXISTS payment_sessions (
    id             TEXT PRIMARY KEY,
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
    status         TEXT NOT NULL DEFAULT 'pending',
    provider       TEXT,
    payer_wallet   TEXT,
    trxid          TEXT,
    attempts       INTEGER NOT NULL DEFAULT 0,
    expires_at     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    paid_at        TEXT,
    UNIQUE(merchant_id, order_id)
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


def _conn(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, detect_types=0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


class SQLiteStore(Store):
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = _conn(path)
        self._write = threading.RLock()

    # ------------------------------------------------------------------ util
    @staticmethod
    def _d(row) -> dict | None:
        return dict(row) if row is not None else None

    def _q(self, sql: str, params=(), one: bool = False):
        cur = self.db.execute(sql, params)
        return self._d(cur.fetchone()) if one else [dict(r) for r in cur.fetchall()]

    def _x(self, sql: str, params=()) -> int:
        with self._write:
            cur = self.db.execute(sql, params)
            self.db.commit()
            return cur.rowcount

    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------------ seed
    def init(self, app) -> None:
        with self._write:
            self.db.executescript(SCHEMA)
            for key, value in DEFAULT_SETTINGS.items():
                self.db.execute(
                    "INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)",
                    (key, value))
            self.db.commit()
        _seed_admin(self, app)

    # -------------------------------------------------------- settings/audit
    def get_setting(self, key, default=""):
        row = self._q("SELECT value FROM settings WHERE key=?", (key,), one=True)
        return row["value"] if row else default

    def set_setting(self, key, value):
        self._x("INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def all_settings(self):
        return {r["key"]: r["value"] for r in self._q("SELECT key, value FROM settings")}

    def audit(self, actor, action, meta=""):
        self._x("INSERT INTO audit_logs(actor, action, meta, created_at)"
                " VALUES(?,?,?,?)", (actor, action, meta, utcnow_iso()))

    def list_audit(self, limit=100):
        return self._q("SELECT actor, action, meta, created_at FROM audit_logs"
                       " ORDER BY id DESC LIMIT ?", (limit,))

    # ---------------------------------------------------------------- admins
    def find_admin(self, username):
        return self._q("SELECT * FROM admins WHERE username=?", (username,), one=True)

    def upsert_admin(self, username, password_hash):
        self._x("INSERT INTO admins(username, password_hash, created_at) VALUES(?,?,?)"
                " ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
                (username, password_hash, utcnow_iso()))

    def set_admin_password(self, username, password_hash):
        self._x("UPDATE admins SET password_hash=? WHERE username=?",
                (password_hash, username))

    # ------------------------------------------------------------- merchants
    def create_merchant(self, email, name, password_hash):
        with self._write:
            try:
                cur = self.db.execute(
                    "INSERT INTO merchants(email, name, password_hash, status,"
                    " created_at) VALUES(?,?,?,'active',?)",
                    (email, name, password_hash, utcnow_iso()))
                self.db.commit()
                return int(cur.lastrowid)
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                raise DuplicateError(str(exc)) from exc

    def find_merchant_by_email(self, email):
        return self._q("SELECT * FROM merchants WHERE email=?", (email,), one=True)

    def get_merchant(self, merchant_id):
        return self._q("SELECT * FROM merchants WHERE id=?", (merchant_id,), one=True)

    def set_merchant_password(self, merchant_id, password_hash):
        self._x("UPDATE merchants SET password_hash=? WHERE id=?",
                (password_hash, merchant_id))

    def set_merchant_status(self, merchant_id, status):
        self._x("UPDATE merchants SET status=? WHERE id=?", (status, merchant_id))

    def count_merchants(self):
        return self._q("SELECT COUNT(*) c FROM merchants", one=True)["c"]

    def list_merchants_enriched(self):
        return self._q(
            "SELECT m.id, m.email, m.name, m.status, m.created_at,"
            " (SELECT COUNT(*) FROM api_keys k WHERE k.merchant_id=m.id) keys,"
            " (SELECT COUNT(*) FROM payment_sessions p WHERE p.merchant_id=m.id"
            "  AND p.status='paid') paid_count,"
            " (SELECT COALESCE(SUM(p.amount_paisa),0) FROM payment_sessions p"
            "  WHERE p.merchant_id=m.id AND p.status='paid') volume"
            " FROM merchants m ORDER BY m.id DESC")

    # ------------------------------------------------------------------ keys
    def create_api_key(self, merchant_id, key_id, secret, label):
        with self._write:
            cur = self.db.execute(
                "INSERT INTO api_keys(merchant_id, key_id, secret, label, status,"
                " created_at) VALUES(?,?,?,?,'active',?)",
                (merchant_id, key_id, secret, label, utcnow_iso()))
            self.db.commit()
            return int(cur.lastrowid)

    def find_active_key(self, key_id):
        return self._q("SELECT * FROM api_keys WHERE key_id=? AND status='active'",
                       (key_id,), one=True)

    def list_keys_for_merchant(self, merchant_id):
        return self._q("SELECT id, key_id, label, status, created_at, last_used_at"
                       " FROM api_keys WHERE merchant_id=? ORDER BY id DESC",
                       (merchant_id,))

    def list_all_keys_enriched(self):
        return self._q(
            "SELECT k.id, k.key_id, k.label, k.status, k.created_at, k.last_used_at,"
            " m.email merchant_email, m.name merchant_name FROM api_keys k"
            " JOIN merchants m ON m.id=k.merchant_id ORDER BY k.id DESC")

    def set_key_status(self, key_pk, status, merchant_id=None):
        if merchant_id is None:
            return self._x("UPDATE api_keys SET status=? WHERE id=?", (status, key_pk))
        return self._x("UPDATE api_keys SET status=? WHERE id=? AND merchant_id=?",
                       (status, key_pk, merchant_id))

    def touch_key(self, key_pk, when):
        self._x("UPDATE api_keys SET last_used_at=? WHERE id=?", (when, key_pk))

    def count_keys(self, merchant_id):
        return self._q("SELECT COUNT(*) c FROM api_keys WHERE merchant_id=?",
                       (merchant_id,), one=True)["c"]

    # ---------------------------------------------------------------- devices
    def create_device(self, device_id, name, secret):
        self._x("INSERT INTO devices(device_id, name, secret, status, created_at)"
                " VALUES(?,?,?,'active',?)", (device_id, name, secret, utcnow_iso()))

    def find_active_device(self, device_id):
        return self._q("SELECT * FROM devices WHERE device_id=? AND status='active'",
                       (device_id,), one=True)

    def list_devices(self):
        return self._q("SELECT id, device_id, name, status, last_seen_at, created_at"
                       " FROM devices ORDER BY id DESC")

    def set_device_status(self, device_id, status):
        self._x("UPDATE devices SET status=? WHERE device_id=?", (status, device_id))

    def touch_device(self, device_id, when):
        self._x("UPDATE devices SET last_seen_at=? WHERE device_id=?", (when, device_id))

    # -------------------------------------------------------------------- sms
    def insert_sms(self, provider, sender, amount_paisa, trxid, device_id,
                   sms_timestamp, raw_hash):
        with self._write:
            try:
                self.db.execute(
                    "INSERT INTO sms_transactions(provider, sender, amount_paisa,"
                    " trxid, device_id, sms_timestamp, raw_hash, status, created_at)"
                    " VALUES(?,?,?,?,?,?,?,'unused',?)",
                    (provider, sender, amount_paisa, trxid, device_id,
                     sms_timestamp, raw_hash, utcnow_iso()))
                self.db.commit()
                return "stored"
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                if "UNIQUE" in str(exc).upper():
                    return "duplicate"
                raise

    def find_sms_by_trxid(self, trxid):
        return self._q("SELECT * FROM sms_transactions WHERE UPPER(trxid)=?",
                       (trxid.upper(),), one=True)

    def get_sms(self, sms_id):
        return self._q("SELECT * FROM sms_transactions WHERE id=?", (sms_id,), one=True)

    def claim_sms(self, sms_id, session_id):
        rowcount = self._x(
            "UPDATE sms_transactions SET status='consumed', matched_session_id=?"
            " WHERE id=? AND status='unused'", (session_id, sms_id))
        return rowcount == 1

    def release_sms(self, sms_id):
        self._x("UPDATE sms_transactions SET status='unused', matched_session_id=NULL"
                " WHERE id=?", (sms_id,))

    def list_sms_since(self, since_id, limit=150):
        return self._q(
            "SELECT s.*, p.order_id, m.name merchant FROM sms_transactions s"
            " LEFT JOIN payment_sessions p ON p.id=s.matched_session_id"
            " LEFT JOIN merchants m ON m.id=p.merchant_id"
            " WHERE s.id>? ORDER BY s.id DESC LIMIT ?", (since_id, limit))

    def list_sms_recent(self, limit=12):
        return self._q(
            "SELECT id, provider, sender, amount_paisa, trxid, device_id, status,"
            " matched_session_id, created_at FROM sms_transactions"
            " ORDER BY id DESC LIMIT ?", (limit,))

    def sms_stats(self):
        return {r["status"]: r["c"] for r in self._q(
            "SELECT status, COUNT(*) c FROM sms_transactions GROUP BY status")}

    # --------------------------------------------------------------- sessions
    def create_session(self, data):
        with self._write:
            try:
                self.db.execute(
                    "INSERT INTO payment_sessions(id, merchant_id, api_key_id,"
                    " order_id, amount_paisa, currency, customer_name,"
                    " customer_email, customer_phone, success_url, cancel_url,"
                    " callback_url, status, expires_at, created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)",
                    (data["id"], data["merchant_id"], data.get("api_key_id"),
                     data["order_id"], data["amount_paisa"],
                     data.get("currency", "BDT"), data.get("customer_name", ""),
                     data.get("customer_email", ""), data.get("customer_phone", ""),
                     data.get("success_url", ""), data.get("cancel_url", ""),
                     data.get("callback_url", ""), data["expires_at"],
                     data.get("created_at") or utcnow_iso()))
                self.db.commit()
            except sqlite3.IntegrityError as exc:
                self.db.rollback()
                raise DuplicateError(str(exc)) from exc

    def find_session(self, session_id):
        return self._q("SELECT * FROM payment_sessions WHERE id=?",
                       (session_id,), one=True)

    def find_session_by_order(self, merchant_id, order_id):
        return self._q("SELECT * FROM payment_sessions WHERE merchant_id=?"
                       " AND order_id=?", (merchant_id, order_id), one=True)

    def mark_session_expired(self, session_id):
        return self._x("UPDATE payment_sessions SET status='expired'"
                       " WHERE id=? AND status='pending'", (session_id,))

    def increment_attempts(self, session_id):
        self._x("UPDATE payment_sessions SET attempts=attempts+1 WHERE id=?",
                (session_id,))

    def mark_session_paid(self, session_id, provider, payer_wallet, trxid, paid_at):
        self._x("UPDATE payment_sessions SET status='paid', provider=?,"
                " payer_wallet=?, trxid=?, paid_at=? WHERE id=?",
                (provider, payer_wallet, trxid, paid_at, session_id))

    def reset_session_to_pending(self, session_id):
        self._x("UPDATE payment_sessions SET status='pending', provider=NULL,"
                " payer_wallet=NULL, trxid=NULL, paid_at=NULL"
                " WHERE id=? AND status='paid'", (session_id,))

    def payment_stats(self, merchant_id=None, since_iso=None):
        sql = ("SELECT COUNT(*) c, COALESCE(SUM(amount_paisa),0) v"
               " FROM payment_sessions WHERE status='paid'")
        params = []
        if merchant_id is not None:
            sql += " AND merchant_id=?"
            params.append(merchant_id)
        if since_iso is not None:
            sql += " AND paid_at>=?"
            params.append(since_iso)
        row = self._q(sql, params, one=True)
        return {"count": row["c"], "volume": row["v"]}

    def count_pending_sessions(self, merchant_id):
        return self._q(
            "SELECT COUNT(*) c FROM payment_sessions"
            " WHERE merchant_id=? AND status='pending'", (merchant_id,), one=True)["c"]

    def list_sessions(self, merchant_id=None, limit=100):
        sql = ("SELECT p.*, m.name merchant FROM payment_sessions p"
               " JOIN merchants m ON m.id=p.merchant_id")
        params: list = []
        if merchant_id is not None:
            sql += " WHERE p.merchant_id=?"
            params.append(merchant_id)
        sql += " ORDER BY p.created_at DESC LIMIT ?"
        params.append(limit)
        return self._q(sql, params)

    def list_paid_recent(self, limit=12):
        return self._q(
            "SELECT p.id, p.order_id, p.amount_paisa, p.provider, p.trxid, p.paid_at,"
            " m.name merchant FROM payment_sessions p JOIN merchants m"
            " ON m.id=p.merchant_id WHERE p.status='paid'"
            " ORDER BY p.paid_at DESC LIMIT ?", (limit,))


# ---------------------------------------------------------------------------
# Deterministic superadmin seeding (shared by both backends via import here)
# ---------------------------------------------------------------------------

def _seed_admin(store: Store, app) -> None:
    """Guarantee the superadmin credential is exactly what ops configured.

    * First boot          -> create with env password, else generated random.
    * Later boots with env -> re-sync hash if it drifted (env is source of truth).
    """
    username = os.environ.get("GATEWAY_ADMIN_USER", "admin")
    env_pass = os.environ.get("GATEWAY_ADMIN_PASSWORD")
    existing = store.find_admin(username)

    if existing is None:
        password = env_pass or secrets.token_urlsafe(9)
        store.upsert_admin(username, hash_password(password))
        store.audit("system", "admin_seeded", username)
        if not env_pass:
            app.logger.warning(
                "\n" + "=" * 64 +
                "\n  GENERATED SUPERADMIN CREDENTIALS (set GATEWAY_ADMIN_PASSWORD"
                "\n  to override):"
                f"\n      username: {username}\n      password: {password}"
                "\n" + "=" * 64)
    elif env_pass:
        from ..security import verify_password
        if not verify_password(env_pass, existing["password_hash"]):
            store.set_admin_password(username, hash_password(env_pass))
            store.audit("system", "admin_password_synced", username)
            app.logger.warning("Superadmin password re-synced from "
                               "GATEWAY_ADMIN_PASSWORD env var.")
