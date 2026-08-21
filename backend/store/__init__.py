"""
MongoDB persistence layer for the gateway.

The app speaks to a document-style store interface (plain dicts in/out),
implemented by ``MongoStore`` (pymongo). MongoDB is the **only** storage
engine — configured with one single-line connection URI:

  MONGO_URI=mongodb://localhost:27017/mfs_gateway
  MONGO_URI=mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/mfs_gateway

The database name is embedded in the URI path (falls back to
``mfs_gateway`` when the URI has no path segment).

Money is integer paisa; timestamps are UTC ISO-8601 strings (lexicographic
ordering matches chronological ordering for the formats we write).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


class DuplicateError(Exception):
    """Raised on unique-constraint violations (trxid, email, order id...)."""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


DEFAULT_SETTINGS = {
    "gateway_name": "MFS Gateway",
    "session_ttl_minutes": "15",
    "max_verify_attempts": "10",
    "provider_wallets": json.dumps({
        "bkash":  {"number": "01700-000000", "type": "Personal", "enabled": True},
        "nagad":  {"number": "01800-000000", "type": "Personal", "enabled": True},
        "rocket": {"number": "01900-0000008", "type": "Agent",   "enabled": True},
        "upay":   {"number": "01600-000000", "type": "Personal", "enabled": True},
        "tap":    {"number": "01500-000000", "type": "Personal", "enabled": False},
        "meghna": {"number": "01300-000000", "type": "Personal", "enabled": False},
    }),
}


class Store:
    """Interface contract (documented; implemented by MongoStore)."""

    # --- lifecycle ---------------------------------------------------------
    def init(self, app) -> None:
        """Create indexes, seed default settings + deterministic admin."""
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - trivial
        pass

    # --- settings / audit --------------------------------------------------
    def get_setting(self, key: str, default: str = "") -> str: ...
    def set_setting(self, key: str, value: str) -> None: ...
    def all_settings(self) -> dict: ...
    def audit(self, actor: str, action: str, meta: str = "") -> None: ...
    def list_audit(self, limit: int = 100) -> list: ...

    # --- admins ------------------------------------------------------------
    def find_admin(self, username: str): ...
    def upsert_admin(self, username: str, password_hash: str) -> None: ...
    def set_admin_password(self, username: str, password_hash: str) -> None: ...

    # --- merchants ---------------------------------------------------------
    def create_merchant(self, email: str, name: str, password_hash: str) -> int: ...
    def find_merchant_by_email(self, email: str): ...
    def get_merchant(self, merchant_id: int): ...
    def set_merchant_password(self, merchant_id: int, password_hash: str) -> None: ...
    def set_merchant_status(self, merchant_id: int, status: str) -> None: ...
    def count_merchants(self) -> int: ...
    def list_merchants_enriched(self) -> list: ...

    # --- api keys ----------------------------------------------------------
    def create_api_key(self, merchant_id: int, key_id: str,
                       secret: str, label: str) -> int: ...
    def find_active_key(self, key_id: str): ...
    def list_keys_for_merchant(self, merchant_id: int) -> list: ...
    def list_all_keys_enriched(self) -> list: ...
    def set_key_status(self, key_pk: int, status: str,
                       merchant_id: int | None = None) -> int: ...
    def touch_key(self, key_pk: int, when: str) -> None: ...
    def count_keys(self, merchant_id: int) -> int: ...

    # --- devices -----------------------------------------------------------
    def create_device(self, device_id: str, name: str, secret: str) -> None: ...
    def find_active_device(self, device_id: str): ...
    def list_devices(self) -> list: ...
    def set_device_status(self, device_id: str, status: str) -> None: ...
    def touch_device(self, device_id: str, when: str) -> None: ...

    # --- sms ledger --------------------------------------------------------
    def insert_sms(self, provider: str, sender: str, amount_paisa: int,
                   trxid: str, device_id: str, sms_timestamp: str,
                   raw_hash: str) -> str: ...        # "stored" | "duplicate"
    def find_sms_by_trxid(self, trxid: str): ...
    def get_sms(self, sms_id: int): ...
    def claim_sms(self, sms_id: int, session_id: str) -> bool: ...
    def release_sms(self, sms_id: int) -> None: ...
    def list_sms_since(self, since_id: int, limit: int = 150) -> list: ...
    def list_sms_recent(self, limit: int = 12) -> list: ...
    def sms_stats(self) -> dict: ...

    # --- payment sessions --------------------------------------------------
    def create_session(self, data: dict) -> None: ...
    def find_session(self, session_id: str): ...
    def find_session_by_order(self, merchant_id: int, order_id: str): ...
    def mark_session_expired(self, session_id: str) -> int: ...
    def increment_attempts(self, session_id: str) -> None: ...
    def mark_session_paid(self, session_id: str, provider: str,
                          payer_wallet: str, trxid: str, paid_at: str) -> None: ...
    def reset_session_to_pending(self, session_id: str) -> None: ...
    def payment_stats(self, merchant_id: int | None = None,
                      since_iso: str | None = None) -> dict: ...
    def count_pending_sessions(self, merchant_id: int) -> int: ...
    def list_sessions(self, merchant_id: int | None = None,
                      limit: int = 100) -> list: ...       # enriched, newest first
    def list_paid_recent(self, limit: int = 12) -> list: ...  # enriched


def _db_name_from_uri(uri: str) -> str:
    """Extract the database name embedded in a mongodb:// / mongodb+srv:// URI.

    Pure string parsing — deliberately NOT pymongo.parse_uri, which performs
    live DNS SRV lookups for mongodb+srv:// (slow/offline-hostile at boot).
    """
    try:
        tail = uri.split("://", 1)[1]                 # drop scheme
        if "/" not in tail:
            return "mfs_gateway"
        path = tail.split("/", 1)[1]                  # drop auth@hosts
        name = path.split("?", 1)[0].strip("/")       # drop ?options + slashes
        return name or "mfs_gateway"
    except IndexError:
        return "mfs_gateway"


def make_store(app) -> Store:
    """Build the MongoDB store. Single-line config: MONGO_URI.

    GATEWAY_MONGO_MOCK=1 swaps the client factory to mongomock (dev/CI shim —
    restricted sandboxes with no reachable server; never in production).
    """
    from . import mongo_store

    mock = os.environ.get("GATEWAY_MONGO_MOCK") == "1"
    if mock:
        import mongomock
        mongo_store.MONGO_CLIENT_FACTORY = mongomock.MongoClient

    uri = os.environ.get("MONGO_URI",
                         "mongodb://localhost:27017/mfs_gateway")
    store = mongo_store.MongoStore(uri=uri, db_name=_db_name_from_uri(uri),
                                   mocked=mock)
    return store
