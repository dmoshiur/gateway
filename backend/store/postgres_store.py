"""PostgreSQL backend (SQLAlchemy Core + psycopg 3) — the gateway's only
production storage engine.

Production:  DATABASE_URL=postgresql+psycopg://user:pass@host:5432/mfs_gateway
             (plain ``postgresql://`` / ``postgres://`` URLs are auto-upgraded
             to the psycopg driver)
Tests/CI:    DATABASE_URL=sqlite:// — the same dialect-neutral SQLAlchemy
             code path on an in-memory SQLite database (no PostgreSQL server
             needed for tests/CI).

Schema notes
------------
* Money is integer paisa (BIGINT); timestamps stay UTC ISO-8601 strings
  (TEXT) so the app's existing string comparisons/``fromisoformat`` parsing
  are unchanged.
* Surrogate ids are auto-incrementing integer PKs (PostgreSQL SERIAL /
  SQLite rowid) — globally unique per table.
* Unique constraints (``trxid_norm``, ``merchants.email``,
  ``api_keys.key_id``, compound ``merchant_id+order_id``) give
  replay/double-spend protection; state transitions (claim, expire, reset)
  are atomic conditional UPDATEs.
"""

from __future__ import annotations

from sqlalchemy import (BigInteger, Column, ForeignKey, Index, Integer,
                        MetaData, Table, Text, UniqueConstraint, create_engine,
                        func, select)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from . import DEFAULT_SETTINGS, DuplicateError, Store, utcnow_iso
from .seeding import seed_admin

metadata = MetaData()

admins = Table(
    "admins", metadata,
    Column("username", Text, primary_key=True),
    Column("password_hash", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

merchants = Table(
    "merchants", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", Text, nullable=False, unique=True),
    Column("name", Text, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

api_keys = Table(
    "api_keys", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("merchant_id", Integer, ForeignKey("merchants.id"), nullable=False),
    Column("key_id", Text, nullable=False, unique=True),
    Column("secret", Text, nullable=False),
    Column("label", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("last_used_at", Text, nullable=True),
)

devices = Table(
    "devices", metadata,
    Column("device_id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("secret", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("last_seen_at", Text, nullable=True),
    Column("created_at", Text, nullable=False),
)

sms_transactions = Table(
    "sms_transactions", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("provider", Text, nullable=False),
    Column("sender", Text, nullable=False),
    Column("amount_paisa", BigInteger, nullable=False),
    Column("trxid", Text, nullable=False),
    Column("trxid_norm", Text, nullable=False, unique=True),
    Column("device_id", Text, nullable=False),
    Column("sms_timestamp", Text, nullable=False),
    Column("raw_hash", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("matched_session_id", Text, nullable=True),
    Column("created_at", Text, nullable=False),
)

payment_sessions = Table(
    "payment_sessions", metadata,
    Column("id", Text, primary_key=True),
    Column("merchant_id", Integer, ForeignKey("merchants.id"), nullable=False),
    Column("api_key_id", Integer, nullable=True),
    Column("order_id", Text, nullable=False),
    Column("amount_paisa", BigInteger, nullable=False),
    Column("currency", Text, nullable=False),
    Column("customer_name", Text, nullable=False),
    Column("customer_email", Text, nullable=False),
    Column("customer_phone", Text, nullable=False),
    Column("success_url", Text, nullable=False),
    Column("cancel_url", Text, nullable=False),
    Column("callback_url", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("provider", Text, nullable=True),
    Column("payer_wallet", Text, nullable=True),
    Column("trxid", Text, nullable=True),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("expires_at", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("paid_at", Text, nullable=True),
    UniqueConstraint("merchant_id", "order_id",
                     name="uq_payment_sessions_merchant_order"),
)

audit_logs = Table(
    "audit_logs", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("actor", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("meta", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

settings = Table(
    "settings", metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
)

# Extra lookup indexes (uniques are already backed by constraints above).
Index("ix_api_keys_merchant_id", api_keys.c.merchant_id)
Index("ix_sms_transactions_status", sms_transactions.c.status)
Index("ix_payment_sessions_merchant_id", payment_sessions.c.merchant_id)
Index("ix_payment_sessions_status", payment_sessions.c.status)


def normalize_url(url: str) -> str:
    """Accept common PostgreSQL URL spellings.

    ``postgres://`` and ``postgresql://`` are upgraded to the psycopg 3
    driver dialect (``postgresql+psycopg://``); SQLite URLs pass through
    untouched for the dev/test shim.
    """
    url = (url or "").strip()
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


class PostgresStore(Store):
    """SQLAlchemy-Core store. PostgreSQL in production; the same code path
    runs on SQLite when ``DATABASE_URL=sqlite://`` (tests/CI)."""

    def __init__(self, url: str):
        self.url = normalize_url(url)
        parsed = make_url(self.url)
        self.dialect_name = parsed.get_backend_name()          # postgresql|sqlite
        self.database_name = parsed.database or "mfs_gateway"
        kwargs = {}
        if self.dialect_name == "sqlite":
            kwargs["connect_args"] = {"check_same_thread": False}
            if parsed.database in (None, "", ":memory:"):
                kwargs["poolclass"] = StaticPool
        self.engine = create_engine(self.url, future=True, **kwargs)

    # ------------------------------------------------------------------ util
    def _dialect_insert(self, table):
        return (sqlite_insert if self.dialect_name == "sqlite"
                else pg_insert)(table)

    @staticmethod
    def _row_dict(row) -> dict | None:
        return dict(row._mapping) if row is not None else None

    def _insert_ignore(self, table, values: dict) -> None:
        """INSERT ... ON CONFLICT DO NOTHING (portable PG/SQLite)."""
        stmt = (self._dialect_insert(table).values(**values)
                .on_conflict_do_nothing())
        with self.engine.begin() as conn:
            conn.execute(stmt)

    def _upsert(self, table, key_name: str, values: dict,
                preserve_on_update: tuple = ()) -> None:
        """Portable upsert; columns in ``preserve_on_update`` keep the old
        value (insert-only on conflict)."""
        set_ = {k: v for k, v in values.items()
                if k != key_name and k not in preserve_on_update}
        stmt = self._dialect_insert(table).values(**values)
        if set_:
            stmt = stmt.on_conflict_do_update(index_elements=[key_name],
                                              set_=set_)
        else:
            stmt = stmt.on_conflict_do_nothing(index_elements=[key_name])
        with self.engine.begin() as conn:
            conn.execute(stmt)

    def close(self) -> None:
        self.engine.dispose()

    # ------------------------------------------------------------------ seed
    def init(self, app) -> None:
        # Creates tables/indexes/constraints only when missing — safe boot.
        metadata.create_all(self.engine)
        for key, value in DEFAULT_SETTINGS.items():
            self._insert_ignore(settings, {"key": key, "value": value})
        seed_admin(self, app)

    # -------------------------------------------------------- settings/audit
    def get_setting(self, key, default=""):
        with self.engine.connect() as conn:
            row = conn.execute(
                select(settings.c.value).where(settings.c.key == key)).first()
        return str(row[0]) if row else default

    def set_setting(self, key, value):
        self._upsert(settings, "key", {"key": key, "value": value})

    def all_settings(self):
        with self.engine.connect() as conn:
            rows = conn.execute(select(settings.c.key, settings.c.value)).all()
        return {k: v for k, v in rows}

    def audit(self, actor, action, meta=""):
        with self.engine.begin() as conn:
            conn.execute(audit_logs.insert().values(
                actor=actor, action=action, meta=meta, created_at=utcnow_iso()))

    def list_audit(self, limit=100):
        with self.engine.connect() as conn:
            rows = conn.execute(select(audit_logs)
                                .order_by(audit_logs.c.id.desc())
                                .limit(limit)).all()
        return [self._row_dict(r) for r in rows]

    # ---------------------------------------------------------------- admins
    def find_admin(self, username):
        with self.engine.connect() as conn:
            row = conn.execute(select(admins)
                               .where(admins.c.username == username)).first()
        return self._row_dict(row)

    def upsert_admin(self, username, password_hash):
        self._upsert(admins, "username", {
            "username": username, "password_hash": password_hash,
            "created_at": utcnow_iso(),
        }, preserve_on_update=("created_at",))

    def set_admin_password(self, username, password_hash):
        with self.engine.begin() as conn:
            conn.execute(admins.update()
                         .where(admins.c.username == username)
                         .values(password_hash=password_hash))

    # ------------------------------------------------------------- merchants
    def create_merchant(self, email, name, password_hash):
        try:
            with self.engine.begin() as conn:
                result = conn.execute(merchants.insert().values(
                    email=email, name=name, password_hash=password_hash,
                    status="active", created_at=utcnow_iso()))
                return int(result.inserted_primary_key[0])
        except IntegrityError as exc:
            raise DuplicateError(str(exc)) from exc

    def find_merchant_by_email(self, email):
        with self.engine.connect() as conn:
            row = conn.execute(select(merchants)
                               .where(merchants.c.email == email)).first()
        return self._row_dict(row)

    def get_merchant(self, merchant_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(merchants)
                               .where(merchants.c.id == int(merchant_id))
                               ).first()
        return self._row_dict(row)

    def set_merchant_password(self, merchant_id, password_hash):
        with self.engine.begin() as conn:
            conn.execute(merchants.update()
                         .where(merchants.c.id == int(merchant_id))
                         .values(password_hash=password_hash))

    def set_merchant_status(self, merchant_id, status):
        with self.engine.begin() as conn:
            conn.execute(merchants.update()
                         .where(merchants.c.id == int(merchant_id))
                         .values(status=status))

    def count_merchants(self):
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count())
                                    .select_from(merchants)).scalar_one())

    def list_merchants_enriched(self):
        paid = (select(payment_sessions.c.merchant_id,
                       func.count().label("paid_count"),
                       func.coalesce(func.sum(payment_sessions.c.amount_paisa),
                                     0).label("volume"))
                .where(payment_sessions.c.status == "paid")
                .group_by(payment_sessions.c.merchant_id).subquery())
        key_counts = (select(api_keys.c.merchant_id,
                             func.count().label("key_count"))
                      .group_by(api_keys.c.merchant_id).subquery())
        stmt = (select(merchants,
                       func.coalesce(key_counts.c.key_count, 0).label("keys"),
                       func.coalesce(paid.c.paid_count, 0).label("paid_count"),
                       func.coalesce(paid.c.volume, 0).label("volume"))
                .select_from(merchants
                             .outerjoin(key_counts,
                                        key_counts.c.merchant_id == merchants.c.id)
                             .outerjoin(paid, paid.c.merchant_id == merchants.c.id))
                .order_by(merchants.c.id.desc()))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [self._row_dict(r) for r in rows]

    # ------------------------------------------------------------------ keys
    def create_api_key(self, merchant_id, key_id, secret, label):
        with self.engine.begin() as conn:
            result = conn.execute(api_keys.insert().values(
                merchant_id=int(merchant_id), key_id=key_id, secret=secret,
                label=label, status="active", created_at=utcnow_iso(),
                last_used_at=None))
            return int(result.inserted_primary_key[0])

    def find_active_key(self, key_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(api_keys)
                               .where(api_keys.c.key_id == key_id,
                                      api_keys.c.status == "active")).first()
        return self._row_dict(row)

    def list_keys_for_merchant(self, merchant_id):
        cols = (api_keys.c.id, api_keys.c.key_id, api_keys.c.label,
                api_keys.c.status, api_keys.c.created_at,
                api_keys.c.last_used_at)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(*cols).where(api_keys.c.merchant_id == int(merchant_id))
                .order_by(api_keys.c.id.desc())).all()
        return [self._row_dict(r) for r in rows]

    def list_all_keys_enriched(self):
        stmt = (select(api_keys.c.id, api_keys.c.merchant_id,
                       api_keys.c.key_id, api_keys.c.label, api_keys.c.status,
                       api_keys.c.created_at, api_keys.c.last_used_at,
                       merchants.c.email.label("merchant_email"),
                       merchants.c.name.label("merchant_name"))
                .select_from(api_keys.join(
                    merchants, api_keys.c.merchant_id == merchants.c.id))
                .order_by(api_keys.c.id.desc()))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [self._row_dict(r) for r in rows]

    def set_key_status(self, key_pk, status, merchant_id=None):
        stmt = (api_keys.update().where(api_keys.c.id == int(key_pk))
                .values(status=status))
        if merchant_id is not None:
            stmt = stmt.where(api_keys.c.merchant_id == int(merchant_id))
        with self.engine.begin() as conn:
            return conn.execute(stmt).rowcount

    def touch_key(self, key_pk, when):
        with self.engine.begin() as conn:
            conn.execute(api_keys.update()
                         .where(api_keys.c.id == int(key_pk))
                         .values(last_used_at=when))

    def count_keys(self, merchant_id):
        with self.engine.connect() as conn:
            return int(conn.execute(
                select(func.count()).select_from(api_keys)
                .where(api_keys.c.merchant_id == int(merchant_id))
            ).scalar_one())

    # ---------------------------------------------------------------- devices
    def create_device(self, device_id, name, secret):
        with self.engine.begin() as conn:
            conn.execute(devices.insert().values(
                device_id=device_id, name=name, secret=secret,
                status="active", last_seen_at=None, created_at=utcnow_iso()))

    def find_active_device(self, device_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(devices)
                               .where(devices.c.device_id == device_id,
                                      devices.c.status == "active")).first()
        return self._row_dict(row)

    def list_devices(self):
        cols = (devices.c.device_id, devices.c.name, devices.c.status,
                devices.c.last_seen_at, devices.c.created_at)
        with self.engine.connect() as conn:
            rows = conn.execute(select(*cols)
                                .order_by(devices.c.created_at.desc())).all()
        out = []
        for r in rows:
            d = self._row_dict(r)
            d["id"] = d.get("device_id")  # templates key on device_id anyway
            out.append(d)
        return out

    def set_device_status(self, device_id, status):
        with self.engine.begin() as conn:
            conn.execute(devices.update()
                         .where(devices.c.device_id == device_id)
                         .values(status=status))

    def touch_device(self, device_id, when):
        with self.engine.begin() as conn:
            conn.execute(devices.update()
                         .where(devices.c.device_id == device_id)
                         .values(last_seen_at=when))

    # -------------------------------------------------------------------- sms
    def insert_sms(self, provider, sender, amount_paisa, trxid, device_id,
                   sms_timestamp, raw_hash):
        try:
            with self.engine.begin() as conn:
                conn.execute(sms_transactions.insert().values(
                    provider=provider, sender=sender,
                    amount_paisa=int(amount_paisa), trxid=trxid.upper(),
                    trxid_norm=trxid.upper(), device_id=device_id,
                    sms_timestamp=sms_timestamp, raw_hash=raw_hash,
                    status="unused", matched_session_id=None,
                    created_at=utcnow_iso()))
            return "stored"
        except IntegrityError:
            return "duplicate"

    def find_sms_by_trxid(self, trxid):
        with self.engine.connect() as conn:
            row = conn.execute(
                select(sms_transactions)
                .where(sms_transactions.c.trxid_norm == trxid.upper())
            ).first()
        return self._row_dict(row)

    def get_sms(self, sms_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(sms_transactions)
                               .where(sms_transactions.c.id == int(sms_id))
                               ).first()
        return self._row_dict(row)

    def claim_sms(self, sms_id, session_id):
        with self.engine.begin() as conn:
            result = conn.execute(
                sms_transactions.update()
                .where(sms_transactions.c.id == int(sms_id),
                       sms_transactions.c.status == "unused")
                .values(status="consumed", matched_session_id=session_id))
            return result.rowcount == 1

    def release_sms(self, sms_id):
        with self.engine.begin() as conn:
            conn.execute(sms_transactions.update()
                         .where(sms_transactions.c.id == int(sms_id))
                         .values(status="unused", matched_session_id=None))

    def list_sms_since(self, since_id, limit=150):
        stmt = (select(sms_transactions,
                       payment_sessions.c.order_id,
                       merchants.c.name.label("merchant"))
                .select_from(
                    sms_transactions
                    .outerjoin(payment_sessions,
                               payment_sessions.c.id ==
                               sms_transactions.c.matched_session_id)
                    .outerjoin(merchants,
                               merchants.c.id ==
                               payment_sessions.c.merchant_id))
                .where(sms_transactions.c.id > int(since_id))
                .order_by(sms_transactions.c.id.desc())
                .limit(limit))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [self._row_dict(r) for r in rows]

    def list_sms_recent(self, limit=12):
        with self.engine.connect() as conn:
            rows = conn.execute(select(sms_transactions)
                                .order_by(sms_transactions.c.id.desc())
                                .limit(limit)).all()
        return [self._row_dict(r) for r in rows]

    def sms_stats(self):
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(sms_transactions.c.status, func.count())
                .group_by(sms_transactions.c.status)).all()
        return {status: int(count) for status, count in rows}

    # --------------------------------------------------------------- sessions
    def create_session(self, data):
        try:
            with self.engine.begin() as conn:
                conn.execute(payment_sessions.insert().values({
                    "id": data["id"],
                    "merchant_id": int(data["merchant_id"]),
                    "api_key_id": data.get("api_key_id"),
                    "order_id": data["order_id"],
                    "amount_paisa": int(data["amount_paisa"]),
                    "currency": data.get("currency", "BDT"),
                    "customer_name": data.get("customer_name", ""),
                    "customer_email": data.get("customer_email", ""),
                    "customer_phone": data.get("customer_phone", ""),
                    "success_url": data.get("success_url", ""),
                    "cancel_url": data.get("cancel_url", ""),
                    "callback_url": data.get("callback_url", ""),
                    "status": "pending", "provider": None,
                    "payer_wallet": None, "trxid": None, "attempts": 0,
                    "expires_at": data["expires_at"],
                    "created_at": data.get("created_at") or utcnow_iso(),
                    "paid_at": None,
                }))
        except IntegrityError as exc:
            raise DuplicateError(str(exc)) from exc

    def find_session(self, session_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(payment_sessions)
                               .where(payment_sessions.c.id == session_id)
                               ).first()
        return self._row_dict(row)

    def find_session_by_order(self, merchant_id, order_id):
        with self.engine.connect() as conn:
            row = conn.execute(
                select(payment_sessions)
                .where(payment_sessions.c.merchant_id == int(merchant_id),
                       payment_sessions.c.order_id == order_id)).first()
        return self._row_dict(row)

    def mark_session_expired(self, session_id):
        with self.engine.begin() as conn:
            result = conn.execute(
                payment_sessions.update()
                .where(payment_sessions.c.id == session_id,
                       payment_sessions.c.status == "pending")
                .values(status="expired"))
            return result.rowcount

    def increment_attempts(self, session_id):
        with self.engine.begin() as conn:
            conn.execute(
                payment_sessions.update()
                .where(payment_sessions.c.id == session_id)
                .values(attempts=payment_sessions.c.attempts + 1))

    def mark_session_paid(self, session_id, provider, payer_wallet, trxid,
                          paid_at):
        with self.engine.begin() as conn:
            conn.execute(
                payment_sessions.update()
                .where(payment_sessions.c.id == session_id)
                .values(status="paid", provider=provider,
                        payer_wallet=payer_wallet, trxid=trxid.upper(),
                        paid_at=paid_at))

    def reset_session_to_pending(self, session_id):
        with self.engine.begin() as conn:
            conn.execute(
                payment_sessions.update()
                .where(payment_sessions.c.id == session_id,
                       payment_sessions.c.status == "paid")
                .values(status="pending", provider=None,
                        payer_wallet=None, trxid=None, paid_at=None))

    def payment_stats(self, merchant_id=None, since_iso=None):
        stmt = select(func.count(),
                      func.coalesce(func.sum(payment_sessions.c.amount_paisa),
                                    0)).where(payment_sessions.c.status == "paid")
        if merchant_id is not None:
            stmt = stmt.where(payment_sessions.c.merchant_id == int(merchant_id))
        if since_iso is not None:
            stmt = stmt.where(payment_sessions.c.paid_at >= since_iso)
        with self.engine.connect() as conn:
            row = conn.execute(stmt).one()
        return {"count": int(row[0]), "volume": int(row[1])}

    def count_pending_sessions(self, merchant_id):
        with self.engine.connect() as conn:
            return int(conn.execute(
                select(func.count()).select_from(payment_sessions)
                .where(payment_sessions.c.merchant_id == int(merchant_id),
                       payment_sessions.c.status == "pending")
            ).scalar_one())

    def list_sessions(self, merchant_id=None, limit=100):
        stmt = (select(payment_sessions,
                       func.coalesce(merchants.c.name, "?").label("merchant"))
                .select_from(payment_sessions.outerjoin(
                    merchants,
                    merchants.c.id == payment_sessions.c.merchant_id))
                .order_by(payment_sessions.c.created_at.desc())
                .limit(limit))
        if merchant_id is not None:
            stmt = stmt.where(payment_sessions.c.merchant_id == int(merchant_id))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [self._row_dict(r) for r in rows]

    def list_paid_recent(self, limit=12):
        stmt = (select(payment_sessions.c.id, payment_sessions.c.order_id,
                       payment_sessions.c.amount_paisa,
                       payment_sessions.c.provider, payment_sessions.c.trxid,
                       payment_sessions.c.paid_at,
                       func.coalesce(merchants.c.name, "?").label("merchant"))
                .select_from(payment_sessions.outerjoin(
                    merchants,
                    merchants.c.id == payment_sessions.c.merchant_id))
                .where(payment_sessions.c.status == "paid")
                .order_by(payment_sessions.c.paid_at.desc())
                .limit(limit))
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [self._row_dict(r) for r in rows]
