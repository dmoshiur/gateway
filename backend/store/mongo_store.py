"""MongoDB backend (pymongo) — the gateway's only storage engine.

Production:  MONGO_URI=mongodb+srv://user:pass@cluster.../mfs_gateway
Single line: database name comes from the URI path (default: mfs_gateway).
Dev/CI:      GATEWAY_MONGO_MOCK=1 patches MONGO_CLIENT_FACTORY to mongomock.
"""

from __future__ import annotations

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError

from . import DEFAULT_SETTINGS, DuplicateError, Store, utcnow_iso
from .seeding import seed_admin

# Tests/dev shim may patch this with mongomock.MongoClient.
MONGO_CLIENT_FACTORY = MongoClient

_LABELLED_KEY_FIELDS = {
    "id": 1, "key_id": 1, "label": 1, "status": 1,
    "created_at": 1, "last_used_at": 1, "_id": 0,
}


class MongoStore(Store):
    def __init__(self, uri: str, db_name: str = "mfs_gateway", mocked: bool = False):
        self.mocked = mocked
        self.uri = uri
        self.db_name = db_name
        kwargs = {} if mocked else {"serverSelectionTimeoutMS": 8000}
        self.client = MONGO_CLIENT_FACTORY(uri, **kwargs)
        self.db = self.client[db_name]

    # ------------------------------------------------------------------ util
    def _next_id(self, name: str) -> int:
        doc = self.db.counters.find_one_and_update(
            {"_id": name}, {"$inc": {"seq": 1}}, upsert=True,
            return_document=ReturnDocument.AFTER)
        return int(doc["seq"])

    @staticmethod
    def _clean(doc):
        if doc is None:
            return None
        doc = dict(doc)
        doc.pop("_id", None)
        return doc

    def close(self) -> None:
        self.client.close()

    # ------------------------------------------------------------------ seed
    def init(self, app) -> None:
        db = self.db
        db.admins.create_index([("username", ASCENDING)], unique=True)
        db.merchants.create_index([("email", ASCENDING)], unique=True)
        db.api_keys.create_index([("key_id", ASCENDING)], unique=True)
        db.api_keys.create_index([("merchant_id", ASCENDING)])
        db.devices.create_index([("device_id", ASCENDING)], unique=True)
        db.sms_transactions.create_index([("trxid_norm", ASCENDING)], unique=True)
        db.sms_transactions.create_index([("id", ASCENDING)], unique=True)
        db.sms_transactions.create_index([("status", ASCENDING)])
        db.payment_sessions.create_index([("merchant_id", ASCENDING)])
        db.payment_sessions.create_index(
            [("merchant_id", ASCENDING), ("order_id", ASCENDING)], unique=True)
        db.audit_logs.create_index([("id", ASCENDING)], unique=True)

        for key, value in DEFAULT_SETTINGS.items():
            db.settings.update_one({"_id": key}, {"$setOnInsert": {"value": value}},
                                   upsert=True)
        seed_admin(self, app)

    # -------------------------------------------------------- settings/audit
    def get_setting(self, key, default=""):
        doc = self.db.settings.find_one({"_id": key})
        return doc["value"] if doc else default

    def set_setting(self, key, value):
        self.db.settings.update_one({"_id": key}, {"$set": {"value": value}},
                                    upsert=True)

    def all_settings(self):
        return {d["_id"]: d["value"] for d in self.db.settings.find()}

    def audit(self, actor, action, meta=""):
        self.db.audit_logs.insert_one({
            "id": self._next_id("audit_logs"), "actor": actor, "action": action,
            "meta": meta, "created_at": utcnow_iso()})

    def list_audit(self, limit=100):
        cur = self.db.audit_logs.find({}, {"_id": 0}).sort("id", DESCENDING).limit(limit)
        return [self._clean(d) for d in cur]

    # ---------------------------------------------------------------- admins
    def find_admin(self, username):
        return self._clean(self.db.admins.find_one({"username": username}))

    def upsert_admin(self, username, password_hash):
        self.db.admins.update_one(
            {"username": username},
            {"$set": {"password_hash": password_hash},
             "$setOnInsert": {"created_at": utcnow_iso()}},
            upsert=True)

    def set_admin_password(self, username, password_hash):
        self.db.admins.update_one({"username": username},
                                  {"$set": {"password_hash": password_hash}})

    # ------------------------------------------------------------- merchants
    def create_merchant(self, email, name, password_hash):
        try:
            mid = self._next_id("merchants")
            self.db.merchants.insert_one({
                "id": mid, "email": email, "name": name,
                "password_hash": password_hash, "status": "active",
                "created_at": utcnow_iso()})
            return mid
        except DuplicateKeyError as exc:
            raise DuplicateError(str(exc)) from exc

    def find_merchant_by_email(self, email):
        return self._clean(self.db.merchants.find_one({"email": email}))

    def get_merchant(self, merchant_id):
        return self._clean(self.db.merchants.find_one({"id": int(merchant_id)}))

    def set_merchant_password(self, merchant_id, password_hash):
        self.db.merchants.update_one({"id": int(merchant_id)},
                                     {"$set": {"password_hash": password_hash}})

    def set_merchant_status(self, merchant_id, status):
        self.db.merchants.update_one({"id": int(merchant_id)},
                                     {"$set": {"status": status}})

    def count_merchants(self):
        return self.db.merchants.count_documents({})

    def list_merchants_enriched(self):
        out = []
        for m in self.db.merchants.find().sort("id", DESCENDING):
            m = self._clean(m)
            paid = [s for s in self.db.payment_sessions.find(
                {"merchant_id": m["id"], "status": "paid"},
                {"amount_paisa": 1, "_id": 0})]
            m["keys"] = self.db.api_keys.count_documents({"merchant_id": m["id"]})
            m["paid_count"] = len(paid)
            m["volume"] = sum(int(s.get("amount_paisa", 0)) for s in paid)
            out.append(m)
        return out

    # ------------------------------------------------------------------ keys
    def create_api_key(self, merchant_id, key_id, secret, label):
        pk = self._next_id("api_keys")
        self.db.api_keys.insert_one({
            "id": pk, "merchant_id": int(merchant_id), "key_id": key_id,
            "secret": secret, "label": label, "status": "active",
            "created_at": utcnow_iso(), "last_used_at": None})
        return pk

    def find_active_key(self, key_id):
        return self._clean(self.db.api_keys.find_one(
            {"key_id": key_id, "status": "active"}))

    def list_keys_for_merchant(self, merchant_id):
        cur = self.db.api_keys.find({"merchant_id": int(merchant_id)},
                                    _LABELLED_KEY_FIELDS).sort("id", DESCENDING)
        return [self._clean(d) for d in cur]

    def list_all_keys_enriched(self):
        merchants = {m["id"]: m for m in
                     (self._clean(x) for x in self.db.merchants.find())}
        out = []
        cur = self.db.api_keys.find({}, {"secret": 0}).sort("id", DESCENDING)
        for k in cur:
            k = self._clean(k)
            m = merchants.get(k["merchant_id"]) or {}
            k["merchant_email"] = m.get("email", "?")
            k["merchant_name"] = m.get("name", "?")
            out.append(k)
        return out

    def set_key_status(self, key_pk, status, merchant_id=None):
        q = {"id": int(key_pk)}
        if merchant_id is not None:
            q["merchant_id"] = int(merchant_id)
        return self.db.api_keys.update_one(q, {"$set": {"status": status}}) \
            .modified_count

    def touch_key(self, key_pk, when):
        self.db.api_keys.update_one({"id": int(key_pk)},
                                    {"$set": {"last_used_at": when}})

    def count_keys(self, merchant_id):
        return self.db.api_keys.count_documents({"merchant_id": int(merchant_id)})

    # ---------------------------------------------------------------- devices
    def create_device(self, device_id, name, secret):
        self._next_id("devices")
        self.db.devices.insert_one({
            "device_id": device_id, "name": name, "secret": secret,
            "status": "active", "last_seen_at": None, "created_at": utcnow_iso()})

    def find_active_device(self, device_id):
        return self._clean(self.db.devices.find_one(
            {"device_id": device_id, "status": "active"}))

    def list_devices(self):
        cur = self.db.devices.find(
            {}, {"secret": 0}).sort("created_at", DESCENDING)
        out = []
        for d in cur:
            d = self._clean(d)
            d["id"] = d.get("device_id")  # templates key on device_id anyway
            out.append(d)
        return out

    def set_device_status(self, device_id, status):
        self.db.devices.update_one({"device_id": device_id},
                                   {"$set": {"status": status}})

    def touch_device(self, device_id, when):
        self.db.devices.update_one({"device_id": device_id},
                                   {"$set": {"last_seen_at": when}})

    # -------------------------------------------------------------------- sms
    def insert_sms(self, provider, sender, amount_paisa, trxid, device_id,
                   sms_timestamp, raw_hash):
        try:
            sid = self._next_id("sms_transactions")
            self.db.sms_transactions.insert_one({
                "id": sid, "provider": provider, "sender": sender,
                "amount_paisa": int(amount_paisa), "trxid": trxid.upper(),
                "trxid_norm": trxid.upper(), "device_id": device_id,
                "sms_timestamp": sms_timestamp, "raw_hash": raw_hash,
                "status": "unused", "matched_session_id": None,
                "created_at": utcnow_iso()})
            return "stored"
        except DuplicateKeyError:
            return "duplicate"

    def find_sms_by_trxid(self, trxid):
        return self._clean(self.db.sms_transactions.find_one(
            {"trxid_norm": trxid.upper()}))

    def get_sms(self, sms_id):
        return self._clean(self.db.sms_transactions.find_one({"id": int(sms_id)}))

    def claim_sms(self, sms_id, session_id):
        doc = self.db.sms_transactions.find_one_and_update(
            {"id": int(sms_id), "status": "unused"},
            {"$set": {"status": "consumed", "matched_session_id": session_id}},
            return_document=ReturnDocument.AFTER)
        return doc is not None

    def release_sms(self, sms_id):
        self.db.sms_transactions.update_one(
            {"id": int(sms_id)},
            {"$set": {"status": "unused", "matched_session_id": None}})

    def list_sms_since(self, since_id, limit=150):
        sms_rows = [self._clean(d) for d in
                    self.db.sms_transactions.find({"id": {"$gt": int(since_id)}})
                    .sort("id", DESCENDING).limit(limit)]
        return self._enrich_sms(sms_rows)

    def list_sms_recent(self, limit=12):
        cur = self.db.sms_transactions.find().sort("id", DESCENDING).limit(limit)
        return [self._clean(d) for d in cur]

    def _enrich_sms(self, rows):
        sessions = {s["id"]: self._clean(s) for s in
                    self.db.payment_sessions.find()}
        merchants = {m["id"]: self._clean(m) for m in self.db.merchants.find()}
        for r in rows:
            sess = sessions.get(r.get("matched_session_id") or "")
            r["order_id"] = sess.get("order_id") if sess else None
            merch = merchants.get(sess["merchant_id"]) if sess else None
            r["merchant"] = merch.get("name") if merch else None
        return rows

    def sms_stats(self):
        stats = {}
        for row in self.db.sms_transactions.find({}, {"status": 1, "_id": 0}):
            stats[row["status"]] = stats.get(row["status"], 0) + 1
        return stats

    # --------------------------------------------------------------- sessions
    def create_session(self, data):
        try:
            doc = {
                "id": data["id"], "merchant_id": int(data["merchant_id"]),
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
                "status": "pending", "provider": None, "payer_wallet": None,
                "trxid": None, "attempts": 0,
                "expires_at": data["expires_at"],
                "created_at": data.get("created_at") or utcnow_iso(),
                "paid_at": None,
            }
            self.db.payment_sessions.insert_one(doc)
        except DuplicateKeyError as exc:
            raise DuplicateError(str(exc)) from exc

    def find_session(self, session_id):
        return self._clean(self.db.payment_sessions.find_one({"id": session_id}))

    def find_session_by_order(self, merchant_id, order_id):
        return self._clean(self.db.payment_sessions.find_one(
            {"merchant_id": int(merchant_id), "order_id": order_id}))

    def mark_session_expired(self, session_id):
        return self.db.payment_sessions.update_one(
            {"id": session_id, "status": "pending"},
            {"$set": {"status": "expired"}}).modified_count

    def increment_attempts(self, session_id):
        self.db.payment_sessions.update_one({"id": session_id},
                                            {"$inc": {"attempts": 1}})

    def mark_session_paid(self, session_id, provider, payer_wallet, trxid, paid_at):
        self.db.payment_sessions.update_one(
            {"id": session_id},
            {"$set": {"status": "paid", "provider": provider,
                      "payer_wallet": payer_wallet, "trxid": trxid.upper(),
                      "paid_at": paid_at}})

    def reset_session_to_pending(self, session_id):
        self.db.payment_sessions.update_one(
            {"id": session_id, "status": "paid"},
            {"$set": {"status": "pending", "provider": None,
                      "payer_wallet": None, "trxid": None, "paid_at": None}})

    def payment_stats(self, merchant_id=None, since_iso=None):
        q = {"status": "paid"}
        if merchant_id is not None:
            q["merchant_id"] = int(merchant_id)
        if since_iso is not None:
            q["paid_at"] = {"$gte": since_iso}
        count, volume = 0, 0
        for s in self.db.payment_sessions.find(q, {"amount_paisa": 1, "_id": 0}):
            count += 1
            volume += int(s.get("amount_paisa", 0))
        return {"count": count, "volume": volume}

    def count_pending_sessions(self, merchant_id):
        return self.db.payment_sessions.count_documents(
            {"merchant_id": int(merchant_id), "status": "pending"})

    def list_sessions(self, merchant_id=None, limit=100):
        q = {}
        if merchant_id is not None:
            q["merchant_id"] = int(merchant_id)
        cur = self.db.payment_sessions.find(q).sort("created_at", DESCENDING) \
            .limit(limit)
        merchants = {m["id"]: self._clean(m) for m in self.db.merchants.find()}
        out = []
        for s in cur:
            s = self._clean(s)
            m = merchants.get(s["merchant_id"]) or {}
            s["merchant"] = m.get("name", "?")
            out.append(s)
        return out

    def list_paid_recent(self, limit=12):
        cur = self.db.payment_sessions.find({"status": "paid"}) \
            .sort("paid_at", DESCENDING).limit(limit)
        merchants = {m["id"]: self._clean(m) for m in self.db.merchants.find()}
        out = []
        for s in cur:
            s = self._clean(s)
            m = merchants.get(s["merchant_id"]) or {}
            s["merchant"] = m.get("name", "?")
            out.append({k: s.get(k) for k in (
                "id", "order_id", "amount_paisa", "provider", "trxid", "paid_at",
                "merchant")})
        return out
