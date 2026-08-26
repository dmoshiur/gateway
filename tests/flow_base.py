"""Shared API/security flow suite — runs against the PostgreSQL store.

Behavioural contract pinned by these tests: webhook HMAC, idempotency,
replay protection, double-spend blocking, amount matching, CSRF/auth walls
and the full payment cycle.

No PostgreSQL server is needed in CI: the app boots with
``DATABASE_URL=sqlite://``, which runs the exact same SQLAlchemy store code
path (``PostgresStore``) on an in-memory SQLite database. Set
``GATEWAY_TEST_DATABASE_URL`` to a PostgreSQL URL to run the suite against a
real PostgreSQL server.
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def sign(secret: str, kid: str, ts: str, body: str) -> str:
    return hmac.new(secret.encode(), f"{kid}\n{ts}\n{body}".encode(),
                    hashlib.sha256).hexdigest()


def build_app() -> tuple:
    """Create an isolated app instance with an isolated in-memory database.

    Default transport is in-memory SQLite (no PostgreSQL server needed);
    ``GATEWAY_TEST_DATABASE_URL`` overrides it (e.g. a PostgreSQL URL).
    """
    tmp = tempfile.mkdtemp(prefix="gateway-test-pg-")
    os.environ["GATEWAY_DATA_DIR"] = tmp
    os.environ.setdefault("GATEWAY_ADMIN_PASSWORD", "test-admin-pass")
    os.environ["DATABASE_URL"] = (os.environ.get("GATEWAY_TEST_DATABASE_URL")
                                  or "sqlite://")

    from backend.app import create_app
    app = create_app()
    from backend.demo import ensure_demo_data
    creds = ensure_demo_data(app)
    return app, creds


class GatewayFlows(unittest.TestCase):
    """Base class: signed-request helpers + app/creds fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.app, cls.creds = build_app()

    def setUp(self):
        self.c = self.app.test_client()

    def _signed(self, method, path, payload, kid, secret, kid_hdr, ts=None):
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        ts = ts or str(int(time.time()))
        return getattr(self.c, method)(
            path, data=body,
            headers={"Content-Type": "application/json", kid_hdr: kid,
                     "X-Timestamp": ts, "X-Signature": sign(secret, kid, ts, body)})

    def merchant(self, method, path, payload=None):
        return self._signed(method, path, payload, self.creds["api_key"],
                            self.creds["api_secret"], "X-Api-Key")

    def device(self, method, path, payload=None, ts=None):
        return self._signed(method, path, payload, self.creds["device_id"],
                            self.creds["device_secret"], "X-Device-Id", ts=ts)

    def make_checkout(self, order_id, amount="500.00"):
        r = self.merchant("post", "/api/v1/checkout/create", {
            "order_id": order_id, "amount": amount,
            "success_url": "https://m.example/ok",
            "cancel_url": "https://m.example/no"})
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def push_sms(self, trxid, amount_paisa=50000, provider="bkash"):
        return self.device("post", "/api/v1/webhook/sms", {
            "provider": provider, "sender": "01711112222",
            "amount_paisa": amount_paisa, "trxid": trxid})

    def buyer_verify(self, sid, trxid):
        r = self.c.post("/api/v1/checkout/verify", json={
            "session_id": sid, "provider": "bkash",
            "wallet": "01711113333", "trxid": trxid})
        self.assertEqual(r.status_code, 200)
        return r.get_json()


class FlowsHappyPath(GatewayFlows):
    def test_full_payment_cycle(self):
        co = self.make_checkout("T-HAPPY-1", "500.00")
        self.assertEqual(self.push_sms("HAPPY1TRX").status_code, 201)
        res = self.buyer_verify(co["session_id"], "HAPPY1TRX")
        self.assertEqual(res["result"], "paid")
        self.assertIn("sig=", res["redirect"])
        r = self.merchant("get", f"/api/v1/payments/{co['session_id']}")
        self.assertEqual(r.get_json()["status"], "paid")

    def test_idempotent_create(self):
        a = self.make_checkout("T-IDEM-1")
        b = self.merchant("post", "/api/v1/checkout/create", {
            "order_id": "T-IDEM-1", "amount": "500.00"}).get_json()
        self.assertTrue(b.get("idempotent_replay"))
        self.assertEqual(a["session_id"], b["session_id"])


class FlowsWebhookSecurity(GatewayFlows):
    def test_unsigned_rejected(self):
        r = self.c.post("/api/v1/webhook/sms", json={"trxid": "X1", "amount_paisa": 1})
        self.assertEqual(r.status_code, 401)

    def test_tampered_body_rejected(self):
        r = self.device("post", "/api/v1/webhook/sms", {
            "provider": "bkash", "sender": "01711112222",
            "amount_paisa": 10000, "trxid": "TAMPERCTRL"})
        self.assertEqual(r.status_code, 201)

        original = json.dumps({"provider": "bkash", "sender": "01711112222",
                               "amount_paisa": 10000, "trxid": "TAMPER02"},
                              separators=(",", ":"), sort_keys=True)
        ts = str(int(time.time()))
        sig = sign(self.creds["device_secret"], self.creds["device_id"], ts, original)
        tampered = original.replace("10000", "999900")
        r2 = self.c.post("/api/v1/webhook/sms", data=tampered, headers={
            "Content-Type": "application/json",
            "X-Device-Id": self.creds["device_id"],
            "X-Timestamp": ts,
            "X-Signature": sig})
        self.assertEqual(r2.status_code, 401)

    def test_stale_timestamp_rejected(self):
        old = str(int(time.time()) - 900)
        r = self.device("post", "/api/v1/webhook/sms",
                        {"provider": "bkash", "amount_paisa": 100, "trxid": "OLD1"},
                        ts=old)
        self.assertEqual(r.status_code, 401)

    def test_wrong_secret_rejected(self):
        r = self._signed("post", "/api/v1/checkout/create",
                         {"order_id": "HACK-1", "amount": "100.00"},
                         "pk_live_NOPE", "sk_live_WRONG", "X-Api-Key")
        self.assertEqual(r.status_code, 401)

    def test_duplicate_trxid_safe(self):
        self.assertEqual(self.push_sms("DUPTRX01").status_code, 201)
        r = self.push_sms("DUPTRX01")
        self.assertEqual((r.status_code, r.get_json()["status"]), (200, "duplicate"))
        hits = [s for s in self.app.store.list_sms_since(0, 500)
                if s["trxid"] == "DUPTRX01"]
        self.assertEqual(len(hits), 1)


class FlowsVerificationRules(GatewayFlows):
    def test_double_spend_blocked(self):
        s1 = self.make_checkout("T-DS-1")["session_id"]
        s2 = self.make_checkout("T-DS-2")["session_id"]
        self.push_sms("DSTRX0001")
        self.assertEqual(self.buyer_verify(s1, "DSTRX0001")["result"], "paid")
        self.assertEqual(self.buyer_verify(s2, "DSTRX0001")["result"], "used")

    def test_amount_mismatch_blocked(self):
        sid = self.make_checkout("T-AMT-1", "777.00")["session_id"]
        self.push_sms("AMTTRX001", amount_paisa=77701)  # 1 poisha off
        self.assertEqual(self.buyer_verify(sid, "AMTTRX001")["result"],
                         "amount_mismatch")

    def test_unknown_trxid_pending(self):
        sid = self.make_checkout("T-PEND-1")["session_id"]
        self.assertEqual(self.buyer_verify(sid, "NOSUCHTRX1")["result"], "pending")

    def test_wallet_format_enforced(self):
        sid = self.make_checkout("T-WLT-1")["session_id"]
        r = self.c.post("/api/v1/checkout/verify", json={
            "session_id": sid, "provider": "bkash",
            "wallet": "12345", "trxid": "WHATEVER1"})
        self.assertEqual(r.get_json()["result"], "invalid")


class FlowsPanelAuth(GatewayFlows):
    def test_admin_api_requires_login(self):
        r = self.c.get("/admin/api/summary")
        self.assertEqual(r.status_code, 401)

    def test_dashboard_api_requires_login(self):
        r = self.c.get("/dashboard/api/summary")
        self.assertEqual(r.status_code, 401)

    def test_admin_login_and_demo_passwords_work(self):
        self.assertEqual(os.environ.get("GATEWAY_ADMIN_PASSWORD"),
                         "test-admin-pass")
        admin = self.app.store.find_admin("admin")
        from backend.security import verify_password
        self.assertTrue(verify_password("test-admin-pass",
                                        admin["password_hash"]))
        self.assertEqual(self.creds["merchant_password"], "demo12345")
