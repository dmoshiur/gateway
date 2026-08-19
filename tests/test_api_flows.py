"""API + security flow tests using Flask's test client (no server needed).

Run:  python tests/test_api_flows.py
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

os.environ.setdefault("GATEWAY_ADMIN_PASSWORD", "test-admin-pass")

_tmp = tempfile.mkdtemp(prefix="gateway-test-")
os.environ["GATEWAY_DB"] = os.path.join(_tmp, "test.db")
os.environ["GATEWAY_DATA_DIR"] = _tmp

from backend.app import create_app  # noqa: E402
from backend.database import connect, ensure_demo_data  # noqa: E402


def sign(secret: str, kid: str, ts: str, body: str) -> str:
    return hmac.new(secret.encode(), f"{kid}\n{ts}\n{body}".encode(),
                    hashlib.sha256).hexdigest()


class GatewayTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.creds = ensure_demo_data(cls.app)

    def setUp(self):
        self.c = self.app.test_client()

    # -- signed helpers ------------------------------------------------------
    def _signed(self, method, path, payload, kid, secret, kid_hdr, ts=None, raw=None):
        body = raw if raw is not None else \
            json.dumps(payload, separators=(",", ":"), sort_keys=True)
        ts = ts or str(int(time.time()))
        return getattr(self.c, method)(
            path, data=body,
            headers={"Content-Type": "application/json", kid_hdr: kid,
                     "X-Timestamp": ts, "X-Signature": sign(secret, kid, ts, body)})

    def merchant(self, method, path, payload=None):
        return self._signed(method, path, payload, self.creds["api_key"],
                            self.creds["api_secret"], "X-Api-Key")

    def device(self, method, path, payload=None, **kw):
        return self._signed(method, path, payload, self.creds["device_id"],
                            self.creds["device_secret"], "X-Device-Id", **kw)

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


class TestHappyPath(GatewayTestCase):
    def test_full_payment_cycle(self):
        co = self.make_checkout("T-HAPPY-1", "500.00")
        self.assertEqual(self.push_sms("HAPPY1TRX").status_code, 201)
        res = self.buyer_verify(co["session_id"], "HAPPY1TRX")
        self.assertEqual(res["result"], "paid")
        self.assertIn("sig=", res["redirect"])
        # Merchant status API agrees
        r = self.merchant("get", f"/api/v1/payments/{co['session_id']}")
        self.assertEqual(r.get_json()["status"], "paid")

    def test_idempotent_create(self):
        a = self.make_checkout("T-IDEM-1")
        b = self.merchant("post", "/api/v1/checkout/create", {
            "order_id": "T-IDEM-1", "amount": "500.00"}).get_json()
        self.assertTrue(b.get("idempotent_replay"))
        self.assertEqual(a["session_id"], b["session_id"])


class TestWebhookSecurity(GatewayTestCase):
    def test_unsigned_rejected(self):
        r = self.c.post("/api/v1/webhook/sms", json={"trxid": "X1", "amount_paisa": 1})
        self.assertEqual(r.status_code, 401)

    def test_tampered_body_rejected(self):
        # Control: genuine signed delivery is accepted.
        r = self.device("post", "/api/v1/webhook/sms", {
            "provider": "bkash", "sender": "01711112222",
            "amount_paisa": 10000, "trxid": "TAMPERCTRL"})
        self.assertEqual(r.status_code, 201)

        # Sign the ORIGINAL payload, then tamper the body mid-flight and send
        # the tampered bytes with the original signature -> must be 401.
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

    def test_duplicate_trxid_safe(self):
        self.assertEqual(self.push_sms("DUPTRX01").status_code, 201)
        r = self.push_sms("DUPTRX01")
        self.assertEqual((r.status_code, r.get_json()["status"]), (200, "duplicate"))
        # and it is stored exactly once
        conn = connect(self.app.config["DATABASE"])
        n = conn.execute("SELECT COUNT(*) c FROM sms_transactions WHERE trxid='DUPTRX01'").fetchone()["c"]
        conn.close()
        self.assertEqual(n, 1)


class TestVerificationRules(GatewayTestCase):
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


if __name__ == "__main__":
    unittest.main()
