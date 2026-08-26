"""Store-level contract tests for the PostgreSQL backend.

Default transport: in-memory SQLite through the same SQLAlchemy code path
(no PostgreSQL server needed). Set ``GATEWAY_TEST_DATABASE_URL`` to a
PostgreSQL URL to run the suite against the real engine.

Run:  python tests/test_postgres_store.py
"""

import unittest

from flow_base import GatewayFlows


class TestPostgresStoreContract(GatewayFlows):
    """PostgreSQL store sanity (auto-increment ids, unique constraints,
    atomic claims, URL normalization)."""

    def test_auto_increment_and_uniques(self):
        store = self.app.store
        m1 = store.create_merchant("m1@test.io", "Shop One", "hash")
        m2 = store.create_merchant("m2@test.io", "Shop Two", "hash")
        self.assertNotEqual(m1, m2)  # sequences increment per table
        from backend.store import DuplicateError
        with self.assertRaises(DuplicateError):
            store.create_merchant("m1@test.io", "Dup Shop", "hash")

    def test_claim_atomicity_and_lookup(self):
        store = self.app.store
        self.assertEqual(store.insert_sms(
            "nagad", "01811112222", 250000, "PGCLAIM1", "dev_x",
            "2026-08-19T00:00:00+00:00", "h"), "stored")
        self.assertEqual(store.insert_sms(
            "nagad", "01811112222", 250000, "pgclaim1", "dev_x", "", "h"),
            "duplicate")  # unique trxid_norm, case-insensitive
        sms = store.find_sms_by_trxid("PGCLAIM1")
        self.assertTrue(store.claim_sms(sms["id"], "ps_m1"))
        self.assertFalse(store.claim_sms(sms["id"], "ps_m2"))
        store.release_sms(sms["id"])
        self.assertTrue(store.claim_sms(sms["id"], "ps_m3"))

    def test_session_order_unique(self):
        store = self.app.store
        mid = store.create_merchant("order@test.io", "Order Shop", "hash")
        base = {
            "id": "ps_order_unique_1", "merchant_id": mid, "api_key_id": None,
            "order_id": "ORD-UNIQUE-1", "amount_paisa": 50000,
            "currency": "BDT", "customer_name": "", "customer_email": "",
            "customer_phone": "", "success_url": "", "cancel_url": "",
            "callback_url": "", "expires_at": "2099-01-01T00:00:00+00:00",
        }
        store.create_session(base)
        from backend.store import DuplicateError
        with self.assertRaises(DuplicateError):
            store.create_session(base)  # UNIQUE(merchant_id, order_id)

    def test_url_normalization(self):
        from backend.store.postgres_store import normalize_url
        self.assertEqual(
            normalize_url("postgresql://u:p@host:5432/mfs_gateway"),
            "postgresql+psycopg://u:p@host:5432/mfs_gateway")
        self.assertEqual(
            normalize_url("postgres://u:p@host:5432/mfs_gateway"),
            "postgresql+psycopg://u:p@host:5432/mfs_gateway")
        self.assertEqual(
            normalize_url("postgresql+psycopg://u:p@host/db"),
            "postgresql+psycopg://u:p@host/db")  # already explicit
        self.assertEqual(normalize_url("sqlite://"), "sqlite://")


if __name__ == "__main__":
    unittest.main()
