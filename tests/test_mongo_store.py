"""Store-level contract tests for the MongoDB backend (mongomock transport).

Run:  python tests/test_mongo_store.py
"""

import unittest

import mongomock  # noqa: F401  (hard requirement for this module)

from flow_base import GatewayFlows


class TestMongoStoreContract(GatewayFlows):
    """MongoDB store sanity (counters, unique indexes, atomic claims)."""

    def test_counters_and_uniques(self):
        store = self.app.store
        m1 = store.create_merchant("m1@test.io", "Shop One", "hash")
        m2 = store.create_merchant("m2@test.io", "Shop Two", "hash")
        self.assertNotEqual(m1, m2)  # counters increment globally
        from backend.store import DuplicateError
        with self.assertRaises(DuplicateError):
            store.create_merchant("m1@test.io", "Dup Shop", "hash")

    def test_claim_atomicity_and_lookup(self):
        store = self.app.store
        self.assertEqual(store.insert_sms(
            "nagad", "01811112222", 250000, "MONGOCLAIM1", "dev_x",
            "2026-08-19T00:00:00+00:00", "h"), "stored")
        self.assertEqual(store.insert_sms(
            "nagad", "01811112222", 250000, "mongoclaim1", "dev_x", "", "h"),
            "duplicate")  # unique trxid_norm, case-insensitive
        sms = store.find_sms_by_trxid("MONGOCLAIM1")
        self.assertTrue(store.claim_sms(sms["id"], "ps_m1"))
        self.assertFalse(store.claim_sms(sms["id"], "ps_m2"))
        store.release_sms(sms["id"])
        self.assertTrue(store.claim_sms(sms["id"], "ps_m3"))

    def test_db_name_comes_from_uri(self):
        from backend.store import _db_name_from_uri
        self.assertEqual(
            _db_name_from_uri("mongodb://localhost:27017/mfs_gateway"),
            "mfs_gateway")
        self.assertEqual(
            _db_name_from_uri("mongodb+srv://u:p@cluster0.x.mongodb.net/my_shop"),
            "my_shop")
        self.assertEqual(_db_name_from_uri("mongodb://localhost:27017"),
                         "mfs_gateway")  # default when no path segment


if __name__ == "__main__":
    unittest.main()
