"""API + security flow tests against the MongoDB backend (via mongomock).

The full shared flow suite from flow_base is re-run with the Mongo store,
proving behavioural parity between SQLite and MongoDB.

Run:  python tests/test_mongo_store.py
"""

import unittest

import mongomock  # noqa: F401  (hard requirement for this module)

from flow_base import (FlowsHappyPath, FlowsPanelAuth, FlowsVerificationRules,
                       FlowsWebhookSecurity, GatewayFlows)


class TestMongoHappyPath(FlowsHappyPath):
    BACKEND = "mongodb"


class TestMongoWebhookSecurity(FlowsWebhookSecurity):
    BACKEND = "mongodb"


class TestMongoVerificationRules(FlowsVerificationRules):
    BACKEND = "mongodb"


class TestMongoPanelAuth(FlowsPanelAuth):
    BACKEND = "mongodb"


class TestMongoStoreContract(GatewayFlows):
    """MongoDB-specific store sanity (counters, unique indexes, atomic claims)."""

    BACKEND = "mongodb"

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


if __name__ == "__main__":
    unittest.main()
