"""API + security flow tests against the SQLite backend (default).

Run:  python tests/test_api_flows.py
"""

import unittest

from flow_base import (FlowsHappyPath, FlowsPanelAuth, FlowsVerificationRules,
                       FlowsWebhookSecurity, GatewayFlows)


class TestSqliteHappyPath(FlowsHappyPath):
    BACKEND = "sqlite"


class TestSqliteWebhookSecurity(FlowsWebhookSecurity):
    BACKEND = "sqlite"


class TestSqliteVerificationRules(FlowsVerificationRules):
    BACKEND = "sqlite"


class TestSqlitePanelAuth(FlowsPanelAuth):
    BACKEND = "sqlite"


class TestSqliteStoreContract(GatewayFlows):
    """SQLite-specific store sanity (duplicates, claim atomicity)."""

    BACKEND = "sqlite"

    def test_store_basic_contract(self):
        store = self.app.store
        r1 = store.insert_sms("bkash", "01711111111", 1500, "SQLSTORE1",
                              "dev_x", "2026-08-19T00:00:00+00:00", "h")
        self.assertEqual(r1, "stored")
        self.assertEqual(store.insert_sms("bkash", "01711111111", 1500,
                                          "SQLSTORE1", "dev_x", "", "h"),
                         "duplicate")
        sms = store.find_sms_by_trxid("sqlstore1")  # case-insensitive lookup
        self.assertEqual(sms["amount_paisa"], 1500)
        self.assertTrue(store.claim_sms(sms["id"], "ps_test_claim"))
        self.assertFalse(store.claim_sms(sms["id"], "ps_test_claim2"))


if __name__ == "__main__":
    unittest.main()
