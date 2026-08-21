"""API + security flow tests — MongoDB store (in-memory transport for CI).

Run:  python tests/test_api_flows.py
"""

import unittest

from flow_base import (FlowsHappyPath, FlowsPanelAuth, FlowsVerificationRules,
                       FlowsWebhookSecurity)


class TestHappyPath(FlowsHappyPath):
    pass


class TestWebhookSecurity(FlowsWebhookSecurity):
    pass


class TestVerificationRules(FlowsVerificationRules):
    pass


class TestPanelAuth(FlowsPanelAuth):
    pass


if __name__ == "__main__":
    unittest.main()
