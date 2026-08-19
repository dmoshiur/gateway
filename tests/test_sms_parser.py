"""Unit tests for the MFS SMS regex engine.

Run:  python -m unittest discover -s tests -v   (from repo root)
or:   python tests/test_sms_parser.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.sms_parser import (  # noqa: E402
    amount_to_paisa,
    detect_provider,
    normalize_msisdn,
    paisa_to_bdt,
    parse_sms,
)


# ---------------------------------------------------------------------------
# Realistic Bangladeshi MFS SMS samples (shape-accurate).
# ---------------------------------------------------------------------------

SAMPLES = [
    # (address, body, provider, sender, amount_paisa, trxid)
    (
        "bKash",
        "You have received Tk 1,500.00 from 01712345678. Fee Tk 0.00. "
        "Balance Tk 2,345.67. TrxID 9HK8A2X1LM at 19/08/2026 14:30",
        "bkash", "01712345678", 150000, "9HK8A2X1LM",
    ),
    (
        "bKash",
        "You have received Tk 250.50 from +8801812345678. TrxID: AB12CD34EF "
        "at 19/08/2026 09:05. Download the bKash App",
        "bkash", "01812345678", 25050, "AB12CD34EF",
    ),
    (
        "Nagad",
        "Money received. Amount: Tk 2,000.00. Sender: 01812345678. "
        "TxnID: 7XQ2M1P9ZA. Balance: Tk 5,678.00",
        "nagad", "01812345678", 200000, "7XQ2M1P9ZA",
    ),
    (
        "Nagad",
        "Dear Customer, Mr ALEX (01912345678) has sent Tk 500.00 to your "
        "Nagad account. TxnID: 8YRT9K3MNC. Fee: Tk 0.00",
        "nagad", "01912345678", 50000, "8YRT9K3MNC",
    ),
    (
        "16216",  # Nagad short-code address carries no keyword in body
        "Dear Customer, Money received Amount: Tk 3,300.75 Sender: 01612345678 "
        "TxnID: 55DD22HHJK Balance: Tk 9,000.75. Nagad",
        "nagad", "01612345678", 330075, "55DD22HHJK",
    ),
    (
        "Rocket",
        "Cash In of Tk 750.00 from 01712345678 successful. "
        "TxnID: 8877665544. Current Balance Tk 1,000.00",
        "rocket", "01712345678", 75000, "8877665544",
    ),
    (
        "DBBL",
        "Dear Customer, Your account has been credited Tk 4,000.00 from "
        "01512345678. Transaction ID: DBBL99AA88BB.",
        "rocket", "01512345678", 400000, "DBBL99AA88BB",
    ),
    (
        "Upay",
        "Your Upay wallet has been credited Tk 1,200.00 from 01612345678. "
        "Transaction ID: UPX123456789. Balance Tk 1,900.00",
        "upay", "01612345678", 120000, "UPX123456789",
    ),
    (
        "Tap",
        "Tk 300.00 received from 01512345678. Txn Id: TP99887766. "
        "Tap'n Pay - always with you.",
        "tap", "01512345678", 30000, "TP99887766",
    ),
    (
        "Meghna",
        "Dear customer, Tk 999.00 received from 01312345678. "
        "Transaction Id: MGH11223344. Meghna Pay.",
        "meghna", "01312345678", 99900, "MGH11223344",
    ),
    # No provider keyword anywhere -> generic fallback, unknown provider
    (
        "+88096000000",
        "Congratulations! Tk 610.10 received from 01777123456. "
        "Transaction ID: GENX77YY99ZZ",
        "unknown", "01777123456", 61010, "GENX77YY99ZZ",
    ),
]

# Messages that must NOT be parsed as incoming money.
NEGATIVE_SAMPLES = [
    "You have sent Tk 500.00 to 01712345678. TrxID ZZ11YY22XX at 19/08/2026",
    "Payment of Tk 1,000.00 to Merchant ABC successful. TrxID 9QWERTYUIO",
    "Cash Out Tk 2,000.00 from Agent 01712345678 successful. TrxID 00OKJHBHGV",
    "Your transaction of Tk 750.00 from 01712345678 failed. TxnID: 8877665544",
    "Dear Customer, Tk 100.00 debited from your account. Txn ID: ABCDEF1234",
]


class TestParseSamples(unittest.TestCase):
    def test_positive_samples(self):
        for address, body, provider, sender, paisa, trxid in SAMPLES:
            with self.subTest(provider=provider, trxid=trxid):
                result = parse_sms(body, address)
                self.assertIsNotNone(result, f"failed to parse: {body}")
                self.assertEqual(result["provider"], provider)
                self.assertEqual(result["sender"], sender)
                self.assertEqual(result["amount_paisa"], paisa)
                self.assertEqual(result["trxid"], trxid)

    def test_negative_samples(self):
        for body in NEGATIVE_SAMPLES:
            with self.subTest(body=body[:40]):
                self.assertIsNone(parse_sms(body), f"false positive: {body}")

    def test_garbage(self):
        self.assertIsNone(parse_sms(""))
        self.assertIsNone(parse_sms("Hello world, your OTP is 483920"))
        self.assertIsNone(parse_sms("Grameenphone: your balance is Tk 12.50"))


class TestHelpers(unittest.TestCase):
    def test_amount_conversion(self):
        self.assertEqual(amount_to_paisa("1,500.00"), 150000)
        self.assertEqual(amount_to_paisa("250.5"), 25050)
        self.assertEqual(amount_to_paisa("99"), 9900)
        self.assertEqual(amount_to_paisa("0.01"), 1)
        self.assertEqual(paisa_to_bdt(150000), "1,500.00")
        self.assertEqual(paisa_to_bdt(99), "0.99")
        with self.assertRaises(ValueError):
            amount_to_paisa("not-a-number")

    def test_msisdn_normalisation(self):
        self.assertEqual(normalize_msisdn("+8801712345678"), "01712345678")
        self.assertEqual(normalize_msisdn("8801712345678"), "01712345678")
        self.assertEqual(normalize_msisdn("01712345678"), "01712345678")
        self.assertEqual(normalize_msisdn("01712-345-678"), "01712345678")

    def test_detect_provider(self):
        self.assertEqual(detect_provider("bKash\nanything"), "bkash")
        self.assertEqual(detect_provider("NAGAD: anything"), "nagad")
        self.assertEqual(detect_provider("DBBL\nanything"), "rocket")
        self.assertIsNone(detect_provider("no keyword here"))


if __name__ == "__main__":
    unittest.main()
