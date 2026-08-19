"""
MFS SMS Parsing Engine
======================

Regex engine that extracts structured payment data from raw Bangladeshi MFS
payment SMS (bKash, Nagad, Rocket, Upay, Tap, Meghna, ...).

The *exact same patterns* are duplicated inside ``termux/termux_listener.py``
(the listener is kept 100% dependency-free so it cannot import this package),
so keep both copies in sync. ``tests/test_sms_parser.py`` pins the behaviour.

Matching strategy (3 tiers, safest first):

  1. If a provider keyword is detected (SMS address header or body), try that
     provider's own patterns, then the generic pattern, credited to the
     detected provider.
  2. Otherwise try only *distinctive* (high-precision, brand-signature)
     patterns of every provider.
  3. Finally fall back to the generic "Tk <amount> ... 01XXXXXXXXX ... ID"
     shape, credited to provider ``unknown``.

Guard rails reject debit / failed / cash-out / outgoing-payment SMS so they
can never be matched as incoming money.

Canonical sample messages the patterns were built against:

  bKash   : "You have received Tk 1,500.00 from 01712345678. Fee Tk 0.00.
             Balance Tk 2,345.67. TrxID 9HK8A2X1LM at 19/08/2026 14:30"
  Nagad   : "Money received. Amount: Tk 2,000.00. Sender: 01812345678.
             TxnID: 7XQ2M1P9ZA. Balance: Tk 5,678.00"
  Nagad(2): "Dear Customer, Mr Alex (01912345678) has sent Tk 500.00 to your
             Nagad account. TxnID: 8YRT9K3MNC. Fee: Tk 0.00"
  Rocket  : "Cash In of Tk 750.00 from 01712345678 successful.
             TxnID: 8877665544. Current Balance Tk 1,000.00"
  Upay    : "Your Upay wallet has been credited Tk 1,200.00 from 01612345678.
             Transaction ID: UPX123456789. Balance Tk 1,900.00"
  Tap     : "Tk 300.00 received from 01512345678. Txn Id: TP99887766.
             Tap'n Pay"
"""

from __future__ import annotations

import re
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Optional

# ---------------------------------------------------------------------------
# Amounts are handled as integer "paisa" (1 BDT = 100 paisa) everywhere in the
# system to avoid binary floating point drift.
# ---------------------------------------------------------------------------

_AMOUNT = r"(?P<amount>[\d,]+(?:\.\d{1,2})?)"
_MSISDN = r"(?P<sender>\+?8801\d{9}|01\d{9})"
_TXN = r"(?P<trxid>[A-Za-z0-9\-]{6,24})"

_FLAGS = re.IGNORECASE | re.DOTALL

# Guard rails: never treat a debit / failure notice as a received payment.
# Phrases are chosen so they cannot fire on receiver-side credit SMS
# (e.g. Nagad's "Mr X (01...) has sent Tk 500.00 to your Nagad account").
_NEGATIVE_GUARD = re.compile(
    r"\b(failed|unsuccessful|reversed|reversal|cancelled|canceled|"
    r"debited|deducted|cash out)\b|"
    r"you have sent|payment of tk",
    re.IGNORECASE,
)


def _rx(pattern: str, distinctive: bool) -> tuple[re.Pattern, bool]:
    return (re.compile(pattern, _FLAGS), distinctive)


# ---------------------------------------------------------------------------
# Provider registry.  Order matters: first matching pattern wins.
# ``distinctive=True`` marks patterns precise enough to attribute a provider
# even when no brand keyword exists in the SMS.
# ---------------------------------------------------------------------------

PROVIDERS: dict[str, dict] = {
    "bkash": {
        "label": "bKash",
        "keywords": ("bkash", "bikash"),
        "patterns": [
            # "You have received Tk 1,500.00 from 01712345678. ... TrxID 9HK8A2X1LM"
            # Exact pattern requested in the spec (with fixed char class):
            #   You have received Tk ([\d,.]+).*from ([0-9]+).*TrxID ([A-Z0-9]+)
            _rx(
                r"you have received tk\s*" + _AMOUNT +
                r"\s*from\s*" + _MSISDN +
                r".*?trx\s*id\s*[:\-]?\s*" + _TXN,
                True,
            ),
            # Alternate ordering seen in some reseller/agent SMS
            _rx(
                r"received tk\s*" + _AMOUNT +
                r".*?from\s*" + _MSISDN +
                r".*?trx\s*id\s*[:\-]?\s*" + _TXN,
                False,
            ),
        ],
    },
    "nagad": {
        "label": "Nagad",
        "keywords": ("nagad", "ngd"),
        "patterns": [
            # "Money received. Amount: Tk 2,000.00. Sender: 01812345678. TxnID: 7XQ2M1P9ZA"
            # Exact pattern requested in the spec (with fixed char class):
            #   Money received Amount: Tk ([\d,.]+).*Sender: ([0-9]+).*TxnID: ([A-Z0-9]+)
            _rx(
                r"(?:amount|amt)\s*:?\s*tk\s*" + _AMOUNT +
                r".*?sender\s*:?\s*" + _MSISDN +
                r".*?txn\s*id\s*:?\s*" + _TXN,
                True,
            ),
            # "Mr Alex (01912345678) has sent Tk 500.00 ... TxnID: 8YRT9K3MNC"
            _rx(
                r"\(?\s*" + _MSISDN + r"\s*\)?\s*has sent tk\s*" + _AMOUNT +
                r".*?txn\s*id\s*:?\s*" + _TXN,
                False,
            ),
            # "credited with Tk ... from 01... TxnID: ..."
            _rx(
                r"credited (?:with |by )?tk\s*" + _AMOUNT +
                r".*?from\s*" + _MSISDN +
                r".*?txn\s*id\s*:?\s*" + _TXN,
                False,
            ),
        ],
    },
    "rocket": {
        "label": "Rocket (DBBL)",
        "keywords": ("rocket", "dbbl", "dutch-bangla", "dutch bangla"),
        "patterns": [
            # "Cash In of Tk 750.00 from 01712345678 successful. TxnID: 8877665544"
            _rx(
                r"(?:cash\s*in|cashin|received|credited)[^\d]{0,25}tk\s*\.?\s*" +
                _AMOUNT + r"\s*(?:from|fr)\s*" + _MSISDN +
                r".*?(?:txn|trx|trnx|transaction|tran)[\s\-]*(?:id|no)?\s*:?\s*" + _TXN,
                True,
            ),
        ],
    },
    "upay": {
        "label": "Upay",
        "keywords": ("upay", "ucb"),
        "patterns": [
            # "Your Upay wallet has been credited Tk 1,200.00 from 01612345678. Transaction ID: UPX123456789"
            _rx(
                r"(?:credited|received)[^\d]{0,20}tk\s*\.?\s*" + _AMOUNT +
                r"\s*from\s*" + _MSISDN +
                r".*?(?:transaction\s*id|txn\s*id|trx\s*id)\s*:?\s*" + _TXN,
                False,
            ),
        ],
    },
    "tap": {
        "label": "Tap",
        "keywords": ("tap'n pay", "tapn pay", "tap'n'pay", " tap"),
        "patterns": [
            _rx(
                r"tk\s*\.?\s*" + _AMOUNT + r"\s*received\s*from\s*" + _MSISDN +
                r".*?(?:txn|trx|tran|transaction)[\s\-]*id\s*:?\s*" + _TXN,
                False,
            ),
        ],
    },
    "meghna": {
        "label": "Meghna Pay",
        "keywords": ("meghna",),
        "patterns": [
            _rx(
                r"(?:received|credited)[^\d]{0,20}tk\s*\.?\s*" + _AMOUNT +
                r"\s*from\s*" + _MSISDN +
                r".*?(?:txn|trx|tran|transaction)[\s\-]*(?:id|no)?\s*:?\s*" + _TXN,
                False,
            ),
        ],
    },
}

# Last-resort pattern matching any "Tk amount ... 01XXXXXXXXX ... ID: XXX".
_GENERIC_PATTERN = re.compile(
    r"tk\s*\.?\s*" + _AMOUNT +
    r".{0,120}?" + _MSISDN +
    r".{0,120}?(?:trx|txn|trnx|transaction|tran)[\s\-]*(?:id|no)\s*[:\-]?\s*" + _TXN,
    _FLAGS,
)


def detect_provider(text: str) -> Optional[str]:
    """Detect the MFS provider from SMS address header + body keywords."""
    haystack = " " + text.lower() + " "
    for name, cfg in PROVIDERS.items():
        for kw in cfg["keywords"]:
            if kw in haystack:
                return name
    return None


def normalize_msisdn(raw: str) -> str:
    """Normalise a Bangladeshi wallet number to local 01XXXXXXXXX format."""
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 13 and digits.startswith("8801"):
        return digits[2:]  # '8801712345678' -> '01712345678'
    if len(digits) == 11 and digits.startswith("01"):
        return digits
    return digits


def amount_to_paisa(raw: str) -> int:
    """'1,500.00' -> 150000 (integer paisa). Raises ValueError on bad input."""
    cleaned = (raw or "").replace(",", "").strip()
    try:
        dec = Decimal(cleaned)
    except InvalidOperation as exc:
        raise ValueError(f"unparseable amount: {raw!r}") from exc
    return int((dec * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def paisa_to_bdt(paisa: int) -> str:
    """150000 -> '1,500.00'"""
    return f"{paisa / 100:,.2f}"


def _build_result(provider: str, m: re.Match) -> Optional[dict]:
    try:
        paisa = amount_to_paisa(m.group("amount"))
    except ValueError:
        return None
    trxid = m.group("trxid").upper().replace("-", "")
    if not re.fullmatch(r"[A-Z0-9]{6,24}", trxid):
        return None
    return {
        "provider": provider,
        "sender": normalize_msisdn(m.group("sender")),
        "amount_paisa": paisa,
        "trxid": trxid,
    }


def _try_provider(name: str, text: str) -> Optional[dict]:
    for pattern, _distinctive in PROVIDERS[name]["patterns"]:
        m = pattern.search(text)
        if m:
            return _build_result(name, m)
    return None


def parse_sms(body: str, address: str = "") -> Optional[dict]:
    """
    Parse a raw SMS body (plus the SMS 'address'/sender-id header) into a
    structured payment dict, or return None if it isn't a recognised
    money-received notification.

    Returns:
        {"provider": "bkash", "sender": "01712345678",
         "amount_paisa": 150000, "trxid": "9HK8A2X1LM"}
    """
    if not body:
        return None
    if _NEGATIVE_GUARD.search(body):
        return None

    combined = f"{address}\n{body}"
    provider = detect_provider(combined)

    # Tier 1 — provider known: try its own patterns, else generic with it.
    if provider:
        result = _try_provider(provider, body) or _try_provider(provider, combined)
        if result:
            return result
        m = _GENERIC_PATTERN.search(body)
        if m:
            return _build_result(provider, m)

    # Tier 2 — only high-precision distinctive patterns may claim a provider
    # the keyword scan did not detect.
    for name, cfg in PROVIDERS.items():
        if name == provider:
            continue
        for pattern, distinctive in cfg["patterns"]:
            if not distinctive:
                continue
            m = pattern.search(body)
            if m:
                return _build_result(name, m)

    # Tier 3 — generic shape, unknown provider (only when nothing detected).
    if not provider:
        m = _GENERIC_PATTERN.search(body)
        if m:
            return _build_result("unknown", m)

    return None
