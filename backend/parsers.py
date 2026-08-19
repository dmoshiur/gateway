"""SMS parsing engine for Bangladeshi Mobile Financial Service (MFS) providers.

Every provider is represented by one or more compiled regexes. ``parse_sms``
runs the raw SMS text against all of them and returns a normalized dict, or
``None`` if nothing matched.

Notes on the raw SMS formats (real-world examples, English locale):

    bKash (receive)  : "You have received Tk 500.00 from 01712345678. Fee Tk 0.00.
                        Balance Tk 1500.00. TrxID 8JX4A2B3C4."
    bKash (send)     : "bKash - Send Money Tk 100.00 to 01711111111 successful. ... TrxID ..."
    Nagad            : "Money received Amount: Tk 500.00. Sender: 01712345678.
                        TxnID: 1A2B3C4D5E. Fee: Tk 0.00."
    Rocket (DBBL)    : "Dear Customer, Your Rocket Account 01934567890 has been
                        credited by Tk 1,000.00 on 12-Aug-2025 ... TxnID: ROCKET2024"
    Upay             : "Upay: You have received Tk 750.00 from 01645678901. ... TxnID: UPAY998877"
    Tap              : "Tap: Tk 300.00 received from 01556789012. TrxID: TAP555321."
"""
import re

# --- Reusable fragments ------------------------------------------------------ #
# Bangladeshi mobile number: 01XXXXXXXXX (optionally +8801... / 8801...).
MOBILE = r"(?P<sender>(?:\+?88)?01[3-9]\d{8})"
# Money amount: "500", "500.00", "1,500.50" — captured raw, normalized later.
AMOUNT = r"(?P<amount>\d[\d,]*(?:\.\d{1,2})?)"
# Transaction reference: letters+digits, typically 6–16 chars.
TRX = r"(?P<trx_id>[A-Za-z0-9]{6,24})"
# Transaction-id keyword — providers use "TrxID" / "TxnID" / "Txn ID" / "Transaction ID".
TXN = r"(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)"

_IX = re.IGNORECASE | re.DOTALL


def normalize_mobile(raw) -> str:
    """Normalize any Bangladeshi mobile format to canonical 01XXXXXXXXX."""
    if not raw:
        return ""
    s = str(raw).strip().replace(" ", "").replace("-", "")
    if s.startswith("+"):
        s = s[1:]
    if s.startswith("880"):
        s = "0" + s[3:]
    return s


def _c(pat: str) -> re.Pattern:
    return re.compile(pat, _IX)


# --------------------------------------------------------------------------- #
# Provider rules — ordered most-specific first. Each pattern carries a
# direction: "credit" (money coming in — the gateway case) or "debit".
# --------------------------------------------------------------------------- #
# Order matters: keyword-anchored providers are matched FIRST so their brand
# name wins over bKash's keyword-less "received Tk X from Y ... TrxID" format
# (real bKash receive SMS contains no "bKash" brand token).
PROVIDER_RULES = [
    {
        "provider": "Meghna Pay", "key": "meghnapay",
        "patterns": [
            ("credit", _c(r"meghna\s*pay\s*:?\s*.*?received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"meghna\s*pay\s*:?\s*.*?Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ],
    },
    {
        "provider": "Tap", "key": "tap",
        "patterns": [
            ("credit", _c(r"tap\s*:?\s*Tk\s*" + AMOUNT + r".*?(?:received\s+from|from)\s*" + MOBILE +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"tap\s*:?\s*.*?Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ],
    },
    {
        "provider": "Upay", "key": "upay",
        "patterns": [
            ("credit", _c(r"upay\s*:?\s*.*?received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"upay\s*:?\s*.*?Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ],
    },
    {
        "provider": "Nagad", "key": "nagad",
        "patterns": [
            ("credit", _c(r"money\s+received\s*(?:amount)?\s*:?\s*Tk\s*" + AMOUNT +
                          r".*?Sender\s*:?\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"nagad\s*:?\s*.*?received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"nagad\s*:?\s*.*?credited\s+(?:by|with)?\s*Tk\s*" + AMOUNT +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ],
    },
    {
        "provider": "Rocket", "key": "rocket",
        "patterns": [
            ("credit", _c(r"rocket\s+account\s+" + MOBILE + r".*?credited\s+by\s+Tk\s*" + AMOUNT +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"rocket\s*:?\s*.*?credited\s+by\s+Tk\s*" + AMOUNT +
                          r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ],
    },
    {
        "provider": "bKash", "key": "bkash",
        "patterns": [
            ("credit", _c(r"received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"cash\s*in\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("credit", _c(r"payment\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("debit",  _c(r"send\s+money\s+Tk\s*" + AMOUNT + r".*?\bto\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
            ("debit",  _c(r"cash\s*out\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ],
    },
]

# Generic last-resort fallback (should rarely fire; requires an explicit
# received/credited keyword plus a transaction id).
GENERIC_RULE = {
    "provider": "Unknown", "key": "unknown",
    "patterns": [
        ("credit", _c(r"(?:received|credited|paid)\s+Tk\s*" + AMOUNT +
                      r".*?(?:from\s*" + MOBILE + r")?.*?" + TXN + r"\s*:?\s*" + TRX)),
    ],
}


def _normalize_amount(raw: str) -> float:
    """'1,500.50' / '500' / '.50' -> float."""
    if not raw:
        return 0.0
    raw = raw.replace(",", "").strip()
    return round(float(raw), 2)


def parse_sms(raw: str):
    """Parse a raw SMS string. Returns a normalized dict or None."""
    if not raw:
        return None
    text = raw.strip()
    for rule in PROVIDER_RULES + [GENERIC_RULE]:
        for direction, pattern in rule["patterns"]:
            m = pattern.search(text)
            if m:
                d = m.groupdict()
                sender = normalize_mobile(d.get("sender"))
                return {
                    "provider": rule["provider"],
                    "provider_key": rule["key"],
                    "sender_number": sender or None,
                    "amount": _normalize_amount(d.get("amount")),
                    "trx_id": (d.get("trx_id") or "").upper(),
                    "direction": direction,
                    "raw": text,
                }
    return None


def parse_many(raw_messages):
    """Parse a list of raw SMS strings, returning only successful parses."""
    out = []
    for msg in raw_messages:
        parsed = parse_sms(msg)
        if parsed:
            out.append(parsed)
    return out
