#!/usr/bin/env python3
"""
Termux SMS Listener — polls the Android SMS inbox via `termux-sms-list`,
parses MFS (bKash / Nagad / Rocket / Upay / Tap / Meghna Pay) transaction
SMS with regex, then securely POSTs the parsed payload to the central
gateway backend over HMAC-signed requests.

Requires (on the phone):
    * Termux            — https://f-droid.org/packages/com.termux/
    * Termux:API        — https://f-droid.org/packages/com.termux.api/
    * Python            — `pkg install python`
    * requests          — `pip install requests`

Usage:
    cp config.example.json config.json   # fill in backend_url / device creds
    python termux_listener.py            # run continuously
    python termux_listener.py --once     # run a single poll and exit
    python termux_listener.py --sms +8801712345678 "You have received Tk ..."  # parse-test

Security notes:
    * Requests are HMAC-SHA256 signed with the device secret; the secret never
      appears in the request, only the signature + plaintext timestamp/nonce.
    * Timestamps are bounded and nonces are single-use server-side (anti-replay).
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# --------------------------------------------------------------------------- #
# SMS parsing (mirrors backend/parsers.py — kept self-contained for Termux)
# --------------------------------------------------------------------------- #
MOBILE = r"(?P<sender>(?:\+?88)?01[3-9]\d{8})"
AMOUNT = r"(?P<amount>\d[\d,]*(?:\.\d{1,2})?)"
TRX = r"(?P<trx_id>[A-Za-z0-9]{6,24})"
TXN = r"(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)"
_IX = re.IGNORECASE | re.DOTALL


def _c(pat):
    return re.compile(pat, _IX)


PROVIDER_RULES = [
    ("Meghna Pay", "meghnapay", [
        ("credit", _c(r"meghna\s*pay\s*:?\s*.*?received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"meghna\s*pay\s*:?\s*.*?Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
    ]),
    ("Tap", "tap", [
        ("credit", _c(r"tap\s*:?\s*Tk\s*" + AMOUNT + r".*?(?:received\s+from|from)\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"tap\s*:?\s*.*?Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
    ]),
    ("Upay", "upay", [
        ("credit", _c(r"upay\s*:?\s*.*?received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"upay\s*:?\s*.*?Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
    ]),
    ("Nagad", "nagad", [
        ("credit", _c(r"money\s+received\s*(?:amount)?\s*:?\s*Tk\s*" + AMOUNT + r".*?Sender\s*:?\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"nagad\s*:?\s*.*?received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"nagad\s*:?\s*.*?credited\s+(?:by|with)?\s*Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
    ]),
    ("Rocket", "rocket", [
        ("credit", _c(r"rocket\s+account\s+" + MOBILE + r".*?credited\s+by\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"rocket\s*:?\s*.*?credited\s+by\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
    ]),
    ("bKash", "bkash", [
        ("credit", _c(r"received\s+Tk\s*" + AMOUNT + r".*?\bfrom\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"cash\s*in\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("credit", _c(r"payment\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("debit",  _c(r"send\s+money\s+Tk\s*" + AMOUNT + r".*?\bto\s*" + MOBILE + r".*?" + TXN + r"\s*:?\s*" + TRX)),
        ("debit",  _c(r"cash\s*out\s+Tk\s*" + AMOUNT + r".*?" + TXN + r"\s*:?\s*" + TRX)),
    ]),
]


def normalize_mobile(raw):
    if not raw:
        return ""
    s = str(raw).strip().replace(" ", "").replace("-", "")
    if s.startswith("+"):
        s = s[1:]
    if s.startswith("880"):
        s = "0" + s[3:]
    return s


def parse_sms(raw):
    if not raw:
        return None
    text = raw.strip()
    for provider, key, patterns in PROVIDER_RULES:
        for direction, pattern in patterns:
            m = pattern.search(text)
            if m:
                d = m.groupdict()
                amount_raw = (d.get("amount") or "").replace(",", "")
                return {
                    "provider": provider,
                    "provider_key": key,
                    "sender_number": normalize_mobile(d.get("sender")) or None,
                    "amount": round(float(amount_raw), 2) if amount_raw else 0.0,
                    "trx_id": (d.get("trx_id") or "").upper(),
                    "direction": direction,
                    "raw": text,
                }
    return None


# --------------------------------------------------------------------------- #
# Config + logging
# --------------------------------------------------------------------------- #
def load_config(path):
    if not os.path.exists(path):
        print(f"[listener] config not found: {path}\n"
              f"          copy config.example.json -> config.json and edit it.", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    log_file = CONFIG.get("log_file")
    if log_file:
        try:
            with open(log_file, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# HMAC signing
# --------------------------------------------------------------------------- #
def sign_request(secret, method, path, body_bytes):
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    message = f"{ts}.{nonce}.{method}.{path}.{hashlib.sha256(body_bytes).hexdigest()}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": signature,
        "X-Device-Id": CONFIG["device_id"],
    }


def post_messages(messages):
    """POST parsed SMS messages to the backend with retry + exponential backoff."""
    if requests is None:
        log("requests module not installed — run: pip install requests")
        return False

    url = CONFIG["backend_url"].rstrip("/") + "/api/v1/webhook/sms"
    body = json.dumps({"messages": messages}).encode("utf-8")
    headers = sign_request(CONFIG["device_secret"], "POST", "/api/v1/webhook/sms", body)
    headers["Content-Type"] = "application/json"

    base_delay = int(CONFIG.get("retry_base_delay_seconds", 2))
    max_retries = int(CONFIG.get("max_retries", 5))
    timeout = int(CONFIG.get("request_timeout_seconds", 20))

    for attempt in range(max_retries):
        try:
            resp = requests.post(url, data=body, headers=headers, timeout=timeout)
            if 200 <= resp.status_code < 300:
                log(f"POST ok -> {len(messages)} message(s) [{resp.status_code}]")
                return True
            # Re-sign on retry (timestamp/nonce must be fresh per attempt).
            log(f"POST failed [{resp.status_code}]: {resp.text[:200]}")
        except requests.RequestException as e:
            log(f"POST error: {e}")

        if attempt < max_retries - 1:
            delay = base_delay * (2 ** attempt)
            log(f"retrying in {delay}s ({attempt + 1}/{max_retries})")
            time.sleep(delay)
        # refresh headers for next attempt (new nonce/timestamp)
        headers = sign_request(CONFIG["device_secret"], "POST", "/api/v1/webhook/sms", body)
        headers["Content-Type"] = "application/json"
    return False


# --------------------------------------------------------------------------- #
# Cursor (avoid re-processing the same SMS)
# --------------------------------------------------------------------------- #
def read_cursor():
    path = CONFIG.get("cursor_file")
    if path and os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f).get("last_id")
        except (OSError, ValueError):
            return None
    return None


def write_cursor(last_id):
    path = CONFIG.get("cursor_file")
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump({"last_id": last_id, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")}, f)
    except OSError as e:
        log(f"cursor write failed: {e}")


# --------------------------------------------------------------------------- #
# termux-sms-list integration
# --------------------------------------------------------------------------- #
def fetch_sms(limit):
    """Call `termux-sms-list` and return a list of message dicts."""
    try:
        proc = subprocess.run(
            ["termux-sms-list", "-l", str(limit)],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        log("termux-sms-list not found. Install Termux:API (pkg install termux-api).")
        sys.exit(1)

    if proc.returncode != 0:
        log(f"termux-sms-list error: {proc.stderr.strip()[:200]}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        log("termux-sms-list returned invalid JSON")
        return []

    return data.get("data", []) if isinstance(data, dict) else []


def _msg_id(msg):
    # Android `_id` is the stable, monotonically increasing cursor key.
    return msg.get("_id") or msg.get("id")


def _msg_body(msg):
    return msg.get("body") or msg.get("message") or ""


def _msg_received(msg):
    return msg.get("received") or msg.get("date") or msg.get("date_sent")


def poll_once():
    limit = int(CONFIG.get("sms_batch_limit", 50))
    cursor = read_cursor()
    sms_list = fetch_sms(limit)

    new_messages = []
    max_id = cursor
    for msg in sms_list:
        mid = _msg_id(msg)
        # Track max numeric id (may be str or int).
        try:
            mid_num = int(mid)
        except (TypeError, ValueError):
            mid_num = None
        if mid_num is not None and (max_id is None or mid_num > max_id):
            max_id = mid_num

        if cursor is not None and mid_num is not None and mid_num <= cursor:
            continue  # already processed

        body = _msg_body(msg)
        if not body:
            continue
        parsed = parse_sms(body)
        if parsed:
            parsed["received_at"] = _msg_received(msg)
            parsed["sms_id"] = mid
            new_messages.append(parsed)

    if new_messages:
        log(f"parsed {len(new_messages)} new MFS SMS")
        ok = post_messages(new_messages)
        if ok and max_id is not None:
            write_cursor(max_id)
    elif cursor is not None and max_id is not None and max_id > cursor:
        # No MFS matches, but advance cursor so we don't re-scan spam/SMS.
        write_cursor(max_id)

    return len(new_messages)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
CONFIG = {}


def main():
    global CONFIG
    parser = argparse.ArgumentParser(description="MFS SMS listener for Termux")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true", help="run one poll and exit")
    parser.add_argument("--sms", nargs="+", help="parse-test: provider-less raw SMS text")
    args = parser.parse_args()

    if args.sms:
        text = " ".join(args.sms)
        print(json.dumps(parse_sms(text), indent=2))
        return

    CONFIG = load_config(args.config)

    interval = int(CONFIG.get("poll_interval_seconds", 15))

    if CONFIG.get("backfill_on_first_run") is False and read_cursor() is None:
        # First run: skip existing history, start from now.
        sms_list = fetch_sms(int(CONFIG.get("sms_batch_limit", 50)))
        max_id = None
        for msg in sms_list:
            try:
                n = int(_msg_id(msg))
                max_id = n if max_id is None else max(max_id, n)
            except (TypeError, ValueError):
                continue
        if max_id is not None:
            write_cursor(max_id)
            log(f"first run — set cursor to {max_id} (skipping {len(sms_list)} old SMS)")

    log("listener started")
    while True:
        try:
            poll_once()
        except KeyboardInterrupt:
            log("stopped by user")
            break
        except Exception as e:  # never die on transient errors
            log(f"unexpected error: {e}")
        if args.once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
