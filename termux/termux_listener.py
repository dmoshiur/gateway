#!/usr/bin/env python3
"""
MFS Gateway — Android Termux SMS Listener
==========================================

Runs on any Android phone (Termux + Termux:API). Continuously polls the SMS
inbox via `termux-sms-list`, extracts payment facts (provider / sender /
amount / TrxID) with the gateway regex engine, and pushes them to the central
Flask backend with an HMAC-SHA256 signed POST. Includes an offline retry
queue, heartbeats, and a Notification-Listener fallback source.

Zero third-party dependencies — Python standard library only.

Setup (see README.md for full walkthrough):
    pkg install python termux-api
    python termux_listener.py --config        # interactive wizard
    python termux_listener.py                 # run forever
    python termux_listener.py --test "You have received Tk 500.00 from ..."

Config file: ~/.mfs_gateway/config.json
    {"server_url": "https://your-gateway.example.com",
     "device_id": "dev_xxxxxxxx", "device_secret": "dsec_...",
     "interval_seconds": 10, "source": "sms"}

Environment variables override config file:
    GATEWAY_SERVER_URL, GATEWAY_DEVICE_ID, GATEWAY_DEVICE_SECRET

NOTE: the provider regexes below mirror backend/sms_parser.py — keep in sync.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".mfs_gateway")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
STATE_FILE = os.path.join(CONFIG_DIR, "state.json")

DEFAULT_INTERVAL = 10            # seconds between inbox polls
HEARTBEAT_EVERY = 6              # loops between heartbeats
MAX_QUEUE_AGE = 6 * 3600         # drop queued payments after 6 hours
MAX_SMS_SCAN = 200               # inbox rows fetched per poll

# ---------------------------------------------------------------------------
# Regex engine — mirrors backend/sms_parser.py (keep in sync!)
# ---------------------------------------------------------------------------

_AMOUNT = r"(?P<amount>[\d,]+(?:\.\d{1,2})?)"
_MSISDN = r"(?P<sender>\+?8801\d{9}|01\d{9})"
_TXN = r"(?P<trxid>[A-Za-z0-9\-]{6,24})"
_FLAGS = re.IGNORECASE | re.DOTALL

_NEGATIVE_GUARD = re.compile(
    r"\b(failed|unsuccessful|reversed|reversal|cancelled|canceled|"
    r"debited|deducted|cash out)\b|you have sent|payment of tk",
    re.IGNORECASE,
)

PROVIDERS = {
    "bkash": {
        "keywords": ("bkash", "bikash"),
        "patterns": [
            (re.compile(r"you have received tk\s*" + _AMOUNT + r"\s*from\s*" + _MSISDN +
                        r".*?trx\s*id\s*[:\-]?\s*" + _TXN, _FLAGS), True),
            (re.compile(r"received tk\s*" + _AMOUNT + r".*?from\s*" + _MSISDN +
                        r".*?trx\s*id\s*[:\-]?\s*" + _TXN, _FLAGS), False),
        ],
    },
    "nagad": {
        "keywords": ("nagad", "ngd"),
        "patterns": [
            (re.compile(r"(?:amount|amt)\s*:?\s*tk\s*" + _AMOUNT + r".*?sender\s*:?\s*" +
                        _MSISDN + r".*?txn\s*id\s*:?\s*" + _TXN, _FLAGS), True),
            (re.compile(r"\(?\s*" + _MSISDN + r"\s*\)?\s*has sent tk\s*" + _AMOUNT +
                        r".*?txn\s*id\s*:?\s*" + _TXN, _FLAGS), False),
            (re.compile(r"credited (?:with |by )?tk\s*" + _AMOUNT + r".*?from\s*" +
                        _MSISDN + r".*?txn\s*id\s*:?\s*" + _TXN, _FLAGS), False),
        ],
    },
    "rocket": {
        "keywords": ("rocket", "dbbl", "dutch-bangla", "dutch bangla"),
        "patterns": [
            (re.compile(r"(?:cash\s*in|cashin|received|credited)[^\d]{0,25}tk\s*\.?\s*" +
                        _AMOUNT + r"\s*(?:from|fr)\s*" + _MSISDN +
                        r".*?(?:txn|trx|trnx|transaction|tran)[\s\-]*(?:id|no)?\s*:?\s*" +
                        _TXN, _FLAGS), True),
        ],
    },
    "upay": {
        "keywords": ("upay", "ucb"),
        "patterns": [
            (re.compile(r"(?:credited|received)[^\d]{0,20}tk\s*\.?\s*" + _AMOUNT +
                        r"\s*from\s*" + _MSISDN +
                        r".*?(?:transaction\s*id|txn\s*id|trx\s*id)\s*:?\s*" + _TXN,
                        _FLAGS), False),
        ],
    },
    "tap": {
        "keywords": ("tap'n pay", "tapn pay", "tap'n'pay", " tap"),
        "patterns": [
            (re.compile(r"tk\s*\.?\s*" + _AMOUNT + r"\s*received\s*from\s*" + _MSISDN +
                        r".*?(?:txn|trx|tran|transaction)[\s\-]*id\s*:?\s*" + _TXN,
                        _FLAGS), False),
        ],
    },
    "meghna": {
        "keywords": ("meghna",),
        "patterns": [
            (re.compile(r"(?:received|credited)[^\d]{0,20}tk\s*\.?\s*" + _AMOUNT +
                        r"\s*from\s*" + _MSISDN +
                        r".*?(?:txn|trx|tran|transaction)[\s\-]*(?:id|no)?\s*:?\s*" + _TXN,
                        _FLAGS), False),
        ],
    },
}

_GENERIC_PATTERN = re.compile(
    r"tk\s*\.?\s*" + _AMOUNT + r".{0,120}?" + _MSISDN +
    r".{0,120}?(?:trx|txn|trnx|transaction|tran)[\s\-]*(?:id|no)\s*[:\-]?\s*" + _TXN,
    _FLAGS,
)


def detect_provider(text: str):
    haystack = " " + text.lower() + " "
    for name, cfg in PROVIDERS.items():
        for kw in cfg["keywords"]:
            if kw in haystack:
                return name
    return None


def normalize_msisdn(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 13 and digits.startswith("8801"):
        return digits[2:]
    if len(digits) == 11 and digits.startswith("01"):
        return digits
    return digits


def amount_to_paisa(raw: str) -> int:
    return int(round(float((raw or "").replace(",", "").strip()) * 100))


def _build(provider: str, m: re.Match):
    trxid = m.group("trxid").upper().replace("-", "")
    if not re.fullmatch(r"[A-Z0-9]{6,24}", trxid):
        return None
    try:
        paisa = amount_to_paisa(m.group("amount"))
    except ValueError:
        return None
    return {"provider": provider, "sender": normalize_msisdn(m.group("sender")),
            "amount_paisa": paisa, "trxid": trxid}


def _try_provider(name: str, text: str):
    for pattern, _distinctive in PROVIDERS[name]["patterns"]:
        m = pattern.search(text)
        if m:
            return _build(name, m)
    return None


def parse_sms(body: str, address: str = ""):
    if not body or _NEGATIVE_GUARD.search(body):
        return None
    combined = f"{address}\n{body}"
    provider = detect_provider(combined)
    if provider:
        result = _try_provider(provider, body) or _try_provider(provider, combined)
        if result:
            return result
        m = _GENERIC_PATTERN.search(body)
        if m:
            return _build(provider, m)
    for name, cfg in PROVIDERS.items():
        if name == provider:
            continue
        for pattern, distinctive in cfg["patterns"]:
            if not distinctive:
                continue
            m = pattern.search(body)
            if m:
                return _build(name, m)
    if not provider:
        m = _GENERIC_PATTERN.search(body)
        if m:
            return _build("unknown", m)
    return None


# ---------------------------------------------------------------------------
# Config / state
# ---------------------------------------------------------------------------

def load_config() -> dict:
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            cfg = json.load(open(CONFIG_FILE, encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    cfg["server_url"] = os.environ.get(
        "GATEWAY_SERVER_URL", cfg.get("server_url", "")).rstrip("/")
    cfg["device_id"] = os.environ.get(
        "GATEWAY_DEVICE_ID", cfg.get("device_id", ""))
    cfg["device_secret"] = os.environ.get(
        "GATEWAY_DEVICE_SECRET", cfg.get("device_secret", ""))
    cfg["interval_seconds"] = int(cfg.get("interval_seconds", DEFAULT_INTERVAL))
    cfg["source"] = cfg.get("source", "sms")
    return cfg


def save_config(cfg: dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)


def load_state() -> dict:
    try:
        return json.load(open(STATE_FILE, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"last_id": 0, "seen_notif": [], "pending": []}


def save_state(state: dict) -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_FILE)


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Termux:API sources
# ---------------------------------------------------------------------------

def _run_termux(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                          check=True).stdout


def fetch_new_sms(state: dict, process_existing: bool) -> list[dict]:
    """Return inbox SMS newer than the stored cursor, oldest first."""
    try:
        raw = _run_termux(["termux-sms-list", "-l", str(MAX_SMS_SCAN), "-t", "inbox"])
    except FileNotFoundError:
        log("FATAL: 'termux-sms-list' not found. Install Termux:API: "
            "pkg install termux-api  (and the Termux:API companion app)")
        sys.exit(2)
    except subprocess.CalledProcessError as exc:
        log(f"termux-sms-list failed: {exc.stderr.strip()[:200]}")
        return []
    except subprocess.TimeoutExpired:
        log("termux-sms-list timed out")
        return []

    try:
        messages = json.loads(raw or "[]")
    except json.JSONDecodeError:
        log("termux-sms-list returned non-JSON output")
        return []

    # Newest first from the API; we want oldest-first processing.
    messages.sort(key=lambda m: int(m.get("_id", 0)))
    last_id = int(state.get("last_id", 0))
    if not last_id and not process_existing:
        # First run: baseline to the newest known SMS, don't replay history.
        state["last_id"] = max((int(m.get("_id", 0)) for m in messages), default=0)
        save_state(state)
        log(f"Baseline set to SMS id {state['last_id']} "
            f"(skipping history; use --process-existing to replay)")
        return []

    fresh = [m for m in messages if int(m.get("_id", 0)) > last_id]
    if fresh:
        state["last_id"] = max(int(m["_id"]) for m in fresh)
    return fresh


# MFS app package names whose notifications usually mirror the SMS.
NOTIF_PACKAGES = (
    "com.bkash", "com.nagad", "com.dbbl", "com.upay", "meghna",
)


def fetch_new_notifications(state: dict) -> list[dict]:
    """Alternative source: parse MFS app notifications via termux-notification-list."""
    try:
        raw = _run_termux(["termux-notification-list"])
        items = json.loads(raw or "[]")
    except (FileNotFoundError, subprocess.SubprocessError, json.JSONDecodeError):
        return []
    seen = state.setdefault("seen_notif", [])
    fresh = []
    for n in items:
        pkg = str(n.get("packageName", ""))
        if not any(p in pkg.lower() for p in NOTIF_PACKAGES):
            continue
        text = f"{n.get('title', '')}\n{n.get('content', n.get('text', ''))}"
        fp = hashlib.sha256(f"{pkg}|{text}".encode()).hexdigest()[:32]
        if fp in seen:
            continue
        seen.append(fp)
        fresh.append({"_id": 0, "address": pkg, "body": text, "date": int(time.time() * 1000)})
    state["seen_notif"] = seen[-500:]
    return fresh


# ---------------------------------------------------------------------------
# Secure upload
# ---------------------------------------------------------------------------

def signed_post(cfg: dict, path: str, payload: dict, timeout: int = 15) -> tuple[bool, str]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    ts = str(int(time.time()))
    canonical = f"{cfg['device_id']}\n{ts}\n{body}"
    sig = hmac.new(cfg["device_secret"].encode(), canonical.encode(),
                   hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        cfg["server_url"] + path,
        data=body.encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Device-Id": cfg["device_id"],
            "X-Timestamp": ts,
            "X-Signature": sig,
            "User-Agent": "mfs-gateway-termux/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return False, ("HTTP 401 — DEVICE_ID/SECRET rejected. Check config "
                           "and that the device is 'active' in the admin panel.")
        return False, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"network: {exc}"


def queue_payment(state: dict, payload: dict) -> None:
    state.setdefault("pending", []).append(
        {"payload": payload, "queued_at": int(time.time()), "attempts": 0})


def flush_queue(cfg: dict, state: dict) -> None:
    pending = state.get("pending", [])
    if not pending:
        return
    remaining = []
    now = int(time.time())
    for item in pending:
        # Honour exponential backoff between retries.
        if item.get("next_try", 0) > now:
            remaining.append(item)
            continue
        if now - item.get("queued_at", now) > MAX_QUEUE_AGE or item.get("attempts", 0) > 40:
            log(f"Dropping stale queued payment "
                f"{item['payload'].get('trxid', '?')} after {item.get('attempts', 0)} attempts")
            continue
        ok, info = signed_post(cfg, "/api/v1/webhook/sms", item["payload"])
        if ok:
            p = item["payload"]
            log(f"UPLOADED {p['provider']} ৳{p['amount_paisa'] / 100:,.2f} "
                f"TrxID={p['trxid']} ({info})")
        else:
            item["attempts"] += 1
            item["next_try"] = now + min(300, 5 * (2 ** min(item["attempts"], 6)))
            remaining.append(item)
            log(f"upload failed ({info}); retry in "
                f"{item['next_try'] - now}s [attempt {item['attempts']}, "
                f"TrxID={item['payload'].get('trxid')}]")
    state["pending"] = remaining


def heartbeat(cfg: dict) -> None:
    ok, info = signed_post(cfg, "/api/v1/device/heartbeat",
                           {"device_id": cfg["device_id"], "ts": int(time.time())})
    log(f"heartbeat {'ok' if ok else 'FAILED'} ({info})")


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def wizard() -> None:
    print("=== MFS Gateway listener setup ===")
    server = input("Gateway base URL (e.g. https://pay.example.com): ").strip().rstrip("/")
    device_id = input("Device ID (from Admin → Devices): ").strip()
    secret = input("Device Secret: ").strip()
    interval = input("Poll interval seconds [10]: ").strip() or "10"
    cfg = {"server_url": server, "device_id": device_id, "device_secret": secret,
           "interval_seconds": int(interval), "source": "sms"}
    save_config(cfg)
    print(f"Saved to {CONFIG_FILE} (chmod 600). Now run: python termux_listener.py")


def test_parse(bodies: list[str]) -> None:
    for body in bodies:
        parsed = parse_sms(body)
        print(json.dumps(parsed, indent=2) if parsed else "NO MATCH (ignored)")


def run_forever(cfg: dict, process_existing: bool = False, once: bool = False) -> None:
    if not cfg["server_url"] or not cfg["device_id"] or not cfg["device_secret"]:
        print(f"Missing config. Run:  python {sys.argv[0]} --config\n"
              f"or set GATEWAY_SERVER_URL / GATEWAY_DEVICE_ID / GATEWAY_DEVICE_SECRET")
        sys.exit(2)

    state = load_state()
    log(f"Listener online → {cfg['server_url']} as {cfg['device_id']} "
        f"(source={cfg['source']}, every {cfg['interval_seconds']}s)")
    heartbeat(cfg)

    loops = 0
    while True:
        loops += 1
        try:
            if cfg["source"] == "notifications":
                fresh = fetch_new_notifications(state)
            else:
                fresh = fetch_new_sms(state, process_existing and loops == 1)
        except Exception as exc:  # noqa: BLE001 — never die in the loop
            log(f"fetch error: {exc}")
            fresh = []

        for sms in fresh:
            address = str(sms.get("address", ""))
            body = str(sms.get("body", ""))
            parsed = parse_sms(body, address)
            if not parsed:
                continue
            payload = {
                **parsed,
                "device_id": cfg["device_id"],
                "sms_timestamp": datetime.fromtimestamp(
                    int(sms.get("date", time.time() * 1000)) / 1000,
                    tz=timezone.utc).replace(microsecond=0).isoformat(),
                "raw_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            }
            log(f"CAPTURED {parsed['provider']} sender={parsed['sender']} "
                f"৳{parsed['amount_paisa'] / 100:,.2f} TrxID={parsed['trxid']}")
            queue_payment(state, payload)

        try:
            flush_queue(cfg, state)
        except Exception as exc:  # noqa: BLE001
            log(f"flush error: {exc}")
        save_state(state)

        if loops % HEARTBEAT_EVERY == 0:
            heartbeat(cfg)
        if once:
            break
        time.sleep(cfg["interval_seconds"] + (os.urandom(1)[0] % 3))  # small jitter


def main() -> None:
    args = sys.argv[1:]
    if "--config" in args:
        wizard()
        return
    if "--test" in args:
        idx = args.index("--test")
        test_parse(args[idx + 1:] or
                   ["You have received Tk 1,500.00 from 01712345678. TrxID 9HK8A2X1LM"])
        return
    cfg = load_config()
    run_forever(cfg,
                process_existing="--process-existing" in args,
                once="--once" in args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nlistener stopped.")
