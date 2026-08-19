#!/usr/bin/env python3
"""
End-to-end demo / merchant SDK reference.

Simulates the complete flow against a running gateway (default localhost:8000):

  1. Merchant server creates a checkout (HMAC-signed)        -> checkout_url
  2. Termux device pushes a parsed payment SMS (HMAC-signed) -> sms stored
  3. Buyer submits wallet + TrxID on the checkout            -> PAID
  4. Merchant receives the signed IPN callback + confirms via status API

Usage:
    python run.py --init-demo           # one terminal: start gateway + demo creds
    python tools/demo_flow.py           # another terminal: run this
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import secrets
import sys
import threading
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
CREDS_FILE = "data/demo_credentials.json"


def canonical(key_id: str, ts: str, body: str) -> str:
    return f"{key_id}\n{ts}\n{body}"


def sign(secret: str, key_id: str, ts: str, body: str) -> str:
    return hmac.new(secret.encode(), canonical(key_id, ts, body).encode(),
                    hashlib.sha256).hexdigest()


def signed_request(secret: str, key_id: str, method: str, url: str,
                   payload: dict | None = None, key_header: str = "X-Api-Key") -> dict:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True) if payload is not None else ""
    ts = str(int(time.time()))
    req = urllib.request.Request(
        url, data=body.encode() or None, method=method,
        headers={"Content-Type": "application/json",
                 key_header: key_id,
                 "X-Timestamp": ts,
                 "X-Signature": sign(secret, key_id, ts, body)})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


# --- tiny local IPN receiver ------------------------------------------------
IPN_HITS: list[dict] = []


class _IpnHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        IPN_HITS.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def start_ipn_server() -> int:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _IpnHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def main() -> int:
    creds = json.load(open(CREDS_FILE, encoding="utf-8"))
    ipn_port = start_ipn_server()

    amount = "442.50"
    order_id = "DEMO-" + secrets.token_hex(3).upper()
    trxid = secrets.token_hex(5).upper()

    print(f"━━ 1) Merchant creates checkout for order {order_id} (৳{amount})")
    created = signed_request(
        creds["api_secret"], creds["api_key"], "POST",
        f"{BASE}/api/v1/checkout/create",
        {"order_id": order_id, "amount": amount, "currency": "BDT",
         "customer_name": "Demo Buyer",
         "success_url": "https://merchant.example/success",
         "cancel_url": "https://merchant.example/cancel",
         "callback_url": f"http://127.0.0.1:{ipn_port}/ipn"})
    print("   → checkout_url:", created["checkout_url"])
    sid = created["session_id"]

    print(f"━━ 2) Termux device pushes parsed SMS (bKash, TrxID {trxid})")
    stored = signed_request(
        creds["device_secret"], creds["device_id"], "POST",
        f"{BASE}/api/v1/webhook/sms",
        {"provider": "bkash", "sender": "01711222333",
         "amount_paisa": int(float(amount) * 100), "trxid": trxid,
         "sms_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
         "raw_hash": hashlib.sha256(b"demo sms body").hexdigest()},
        key_header="X-Device-Id")
    print("   →", stored)

    print("━━ 3) Buyer submits wallet + TrxID on the checkout page")
    req = urllib.request.Request(
        f"{BASE}/api/v1/checkout/verify",
        data=json.dumps({"session_id": sid, "provider": "bkash",
                         "wallet": "01711222333", "trxid": trxid}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    verified = json.loads(urllib.request.urlopen(req, timeout=15).read())
    print("   → result:", verified["result"],
          "| redirect:", (verified.get("redirect") or "")[:100] + "…")

    print("━━ 4) Merchant confirms server-side via status API")
    status = signed_request(creds["api_secret"], creds["api_key"], "GET",
                            f"{BASE}/api/v1/payments/{sid}")
    print("   → status:", status["status"], "| trxid:", status["trxid"])

    time.sleep(0.6)
    print("━━ 5) IPN callback received:", "YES" if IPN_HITS else "no (async)")
    if IPN_HITS:
        print("   → event:", IPN_HITS[0]["event"], "| order:", IPN_HITS[0]["order_id"])

    ok = (verified["result"] == "paid" and status["status"] == "paid"
          and status["trxid"] == trxid)
    print("\n" + ("✅ END-TO-END FLOW PASSED" if ok else "❌ FLOW FAILED"))
    print(f"   Open the checkout yourself: {created['checkout_url']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
