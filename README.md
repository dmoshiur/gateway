# ⚡ MFS Payment Gateway

An automated **Mobile Financial Services (MFS) payment gateway** for Bangladesh
(bKash · Nagad · Rocket · Upay · Tap · Meghna Pay) with **Android Termux SMS
automation**, a Flask backend, HMAC-signed APIs, a merchant/superadmin console,
and a cyberpunk glassmorphism checkout portal.

```
                         ┌──────────────────────────────────────────────┐
  Customer sends money   │  Android phone (Termux)                       │
  to your MFS number ───►│  termux_listener.py polls termux-sms-list     │
                         │  → regex-parse SMS → HMAC-sign → POST          │
                         └───────────────────┬──────────────────────────┘
                                             │ HTTPS  /api/v1/webhook/sms
                                             ▼
                    ┌──────────────────────────────────────────────┐
                    │  Central Backend (Flask)                      │
                    │  · verify webhook (device HMAC)               │
                    │  · store parsed SMS in SQLite/PostgreSQL      │
                    │  · auto-match pending checkouts (TrxID+amount)│
                    │  · API-key management (unlimited per merchant)│
                    │  · superadmin + merchant dashboards           │
                    └───────────────┬───────────────────────────────┘
                                    │  /api/v1/checkout/verify (HMAC)
                                    ▼
                    ┌──────────────────────────────────────────────┐
                    │  Merchant website / checkout portal           │
                    │  verify TrxID + amount → confirmed / mismatch │
                    └──────────────────────────────────────────────┘
```

---

## 1. Project structure

```
gateway/
├── backend/
│   ├── app.py          # Flask app factory + all routes
│   ├── config.py       # env-driven configuration
│   ├── db.py           # SQLite layer + schema + seed (swap for Postgres)
│   ├── parsers.py      # MFS SMS regex parsing engine
│   └── auth.py         # HMAC signing, API keys, checkout tokens
├── templates/          # checkout / login / admin / dashboard (Jinja)
├── static/
│   ├── css/style.css   # cyberpunk / glassmorphism design system
│   └── js/             # checkout.js · admin.js · dashboard.js
├── termux/
│   ├── termux_listener.py   # SMS listener (self-contained)
│   ├── config.example.json
│   └── install.sh
├── run.py              # entry point
└── requirements.txt
```

---

## 2. Quick start (backend)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python run.py                    # http://0.0.0.0:5000
# or: python run.py --port 8000 --init-only   (DB only)
```

On first boot the database is created and **demo data is seeded**:

| Role       | Login                          | Notes                         |
|------------|--------------------------------|-------------------------------|
| Superadmin | `admin` / `admin123`           | `/admin` full system control  |
| Merchant   | `merchant@demo.com` / `demo123`| `/dashboard` merchant console |
| Device     | `termux-demo-device`           | secret `demo-device-secret`   |

> ⚠️ These are **demo credentials** — change them (or set `SEED_*` env vars)
> before any real deployment.

### Test the checkout immediately

The seed includes sample SMS logs, so you can verify a payment out of the box:

1. Open **`/checkout`**.
2. Pick **bKash**, enter phone `01712345678`, amount **৳ 500.00**.
3. Enter TrxID **`8JX4A2B3C4`** → ✅ *Payment verified*.

Other seeded test cases: `NAGAD123456` (৳ 250.50), `ROCKET2024` (৳ 1000),
`UPAY998877` (৳ 750), `TAP555321` (৳ 300).

---

## 3. Termux listener setup

```bash
# on the Android phone, in Termux
pkg update && pkg install python termux-api
pip install requests
termux-setup-storage                       # grant storage access
termux-sms-list -l 3                       # verify SMS access works

# copy the listener over (scp / adb push) then:
cd ~/mfs-gateway/termux
cp config.example.json config.json         # edit backend_url + device creds
python termux_listener.py --once           # single poll test
python termux_listener.py                  # run continuously
```

`install.sh` also sets up a **Termux:Boot** autostart script (needs the
Termux:Boot app) and `termux-wake-lock` to keep the listener alive.

The listener:
- polls `termux-sms-list` at `poll_interval_seconds`,
- parses incoming MFS SMS with the same regex engine as the backend,
- POSTs `{ messages: [ {provider, amount, trx_id, sender_number, raw, ...} ] }`
  to `/api/v1/webhook/sms` signed with the device secret,
- retries with exponential backoff and tracks a cursor so no SMS is processed twice.

---

## 4. API reference

All request bodies are JSON. HMAC-signed endpoints require these headers:

| Header        | Value                                              |
|---------------|----------------------------------------------------|
| `X-Timestamp` | Unix epoch seconds (rejected if > 300 s old)       |
| `X-Nonce`     | Random per-request string (single-use)             |
| `X-Signature` | `HMAC-SHA256(secret, "<ts>.<nonce>.<METHOD>.<path>.<sha256(body)>")` hex |
| `X-Device-Id` | *(webhook only)* the device identifier             |
| `X-Api-Key`   | *(checkout only)* the merchant public API key      |

Signature canonical string:

```
message   = f"{timestamp}.{nonce}.{method}.{path}.{sha256_hex(body)}"
signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
```

### `POST /api/v1/webhook/sms` — Termux → backend
```json
{ "messages": [ { "raw": "You have received Tk 500 ... TrxID 8JX4A2B3C4", "received_at": "..." } ] }
```
or pre-parsed:
```json
{ "messages": [ { "provider": "bKash", "amount": 500.0, "trx_id": "8JX4A2B3C4", "sender_number": "01712345678" } ] }
```

### `POST /api/v1/checkout/verify` — payment verification
Server-to-server (HMAC with `X-Api-Key`) **or** hosted checkout (pass the
server-issued `checkout_token`):
```json
{ "trx_id": "8JX4A2B3C4", "amount": 500.0, "provider": "bkash", "customer_phone": "01712345678" }
```
Response statuses: `verified` | `pending` | `mismatch`.

### `POST /api/v1/merchant/keys/generate` — create an API key (session-auth)
```json
{ "label": "Production key" }
```

### UI routes
`GET /checkout` · `GET /admin` · `GET /dashboard` · `GET /login` · `GET /logout`

Additional admin/merchant/dashboard JSON endpoints are listed in
`backend/app.py` (stats, merchants, devices, transactions, sms, keys, sandbox).

---

## 5. SMS regex patterns

Exact Python regex fragments used by `backend/parsers.py` (also embedded in the
listener). Note the amount class is `[0-9,.]`-style — the examples in many
tutorials mistakenly write `[0-0,.]`; the correct digit range is `0-9`.

| Field  | Fragment |
|--------|----------|
| Amount | `(?P<amount>\d[\d,]*(?:\.\d{1,2})?)` |
| Mobile | `(?P<sender>(?:\+?88)?01[3-9]\d{8})` |
| TrxID  | `(?P<trx_id>[A-Za-z0-9]{6,24})` |
| Txn kw | `(?:Trx\s*ID\|Txn\s*ID\|TrxID\|TxnID\|Transaction\s+ID)` |

**bKash (receive)**
```regex
received\s+Tk\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?).*?\bfrom\s*(?P<sender>(?:\+?88)?01[3-9]\d{8}).*?(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)\s*:?\s*(?P<trx_id>[A-Za-z0-9]{6,24})
```
**bKash (send money — debit)**
```regex
send\s+money\s+Tk\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?).*?\bto\s*(?P<sender>(?:\+?88)?01[3-9]\d{8}).*?(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)\s*:?\s*(?P<trx_id>[A-Za-z0-9]{6,24})
```
**Nagad**
```regex
money\s+received\s*(?:amount)?\s*:?\s*Tk\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?).*?Sender\s*:?\s*(?P<sender>(?:\+?88)?01[3-9]\d{8}).*?(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)\s*:?\s*(?P<trx_id>[A-Za-z0-9]{6,24})
```
**Rocket (DBBL)**
```regex
rocket\s+account\s+(?P<sender>(?:\+?88)?01[3-9]\d{8}).*?credited\s+by\s+Tk\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?).*?(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)\s*:?\s*(?P<trx_id>[A-Za-z0-9]{6,24})
```
**Upay**
```regex
upay\s*:?\s*.*?received\s+Tk\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?).*?\bfrom\s*(?P<sender>(?:\+?88)?01[3-9]\d{8}).*?(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)\s*:?\s*(?P<trx_id>[A-Za-z0-9]{6,24})
```
**Tap**
```regex
tap\s*:?\s*Tk\s*(?P<amount>\d[\d,]*(?:\.\d{1,2})?).*?(?:received\s+from|from)\s*(?P<sender>(?:\+?88)?01[3-9]\d{8}).*?(?:Trx\s*ID|Txn\s*ID|TrxID|TxnID|Transaction\s+ID)\s*:?\s*(?P<trx_id>[A-Za-z0-9]{6,24})
```

> **Provider attribution tip:** real bKash "receive" SMS has no `bKash` brand
> token, so the engine matches keyword-anchored providers (Upay/Nagad/Rocket/
> Tap/Meghna) first and falls back to bKash. For the highest accuracy in
> production, bind each SIM/device to a single provider (a merchant's
> bKash number receives bKash SMS only) — the `sender_number` of the SMS and
> the device binding together resolve any ambiguity.

---

## 6. Security model

- **HMAC-SHA256 request signing** for both device webhooks and merchant APIs —
  secrets are never transmitted, only digests.
- **Replay protection**: bounded timestamps (±300 s) + single-use nonces.
- **Constant-time** signature comparison (`hmac.compare_digest`).
- **Password hashing** via Werkzeug (scrypt/PBKDF2) for admin/merchant logins.
- **No secrets in the browser**: the hosted checkout uses short-lived signed
  tokens issued server-side; merchant secrets stay server-side.
- **Least privilege**: merchant keys can only verify payments & read their own
  transactions; superadmin controls merchants, devices, and system state.

### Production hardening checklist
1. Put the gateway behind **TLS** (nginx/caddy) — never expose plain HTTP.
2. Set a strong `SECRET_KEY`, and change all `SEED_*` credentials.
3. Swap `backend/db.py`'s SQLite for **PostgreSQL** (schema is plain SQL; add
   connection pooling) for multi-instance scale.
4. Run with **gunicorn** (`gunicorn -w 4 run:app`) instead of the dev server.
5. Rate-limit `/api/v1/checkout/verify` and `/api/v1/webhook/sms`.
6. Register a unique device per MFS SIM; store `device_secret` off-device.

---

## 7. Implementation walkthrough

1. **Clone & install** → `pip install -r requirements.txt`, `python run.py`.
2. **Login** → `/admin` (superadmin) or `/dashboard` (merchant).
3. **Add a device** (production) → generate `device_id`/`device_secret` in the
   admin panel, plug them into `termux/config.json`.
4. **Deploy the listener** on the phone (Section 3).
5. **Embed the gateway** → merchant generates API keys on the dashboard, then
   calls `POST /api/v1/checkout/verify` (HMAC) from their backend, or redirects
   customers to `/checkout` with a signed checkout token.
6. **Reconcile** → the superadmin panel shows every SMS log, device heartbeat,
   and transaction with full traceability.
