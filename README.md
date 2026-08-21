# ৳ MFS Payment Gateway — Automated SMS-Driven Checkout for Bangladesh

Accept **bKash, Nagad, Rocket, Upay, Tap & Meghna Pay** payments automatically,
verified by the real payment **SMS** landing on an Android phone you control —
no aggregator contracts, no per-transaction middleman fees.

```
┌──────────────────┐   SMS (money received)   ┌───────────────────────┐
│  MFS Provider    │ ───────────────────────▶ │ Android + Termux       │
│  (bKash/Nagad/…) │                          │ termux_listener.py     │
└──────────────────┘                          └─────────┬─────────────┘
                                                        │ HMAC-signed POST
                                                        ▼
┌──────────────────┐   checkout_url   ┌───────────────────────────────┐
│  Merchant Shop   │ ◀─────────────── │ Central Gateway (Flask+SQLite) │
│  (your app)      │                  │  • SMS ledger + TrxID matcher  │
└──────┬───────────┘                  │  • Admin + Merchant consoles   │
       │ buyer pays, submits TrxID    │  • IPN webhooks                │
       └────────────────────────────▶ └───────────────────────────────┘
```

---

## 1. Quick start (5 minutes)

```bash
pip install -r requirements.txt

# start the gateway (creates the store, admin + demo merchant/device)
export GATEWAY_ADMIN_PASSWORD='choose-a-strong-admin-password'
python run.py --init-demo

# in a second terminal: full end-to-end simulation
# (checkout create → SMS webhook → buyer verify → IPN callback)
python tools/demo_flow.py
```

> **Credentials are deterministic and self-healing.** On every boot:
> * if `GATEWAY_ADMIN_PASSWORD` is set, the superadmin hash is re-synced to it
>   (fixing any drift from old DBs/restores);
> * `--init-demo` re-syncs the demo merchant password (`demo12345`),
>   API key pair and Termux device — credentials always match
>   `data/demo_credentials.json`.
> * Login input is whitespace-trimmed (copy-paste safe).

| Surface            | URL                        | Credentials (demo mode)                    |
|--------------------|----------------------------|---------------------------------------------|
| Superadmin console | `/admin`                   | `admin` / `$GATEWAY_ADMIN_PASSWORD`         |
| Merchant dashboard | `/dashboard`               | `demo@merchant.test` / `demo12345`          |
| Landing page       | `/`                        | —                                           |
| Demo credentials   | `data/demo_credentials.json` | merchant API key pair + Termux device secret |

Run the test suites (parser + full API/security flows on **both** SQLite and
MongoDB-via-mongomock):

```bash
cd tests && python -m unittest discover -s . -p "test_*.py"   # 65 tests
python tests/test_sms_parser.py
python termux/termux_listener.py --test \
  "You have received Tk 1,500.00 from 01712345678. TrxID 9HK8A2X1LM at 19/08/2026 14:30"
```

---

## 2. Architecture

### 2.1 Android Termux listener (`termux/termux_listener.py`)

A **zero-dependency** (stdlib-only) Python daemon running on the phone that
receives MFS balance-update SMS:

1. Polls the inbox every N seconds: `termux-sms-list -l 200 -t inbox`
   (alternative source: MFS-app notifications via `termux-notification-list`
   with `"source": "notifications"` in config).
2. Tracks the `_id` cursor in `~/.mfs_gateway/state.json`; first run baselines
   to the newest SMS (no history replay — use `--process-existing` to override).
3. Runs the provider regex engine → `{provider, sender, amount_paisa, trxid}`.
4. Hashes the raw body (`raw_hash`) — **raw SMS never leaves the phone**.
5. POSTs to `POST /api/v1/webhook/sms`, HMAC-SHA256 signed:
   `hex(HMAC(secret, "{device_id}\n{unix_ts}\n{exact_body}"))`.
6. Offline retry queue with exponential backoff (survives mobile-data dropouts),
   heartbeats every ~60 s so the admin panel shows the phone as online.

### 2.2 Central backend (`backend/`)

| Module                | Responsibility |
|-----------------------|----------------|
| `app.py`              | All HTTP routes, auth decorators, rate limiting, IPN dispatch |
| `store/`              | **Pluggable persistence layer** — `SQLiteStore` (default, zero-infra) or `MongoStore` (`pymongo`), identical document semantics, interchangeable via one env var |
| `sms_parser.py`       | Regex engine (mirrored in the listener) |
| `security.py`         | HMAC signing/verify, PBKDF2 passwords, key generation |
| `demo.py`             | Deterministic demo seeding |

**Choosing MongoDB (GATEWAY_DB_BACKEND=mongodb):**

```bash
pip install -r requirements.txt            # includes pymongo

# local mongod
mongod --dbpath /var/lib/mongo &
GATEWAY_DB_BACKEND=mongodb MONGO_URI=mongodb://localhost:27017 python run.py --init-demo

# or MongoDB Atlas
GATEWAY_DB_BACKEND=mongodb \
MONGO_URI='mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net' \
MONGO_DB=mfs_gateway python run.py --init-demo
```

The Mongo backend uses unique indexes (`trxid_norm`, `merchants.email`,
`api_keys.key_id`, compound `merchant_id+order_id`) and atomic
`findOneAndUpdate` claims — the same replay/double-spend guarantees as
SQLite. `GET /healthz` reports the active backend.

> Scaling notes: SQLite (WAL) comfortably handles single-gateway volumes;
> choose MongoDB when you need replica-set durability, ops tooling, or
> horizontal sharding of the SMS ledger. Both backends pass the identical
> 60+ test flow suite (`tests/`).

**Payment ledger model** — webhook facts and checkout sessions are separate
tables joined at verification time:

* `sms_transactions` — one row per received payment SMS. `UNIQUE(trxid)`
  globally ⇒ a TrxID can never be entered twice (replay-proof ledger).
* `payment_sessions` — merchant orders. `UNIQUE(merchant_id, order_id)` ⇒
  idempotent checkout creation.

Verification (`POST /api/v1/checkout/verify`) is an **atomic claim**:
the SMS row flips `unused → consumed` and the session flips `pending → paid`
in one transaction — the same TrxID can never pay two orders.

### 2.3 Consoles

* **Superadmin** (`/admin`) — live volume stats, SMS feed, payment sessions,
  merchant suspend/activate, device register/revoke, global API-key revoke,
  gateway settings (provider wallet numbers shown at checkout, session TTL),
  audit log, and a **test SMS injector** for end-to-end tests without a phone.
* **Merchant** (`/dashboard`) — unlimited API key generation (secrets shown
  once), live transaction table, sandbox “test checkout” launcher, and a
  copy-paste integration snippet.

---

## 3. Deploying the Termux listener

On the Android phone that receives the payment SMS (use the **dedicated shop
wallet SIM**), install **Termux** and the **Termux:API** companion app
(F-Droid builds recommended — keep both from the same source):

```bash
# inside Termux, from this repo's termux/ folder:
bash install.sh
```

The installer will:

1. `pkg install python termux-api`
2. copy the listener to `~/.mfs_gateway/termux_listener.py`
3. write `~/.mfs_gateway/config.json` (chmod 600) with your **Device ID / Secret**
   (create them first in **Admin → Devices → + Register Device**)
4. install a `~/.termux/boot/` hook so the listener survives reboots
   (requires the Termux:Boot app)

Android housekeeping (critical for reliability):

* **Settings → Apps → Termux:API → Permissions → SMS → Allow**
* **Battery → Termux → “Unrestricted”** — otherwise Android kills the loop
* Start listening: `termux-wake-lock && python ~/.mfs_gateway/termux_listener.py`

---

## 4. SMS regex reference

The engine normalises everything to integer **paisa** (1 BDT = 100 paisa) and
uppercase TrxIDs. Note: the patterns in the original brief use `[0-0,.]+`,
which only matches the character `0` — working equivalents (comma-aware,
decimal-aware) are below.

### bKash
```
You have received Tk ([\d,]+(?:\.\d{1,2})?)\s*from\s*(\+?8801\d{9}|01\d{9}).*?Trx\s*ID\s*[:\-]?\s*([A-Za-z0-9\-]{6,24})
```
> `You have received Tk 1,500.00 from 01712345678. Fee Tk 0.00. TrxID 9HK8A2X1LM at 19/08/2026 14:30`

### Nagad
```
(?:Amount|Amt)\s*:?\s*Tk\s*([\d,]+(?:\.\d{1,2})?).*?Sender\s*:?\s*(\+?8801\d{9}|01\d{9}).*?Txn\s*ID\s*:?\s*([A-Za-z0-9\-]{6,24})
```
> `Money received. Amount: Tk 2,000.00. Sender: 01812345678. TxnID: 7XQ2M1P9ZA.`

Plus alternates for the *“Mr X (01XXXXXXXXX) has sent Tk … TxnID: …”* and
*“credited with Tk …”* variants (see `backend/sms_parser.py`).

### Rocket (DBBL)
```
(?:Cash\s*In|CashIn|Received|Credited)[^\d]{0,25}Tk\s*\.?\s*([\d,]+(?:\.\d{1,2})?)\s*(?:from|fr)\s*(\+?8801\d{9}|01\d{9}).*?(?:Txn|Trx|Trnx|Transaction)[\s\-]*(?:ID|No)?\s*:?\s*([A-Za-z0-9\-]{6,24})
```
> `Cash In of Tk 750.00 from 01712345678 successful. TxnID: 8877665544.`

### Upay / Tap / Meghna & generic fallback
Receiver-side credit patterns of the same shape, plus a final generic
`Tk <amount> … 01XXXXXXXXX … (Trx|Txn|Transaction) ID: XXXX` matcher that
captures **any** provider as `provider: "unknown"`.

**Guard rails:** messages containing `failed`, `reversed`, `debited`,
`cash out`, `you have sent`, `payment of tk`, … are never treated as incoming
money. All patterns run `re.IGNORECASE | re.DOTALL`.

---

## 5. Merchant integration

All merchant calls are HMAC-signed. Canonical string:
`"{api_key}\n{unix_timestamp}\n{raw_body}"` → headers `X-Api-Key`,
`X-Timestamp`, `X-Signature`. Timestamp must be within ±300 s of server time.

### 5.1 Create a checkout — `POST /api/v1/checkout/create`

```bash
curl -X POST https://YOUR-GATEWAY/api/v1/checkout/create \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: pk_live_..." -H "X-Timestamp: $(date +%s)" \
  -H "X-Signature: <hex HMAC_SHA256(secret, keyId+'\n'+ts+'\n'+body)>" \
  -d '{"order_id":"ORD-1001","amount":"250.00","currency":"BDT",
       "customer_name":"Rahim Uddin",
       "success_url":"https://yourshop.com/pay/success",
       "cancel_url":"https://yourshop.com/pay/cancel",
       "callback_url":"https://yourshop.com/api/ipn"}'
```

Response `201`:
```json
{ "session_id": "ps_...", "status": "pending",
  "checkout_url": "https://YOUR-GATEWAY/checkout/ps_...",
  "amount_paisa": 25000, "amount_bdt": "250.00", "expires_at": "..." }
```
Redirect the buyer to `checkout_url`. Re-creating with the same `order_id`
returns the existing session (`idempotent_replay: true`).

### 5.2 Buyer flow

Buyer opens the checkout → picks bKash/Nagad/… → sends the exact amount to the
shown gateway wallet → submits wallet number + TrxID → the gateway matches the
incoming SMS ledger in real time (`paid` / `pending` auto-poll / clear error
states for `amount_mismatch`, `used`, `locked`, `expired`).

### 5.3 Confirm payment server-side (always do this)

The buyer is redirected to your `success_url` with signed params:
`...?status=paid&session_id=ps_...&order_id=ORD-1001&amount_paisa=25000&currency=BDT&trxid=9HK...&sig=...`

`sig = hex(HMAC_SHA256(GATEWAY_SECRET, "session_id|order_id|amount_paisa|trxid"))`

Verify it — and better, fetch the source of truth with your API key:

`GET /api/v1/payments/{session_id}` → status, trxid, payer_wallet, paid_at.

### 5.4 IPN webhook

If you pass `callback_url`, the gateway POSTs
`{"event":"payment.success", session_id, order_id, amount_paisa, provider,
trxid, payer_wallet, paid_at, signature}` with header `X-Gateway-Signature`.
Best-effort delivery — always reconcile with the status API.

### 5.5 Device webhooks (Termux → gateway)

`POST /api/v1/webhook/sms` with `X-Device-Id / X-Timestamp / X-Signature` and
body `{provider, sender, amount_paisa, trxid, sms_timestamp, raw_hash}`.
Duplicates return `{"status":"duplicate"}` safely.

---

## 6. Security model

| Threat | Control |
|---|---|
| Forged webhooks | HMAC-SHA256 per-device secret, ±300 s timestamp window, timing-safe compare |
| TrxID replay / double-spend | `UNIQUE(trxid)` ledger + atomic `unused→consumed` claim |
| Order replay | `UNIQUE(merchant_id, order_id)` idempotency |
| Brute force on verify | per-session attempt cap (10) + per-IP rate limiting + session expiry (15 min) |
| Credential storage | passwords PBKDF2-HMAC-SHA256 (210k); panel CSRF tokens; `HttpOnly` sessions |
| Raw SMS privacy | only the SHA-256 hash of the SMS is stored/uploaded |
| Amount drift | integer paisa throughout, no floats |

> **Production notes.** API/device secrets are stored server-side (like Stripe
> live secrets) so HMAC can be verified; `data/` is `0600`-permissioned and
> git-ignored. For high-volume deployments: swap SQLite → PostgreSQL
> (`backend/store/` is the only layer to swap — MongoDB support already
> ships; PostgreSQL would be a third backend behind the same interface), put secrets behind KMS/Vault,
> run behind gunicorn + TLS (Caddy/Nginx), enforce HTTPS, and rotate keys via
> the admin panel. Prefer **Personal** wallets with unique per-order reference
> codes if you expect same-amount collisions within minutes.

---

## 7. Repository layout

```
├── run.py                     # entry point (python run.py [--init-demo])
├── requirements.txt
├── backend/
│   ├── app.py                 # routes: webhook, checkout, panels
│   ├── store/
│   │   ├── __init__.py        # store contract + backend factory
│   │   ├── sqlite_store.py    # default single-file backend
│   │   └── mongo_store.py     # MongoDB backend (pymongo)
│   ├── demo.py                # deterministic demo seeding
│   ├── security.py            # HMAC / PBKDF2 / keygen
│   ├── sms_parser.py          # provider regex engine
│   └── templates/             # checkout, admin, dashboard, auth UIs
├── termux/
│   ├── termux_listener.py     # Android daemon (stdlib-only)
│   └── install.sh             # Termux bootstrap
├── tests/
│   ├── test_sms_parser.py     # regex unit tests
│   ├── flow_base.py           # shared API/security flow suite
│   ├── test_api_flows.py      #   → run against SQLite
│   └── test_mongo_store.py    #   → run against MongoDB (mongomock)
└── tools/demo_flow.py         # E2E simulation + merchant SDK reference
```

## 8. Configuration

Config comes from environment variables. `run.py` auto-loads a local
**`.env`** file (copy from **`.env.example`**, never commit real values —
it's git-ignored); variables already set in the shell always win over `.env`.

| Env var                  | Default                | Purpose |
|--------------------------|------------------------|---------|
| `PORT`                   | `8000`                 | HTTP port |
| `GATEWAY_DB_BACKEND`     | `sqlite`               | `sqlite` or `mongodb` |
| `GATEWAY_DB`             | `data/gateway.db`      | SQLite path (sqlite backend) |
| `MONGO_URI`              | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB`               | `mfs_gateway`          | MongoDB database name |
| `GATEWAY_SECRET`         | generated → `data/secret_key` | session + redirect/IPN signing key |
| `GATEWAY_ADMIN_USER`     | `admin`                | superadmin username (created/synced at boot) |
| `GATEWAY_ADMIN_PASSWORD` | random (printed once)  | superadmin password — **re-synced every boot** |
| `GATEWAY_SHOW_LOGIN_HINTS` | —                    | `1` = show configured/demo creds on login pages (dev only!) |
| `GATEWAY_SERVER_URL` / `GATEWAY_DEVICE_ID` / `GATEWAY_DEVICE_SECRET` | — | Termux listener overrides |

Provider wallet numbers, checkout TTL, gateway branding: **Admin → Settings**.
