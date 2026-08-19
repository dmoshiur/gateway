"""MFS Payment Gateway — Flask application.

Route map
---------
Public / UI
    GET  /health                          health check
    GET  /login, POST /login, /logout     session login (admin + merchant)
    GET  /checkout                        hosted Bangladesh-style checkout (demo)
    GET  /admin                           superadmin panel (login required)
    GET  /dashboard                       merchant panel (login required)

Core API (HMAC-signed)
    POST /api/v1/webhook/sms              Termux → backend (device HMAC)
    POST /api/v1/checkout/verify          merchant checkout verification
    POST /api/v1/merchant/keys/generate   merchant generates an API key (session)

Admin API (session)
    GET  /api/v1/admin/stats, /merchants, /transactions, /devices, /sms
    POST /api/v1/admin/merchants, /merchants/<id>/toggle

Merchant API (session)
    GET  /api/v1/dashboard/stats, /transactions, /keys, /sms
    POST /api/v1/dashboard/keys, /keys/<id>/revoke
    POST /api/v1/sandbox/simulate         simulate an incoming SMS (demo/testing)
"""
import time
from functools import wraps

from flask import (Flask, jsonify, redirect, render_template, request, session,
                   url_for)

from . import auth, parsers
from .config import Config
from .db import close_db, execute, get_db, init_db, now_iso, query


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)

    with app.app_context():
        init_db()

    app.teardown_appcontext(close_db)

    # ------------------------------------------------------------------ #
    # Auth decorators
    # ------------------------------------------------------------------ #
    def admin_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if not session.get("admin_id"):
                if request.path.startswith("/api"):
                    return jsonify(error="unauthorized"), 401
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return wrapper

    def merchant_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if not session.get("merchant_id"):
                if request.path.startswith("/api"):
                    return jsonify(error="unauthorized"), 401
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return wrapper

    def any_user_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if not (session.get("admin_id") or session.get("merchant_id")):
                if request.path.startswith("/api"):
                    return jsonify(error="unauthorized"), 401
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return wrapper

    # ------------------------------------------------------------------ #
    # UI pages
    # ------------------------------------------------------------------ #
    @app.get("/")
    def index():
        return redirect(url_for("checkout"))

    @app.get("/health")
    def health():
        return jsonify(status="ok", service="mfs-gateway", time=now_iso())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        from werkzeug.security import check_password_hash
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            admin = query("SELECT * FROM admins WHERE username = ?", (username,), one=True)
            merchant = None
            if not admin:
                merchant = query("SELECT * FROM merchants WHERE email = ?", (username,), one=True)

            if admin and check_password_hash(admin["password_hash"], password):
                session.clear()
                session["admin_id"] = admin["id"]
                return redirect(url_for("admin"))
            if merchant and merchant["is_active"] and check_password_hash(merchant["password_hash"], password):
                session.clear()
                session["merchant_id"] = merchant["id"]
                return redirect(url_for("dashboard"))
            return render_template("login.html", error="Invalid credentials", next=request.args.get("next"))
        return render_template("login.html", error=None, next=request.args.get("next"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/checkout")
    def checkout():
        """Hosted demo checkout. Renders for the first active merchant."""
        merchant = query("SELECT * FROM merchants WHERE is_active = 1 ORDER BY id LIMIT 1", one=True)
        if not merchant:
            return render_template("checkout.html", merchant=None, token=None,
                                   error="No active merchant configured.")
        key = query("SELECT * FROM api_keys WHERE merchant_id = ? AND is_active = 1 ORDER BY id LIMIT 1",
                    (merchant["id"],), one=True)
        token = auth.issue_checkout_token(key["api_secret"], key["api_key"], merchant["id"]) if key else None
        return render_template("checkout.html",
                               merchant=merchant, api_key=key["api_key"] if key else None,
                               token=token, error=None)

    @app.get("/admin")
    @admin_required
    def admin():
        return render_template("admin.html")

    @app.get("/dashboard")
    @merchant_required
    def dashboard():
        merchant = query("SELECT * FROM merchants WHERE id = ?", (session["merchant_id"],), one=True)
        return render_template("dashboard.html", merchant=merchant)

    # ------------------------------------------------------------------ #
    # Core API: Termux webhook
    # ------------------------------------------------------------------ #
    @app.post("/api/v1/webhook/sms")
    def webhook_sms():
        """Receive parsed/raw SMS from a Termux listener (device HMAC)."""
        body = request.get_data()
        headers = request.headers
        device_id = headers.get("X-Device-Id")
        if not device_id:
            return jsonify(error="missing X-Device-Id"), 401

        device = query("SELECT * FROM devices WHERE device_id = ?", (device_id,), one=True)
        if not device or not device["is_active"]:
            return jsonify(error="unknown or inactive device"), 401

        try:
            auth.verify_hmac(device["device_secret"], headers, "POST", request.path, body)
            auth._check_nonce(headers.get("X-Nonce"))
        except auth.SignatureError as e:
            return jsonify(error=str(e)), e.code

        data = request.get_json(silent=True) or {}
        messages = data.get("messages") or []
        if not isinstance(messages, list):
            messages = [messages]

        accepted, rejected = [], []
        for msg in messages:
            # Pre-parsed payload wins; otherwise re-parse raw server-side.
            parsed = None
            if msg.get("raw"):
                parsed = parsers.parse_sms(msg["raw"])
            elif msg.get("trx_id") and msg.get("provider"):
                parsed = {
                    "provider": msg.get("provider"),
                    "provider_key": msg.get("provider_key"),
                    "sender_number": msg.get("sender_number"),
                    "amount": float(msg.get("amount") or 0),
                    "trx_id": str(msg.get("trx_id")).upper(),
                    "direction": msg.get("direction", "credit"),
                    "raw": msg.get("raw"),
                }

            if not parsed or not parsed.get("trx_id"):
                rejected.append(msg)
                continue

            # De-duplicate on trx_id to keep the ledger clean.
            dup = query("SELECT id FROM sms_logs WHERE trx_id = ?",
                        (parsed["trx_id"],), one=True)
            if dup:
                rejected.append({"trx_id": parsed["trx_id"], "reason": "duplicate"})
                continue

            cur = execute(
                "INSERT INTO sms_logs (provider, provider_key, sender_number, amount, trx_id, "
                "sms_timestamp, direction, status, raw, device_id, created_at) "
                "VALUES (?,?,?,?,?,?,?, 'new', ?,?,?)",
                (parsed["provider"], parsed.get("provider_key"), parsed.get("sender_number"),
                 parsed.get("amount"), parsed["trx_id"], msg.get("received_at"),
                 parsed.get("direction", "credit"), msg.get("raw") or parsed.get("raw"),
                 device_id, now_iso()),
            )
            accepted.append(parsed["trx_id"])
            _auto_match(cur.lastrowid)

        execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now_iso(), device["id"]))
        return jsonify(ok=True, accepted=accepted, rejected=len(rejected),
                       received_at=now_iso())

    # ------------------------------------------------------------------ #
    # Core API: checkout verification
    # ------------------------------------------------------------------ #
    def _resolve_merchant_from_request(data):
        """Resolve the merchant either via HMAC (server-to-server) or via a
        hosted-checkout token. Returns (merchant_row, api_key_row)."""
        body = request.get_data()
        api_key_header = request.headers.get("X-Api-Key")
        if api_key_header:
            key_row = query("SELECT * FROM api_keys WHERE api_key = ?", (api_key_header,), one=True)
            if not key_row or not key_row["is_active"]:
                raise auth.SignatureError("unknown or inactive API key")
            auth.verify_hmac(key_row["api_secret"], request.headers, "POST", request.path, body)
            auth._check_nonce(request.headers.get("X-Nonce"))
            merchant = query("SELECT * FROM merchants WHERE id = ?", (key_row["merchant_id"],), one=True)
            if not merchant or not merchant["is_active"]:
                raise auth.SignatureError("merchant inactive", 403)
            return merchant, key_row

        token = data.get("checkout_token")
        if token:
            payload = auth.verify_checkout_token(token)
            key_row = query("SELECT * FROM api_keys WHERE api_key = ?", (payload["api_key"],), one=True)
            merchant = query("SELECT * FROM merchants WHERE id = ?", (payload["merchant_id"],), one=True)
            if not merchant or not merchant["is_active"]:
                raise auth.SignatureError("merchant inactive", 403)
            return merchant, key_row

        raise auth.SignatureError("missing credentials (X-Api-Key + signature, or checkout_token)")

    @app.post("/api/v1/checkout/verify")
    def checkout_verify():
        data = request.get_json(silent=True) or {}
        try:
            merchant, key_row = _resolve_merchant_from_request(data)
        except auth.SignatureError as e:
            return jsonify(error=str(e)), e.code

        trx_id = (data.get("trx_id") or "").strip().upper()
        amount = data.get("amount")
        provider = (data.get("provider") or "").strip().lower()
        phone = (data.get("customer_phone") or data.get("phone") or "").strip()

        if not trx_id:
            return jsonify(error="trx_id is required"), 400

        try:
            amount = round(float(amount), 2) if amount not in (None, "") else None
        except (TypeError, ValueError):
            return jsonify(error="invalid amount"), 400

        result = _verify_payment(merchant["id"], key_row["id"], trx_id, amount, provider, phone)
        execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now_iso(), key_row["id"]))
        return jsonify(result)

    def _verify_payment(merchant_id, api_key_id, trx_id, amount, provider, phone):
        """Core matching logic against the SMS ledger."""
        sms = query("SELECT * FROM sms_logs WHERE UPPER(trx_id) = ? ORDER BY id DESC LIMIT 1",
                    (trx_id,), one=True)

        def _record(status, sms_id=None, note=None):
            execute(
                "INSERT INTO transactions (merchant_id, api_key_id, trx_id, amount, provider, "
                "customer_phone, status, sms_log_id, gateway_note, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (merchant_id, api_key_id, trx_id, amount, provider or None, phone or None,
                 status, sms_id, note, now_iso()),
            )
            return {"status": status, "trx_id": trx_id, "message": note}

        if not sms:
            return _record("pending", note="No matching SMS received yet. Ask the customer to re-check the TrxID.")

        # Amount check (tolerance protects against float/format drift).
        if amount is not None and sms["amount"] is not None and \
                abs(sms["amount"] - amount) > Config.AMOUNT_TOLERANCE:
            return _record("mismatch", sms["id"],
                           f"Amount mismatch: expected {amount}, SMS shows {sms['amount']}.")

        # Provider check.
        if provider and sms["provider_key"] and sms["provider_key"].lower() != provider:
            return _record("mismatch", sms["id"],
                           f"Provider mismatch: expected {provider}, SMS is {sms['provider_key']}.")

        # Sender/customer phone check.
        if phone and sms["sender_number"]:
            norm = parsers.normalize_mobile(phone)
            if sms["sender_number"] != norm:
                return _record("mismatch", sms["id"],
                               f"Sender mismatch: SMS sender {sms['sender_number']} != {norm}.")

        execute("UPDATE sms_logs SET status = 'matched' WHERE id = ?", (sms["id"],))
        return _record("verified", sms["id"],
                       f"Payment verified: {sms['provider']} {sms['amount']} from {sms['sender_number']}.")

    def _auto_match(sms_id):
        """When a new SMS arrives, auto-settle any pending transaction that
        matches its TrxID and amount."""
        sms = query("SELECT * FROM sms_logs WHERE id = ?", (sms_id,), one=True)
        if not sms:
            return
        pending = query(
            "SELECT * FROM transactions WHERE UPPER(trx_id) = ? AND status = 'pending'",
            (sms["trx_id"].upper(),),
        )
        for tx in pending:
            if tx["amount"] is not None and sms["amount"] is not None and \
                    abs(tx["amount"] - sms["amount"]) > Config.AMOUNT_TOLERANCE:
                execute("UPDATE transactions SET status='mismatch', updated_at=? WHERE id=?",
                        (now_iso(), tx["id"]))
                continue
            execute("UPDATE transactions SET status='verified', sms_log_id=?, updated_at=? WHERE id=?",
                    (sms_id, now_iso(), tx["id"]))

    # ------------------------------------------------------------------ #
    # Merchant API key management (session)
    # ------------------------------------------------------------------ #
    @app.post("/api/v1/merchant/keys/generate")
    @merchant_required
    def merchant_keys_generate():
        data = request.get_json(silent=True) or {}
        label = (data.get("label") or "API key").strip()[:80]
        pub, sec = auth.generate_api_key()
        execute(
            "INSERT INTO api_keys (merchant_id, label, api_key, api_secret, is_active, created_at) "
            "VALUES (?,?,?,?,1,?)",
            (session["merchant_id"], label, pub, sec, now_iso()),
        )
        return jsonify(ok=True, api_key=pub, api_secret=sec, label=label)

    @app.get("/api/v1/dashboard/keys")
    @merchant_required
    def dashboard_keys():
        rows = query(
            "SELECT id, label, api_key, is_active, last_used_at, created_at "
            "FROM api_keys WHERE merchant_id = ? ORDER BY id DESC",
            (session["merchant_id"],),
        )
        return jsonify(keys=[dict(r) for r in rows])

    @app.post("/api/v1/dashboard/keys/<int:key_id>/revoke")
    @merchant_required
    def dashboard_keys_revoke(key_id):
        execute("UPDATE api_keys SET is_active = 0 WHERE id = ? AND merchant_id = ?",
                (key_id, session["merchant_id"]))
        return jsonify(ok=True)

    # ------------------------------------------------------------------ #
    # Merchant dashboard data
    # ------------------------------------------------------------------ #
    @app.get("/api/v1/dashboard/stats")
    @merchant_required
    def dashboard_stats():
        mid = session["merchant_id"]
        total = query("SELECT COUNT(*) c FROM transactions WHERE merchant_id = ?", (mid,), one=True)["c"]
        verified = query("SELECT COUNT(*) c FROM transactions WHERE merchant_id = ? AND status='verified'",
                         (mid,), one=True)["c"]
        pending = query("SELECT COUNT(*) c FROM transactions WHERE merchant_id = ? AND status='pending'",
                        (mid,), one=True)["c"]
        volume = query("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE merchant_id = ? AND status='verified'",
                       (mid,), one=True)["s"]
        return jsonify(total=total, verified=verified, pending=pending, volume=round(volume, 2))

    @app.get("/api/v1/dashboard/transactions")
    @merchant_required
    def dashboard_transactions():
        rows = query(
            "SELECT * FROM transactions WHERE merchant_id = ? ORDER BY id DESC LIMIT 200",
            (session["merchant_id"],),
        )
        return jsonify(transactions=[dict(r) for r in rows])

    @app.get("/api/v1/dashboard/sms")
    @merchant_required
    def dashboard_sms():
        rows = query("SELECT * FROM sms_logs ORDER BY id DESC LIMIT 200")
        return jsonify(sms=[dict(r) for r in rows])

    # ------------------------------------------------------------------ #
    # Sandbox simulation (demo/testing)
    # ------------------------------------------------------------------ #
    @app.post("/api/v1/sandbox/simulate")
    @any_user_required
    def sandbox_simulate():
        """Simulate an incoming MFS SMS so the real-time flow can be tested."""
        data = request.get_json(silent=True) or {}
        provider = data.get("provider") or "bKash"
        amount = round(float(data.get("amount") or 100.0), 2)
        phone = data.get("phone") or "01712345678"
        trx_id = data.get("trx_id") or ("SIM" + auth.sign("sandbox", f"{time.time()}")[:10].upper())

        raw = f"{provider}: You have received Tk {amount} from {phone}. TrxID {trx_id}"
        # Trust the explicitly selected provider (simulate), and normalize the
        # number/trx the same way the parser would.
        parsed = {
            "provider": provider,
            "provider_key": provider.lower().replace(" ", ""),
            "sender_number": parsers.normalize_mobile(phone),
            "amount": amount,
            "trx_id": trx_id.upper(),
            "direction": "credit",
            "raw": raw,
        }
        cur = execute(
            "INSERT INTO sms_logs (provider, provider_key, sender_number, amount, trx_id, "
            "direction, status, raw, device_id, created_at) VALUES (?,?,?,?,?,?, 'new', ?,?,?)",
            (parsed["provider"], parsed.get("provider_key"), parsed.get("sender_number"),
             parsed.get("amount"), parsed["trx_id"], parsed.get("direction", "credit"),
             raw, "sandbox", now_iso()),
        )
        _auto_match(cur.lastrowid)
        return jsonify(ok=True, trx_id=trx_id, amount=amount, phone=phone,
                       provider=parsed["provider"], raw=raw)

    # ------------------------------------------------------------------ #
    # Admin data + management
    # ------------------------------------------------------------------ #
    @app.get("/api/v1/admin/stats")
    @admin_required
    def admin_stats():
        merchants = query("SELECT COUNT(*) c FROM merchants", one=True)["c"]
        devices = query("SELECT COUNT(*) c FROM devices", one=True)["c"]
        sms = query("SELECT COUNT(*) c FROM sms_logs", one=True)["c"]
        txs = query("SELECT COUNT(*) c FROM transactions", one=True)["c"]
        verified = query("SELECT COUNT(*) c FROM transactions WHERE status='verified'", one=True)["c"]
        volume = query("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE status='verified'", one=True)["s"]
        return jsonify(merchants=merchants, devices=devices, sms=sms, transactions=txs,
                       verified=verified, volume=round(volume, 2))

    @app.get("/api/v1/admin/merchants")
    @admin_required
    def admin_merchants():
        rows = query("SELECT * FROM merchants ORDER BY id DESC")
        out = []
        for m in rows:
            keys = query("SELECT COUNT(*) c FROM api_keys WHERE merchant_id = ?", (m["id"],), one=True)["c"]
            d = dict(m)
            d["key_count"] = keys
            out.append(d)
        return jsonify(merchants=out)

    @app.post("/api/v1/admin/merchants/<int:mid>/toggle")
    @admin_required
    def admin_merchant_toggle(mid):
        m = query("SELECT * FROM merchants WHERE id = ?", (mid,), one=True)
        if not m:
            return jsonify(error="not found"), 404
        execute("UPDATE merchants SET is_active = ? WHERE id = ?", (0 if m["is_active"] else 1, mid))
        return jsonify(ok=True, is_active=not m["is_active"])

    @app.get("/api/v1/admin/devices")
    @admin_required
    def admin_devices():
        rows = query("SELECT * FROM devices ORDER BY id DESC")
        return jsonify(devices=[dict(r) for r in rows])

    @app.post("/api/v1/admin/devices/<int:did>/toggle")
    @admin_required
    def admin_device_toggle(did):
        d = query("SELECT * FROM devices WHERE id = ?", (did,), one=True)
        if not d:
            return jsonify(error="not found"), 404
        execute("UPDATE devices SET is_active = ? WHERE id = ?", (0 if d["is_active"] else 1, did))
        return jsonify(ok=True, is_active=not d["is_active"])

    @app.get("/api/v1/admin/transactions")
    @admin_required
    def admin_transactions():
        rows = query(
            "SELECT t.*, m.name AS merchant_name FROM transactions t "
            "LEFT JOIN merchants m ON m.id = t.merchant_id ORDER BY t.id DESC LIMIT 500",
        )
        return jsonify(transactions=[dict(r) for r in rows])

    @app.get("/api/v1/admin/sms")
    @admin_required
    def admin_sms():
        rows = query("SELECT * FROM sms_logs ORDER BY id DESC LIMIT 500")
        return jsonify(sms=[dict(r) for r in rows])

    return app
