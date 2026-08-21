"""
Automated MFS Payment Gateway — central backend.

Flask + pluggable store (SQLite default, MongoDB via GATEWAY_DB_BACKEND=mongodb).
Money is integer paisa everywhere; timestamps are UTC ISO-8601.

Public / device API
    POST /api/v1/webhook/sms            Termux listener pushes parsed SMS (HMAC)
    POST /api/v1/device/heartbeat       Listener liveness ping (HMAC)

Merchant API (HMAC-signed)
    POST /api/v1/checkout/create        Create payment session -> checkout URL
    GET  /api/v1/payments/<session_id>  Query payment status server-to-server

Checkout (buyer-facing)
    GET  /checkout/<session_id>         Bangladesh-style checkout page
    GET  /api/v1/checkout/<session_id>  Session state JSON (methods, amount...)
    POST /api/v1/checkout/verify        Buyer submits wallet + TrxID
    GET  /api/v1/checkout/<sid>/status  Polling endpoint for spinners

Panels
    /admin       Superadmin console (+ /admin/api/*)
    /dashboard   Merchant console    (+ /dashboard/api/*)
    POST /api/v1/merchant/keys/generate   (spec route; merchant session auth)
"""

from __future__ import annotations

import functools
import json
import logging
import os
import re
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from flask import (Flask, abort, current_app, jsonify, redirect,
                   render_template, request, session, url_for)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix

from .security import (generate_api_key_pair, generate_device_credentials,
                       hash_password, new_csrf_token, new_session_id, safe_int,
                       sha256_hex, sign_payload, verify_password,
                       verify_request_signature)
from .sms_parser import amount_to_paisa, normalize_msisdn, paisa_to_bdt
from .store import DuplicateError, make_store, utcnow_iso

log = logging.getLogger("gateway")

MIN_AMOUNT_PAISA = 1_000          # ৳10.00
MAX_AMOUNT_PAISA = 50_000_000     # ৳500,000
MAX_MERCHANT_KEYS = 50
SESSION_RE = re.compile(r"^ps_[A-Za-z0-9_\-]{8,64}$")
TRXID_RE = re.compile(r"^[A-Za-z0-9\-]{6,24}$")
WALLET_RE = re.compile(r"^01\d{9}$")
ORDER_RE = re.compile(r"^[A-Za-z0-9_\-\.]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_RATE_BUCKETS: dict[str, list[float]] = {}
_RATE_LOCK = threading.Lock()


class AdaptiveSessionInterface(SecureCookieSessionInterface):
    """Session cookies that survive iframe-embedded HTTPS previews.

    Over HTTPS (reverse proxy sets X-Forwarded-Proto via ProxyFix) we emit
    SameSite=None + Secure so the cookie is accepted inside cross-site
    iframes (e.g. hosted live previews). Over plain HTTP localhost we keep
    the relaxed Lax/non-secure defaults so local development still works.
    """

    def _https(self) -> bool:
        try:
            return request.scheme == "https"
        except RuntimeError:
            return False

    def get_cookie_samesite(self, app):
        if self._https():
            return "None"
        return super().get_cookie_samesite(app)

    def get_cookie_secure(self, app):
        if self._https():
            return True
        return super().get_cookie_secure(app)


def _store():
    return current_app.store


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # type: ignore[attr-defined]
    app.session_interface = AdaptiveSessionInterface()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    data_dir = os.environ.get("GATEWAY_DATA_DIR", os.path.join(root, "data"))
    os.makedirs(data_dir, exist_ok=True)
    app.config["DATABASE"] = os.environ.get(
        "GATEWAY_DB", os.path.join(data_dir, "gateway.db"))

    # Secret key: env override, otherwise generated once and persisted.
    env_secret = os.environ.get("GATEWAY_SECRET")
    if env_secret:
        app.secret_key = env_secret
    else:
        secret_file = os.path.join(data_dir, "secret_key")
        if os.path.exists(secret_file):
            app.secret_key = open(secret_file, encoding="utf-8").read().strip()
        else:
            import secrets as _s
            app.secret_key = _s.token_urlsafe(48)
            fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(app.secret_key)

    app.permanent_session_lifetime = timedelta(hours=12)

    # Persistence backend (SQLite or MongoDB). Handles schema/indexes,
    # default settings and deterministic superadmin on init.
    app.store = make_store(app)
    app.store.init(app)

    # ------------------------------------------------------------------
    # Request lifecycle
    # ------------------------------------------------------------------

    @app.before_request
    def _ensure_csrf():
        if "csrf" not in session:
            session["csrf"] = new_csrf_token()

    @app.after_request
    def _security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Cache-Control"] = "no-store"  # payment pages: never cache
        return resp

    @app.context_processor
    def _inject():
        return {"csrf_token": session.get("csrf", "")}

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _check_csrf() -> bool:
        import hmac as _h
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf", "")
        return _h.compare_digest(session.get("csrf", ""), token or "")

    def require_admin(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("admin_id"):
                if request.path.startswith("/admin/api"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("admin_login"))
            return fn(*a, **kw)
        return wrapper

    def require_merchant(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("merchant_id"):
                if request.path.startswith(("/dashboard/api", "/api/v1/")):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("merchant_login"))
            return fn(*a, **kw)
        return wrapper

    def csrf_guard(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not _check_csrf():
                return jsonify({"error": "bad_csrf"}), 403
            return fn(*a, **kw)
        return wrapper

    def _rate_ok(group: str, limit: int, window: int = 60) -> bool:
        key = f"{group}:{request.headers.get('X-Forwarded-For', request.remote_addr)}"
        now = time.time()
        with _RATE_LOCK:
            hits = [t for t in _RATE_BUCKETS.get(key, []) if now - t < window]
            if len(hits) >= limit:
                _RATE_BUCKETS[key] = hits
                return False
            hits.append(now)
            _RATE_BUCKETS[key] = hits
            return True

    def _device_auth():
        """Validate X-Device-Id / X-Timestamp / X-Signature HMAC, return row."""
        device_id = request.headers.get("X-Device-Id", "")
        ts = request.headers.get("X-Timestamp", "")
        sig = request.headers.get("X-Signature", "")
        body = request.get_data(cache=True, as_text=True) or ""
        row = _store().find_active_device(device_id)
        if not row:
            return None
        if not verify_request_signature(secret=row["secret"], key_id=device_id,
                                        timestamp=ts, body=body, provided_signature=sig):
            return None
        return row

    def _merchant_api_auth():
        """Validate merchant HMAC headers, return (key_row, merchant_row)."""
        key_id = request.headers.get("X-Api-Key", "")
        ts = request.headers.get("X-Timestamp", "")
        sig = request.headers.get("X-Signature", "")
        body = request.get_data(cache=True, as_text=True) or ""
        store = _store()
        key = store.find_active_key(key_id)
        if not key:
            return None, None
        merchant = store.get_merchant(key["merchant_id"])
        if not merchant or merchant["status"] != "active":
            return None, None
        if not verify_request_signature(secret=key["secret"], key_id=key_id,
                                        timestamp=ts, body=body, provided_signature=sig):
            return None, None
        store.touch_key(key["id"], utcnow_iso())
        return key, merchant

    def _touch_session(sess: dict) -> dict:
        """Return session dict, lazily flipping pending->expired."""
        sess = dict(sess)
        if sess["status"] == "pending":
            exp = datetime.fromisoformat(sess["expires_at"])
            if datetime.now(timezone.utc) > exp:
                _store().mark_session_expired(sess["id"])
                sess["status"] = "expired"
        return sess

    def _provider_wallets() -> dict:
        try:
            return json.loads(_store().get_setting("provider_wallets", "{}"))
        except json.JSONDecodeError:
            return {}

    def _session_public_dict(sess: dict) -> dict:
        store = _store()
        wallets = _provider_wallets()
        methods = {
            name: {"number": cfg.get("number", ""), "type": cfg.get("type", "Personal")}
            for name, cfg in wallets.items() if cfg.get("enabled")
        }
        merch = store.get_merchant(sess["merchant_id"])
        return {
            "session_id": sess["id"],
            "merchant_name": merch["name"] if merch else "Merchant",
            "order_id": sess["order_id"],
            "amount_paisa": sess["amount_paisa"],
            "amount_bdt": paisa_to_bdt(sess["amount_paisa"]),
            "currency": sess["currency"],
            "customer_name": sess.get("customer_name", ""),
            "status": sess["status"],
            "trxid": sess.get("trxid"),
            "provider": sess.get("provider"),
            "expires_at": sess["expires_at"],
            "methods": methods,
            "gateway_name": store.get_setting("gateway_name", "MFS Gateway"),
        }

    def _dispatch_ipn(sess: dict) -> None:
        """Best-effort signed IPN POST to the merchant callback URL."""
        url = sess.get("callback_url") or ""
        if not url.startswith(("http://", "https://")):
            return
        canonical = f"{sess['id']}|{sess['order_id']}|{sess['amount_paisa']}|{sess.get('trxid') or ''}"
        payload = json.dumps({
            "event": "payment.success",
            "session_id": sess["id"],
            "order_id": sess["order_id"],
            "amount_paisa": sess["amount_paisa"],
            "currency": sess["currency"],
            "provider": sess.get("provider"),
            "trxid": sess.get("trxid"),
            "payer_wallet": sess.get("payer_wallet"),
            "paid_at": sess.get("paid_at"),
            "signature": sign_payload(app.secret_key, canonical),
        })

        def _send():
            try:
                req = urllib.request.Request(
                    url, data=payload.encode("utf-8"),
                    headers={"Content-Type": "application/json",
                             "X-Gateway-Signature":
                                 sign_payload(app.secret_key, canonical)},
                    method="POST")
                urllib.request.urlopen(req, timeout=8).read()
            except Exception as exc:  # noqa: BLE001 - best effort, merchant can poll
                log.warning("IPN delivery failed for %s: %s", sess["id"], exc)

        threading.Thread(target=_send, daemon=True).start()

    def _signed_redirect(base_url: str, sess: dict) -> str:
        canonical = f"{sess['id']}|{sess['order_id']}|{sess['amount_paisa']}|{sess.get('trxid') or ''}"
        params = {
            "status": sess["status"],
            "session_id": sess["id"],
            "order_id": sess["order_id"],
            "amount_paisa": sess["amount_paisa"],
            "currency": sess["currency"],
            "trxid": sess.get("trxid") or "",
            "sig": sign_payload(app.secret_key, canonical),
        }
        sep = "&" if "?" in base_url else "?"
        return base_url + sep + urlencode(params)

    # ==================================================================
    # DEVICE API
    # ==================================================================

    @app.post("/api/v1/webhook/sms")
    def webhook_sms():
        if not _rate_ok("webhook", 240):
            return jsonify({"error": "rate_limited"}), 429
        device = _device_auth()
        if not device:
            return jsonify({"error": "invalid_signature"}), 401
        payload = request.get_json(silent=True) or {}

        provider = str(payload.get("provider", "unknown"))[:24].lower()
        trxid = str(payload.get("trxid", "")).upper().strip()
        sender = normalize_msisdn(str(payload.get("sender", "")))[:16]
        amount = safe_int(payload.get("amount_paisa"), -1)
        sms_ts = str(payload.get("sms_timestamp", ""))[:40]
        raw_hash = str(payload.get("raw_hash", ""))[:64]

        if not TRXID_RE.fullmatch(trxid) or amount <= 0:
            return jsonify({"error": "invalid_payload"}), 400

        store = _store()
        result = store.insert_sms(provider, sender, amount, trxid,
                                  device["device_id"], sms_ts or utcnow_iso(),
                                  raw_hash)
        store.touch_device(device["device_id"], utcnow_iso())
        if result == "duplicate":
            return jsonify({"status": "duplicate"}), 200
        store.audit(f"device:{device['device_id']}", "sms_received",
                    f"{provider} {trxid} ৳{paisa_to_bdt(amount)}")
        return jsonify({"status": "stored", "trxid": trxid}), 201

    @app.post("/api/v1/device/heartbeat")
    def device_heartbeat():
        device = _device_auth()
        if not device:
            return jsonify({"error": "invalid_signature"}), 401
        _store().touch_device(device["device_id"], utcnow_iso())
        return jsonify({"status": "ok", "server_time": utcnow_iso()})

    # ==================================================================
    # MERCHANT API (HMAC)
    # ==================================================================

    @app.post("/api/v1/checkout/create")
    def checkout_create():
        if not _rate_ok("create", 120):
            return jsonify({"error": "rate_limited"}), 429
        key, merchant = _merchant_api_auth()
        if not key:
            return jsonify({"error": "invalid_signature"}), 401
        data = request.get_json(silent=True) or {}

        order_id = str(data.get("order_id", "")).strip()
        if not ORDER_RE.fullmatch(order_id):
            return jsonify({"error": "order_id must be 3-64 chars [A-Za-z0-9_.-]"}), 400
        try:
            amount = amount_to_paisa(str(data.get("amount", "")))
        except ValueError:
            return jsonify({"error": "invalid amount"}), 400
        if not (MIN_AMOUNT_PAISA <= amount <= MAX_AMOUNT_PAISA):
            return jsonify({"error": "amount out of range (BDT 10 - 500,000)"}), 400

        success_url = str(data.get("success_url", ""))[:2048]
        cancel_url = str(data.get("cancel_url", ""))[:2048]
        callback_url = str(data.get("callback_url", ""))[:2048]
        for u in (success_url, cancel_url, callback_url):
            if u and not u.startswith(("http://", "https://")):
                return jsonify({"error": "URLs must be absolute http(s)"}), 400

        store = _store()
        existing = store.find_session_by_order(merchant["id"], order_id)
        if existing:
            sess = _touch_session(existing)
            return jsonify({
                "idempotent_replay": True,
                "session_id": sess["id"],
                "status": sess["status"],
                "checkout_url": url_for("checkout_page", session_id=sess["id"],
                                        _external=True),
                "amount_paisa": sess["amount_paisa"],
                "currency": sess["currency"],
            })

        ttl = max(5, safe_int(store.get_setting("session_ttl_minutes", "15"), 15))
        sid = new_session_id()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=ttl)) \
            .replace(microsecond=0).isoformat()
        store.create_session({
            "id": sid, "merchant_id": merchant["id"], "api_key_id": key["id"],
            "order_id": order_id, "amount_paisa": amount,
            "currency": str(data.get("currency", "BDT"))[:3].upper() or "BDT",
            "customer_name": str(data.get("customer_name", ""))[:120],
            "customer_email": str(data.get("customer_email", ""))[:120],
            "customer_phone": str(data.get("customer_phone", ""))[:20],
            "success_url": success_url, "cancel_url": cancel_url,
            "callback_url": callback_url, "expires_at": expires,
        })
        store.audit(f"merchant:{merchant['email']}", "session_created",
                    f"{sid} {order_id} ৳{paisa_to_bdt(amount)}")

        return jsonify({
            "session_id": sid,
            "status": "pending",
            "checkout_url": url_for("checkout_page", session_id=sid, _external=True),
            "amount_paisa": amount,
            "amount_bdt": paisa_to_bdt(amount),
            "currency": "BDT",
            "expires_at": expires,
        }), 201

    @app.get("/api/v1/payments/<session_id>")
    def payment_status_api(session_id):
        key, merchant = _merchant_api_auth()
        if not key:
            return jsonify({"error": "invalid_signature"}), 401
        raw = _store().find_session(session_id)
        if not raw or raw["merchant_id"] != merchant["id"]:
            return jsonify({"error": "not_found"}), 404
        sess = _touch_session(raw)
        return jsonify({
            "session_id": sess["id"], "order_id": sess["order_id"],
            "status": sess["status"], "amount_paisa": sess["amount_paisa"],
            "currency": sess["currency"], "provider": sess.get("provider"),
            "trxid": sess.get("trxid"), "payer_wallet": sess.get("payer_wallet"),
            "created_at": sess["created_at"], "paid_at": sess.get("paid_at"),
            "verification": {
                "canonical": f"{sess['id']}|{sess['order_id']}|{sess['amount_paisa']}|{sess.get('trxid') or ''}",
                "sig": sign_payload(app.secret_key, f"{sess['id']}|{sess['order_id']}|{sess['amount_paisa']}|{sess.get('trxid') or ''}"),
            } if sess["status"] == "paid" else None,
        })

    # ==================================================================
    # CHECKOUT (buyer-facing)
    # ==================================================================

    @app.get("/checkout/<session_id>")
    def checkout_page(session_id):
        if not SESSION_RE.fullmatch(session_id or ""):
            abort(404)
        return render_template("checkout.html", session_id=session_id)

    @app.get("/api/v1/checkout/<session_id>")
    def checkout_state(session_id):
        raw = _store().find_session(session_id)
        if not raw:
            return jsonify({"error": "not_found"}), 404
        return jsonify(_session_public_dict(_touch_session(raw)))

    @app.get("/api/v1/checkout/<session_id>/status")
    def checkout_status(session_id):
        raw = _store().find_session(session_id)
        if not raw:
            return jsonify({"error": "not_found"}), 404
        sess = _touch_session(raw)
        out = {"status": sess["status"], "trxid": sess.get("trxid"),
               "provider": sess.get("provider")}
        if sess["status"] == "paid" and sess["success_url"]:
            out["redirect"] = _signed_redirect(sess["success_url"], sess)
        elif sess["status"] in ("expired", "cancelled") and sess.get("cancel_url"):
            out["redirect"] = sess["cancel_url"]
        return jsonify(out)

    @app.post("/api/v1/checkout/verify")
    def checkout_verify():
        if not _rate_ok("verify", 30):
            return jsonify({"result": "rate_limited",
                            "message": "Too many attempts. Wait a minute."}), 429
        data = request.get_json(silent=True) or {}
        session_id = str(data.get("session_id", ""))
        provider = str(data.get("provider", "")).lower()[:24]
        wallet = normalize_msisdn(str(data.get("wallet", "")))
        trxid = str(data.get("trxid", "")).upper().replace(" ", "").replace("-", "")

        if not SESSION_RE.fullmatch(session_id):
            return jsonify({"result": "invalid", "message": "Bad session."}), 400
        if not WALLET_RE.fullmatch(wallet):
            return jsonify({"result": "invalid",
                            "message": "Enter a valid wallet number (01XXXXXXXXX)."}), 400
        if not TRXID_RE.fullmatch(trxid):
            return jsonify({"result": "invalid",
                            "message": "Transaction ID must be 6-24 letters/digits."}), 400

        store = _store()
        raw = store.find_session(session_id)
        if not raw:
            return jsonify({"result": "invalid", "message": "Session not found."}), 404
        sess = _touch_session(raw)

        if sess["status"] == "paid":
            return jsonify({"result": "paid",
                            "redirect": _signed_redirect(sess["success_url"], sess)
                            if sess["success_url"] else None})
        if sess["status"] == "expired":
            return jsonify({"result": "expired",
                            "message": "Payment window expired. Start a new order."})
        if sess["status"] != "pending":
            return jsonify({"result": sess["status"],
                            "message": "This payment session is no longer active."})

        max_attempts = safe_int(store.get_setting("max_verify_attempts", "10"), 10)
        if sess["attempts"] >= max_attempts:
            return jsonify({"result": "locked",
                            "message": "Too many attempts. Contact the merchant."})

        store.increment_attempts(session_id)
        sms = store.find_sms_by_trxid(trxid)

        if not sms:
            # Buyer may have just paid; SMS might still be in flight.
            return jsonify({
                "result": "pending",
                "message": "Transaction not received yet. If you already paid, "
                           "wait 30-60 seconds and press Verify again.",
            })

        if sms["status"] == "consumed" and sms.get("matched_session_id") != session_id:
            return jsonify({"result": "used",
                            "message": "This TrxID was already used for another payment."})

        if sms["amount_paisa"] != sess["amount_paisa"]:
            store.audit("checkout", "amount_mismatch",
                        f"{session_id} {trxid} expected BDT {sess['amount_paisa']} "
                        f"got {sms['amount_paisa']}")
            return jsonify({
                "result": "amount_mismatch",
                "message": f"TrxID found but the amount doesn't match "
                           f"(expected ৳{paisa_to_bdt(sess['amount_paisa'])}).",
            })

        # Atomic claim: exactly one session may consume an SMS fact.
        if not store.claim_sms(sms["id"], session_id):
            return jsonify({"result": "used",
                            "message": "This TrxID was already consumed."})

        paid_at = utcnow_iso()
        store.mark_session_paid(session_id, sms["provider"], wallet, trxid, paid_at)
        store.audit("checkout", "payment_verified",
                    f"{session_id} {sms['provider']} {trxid} "
                    f"৳{paisa_to_bdt(sess['amount_paisa'])}")

        sess.update({"status": "paid", "trxid": trxid, "paid_at": paid_at,
                     "payer_wallet": wallet, "provider": sms["provider"]})
        _dispatch_ipn(sess)
        return jsonify({
            "result": "paid",
            "provider": sms["provider"],
            "trxid": trxid,
            "redirect": _signed_redirect(sess["success_url"], sess)
            if sess["success_url"] else None,
        })

    # ==================================================================
    # MERCHANT AUTH + DASHBOARD
    # ==================================================================

    @app.route("/register", methods=["GET", "POST"])
    def merchant_register():
        error = None
        if request.method == "POST" and _check_csrf():
            f = request.form
            email = f.get("email", "").strip().lower()[:120]
            name = f.get("name", "").strip()[:120]
            password = f.get("password", "").strip()
            if not EMAIL_RE.fullmatch(email) or not name or len(password) < 8:
                error = "Valid email, business name, and 8+ char password required."
            else:
                try:
                    _store().create_merchant(email, name, hash_password(password))
                    _store().audit(email, "merchant_registered", name)
                    return redirect(url_for("merchant_login", registered="1"))
                except DuplicateError:
                    error = "This email is already registered."
        elif request.method == "POST":
            error = "Session expired — please retry."
        return render_template("merchant_register.html", error=error)

    @app.route("/login", methods=["GET", "POST"])
    def merchant_login():
        error = None
        if request.method == "POST" and _check_csrf():
            email = request.form.get("email", "").strip().lower()
            row = _store().find_merchant_by_email(email)
            if row and row["status"] == "active" and verify_password(
                    request.form.get("password", "").strip(), row["password_hash"]):
                session.clear()
                session["merchant_id"] = row["id"]
                session["csrf"] = new_csrf_token()
                session.permanent = True
                return redirect(url_for("merchant_dashboard"))
            error = "Invalid credentials or account suspended."
        elif request.method == "POST":
            error = "Session expired — please retry."
        demo_hint = (os.environ.get("GATEWAY_SHOW_LOGIN_HINTS") == "1"
                     and _store().find_merchant_by_email("demo@merchant.test")
                     is not None)
        return render_template("merchant_login.html", error=error,
                               demo_hint=demo_hint)

    @app.get("/logout")
    def merchant_logout():
        session.clear()
        return redirect(url_for("merchant_login"))

    @app.get("/dashboard")
    @require_merchant
    def merchant_dashboard():
        return render_template("dashboard.html")

    @app.get("/dashboard/api/summary")
    @require_merchant
    def merchant_summary():
        mid = session["merchant_id"]
        store = _store()
        row = store.get_merchant(mid)
        today = datetime.now(timezone.utc).date().isoformat()
        stats = {
            "today": store.payment_stats(mid, today),
            "all": store.payment_stats(mid, None),
            "pending": store.count_pending_sessions(mid),
        }
        for k in ("today", "all"):
            stats[k] = {"count": stats[k]["count"],
                        "volume": paisa_to_bdt(stats[k]["volume"])}
        keys = store.list_keys_for_merchant(mid)
        recent = store.list_sessions(mid, 50)
        return jsonify({
            "merchant": {"name": row["name"], "email": row["email"],
                         "created_at": row["created_at"]},
            "stats": stats,
            "keys": keys,
            "sessions": [_session_view(r) for r in recent],
        })

    @app.get("/dashboard/api/transactions")
    @require_merchant
    def merchant_transactions():
        rows = _store().list_sessions(session["merchant_id"], 100)
        return jsonify({"sessions": [
            _session_view(r) | {"checkout_url": url_for(
                "checkout_page", session_id=r["id"], _external=True)}
            for r in rows]})

    @app.post("/api/v1/merchant/keys/generate")
    @require_merchant
    @csrf_guard
    def generate_key():
        data = request.get_json(silent=True) or {}
        label = str(data.get("label", "default"))[:60]
        store = _store()
        if store.count_keys(session["merchant_id"]) >= MAX_MERCHANT_KEYS:
            return jsonify({"error": f"key limit reached ({MAX_MERCHANT_KEYS})"}), 400
        pk, sk = generate_api_key_pair()
        store.create_api_key(session["merchant_id"], pk, sk, label)
        store.audit(f"merchant:{session['merchant_id']}", "key_generated", label)
        return jsonify({"key_id": pk, "secret": sk, "label": label}), 201

    @app.post("/dashboard/api/keys/<int:key_id>/status")
    @require_merchant
    @csrf_guard
    def merchant_key_status(key_id):
        data = request.get_json(silent=True) or {}
        status = data.get("status")
        if status not in ("active", "revoked"):
            return jsonify({"error": "bad status"}), 400
        updated = _store().set_key_status(key_id, status, session["merchant_id"])
        _store().audit(f"merchant:{session['merchant_id']}", "key_status",
                       f"key={key_id} -> {status}")
        return jsonify({"updated": updated})

    @app.post("/dashboard/api/test-checkout")
    @require_merchant
    @csrf_guard
    def merchant_test_checkout():
        data = request.get_json(silent=True) or {}
        try:
            amount = amount_to_paisa(str(data.get("amount", "250.00")))
        except ValueError:
            return jsonify({"error": "invalid amount"}), 400
        amount = min(max(amount, MIN_AMOUNT_PAISA), MAX_AMOUNT_PAISA)
        store = _store()
        active_keys = [k for k in store.list_keys_for_merchant(session["merchant_id"])
                       if k["status"] == "active"]
        sid = new_session_id()
        ttl = max(5, safe_int(store.get_setting("session_ttl_minutes", "15"), 15))
        expires = (datetime.now(timezone.utc) + timedelta(minutes=ttl)) \
            .replace(microsecond=0).isoformat()
        import secrets as _sec
        store.create_session({
            "id": sid, "merchant_id": session["merchant_id"],
            "api_key_id": active_keys[0]["id"] if active_keys else None,
            "order_id": f"TEST-{_sec.token_hex(4).upper()}", "amount_paisa": amount,
            "currency": "BDT", "customer_name": "Test Customer",
            "expires_at": expires,
        })
        store.audit(f"merchant:{session['merchant_id']}", "test_checkout", sid)
        return jsonify({"session_id": sid,
                        "checkout_url": url_for("checkout_page", session_id=sid,
                                                _external=True)})

    # ==================================================================
    # SUPERADMIN
    # ==================================================================

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        error = None
        if request.method == "POST" and _check_csrf():
            username = request.form.get("username", "").strip()[:60]
            row = _store().find_admin(username)
            if row and verify_password(request.form.get("password", "").strip(),
                                       row["password_hash"]):
                session.clear()
                session["admin_id"] = username
                session["admin_name"] = username
                session["csrf"] = new_csrf_token()
                session.permanent = True
                return redirect(url_for("admin_panel"))
            error = "Invalid credentials."
        elif request.method == "POST":
            error = "Session expired — please retry."
        # Login hints are DEV-ONLY: shown when GATEWAY_SHOW_LOGIN_HINTS=1
        # (this sandbox sets it; production never should).
        show_hints = os.environ.get("GATEWAY_SHOW_LOGIN_HINTS") == "1"
        admin_user = os.environ.get("GATEWAY_ADMIN_USER", "admin")
        return render_template(
            "admin_login.html", error=error,
            admin_hint=admin_user if show_hints else None,
            admin_env_password=(os.environ.get("GATEWAY_ADMIN_PASSWORD")
                                if show_hints else None))

    @app.get("/admin/logout")
    def admin_logout():
        session.clear()
        return redirect(url_for("admin_login"))

    @app.get("/admin")
    @require_admin
    def admin_panel():
        return render_template("admin.html")

    @app.get("/admin/api/summary")
    @require_admin
    def admin_summary():
        store = _store()
        today = datetime.now(timezone.utc).date().isoformat()
        vol = store.payment_stats(None, today)
        tot = store.payment_stats(None, None)
        online_cut = (datetime.now(timezone.utc) - timedelta(minutes=5)) \
            .replace(microsecond=0).isoformat()
        devices = [d | {"online": bool(d.get("last_seen_at") and
                                           d["last_seen_at"] >= online_cut)}
                   for d in store.list_devices()]
        recent_sms = [_sms_view(r) for r in store.list_sms_recent(12)]
        recent_paid = [{k: r.get(k) for k in (
            "id", "order_id", "merchant")} | {"provider": r.get("provider"),
            "trxid": r.get("trxid"), "paid_at": r.get("paid_at"),
            "amount_bdt": paisa_to_bdt(r["amount_paisa"])}
            for r in store.list_paid_recent(12)]
        return jsonify({
            "today_volume": paisa_to_bdt(vol["volume"]), "today_count": vol["count"],
            "total_volume": paisa_to_bdt(tot["volume"]), "total_count": tot["count"],
            "merchants": store.count_merchants(),
            "sms": store.sms_stats(), "devices": devices,
            "recent_sms": recent_sms, "recent_paid": recent_paid,
        })

    @app.get("/admin/api/transactions")
    @require_admin
    def admin_transactions():
        store = _store()
        since = safe_int(request.args.get("since_id"), 0)
        rows = store.list_sms_since(since, 150)
        sessions = store.list_sessions(None, 100)
        return jsonify({
            "sms": [_sms_view(r) for r in rows],
            "sessions": [_session_view(r) for r in sessions],
        })

    @app.post("/admin/api/transactions/<int:sms_id>/release")
    @require_admin
    @csrf_guard
    def admin_release_sms(sms_id):
        store = _store()
        row = store.get_sms(sms_id)
        if not row:
            return jsonify({"error": "not_found"}), 404
        store.release_sms(sms_id)
        if row.get("matched_session_id"):
            store.reset_session_to_pending(row["matched_session_id"])
        store.audit(f"admin:{session.get('admin_name')}", "sms_released",
                    f"{row['trxid']} id={sms_id}")
        return jsonify({"released": True})

    @app.post("/admin/api/sms/inject")
    @require_admin
    @csrf_guard
    def admin_inject_sms():
        """Console-side test injector: simulates an SMS fact without a phone."""
        data = request.get_json(silent=True) or {}
        provider = str(data.get("provider", "bkash"))[:24].lower()
        sender = normalize_msisdn(str(data.get("sender", "01711222333")))
        trxid = str(data.get("trxid", "")).upper().strip()
        try:
            amount = amount_to_paisa(str(data.get("amount", "")))
        except ValueError:
            return jsonify({"error": "invalid amount"}), 400
        if not TRXID_RE.fullmatch(trxid) or amount <= 0:
            return jsonify({"error": "invalid_payload"}), 400
        store = _store()
        result = store.insert_sms(provider, sender, amount, trxid, "admin-console",
                                  utcnow_iso(), sha256_hex(f"inject:{trxid}"))
        if result == "duplicate":
            return jsonify({"error": "trxid already exists"}), 409
        store.audit(f"admin:{session.get('admin_name')}", "sms_injected",
                    f"{provider} {trxid} ৳{paisa_to_bdt(amount)}")
        return jsonify({"injected": True}), 201

    @app.get("/admin/api/merchants")
    @require_admin
    def admin_merchants():
        rows = _store().list_merchants_enriched()
        return jsonify({"merchants": [
            r | {"volume_bdt": paisa_to_bdt(r["volume"])} for r in rows]})

    @app.post("/admin/api/merchants/<int:mid>/status")
    @require_admin
    @csrf_guard
    def admin_merchant_status(mid):
        data = request.get_json(silent=True) or {}
        status = data.get("status")
        if status not in ("active", "suspended"):
            return jsonify({"error": "bad status"}), 400
        _store().set_merchant_status(mid, status)
        _store().audit(f"admin:{session.get('admin_name')}", "merchant_status",
                       f"merchant={mid} -> {status}")
        return jsonify({"updated": True})

    @app.get("/admin/api/keys")
    @require_admin
    def admin_keys():
        return jsonify({"keys": _store().list_all_keys_enriched()})

    @app.post("/admin/api/keys/<int:key_id>/revoke")
    @require_admin
    @csrf_guard
    def admin_revoke_key(key_id):
        _store().set_key_status(key_id, "revoked")
        _store().audit(f"admin:{session.get('admin_name')}", "key_revoked",
                       f"key={key_id}")
        return jsonify({"revoked": True})

    @app.route("/admin/api/devices", methods=["GET", "POST"])
    @require_admin
    def admin_devices():
        store = _store()
        if request.method == "POST":
            if not _check_csrf():
                return jsonify({"error": "bad_csrf"}), 403
            data = request.get_json(silent=True) or {}
            name = str(data.get("name", "Termux Phone"))[:80]
            device_id, secret = generate_device_credentials()
            store.create_device(device_id, name, secret)
            store.audit(f"admin:{session.get('admin_name')}", "device_created",
                        device_id)
            return jsonify({"device_id": device_id, "secret": secret,
                            "name": name}), 201
        return jsonify({"devices": store.list_devices()})

    @app.post("/admin/api/devices/<device_id>/status")
    @require_admin
    @csrf_guard
    def admin_device_status(device_id):
        data = request.get_json(silent=True) or {}
        status = data.get("status")
        if status not in ("active", "revoked"):
            return jsonify({"error": "bad status"}), 400
        _store().set_device_status(device_id, status)
        _store().audit(f"admin:{session.get('admin_name')}", "device_status",
                       f"{device_id} -> {status}")
        return jsonify({"updated": True})

    @app.route("/admin/api/settings", methods=["GET", "POST"])
    @require_admin
    def admin_settings():
        store = _store()
        if request.method == "POST":
            if not _check_csrf():
                return jsonify({"error": "bad_csrf"}), 403
            data = request.get_json(silent=True) or {}
            if "gateway_name" in data:
                store.set_setting("gateway_name", str(data["gateway_name"])[:80])
            if "session_ttl_minutes" in data:
                store.set_setting("session_ttl_minutes", str(max(5, min(
                    safe_int(data["session_ttl_minutes"], 15), 120))))
            if "max_verify_attempts" in data:
                store.set_setting("max_verify_attempts", str(max(3, min(
                    safe_int(data["max_verify_attempts"], 10), 50))))
            if "provider_wallets" in data:
                try:
                    wallets = data["provider_wallets"]
                    assert isinstance(wallets, dict)
                    clean = {}
                    for name, cfg in wallets.items():
                        name = re.sub(r"[^a-z]", "", str(name).lower())[:24]
                        if not name:
                            continue
                        clean[name] = {
                            "number": str(cfg.get("number", ""))[:20],
                            "type": "Agent" if cfg.get("type") == "Agent" else "Personal",
                            "enabled": bool(cfg.get("enabled")),
                        }
                    store.set_setting("provider_wallets", json.dumps(clean))
                except (AssertionError, AttributeError, TypeError):
                    return jsonify({"error": "invalid provider_wallets"}), 400
            store.audit(f"admin:{session.get('admin_name')}", "settings_updated", "")
        return jsonify(store.all_settings())

    @app.get("/admin/api/audit")
    @require_admin
    def admin_audit():
        return jsonify({"logs": _store().list_audit(100)})

    # ==================================================================
    # MISC
    # ==================================================================

    def _sms_view(r: dict) -> dict:
        keep = ("id", "provider", "sender", "trxid", "device_id", "status",
                "matched_session_id", "created_at", "order_id", "merchant")
        out = {k: r.get(k) for k in keep}
        out["amount_bdt"] = paisa_to_bdt(r["amount_paisa"])
        return out

    def _session_view(r: dict) -> dict:
        keep = ("id", "order_id", "merchant", "currency", "status", "provider",
                "trxid", "payer_wallet", "attempts", "customer_name",
                "created_at", "paid_at")
        out = {k: r.get(k) for k in keep}
        out["amount_bdt"] = paisa_to_bdt(r["amount_paisa"])
        out["amount_paisa"] = r["amount_paisa"]
        return out

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            gateway_name=_store().get_setting("gateway_name", "MFS Gateway"))

    @app.get("/healthz")
    def healthz():
        backend = os.environ.get("GATEWAY_DB_BACKEND", "sqlite")
        out = {"status": "ok", "time": utcnow_iso(), "backend": backend}
        if backend == "mongodb":
            out["mongo_transport"] = ("mock (dev shim)"
                                      if os.environ.get("GATEWAY_MONGO_MOCK") == "1"
                                      else "real server")
        return jsonify(out)

    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith(("/api/", "/admin/api", "/dashboard/api")):
            return jsonify({"error": "not_found"}), 404
        return render_template("error.html", code=404,
                               message="Page not found"), 404

    return app


app = create_app()


def main():
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if "--init-demo" in sys.argv:
        from .demo import ensure_demo_data
        creds = ensure_demo_data(app)
        out = json.dumps(creds, indent=2)
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        data_dir = os.environ.get("GATEWAY_DATA_DIR", os.path.join(root, "data"))
        creds_file = os.path.join(data_dir, "demo_credentials.json")
        with open(creds_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("Demo credentials written to", creds_file, "\n", out)
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, threaded=True)


if __name__ == "__main__":
    main()
