"""Authentication & request-signing primitives.

Three credential types are managed here:

1. **Merchant API keys** — ``api_key`` (public id) + ``api_secret`` (HMAC key).
   Merchants can generate an *unlimited* number of these from the dashboard.
2. **Device credentials** — Termux/Android listeners get a ``device_id`` +
   ``device_secret`` so the webhook endpoint can authenticate them.
3. **Hosted-checkout tokens** — short-lived, secret-signed tokens so the browser
   checkout never needs to hold a merchant secret.

Signing scheme (HMAC-SHA256, hex digest):

    message    = f"{timestamp}.{nonce}.{method}.{path}.{sha256_hex(body)}"
    signature  = HMAC-SHA256(secret, message)

The client sends the signature plus the plaintext timestamp/nonce in headers so
the server can recompute it. Timestamps are bounded by HMAC_TIMESTAMP_WINDOW and
nonces are single-use within NONCE_TTL (replay protection).
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from .config import Config


# --------------------------------------------------------------------------- #
# Low-level HMAC helpers
# --------------------------------------------------------------------------- #
def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sign(secret: str, message: str) -> str:
    """Return the hex HMAC-SHA256 of ``message`` keyed with ``secret``."""
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def canonical_message(timestamp: str, nonce: str, method: str, path: str,
                      body: bytes) -> str:
    return f"{timestamp}.{nonce}.{method}.{path}.{sha256_hex(body)}"


def compute_signature(secret: str, timestamp: str, nonce: str, method: str,
                      path: str, body: bytes) -> str:
    return sign(secret, canonical_message(timestamp, nonce, method, path, body))


# --------------------------------------------------------------------------- #
# Credential generation
# --------------------------------------------------------------------------- #
def generate_api_key():
    """Return (api_key, api_secret) for a merchant.

    ``api_key`` is a public, non-sensitive identifier (safe to log / show).
    ``api_secret`` is the HMAC key and must be treated as a password.
    """
    public = "gw_" + secrets.token_urlsafe(24).replace("-", "").replace("_", "")[:32]
    secret = "sk_" + secrets.token_urlsafe(48)
    return public, secret


def generate_device_credentials():
    """Return (device_id, device_secret) for a Termux listener."""
    device_id = "dev_" + secrets.token_hex(12)
    device_secret = secrets.token_urlsafe(48)
    return device_id, device_secret


# --------------------------------------------------------------------------- #
# Server-side verification
# --------------------------------------------------------------------------- #
class SignatureError(Exception):
    """Raised when a request signature is missing/invalid/expired/replayed."""
    def __init__(self, message, code=401):
        super().__init__(message)
        self.code = code


def _check_nonce(nonce: str) -> None:
    """Reject reused nonces and prune expired ones."""
    from . import db as _db
    if not nonce:
        raise SignatureError("missing nonce")
    now = int(time.time())
    _db.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
    existing = _db.query("SELECT nonce FROM nonces WHERE nonce = ?", (nonce,), one=True)
    if existing:
        raise SignatureError("nonce already used (replay rejected)")
    _db.execute("INSERT INTO nonces (nonce, expires_at) VALUES (?,?)",
                (nonce, now + Config.NONCE_TTL))


def verify_hmac(secret: str, headers, method: str, path: str, body: bytes) -> bool:
    """Verify an HMAC-signed request given the shared secret.

    Headers expected: X-Timestamp, X-Nonce, X-Signature.
    """
    ts = headers.get("X-Timestamp")
    nonce = headers.get("X-Nonce")
    provided = headers.get("X-Signature")
    if not ts or not nonce or not provided:
        raise SignatureError("missing signature headers (X-Timestamp, X-Nonce, X-Signature)")
    try:
        ts_int = int(ts)
    except ValueError:
        raise SignatureError("invalid X-Timestamp")
    if abs(int(time.time()) - ts_int) > Config.HMAC_TIMESTAMP_WINDOW:
        raise SignatureError("timestamp outside allowed window", 403)
    expected = compute_signature(secret, ts, nonce, method.upper(), path, body)
    if not constant_time_equal(expected, provided):
        raise SignatureError("invalid signature", 401)
    return True


# --------------------------------------------------------------------------- #
# Hosted-checkout tokens (browser-safe)
# --------------------------------------------------------------------------- #
def issue_checkout_token(api_secret: str, api_key: str, merchant_id: int,
                         ttl: int = None) -> str:
    """Issue a short-lived token for the hosted checkout page.

    Format: base64url(json).base64url(hmac). The browser only ever sees this
    opaque token; the merchant secret never leaves the server.
    """
    ttl = ttl or Config.CHECKOUT_TOKEN_TTL
    payload = {
        "api_key": api_key,
        "merchant_id": merchant_id,
        "exp": int(time.time()) + ttl,
    }
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = sign(api_secret, raw)
    return f"{raw}.{sig}"


def verify_checkout_token(token: str) -> dict:
    """Validate a hosted-checkout token. Returns its payload dict."""
    from . import db as _db  # local import to avoid cycle
    try:
        raw, sig = token.rsplit(".", 1)
    except ValueError:
        raise SignatureError("malformed checkout token")
    payload_b = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    try:
        payload = json.loads(payload_b)
    except (ValueError, json.JSONDecodeError):
        raise SignatureError("malformed checkout token")

    if payload.get("exp", 0) < int(time.time()):
        raise SignatureError("checkout token expired", 403)

    # Look up the matching API key's secret to verify the signature.
    key_row = _db.query("SELECT * FROM api_keys WHERE api_key = ?",
                        (payload.get("api_key"),), one=True)
    if not key_row or not key_row["is_active"]:
        raise SignatureError("unknown or inactive API key")
    if not constant_time_equal(sign(key_row["api_secret"], raw), sig):
        raise SignatureError("invalid checkout token signature")
    return payload
