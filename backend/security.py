"""
Security primitives for the gateway.

- API key / device credential generation
- HMAC-SHA256 request signing (devices and merchants)
- PBKDF2 password hashing (stdlib only, no external deps)
- Session ID generation, timing-safe comparison helpers
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

PBKDF2_ITERATIONS = 210_000


# ---------------------------------------------------------------------------
# Credential generation
# ---------------------------------------------------------------------------

def generate_api_key_pair() -> tuple[str, str]:
    """Return (key_id, secret). Secret is shown to the merchant exactly once."""
    return "pk_live_" + secrets.token_urlsafe(18), "sk_live_" + secrets.token_urlsafe(36)


def generate_device_credentials() -> tuple[str, str]:
    """Return (device_id, device_secret)."""
    return "dev_" + secrets.token_hex(4), "dsec_" + secrets.token_urlsafe(36)


def new_session_id() -> str:
    return "ps_" + secrets.token_urlsafe(18)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# HMAC request signing
#
# Canonical string (identical on listener, merchant SDK examples and server):
#     f"{key_or_device_id}\n{unix_timestamp}\n{raw_body}"
# Signature = hex(HMAC_SHA256(secret, canonical))
# ---------------------------------------------------------------------------

def sign_request(secret: str, key_id: str, timestamp: str, body: str) -> str:
    canonical = f"{key_id}\n{timestamp}\n{body}"
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def verify_request_signature(
    *,
    secret: str,
    key_id: str,
    timestamp: str,
    body: str,
    provided_signature: str,
    max_skew_seconds: int = 300,
) -> bool:
    """Constant-time HMAC verification with replay window enforcement."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    expected = sign_request(secret, key_id, timestamp, body)
    return hmac.compare_digest(expected, provided_signature or "")


def sign_payload(secret: str, canonical: str) -> str:
    """Signs redirect/IPN parameter strings with the gateway signing key."""
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"),
                    hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Passwords (PBKDF2-HMAC-SHA256). Format: pbkdf2$iterations$salt_hex$dk_hex
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _scheme, iterations, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(iterations),
        )
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
