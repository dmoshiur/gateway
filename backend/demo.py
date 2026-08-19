"""Demo seeding — deterministic, idempotent, shared by run.py and tests.

Every run of ``python run.py --init-demo`` guarantees:
  * merchant demo@merchant.test exists with password ``demo12345`` (re-synced)
  * device ``dev_demo`` exists (secret preserved once created)
  * a demo API key pair exists for that merchant
and returns/prints the same credentials JSON each time.
"""

from __future__ import annotations

import secrets

from .security import generate_api_key_pair, hash_password

DEMO_EMAIL = "demo@merchant.test"
DEMO_PASSWORD = "demo12345"
DEMO_DEVICE_ID = "dev_demo"


def ensure_demo_data(app) -> dict:
    store = app.store

    merchant = store.find_merchant_by_email(DEMO_EMAIL)
    if merchant is None:
        mid = store.create_merchant(DEMO_EMAIL, "Demo Store BD",
                                    hash_password(DEMO_PASSWORD))
        merchant = store.get_merchant(mid)
    else:
        # Force-sync so the documented demo password ALWAYS works,
        # even if the DB was seeded with something else before.
        store.set_merchant_password(merchant["id"], hash_password(DEMO_PASSWORD))
        store.set_merchant_status(merchant["id"], "active")

    if not any(d["device_id"] == DEMO_DEVICE_ID for d in store.list_devices()):
        store.create_device(DEMO_DEVICE_ID, "Demo Termux Phone",
                            "dsec_" + secrets.token_urlsafe(18))
    store.set_device_status(DEMO_DEVICE_ID, "active")  # no-op if already active
    device = store.find_active_device(DEMO_DEVICE_ID)

    key = None
    for k in store.list_keys_for_merchant(merchant["id"]):
        if k.get("label") == "demo" and k.get("status") == "active":
            key = k
            break
    if key is None:
        pk, sk = generate_api_key_pair()
        store.create_api_key(merchant["id"], pk, sk, "demo")
        key = store.find_active_key(pk)
    else:
        # list view hides the secret — fetch the full row for the creds file
        key = store.find_active_key(key["key_id"])

    store.audit("system", "demo_seeded", DEMO_EMAIL)
    return {
        "merchant_email": DEMO_EMAIL,
        "merchant_password": DEMO_PASSWORD,
        "api_key": key["key_id"],
        "api_secret": key["secret"],
        "device_id": device["device_id"],
        "device_secret": device["secret"],
    }
