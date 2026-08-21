"""Deterministic superadmin seeding (shared by store backends)."""

from __future__ import annotations

import os
import secrets

from ..security import hash_password, verify_password


def seed_admin(store, app) -> None:
    """Guarantee the superadmin credential is exactly what ops configured.

    * First boot           -> create with env password, else generated random.
    * Later boots with env -> re-sync hash if it drifted (env is source of truth).
    """
    username = os.environ.get("GATEWAY_ADMIN_USER", "admin")
    env_pass = os.environ.get("GATEWAY_ADMIN_PASSWORD")
    existing = store.find_admin(username)

    if existing is None:
        password = env_pass or secrets.token_urlsafe(9)
        store.upsert_admin(username, hash_password(password))
        store.audit("system", "admin_seeded", username)
        if not env_pass:
            app.logger.warning(
                "\n" + "=" * 64 +
                "\n  GENERATED SUPERADMIN CREDENTIALS (set GATEWAY_ADMIN_PASSWORD"
                "\n  to override):"
                f"\n      username: {username}\n      password: {password}"
                "\n" + "=" * 64)
    elif env_pass:
        if not verify_password(env_pass, existing["password_hash"]):
            store.set_admin_password(username, hash_password(env_pass))
            store.audit("system", "admin_password_synced", username)
            app.logger.warning("Superadmin password re-synced from "
                               "GATEWAY_ADMIN_PASSWORD env var.")
