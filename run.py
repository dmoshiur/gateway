#!/usr/bin/env python3
"""Entry point:  python run.py [--init-demo]

Configuration comes from environment variables; a local ``.env`` file in the
repo root is loaded automatically (existing env vars win — see .env.example).

Flags:
  --init-demo   Seed a demo merchant (demo@merchant.test / demo12345), a demo
                API key pair and a demo Termux device; write the credentials
                to data/demo_credentials.json, then start the server.

Env (see .env.example for full docs):
  PORT                  default 8000
  DATABASE_URL          single-line PostgreSQL connection URL
                        (default postgresql+psycopg://localhost:5432/mfs_gateway;
                        DATABASE_URL=sqlite:// = dev/test in-memory shim)
  GATEWAY_SECRET        Flask/session + signing secret
  GATEWAY_ADMIN_USER    superadmin username (re-synced every boot)
  GATEWAY_ADMIN_PASSWORD superadmin password (re-synced every boot)
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv(path: str) -> None:
    """Minimal .env loader (KEY=VALUE lines, # comments, optional quotes).

    Uses setdefault semantics: variables already present in the real
    environment always take precedence over the file.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except FileNotFoundError:
        pass


_load_dotenv(os.path.join(ROOT, ".env"))
sys.path.insert(0, ROOT)

from backend.app import main  # noqa: E402  (import AFTER env is loaded)

if __name__ == "__main__":
    main()
