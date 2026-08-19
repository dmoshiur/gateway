#!/usr/bin/env python3
"""Entry point:  python run.py [--init-demo]

Flags:
  --init-demo   Seed a demo merchant (demo@merchant.test / demo12345), a demo
                API key pair and a demo Termux device; write the credentials
                to data/demo_credentials.json, then start the server.

Env:
  PORT                  default 8000
  GATEWAY_DB            SQLite path (default data/gateway.db)
  GATEWAY_SECRET        Flask/session + signing secret
  GATEWAY_ADMIN_USER    superadmin username (first-boot seeding)
  GATEWAY_ADMIN_PASSWORD superadmin password (first-boot seeding)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import main  # noqa: E402

if __name__ == "__main__":
    main()
