"""Entry point for the MFS Payment Gateway backend.

Usage:
    python run.py                 # start on 0.0.0.0:5000 (dev)
    python run.py --port 8000     # custom port
    python run.py --init-only     # create DB + seed demo data, then exit
"""
import argparse

from backend.app import create_app
from backend.db import init_db, seed

parser = argparse.ArgumentParser(description="MFS Payment Gateway")
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, default=5000)
parser.add_argument("--debug", action="store_true")
parser.add_argument("--init-only", action="store_true")
args = parser.parse_args()

app = create_app()
with app.app_context():
    init_db()
    seed()

if args.init_only:
    print("[gateway] Database initialized and seeded. Exiting.")
    raise SystemExit(0)

print(f"[gateway] Listening on http://{args.host}:{args.port}")
app.run(host=args.host, port=args.port, debug=args.debug)
