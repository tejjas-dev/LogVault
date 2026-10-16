"""Restore a downloaded encrypted backup (.zip) on your own machine.

Usage:  python restore_backup.py backup.zip restored.log
Needs LOGVAULT_MASTER_KEY in the environment or .env (same key used for upload).
"""
import os
import sys

from dotenv import load_dotenv

from logvault.crypto import CryptoError, _decode_key
from logvault.service import restore_from_backup_zip

load_dotenv()
if len(sys.argv) != 3:
    sys.exit(__doc__)
if not os.environ.get("LOGVAULT_MASTER_KEY"):
    sys.exit("Set LOGVAULT_MASTER_KEY first.")
try:
    digest = restore_from_backup_zip(sys.argv[1], _decode_key(os.environ["LOGVAULT_MASTER_KEY"]), sys.argv[2])
except (CryptoError, ValueError) as exc:
    sys.exit(f"VERIFICATION FAILED: {exc}")
print(f"Restored to {sys.argv[2]}\nSHA-256 verified: {digest}")
