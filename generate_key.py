"""Print a fresh random AES-256 key (base64). Put it in .env as LOGVAULT_MASTER_KEY."""
from logvault.crypto import generate_key_b64

print(generate_key_b64())
