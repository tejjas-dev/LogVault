"""Block splitting + AES-256-GCM encryption helpers."""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import BinaryIO, Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12  # 96-bit nonce, random per block


class CryptoError(Exception):
    """Raised when a block cannot be authenticated/decrypted."""


def generate_key_b64() -> str:
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode()


def _decode_key(value: str) -> bytes:
    key = base64.urlsafe_b64decode(value.strip().encode())
    if len(key) != 32:
        raise RuntimeError("LOGVAULT_MASTER_KEY must decode to exactly 32 bytes")
    return key


def load_master_key(app) -> bytes:
    """Key comes from env. For local dev only, one is generated into instance/."""
    value = app.config.get("LOGVAULT_MASTER_KEY")
    if value:
        return _decode_key(value)
    if app.config["STORAGE_BACKEND"] == "local" or app.config.get("TESTING"):
        path = Path(app.instance_path) / "dev_master.key"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(generate_key_b64())
            os.chmod(path, 0o600)
        return _decode_key(path.read_text())
    raise RuntimeError(
        "LOGVAULT_MASTER_KEY is not set. Generate one with: python generate_key.py"
    )


def file_key(master_key: bytes, file_id: str) -> bytes:
    """Derive a separate AES-256 key per file from the master key (HKDF)."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=file_id.encode(), info=b"logvault-file-key"
    ).derive(master_key)


def split_blocks(stream: BinaryIO, block_size: int) -> Iterator[bytes]:
    while True:
        chunk = stream.read(block_size)
        if not chunk:
            return
        # read() on some streams may return short chunks - fill up to block_size
        while len(chunk) < block_size:
            more = stream.read(block_size - len(chunk))
            if not more:
                break
            chunk += more
        yield chunk


def _aad(file_id: str, index: int) -> bytes:
    # Binds each block to its file and position: blocks cannot be swapped/reordered.
    return f"{file_id}:{index}".encode()


def encrypt_block(key: bytes, file_id: str, index: int, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, _aad(file_id, index))


def decrypt_block(key: bytes, file_id: str, index: int, blob: bytes) -> bytes:
    if len(blob) < NONCE_SIZE + 16:
        raise CryptoError(f"block {index} is too short")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _aad(file_id, index))
    except Exception as exc:  # InvalidTag
        raise CryptoError(f"block {index} failed authentication (tampered or wrong key)") from exc
