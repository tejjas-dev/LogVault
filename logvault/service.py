"""Core operations: archive (split+encrypt+store), backup, restore+verify."""
from __future__ import annotations

import hashlib
import json
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from . import crypto


def block_key(file_id: str, index: int) -> str:
    return f"files/{file_id}/blocks/{index:06d}.enc"


def manifest_key(file_id: str) -> str:
    return f"files/{file_id}/manifest.json"


def archive_file(storage, master_key: bytes, stream: BinaryIO, filename: str, block_size: int) -> dict:
    """Read the stream in blocks, hash it, encrypt each block and upload it."""
    file_id = uuid.uuid4().hex
    key = crypto.file_key(master_key, file_id)
    sha = hashlib.sha256()
    total = 0
    count = 0
    for index, block in enumerate(crypto.split_blocks(stream, block_size)):
        sha.update(block)
        total += len(block)
        storage.put(block_key(file_id, index), crypto.encrypt_block(key, file_id, index, block))
        count = index + 1
    manifest = {
        "version": 1,
        "file_id": file_id,
        "filename": filename,
        "size_bytes": total,
        "block_size": block_size,
        "block_count": count,
        "sha256": sha.hexdigest(),
        "cipher": "AES-256-GCM",
    }
    storage.put(manifest_key(file_id), json.dumps(manifest, indent=2).encode())
    return manifest


@dataclass
class RestoreResult:
    ok: bool
    detail: str
    computed_sha256: str | None = None
    data: BinaryIO | None = None  # temp file positioned at 0 when ok


def restore_file(storage, master_key: bytes, record) -> RestoreResult:
    """Download every block, decrypt, rebuild the file and check its SHA-256."""
    file_id = record["id"]
    key = crypto.file_key(master_key, file_id)
    out = tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
    sha = hashlib.sha256()
    try:
        for index in range(record["block_count"]):
            try:
                blob = storage.get(block_key(file_id, index))
            except Exception as exc:
                out.close()
                return RestoreResult(False, f"Block {index} could not be downloaded ({type(exc).__name__}).")
            try:
                plain = crypto.decrypt_block(key, file_id, index, blob)
            except crypto.CryptoError as exc:
                out.close()
                return RestoreResult(False, str(exc))
            sha.update(plain)
            out.write(plain)
    except Exception:
        out.close()
        raise
    computed = sha.hexdigest()
    if computed != record["sha256"]:
        out.close()
        return RestoreResult(False, "SHA-256 mismatch: restored file differs from the original.", computed)
    out.seek(0)
    return RestoreResult(True, "SHA-256 of restored file matches the original.", computed, out)


def build_backup_zip(storage, record) -> BinaryIO:
    """Encrypted backup = manifest.json + all still-encrypted blocks. No key inside."""
    file_id = record["id"]
    tmp = tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", storage.get(manifest_key(file_id)))
        for index in range(record["block_count"]):
            zf.writestr(f"blocks/{index:06d}.enc", storage.get(block_key(file_id, index)))
    tmp.seek(0)
    return tmp


def restore_from_backup_zip(zip_path: str, master_key: bytes, out_path: str) -> str:
    """Offline restore used by restore_backup.py. Returns the SHA-256 (raises on failure)."""
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        file_id = manifest["file_id"]
        key = crypto.file_key(master_key, file_id)
        sha = hashlib.sha256()
        with open(out_path, "wb") as out:
            for index in range(manifest["block_count"]):
                plain = crypto.decrypt_block(key, file_id, index, zf.read(f"blocks/{index:06d}.enc"))
                sha.update(plain)
                out.write(plain)
    if sha.hexdigest() != manifest["sha256"]:
        raise ValueError("SHA-256 mismatch")
    return sha.hexdigest()
