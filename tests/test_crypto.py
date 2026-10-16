import io

import pytest

from logvault import crypto


def test_split_blocks_sizes():
    blocks = list(crypto.split_blocks(io.BytesIO(b"a" * 2500), 1000))
    assert [len(b) for b in blocks] == [1000, 1000, 500]


def test_default_block_size_is_1mb():
    from logvault.config import BLOCK_SIZE
    assert BLOCK_SIZE == 1024 * 1024


def test_roundtrip_and_unique_nonces():
    key = crypto.file_key(b"k" * 32, "f1")
    a = crypto.encrypt_block(key, "f1", 0, b"hello")
    b = crypto.encrypt_block(key, "f1", 0, b"hello")
    assert a != b and a[:12] != b[:12]  # fresh nonce every time
    assert crypto.decrypt_block(key, "f1", 0, a) == b"hello"


def test_tamper_detected():
    key = crypto.file_key(b"k" * 32, "f1")
    blob = bytearray(crypto.encrypt_block(key, "f1", 0, b"hello"))
    blob[-1] ^= 1
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_block(key, "f1", 0, bytes(blob))


def test_block_cannot_be_moved_to_other_position():
    key = crypto.file_key(b"k" * 32, "f1")
    blob = crypto.encrypt_block(key, "f1", 0, b"hello")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_block(key, "f1", 1, blob)


def test_wrong_key_fails():
    blob = crypto.encrypt_block(crypto.file_key(b"a" * 32, "f"), "f", 0, b"x")
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_block(crypto.file_key(b"b" * 32, "f"), "f", 0, blob)
