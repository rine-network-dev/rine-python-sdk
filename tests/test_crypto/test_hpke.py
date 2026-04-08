"""Tests for HPKE seal/open — RFC 9180 Base mode."""

from __future__ import annotations

import pytest

from rine._crypto.hpke import VERSION_HPKE, open, seal
from rine._crypto.keys import generate_encryption_keypair
from rine.errors import CryptoError


class TestHPKE:
    def test_seal_open_round_trip(self):
        kp = generate_encryption_keypair()
        plaintext = b"hello, encrypted world!"
        ct = seal(kp.public_key, plaintext)
        recovered = open(kp.private_key, ct)
        assert recovered == plaintext

    def test_wire_format_version_byte(self):
        kp = generate_encryption_keypair()
        ct = seal(kp.public_key, b"test")
        assert ct[0] == VERSION_HPKE

    def test_wire_format_includes_ephemeral_key(self):
        kp = generate_encryption_keypair()
        ct = seal(kp.public_key, b"test")
        # version (1) + ephemeral pk (32) + ciphertext (>= 1 + 16 tag)
        assert len(ct) >= 1 + 32 + 17

    def test_different_ephemeral_keys_each_call(self):
        kp = generate_encryption_keypair()
        ct1 = seal(kp.public_key, b"same data")
        ct2 = seal(kp.public_key, b"same data")
        # Ephemeral keys differ → ciphertext differs
        assert ct1 != ct2
        # But both decrypt to same plaintext
        assert open(kp.private_key, ct1) == open(kp.private_key, ct2)

    def test_wrong_key_raises(self):
        kp1 = generate_encryption_keypair()
        kp2 = generate_encryption_keypair()
        ct = seal(kp1.public_key, b"secret")
        with pytest.raises(CryptoError, match="wrong recipient key"):
            open(kp2.private_key, ct)

    def test_payload_too_short_raises(self):
        kp = generate_encryption_keypair()
        with pytest.raises(CryptoError, match="too short"):
            open(kp.private_key, b"\x01")

    def test_unknown_version_raises(self):
        kp = generate_encryption_keypair()
        ct = seal(kp.public_key, b"test")
        tampered = bytes([0xFF]) + ct[1:]
        with pytest.raises(CryptoError, match="Unknown HPKE version"):
            open(kp.private_key, tampered)

    def test_tampered_ciphertext_raises(self):
        kp = generate_encryption_keypair()
        ct = seal(kp.public_key, b"test")
        tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with pytest.raises(CryptoError):
            open(kp.private_key, tampered)

    def test_with_aad(self):
        kp = generate_encryption_keypair()
        aad = b"context data"
        ct = seal(kp.public_key, b"payload", aad=aad)
        recovered = open(kp.private_key, ct, aad=aad)
        assert recovered == b"payload"

    def test_wrong_aad_raises(self):
        kp = generate_encryption_keypair()
        ct = seal(kp.public_key, b"payload", aad=b"correct")
        with pytest.raises(CryptoError):
            open(kp.private_key, ct, aad=b"wrong")

    def test_large_payload(self):
        kp = generate_encryption_keypair()
        large = b"A" * 100_000
        ct = seal(kp.public_key, large)
        assert open(kp.private_key, ct) == large

    def test_empty_payload(self):
        kp = generate_encryption_keypair()
        ct = seal(kp.public_key, b"")
        assert open(kp.private_key, ct) == b""
