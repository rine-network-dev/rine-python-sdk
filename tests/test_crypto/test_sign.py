"""Tests for Ed25519 signing and verification."""

from __future__ import annotations

from rine._crypto.keys import generate_signing_keypair
from rine._crypto.sign import sign_payload, verify_signature


class TestSignVerify:
    def test_sign_produces_64_bytes(self):
        kp = generate_signing_keypair()
        sig = sign_payload(kp.private_key, b"test message")
        assert len(sig) == 64

    def test_verify_valid_signature(self):
        kp = generate_signing_keypair()
        msg = b"hello world"
        sig = sign_payload(kp.private_key, msg)
        assert verify_signature(kp.public_key, msg, sig) is True

    def test_verify_wrong_message_returns_false(self):
        kp = generate_signing_keypair()
        sig = sign_payload(kp.private_key, b"correct message")
        assert verify_signature(kp.public_key, b"wrong message", sig) is False

    def test_verify_wrong_key_returns_false(self):
        kp1 = generate_signing_keypair()
        kp2 = generate_signing_keypair()
        sig = sign_payload(kp1.private_key, b"test")
        assert verify_signature(kp2.public_key, b"test", sig) is False

    def test_verify_corrupt_signature_returns_false(self):
        kp = generate_signing_keypair()
        sig = sign_payload(kp.private_key, b"test")
        corrupt = bytearray(sig)
        corrupt[0] ^= 0xFF
        assert verify_signature(kp.public_key, b"test", bytes(corrupt)) is False

    def test_verify_never_raises(self):
        """verify_signature should return False, never raise."""
        kp = generate_signing_keypair()
        assert verify_signature(kp.public_key, b"test", b"too-short") is False
        assert verify_signature(b"bad-key", b"test", b"x" * 64) is False
