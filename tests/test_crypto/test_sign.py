"""Tests for Ed25519 signing and verification."""

from __future__ import annotations

from rine._crypto.sign import MessageSig, sign_message, verify_message_signature
from rine.testing import WORLD

SIGNER_ID = "11111111-1111-1111-1111-111111111111"
RECIPIENT_ID = "22222222-2222-2222-2222-222222222222"


class TestSignVerify:
    def test_sign_produces_64_bytes(self):
        kp = WORLD.keys(SIGNER_ID).signing
        sig = sign_message(kp.private_key, MessageSig(RECIPIENT_ID), b"test message")
        assert len(sig) == 64

    def test_verify_valid_signature(self):
        kp = WORLD.keys(SIGNER_ID).signing
        msg = b"hello world"
        sig = sign_message(kp.private_key, MessageSig(RECIPIENT_ID), msg)
        assert verify_message_signature(kp.public_key, MessageSig(RECIPIENT_ID), msg, sig) is True

    def test_verify_wrong_message_returns_false(self):
        kp = WORLD.keys(SIGNER_ID).signing
        sig = sign_message(kp.private_key, MessageSig(RECIPIENT_ID), b"correct message")
        assert (
            verify_message_signature(
                kp.public_key, MessageSig(RECIPIENT_ID), b"wrong message", sig
            )
            is False
        )

    def test_verify_wrong_key_returns_false(self):
        kp1 = WORLD.keys(SIGNER_ID).signing
        kp2 = WORLD.keys(RECIPIENT_ID).signing
        sig = sign_message(kp1.private_key, MessageSig(RECIPIENT_ID), b"test")
        assert (
            verify_message_signature(kp2.public_key, MessageSig(RECIPIENT_ID), b"test", sig)
            is False
        )

    def test_verify_corrupt_signature_returns_false(self):
        kp = WORLD.keys(SIGNER_ID).signing
        sig = sign_message(kp.private_key, MessageSig(RECIPIENT_ID), b"test")
        corrupt = bytearray(sig)
        corrupt[0] ^= 0xFF
        assert (
            verify_message_signature(
                kp.public_key, MessageSig(RECIPIENT_ID), b"test", bytes(corrupt)
            )
            is False
        )

    def test_verify_never_raises(self):
        """verify_message_signature should return False, never raise."""
        kp = WORLD.keys(SIGNER_ID).signing
        scope = MessageSig(RECIPIENT_ID)
        assert verify_message_signature(kp.public_key, scope, b"test", b"too-short") is False
        assert verify_message_signature(b"bad-key", scope, b"test", b"x" * 64) is False
