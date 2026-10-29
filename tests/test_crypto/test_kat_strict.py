"""Known-answer tests for the strict Ed25519 verifier."""

from __future__ import annotations

from typing import Any

from rine._crypto.ed25519_strict import verify_ed25519_strict
from tests.test_crypto.kat import load_kat


def _strict_vectors() -> dict[str, Any]:
    """Return the fixture's ``signatures.ed25519_strict`` section."""
    return load_kat()["signatures"]["ed25519_strict"]


class TestStrictControl:
    """The control signature is accepted."""

    def test_control_accepts(self) -> None:
        """The fixture's control signature verifies."""
        control = _strict_vectors()["control"]
        assert (
            verify_ed25519_strict(
                bytes.fromhex(control["public_key"]),
                bytes.fromhex(control["message"]),
                bytes.fromhex(control["signature"]),
            )
            is True
        )


class TestStrictNegatives:
    """Every strict negative is refused."""

    def test_every_negative_is_refused(self) -> None:
        """Each negative vector returns ``False``."""
        for entry in _strict_vectors()["negatives"]:
            assert entry["expect"] == "refuse"
            assert (
                verify_ed25519_strict(
                    bytes.fromhex(entry["public_key"]),
                    bytes.fromhex(entry["message"]),
                    bytes.fromhex(entry["signature"]),
                )
                is False
            ), entry["name"]


class TestStrictLengths:
    """A wrong key or signature length is refused without raising."""

    def test_wrong_public_key_length_is_refused(self) -> None:
        """A public key that is not 32 bytes returns ``False``."""
        control = _strict_vectors()["control"]
        signature = bytes.fromhex(control["signature"])
        message = bytes.fromhex(control["message"])
        assert verify_ed25519_strict(b"", message, signature) is False
        assert verify_ed25519_strict(b"\x00" * 31, message, signature) is False
        assert verify_ed25519_strict(b"\x00" * 33, message, signature) is False

    def test_wrong_signature_length_is_refused(self) -> None:
        """A signature that is not 64 bytes returns ``False``."""
        control = _strict_vectors()["control"]
        public_key = bytes.fromhex(control["public_key"])
        message = bytes.fromhex(control["message"])
        assert verify_ed25519_strict(public_key, message, b"") is False
        assert verify_ed25519_strict(public_key, message, b"\x00" * 63) is False
        assert verify_ed25519_strict(public_key, message, b"\x00" * 65) is False


def test_ml_kem_modulus_is_not_this_module_s_concern() -> None:
    """The ML-KEM modulus vectors belong to the post-quantum lane, not here."""
    assert "ml_kem_modulus" in load_kat()["signatures"]
