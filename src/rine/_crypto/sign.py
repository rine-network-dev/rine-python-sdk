"""Ed25519 signing and verification.

Signs and verifies raw plaintext payloads — no hash prefix or encoding.
Produces 64-byte signatures compatible with rine-core's ``@noble/curves``.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from rine._logging import logger


def sign_payload(private_key: bytes, plaintext: bytes) -> bytes:
    """Sign a plaintext payload with Ed25519.

    Args:
        private_key: 32-byte Ed25519 private seed.
        plaintext: Raw bytes to sign.

    Returns:
        64-byte Ed25519 signature.
    """
    sk = Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.sign(plaintext)


def verify_signature(public_key: bytes, plaintext: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Never raises on verification failure — returns ``False`` instead.

    Args:
        public_key: 32-byte Ed25519 public key.
        plaintext: The original signed data.
        signature: 64-byte signature to verify.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        pk.verify(signature, plaintext)
        return True
    except InvalidSignature:
        logger.debug("Signature verification failed: invalid signature")
        return False
    except (ValueError, TypeError):
        # Bad public key bytes or wrong types
        logger.debug("Signature verification failed: bad key format", exc_info=True)
        return False
