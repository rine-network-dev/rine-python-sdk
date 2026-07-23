"""``hpke-hybrid-v1``: the post-quantum 1:1 DM envelope.

X25519 and ML-KEM-768 in parallel, their shared secrets combined with
HKDF-SHA256 into one AES-256-GCM key. Hybrid means an attacker has to break
*both*: X25519 today, or ML-KEM-768 once a quantum computer exists — so a DM
harvested now is not decryptable later by breaking only one of them.

Wire format, byte-for-byte the same as the TypeScript stack's
``rine-core/src/crypto/hybrid.ts``::

    [1 byte: version 0x03]
    [32 bytes: ephemeral X25519 public key]
    [1088 bytes: ML-KEM-768 ciphertext]
    [remaining: AES-256-GCM ciphertext + 16-byte auth tag]

The AEAD nonce is twelve zero bytes and is not on the wire. That is safe here
and only here: both halves of the key exchange are freshly randomized per
message, so the derived key is used exactly once and can never repeat under a
fixed nonce.

The ML-KEM half comes from the ``rine-mls`` wheel — the same post-quantum
implementation the MLS group ciphersuite runs on.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rine._crypto import _mlkem
from rine.errors import CryptoError

VERSION_HYBRID = 0x03
X25519_ENC_SIZE = 32
AES_KEY_SIZE = 32
HKDF_INFO = b"rine.e2ee.v1.hpke-hybrid"

_GCM_NONCE = b"\x00" * 12
_HEADER_SIZE = 1 + X25519_ENC_SIZE + _mlkem.CIPHERTEXT_SIZE


def _combine_secrets(x25519_shared: bytes, mlkem_shared: bytes) -> bytes:
    """HKDF-SHA256 over the two shared secrets, classical half first.

    The concatenation order and the ``info`` string are both wire format: swap
    either and the two stacks derive different keys.
    """
    return HKDF(algorithm=SHA256(), length=AES_KEY_SIZE, salt=None, info=HKDF_INFO).derive(
        x25519_shared + mlkem_shared
    )


def seal(
    recipient_x25519_pk: bytes,
    recipient_mlkem_pk: bytes,
    inner_envelope: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Encrypt an inner envelope to a recipient's classical + PQ public keys.

    Args:
        recipient_x25519_pk: Recipient's 32-byte X25519 public key.
        recipient_mlkem_pk: Recipient's 1184-byte ML-KEM-768 public key.
        inner_envelope: Plaintext inner envelope bytes.
        aad: Optional additional authenticated data.

    Returns:
        Encrypted payload: ``[0x03][32B enc][1088B ML-KEM ct][ciphertext+tag]``.

    Raises:
        CryptoError: If either recipient key is malformed, or encryption fails.
    """
    try:
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes_raw()
        x25519_shared = eph_sk.exchange(X25519PublicKey.from_public_bytes(recipient_x25519_pk))
        mlkem_ct, mlkem_shared = _mlkem.encapsulate(recipient_mlkem_pk)

        key = _combine_secrets(x25519_shared, mlkem_shared)
        ciphertext = AESGCM(key).encrypt(_GCM_NONCE, inner_envelope, aad)
    except Exception as exc:
        raise CryptoError(f"hpke-hybrid-v1 seal failed: {exc}") from exc

    return bytes([VERSION_HYBRID]) + eph_pk + mlkem_ct + ciphertext


def open(  # noqa: A001 - mirrors `hpke.open`, the classical counterpart
    recipient_x25519_sk: bytes,
    recipient_mlkem_sk: bytes,
    encrypted_payload: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt an ``hpke-hybrid-v1`` payload.

    Args:
        recipient_x25519_sk: Recipient's 32-byte X25519 private key.
        recipient_mlkem_sk: Recipient's 2400-byte ML-KEM-768 private key.
        encrypted_payload: Encrypted bytes from :func:`seal`.
        aad: Optional additional authenticated data (must match the seal).

    Returns:
        Decrypted inner envelope bytes.

    Raises:
        CryptoError: If the payload is malformed, or decryption fails.
    """
    if len(encrypted_payload) < _HEADER_SIZE + 1:
        raise CryptoError(
            f"hpke-hybrid-v1 payload too short: {len(encrypted_payload)} bytes "
            f"(min {_HEADER_SIZE + 1})"
        )
    version = encrypted_payload[0]
    if version != VERSION_HYBRID:
        raise CryptoError(
            f"Unknown hybrid version: 0x{version:02x} (expected 0x{VERSION_HYBRID:02x})"
        )

    if len(recipient_mlkem_sk) != _mlkem.PRIVATE_KEY_SIZE:
        raise CryptoError(
            f"ML-KEM-768 private key must be {_mlkem.PRIVATE_KEY_SIZE} bytes, "
            f"got {len(recipient_mlkem_sk)}"
        )

    eph_pk = encrypted_payload[1 : 1 + X25519_ENC_SIZE]
    mlkem_ct = encrypted_payload[1 + X25519_ENC_SIZE : _HEADER_SIZE]
    ciphertext = encrypted_payload[_HEADER_SIZE:]

    try:
        recipient_sk = X25519PrivateKey.from_private_bytes(recipient_x25519_sk)
        x25519_shared = recipient_sk.exchange(X25519PublicKey.from_public_bytes(eph_pk))
        mlkem_shared = _mlkem.decapsulate(mlkem_ct, recipient_mlkem_sk)

        key = _combine_secrets(x25519_shared, mlkem_shared)
        return AESGCM(key).decrypt(_GCM_NONCE, ciphertext, aad)
    except Exception as exc:
        raise CryptoError(
            f"hpke-hybrid-v1 decryption failed — wrong recipient key? {exc}"
        ) from exc
