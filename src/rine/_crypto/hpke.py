"""HPKE Base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.

Implements RFC 9180 HPKE Base mode from ``cryptography`` primitives.
Wire-format compatible with rine-core's ``@hpke/core`` TypeScript implementation.

Wire format::

    [1 byte: version 0x01]
    [32 bytes: ephemeral X25519 public key (enc)]
    [remaining: AES-256-GCM ciphertext + 16-byte auth tag]

Note: no explicit nonce in the wire format — the nonce is derived from the
HPKE key schedule (base_nonce at sequence 0).
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from rine.errors import CryptoError

VERSION_HPKE = 0x01
ENC_SIZE = 32
INFO = b"rine.e2ee.v1.hpke"

# RFC 9180 identifiers
_KEM_ID = 0x0020  # DHKEM(X25519, HKDF-SHA256)
_KDF_ID = 0x0001  # HKDF-SHA256
_AEAD_ID = 0x0002  # AES-256-GCM

_KEM_SUITE_ID = b"KEM" + _KEM_ID.to_bytes(2, "big")
_HPKE_SUITE_ID = (
    b"HPKE"
    + _KEM_ID.to_bytes(2, "big")
    + _KDF_ID.to_bytes(2, "big")
    + _AEAD_ID.to_bytes(2, "big")
)

_N_SECRET = 32  # KEM shared secret length
_N_H = 32  # Hash output length (SHA-256)
_N_K = 32  # AEAD key length (AES-256)
_N_N = 12  # AEAD nonce length

_LABEL_VERSION = b"HPKE-v1"


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, ikm) per RFC 5869."""
    if not salt:
        salt = b"\x00" * _N_H
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand(prk, info, length) per RFC 5869."""
    return HKDFExpand(algorithm=SHA256(), length=length, info=info).derive(prk)


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    """RFC 9180 LabeledExtract."""
    labeled_ikm = _LABEL_VERSION + suite_id + label + ikm
    return _hkdf_extract(salt, labeled_ikm)


def _labeled_expand(
    suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    """RFC 9180 LabeledExpand."""
    labeled_info = length.to_bytes(2, "big") + _LABEL_VERSION + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    """KEM ExtractAndExpand per RFC 9180 Section 4.1."""
    eae_prk = _labeled_extract(_KEM_SUITE_ID, b"", b"eae_prk", dh)
    return _labeled_expand(_KEM_SUITE_ID, eae_prk, b"shared_secret", kem_context, _N_SECRET)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    """HPKE Base mode KeySchedule per RFC 9180 Section 5.1.

    Returns:
        Tuple of (aead_key, base_nonce).
    """
    mode = b"\x00"  # Base
    psk = b""
    psk_id = b""

    psk_id_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"psk_id_hash", psk_id)
    info_hash = _labeled_extract(_HPKE_SUITE_ID, b"", b"info_hash", info)
    ks_context = mode + psk_id_hash + info_hash

    secret = _labeled_extract(_HPKE_SUITE_ID, shared_secret, b"secret", psk)

    key = _labeled_expand(_HPKE_SUITE_ID, secret, b"key", ks_context, _N_K)
    base_nonce = _labeled_expand(
        _HPKE_SUITE_ID, secret, b"base_nonce", ks_context, _N_N
    )

    return key, base_nonce


def seal(
    recipient_public_key: bytes,
    inner_envelope: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Encrypt an inner envelope for a recipient using HPKE Base mode.

    Args:
        recipient_public_key: 32-byte X25519 public key.
        inner_envelope: Plaintext inner envelope bytes.
        aad: Optional additional authenticated data.

    Returns:
        Encrypted payload: ``[0x01][32B enc][ciphertext+tag]``.

    Raises:
        CryptoError: If encryption fails.
    """
    try:
        # Generate ephemeral keypair
        eph_sk = X25519PrivateKey.generate()
        eph_pk_bytes = eph_sk.public_key().public_bytes_raw()

        # DH: ephemeral private x recipient public
        recipient_pk = X25519PublicKey.from_public_bytes(recipient_public_key)
        dh = eph_sk.exchange(recipient_pk)

        # KEM: ExtractAndExpand
        kem_context = eph_pk_bytes + recipient_public_key
        shared_secret = _extract_and_expand(dh, kem_context)

        # Key schedule
        key, base_nonce = _key_schedule(shared_secret, INFO)

        # Encrypt (seq=0, so nonce = base_nonce)
        ciphertext = AESGCM(key).encrypt(base_nonce, inner_envelope, aad)

        return bytes([VERSION_HPKE]) + eph_pk_bytes + ciphertext
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(f"HPKE seal failed: {exc}") from exc


def open(
    recipient_private_key: bytes,
    encrypted_payload: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt an HPKE-encrypted payload.

    Args:
        recipient_private_key: 32-byte X25519 private key.
        encrypted_payload: Encrypted bytes from ``seal()``.
        aad: Optional additional authenticated data (must match seal).

    Returns:
        Decrypted inner envelope bytes.

    Raises:
        CryptoError: If decryption fails (wrong key, tampered data, etc.).
    """
    min_len = 1 + ENC_SIZE + 1
    if len(encrypted_payload) < min_len:
        raise CryptoError(
            f"HPKE payload too short: {len(encrypted_payload)} bytes (min {min_len})"
        )

    version = encrypted_payload[0]
    if version != VERSION_HPKE:
        raise CryptoError(
            f"Unknown HPKE version: 0x{version:02x} (expected 0x{VERSION_HPKE:02x})"
        )

    enc = encrypted_payload[1 : 1 + ENC_SIZE]
    ct = encrypted_payload[1 + ENC_SIZE :]

    try:
        # Recipient's keys
        recipient_sk = X25519PrivateKey.from_private_bytes(recipient_private_key)
        recipient_pk_bytes = recipient_sk.public_key().public_bytes_raw()

        # DH: recipient private x ephemeral public
        eph_pk = X25519PublicKey.from_public_bytes(enc)
        dh = recipient_sk.exchange(eph_pk)

        # KEM: ExtractAndExpand
        kem_context = enc + recipient_pk_bytes
        shared_secret = _extract_and_expand(dh, kem_context)

        # Key schedule
        key, base_nonce = _key_schedule(shared_secret, INFO)

        # Decrypt (seq=0)
        return AESGCM(key).decrypt(base_nonce, ct, aad)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError(
            f"HPKE decryption failed — wrong recipient key? {exc}"
        ) from exc
