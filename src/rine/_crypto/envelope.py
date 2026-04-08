"""Inner envelope binary format: KID + Ed25519 signature + payload.

Wire format::

    [1 byte: kid_len]
    [kid_len bytes: UTF-8 key ID]
    [64 bytes: Ed25519 signature]
    [remaining: payload bytes]
"""

from __future__ import annotations

from dataclasses import dataclass

from rine.errors import CryptoError

SIGNATURE_SIZE = 64
MAX_KID_LENGTH = 255


@dataclass
class InnerEnvelope:
    """Decoded inner envelope."""

    kid: str
    signature: bytes
    payload: bytes


def encode_envelope(kid: str, signature: bytes, payload: bytes) -> bytes:
    """Encode an inner envelope.

    Args:
        kid: Key ID string (max 255 UTF-8 bytes).
        signature: 64-byte Ed25519 signature.
        payload: Plaintext payload bytes.

    Returns:
        Encoded envelope bytes.

    Raises:
        CryptoError: If KID too long or signature wrong size.
    """
    kid_bytes = kid.encode("utf-8")
    if len(kid_bytes) > MAX_KID_LENGTH:
        raise CryptoError(
            f"KID too long: {len(kid_bytes)} bytes (max {MAX_KID_LENGTH})"
        )
    if len(signature) != SIGNATURE_SIZE:
        raise CryptoError(
            f"Signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}"
        )

    return bytes([len(kid_bytes)]) + kid_bytes + signature + payload


def decode_envelope(data: bytes) -> InnerEnvelope:
    """Decode an inner envelope.

    Args:
        data: Raw envelope bytes.

    Returns:
        Decoded InnerEnvelope with kid, signature, and payload.

    Raises:
        CryptoError: If data is too short or malformed.
    """
    if len(data) < 1:
        raise CryptoError("Envelope too short: empty data")

    kid_len = data[0]
    min_len = 1 + kid_len + SIGNATURE_SIZE
    if len(data) < min_len:
        raise CryptoError(
            f"Envelope too short: {len(data)} bytes, need at least {min_len}"
        )

    try:
        kid = data[1 : 1 + kid_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError(f"Invalid UTF-8 in KID: {exc}") from exc

    sig_start = 1 + kid_len
    signature = bytes(data[sig_start : sig_start + SIGNATURE_SIZE])
    payload = bytes(data[sig_start + SIGNATURE_SIZE :])

    return InnerEnvelope(kid=kid, signature=signature, payload=payload)
