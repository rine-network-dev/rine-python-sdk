"""Strict Ed25519 verification: RFC 8032 with every malleability refusal explicit.

OpenSSL enforces the cofactorless RFC 8032 equation and a canonical ``S``, but it
decodes ``x = 0`` with the sign bit set as the identity or the order-2 point, so
a lax decode leaves a universal forgery under such a key. This module decodes the
public key and ``R`` itself, so the verdict matches the server and the TypeScript
client byte for byte: canonical field encodings, points that decode, no
small-order key or ``R``, and ``S < L``. The point arithmetic mirrors
``src/rine/auth/ed25519_strict.py`` in the server (two packages own the ``rine``
import name, so it cannot be shared); the golden vectors in ``org-root-v1.json``
are the guard that keeps the two copies equal.
"""

from __future__ import annotations

from typing import TypeAlias

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_KEY_LEN = 32
_SIG_LEN = 64

_Point: TypeAlias = tuple[int, int]  # noqa: UP040 (`type` statements need Python 3.12)
_IDENTITY: _Point = (0, 1)


def _decode_point(encoded: bytes) -> _Point | None:
    """Decode a canonical compressed Edwards point, or None if it is not one."""
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = (u * pow(v, -1, _P)) % _P
    x = pow(x, (_P + 3) // 8, _P)
    if (v * x * x - u) % _P:
        x = (x * _SQRT_M1) % _P
    if (v * x * x - u) % _P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return x, y


def _add(a: _Point, b: _Point) -> _Point:
    (x1, y1), (x2, y2) = a, b
    t = (_D * x1 * x2 * y1 * y2) % _P
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + t, -1, _P)) % _P
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - t, -1, _P)) % _P
    return x3, y3


def _is_small_order(point: _Point) -> bool:
    for _ in range(3):
        point = _add(point, point)
    return point == _IDENTITY


def _usable_point(encoded: bytes) -> bool:
    point = _decode_point(encoded)
    return point is not None and not _is_small_order(point)


def is_valid_public_key(public_key: bytes) -> bool:
    """Return whether ``public_key`` is a canonical, decodable, non-small-order point."""
    return len(public_key) == _KEY_LEN and _usable_point(public_key)


def verify_ed25519_strict(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature under the strict profile.

    Never raises on a bad key or signature: a malformed input, a small-order or
    non-canonical key or ``R``, a non-canonical ``S`` and a signature OpenSSL
    refuses all come back as ``False``.

    Args:
        public_key: 32-byte Ed25519 public key.
        message: The signed message.
        signature: 64-byte Ed25519 signature.

    Returns:
        ``True`` only when the signature is valid and every strict refusal
        passes.
    """
    if len(signature) != _SIG_LEN or not is_valid_public_key(public_key):
        return False
    if int.from_bytes(signature[32:], "little") >= _L or not _usable_point(signature[:32]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
