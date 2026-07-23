"""The ML-KEM-768 half of the ``rine-mls`` wheel.

The wheel has two surfaces and each has exactly one owner in this SDK:
``rine._mls.binding`` owns the MLS group surface, and this module owns the raw
post-quantum primitives the 1:1 ``hpke-hybrid-v1`` DM envelope is built from.
They are separate files rather than one because ``rine._mls`` pulls in the whole
group stack on import, and the DM path must not.

Groups and DMs going through the same wheel is the point: one post-quantum
implementation, audited and updated once, instead of two that happen to agree
today. ``rine._crypto.hybrid`` is this module's only consumer — it owns the wire
format and turns these failures into ``CryptoError``.

Encodings are FIPS 203's, which is what the TypeScript stack's
``@noble/post-quantum`` also produces, so a key or ciphertext from either stack
is readable by the other.
"""

from __future__ import annotations

from rine.errors import CryptoError

try:
    import rine_mls
except ImportError as exc:  # pragma: no cover - depends on the install platform
    raise CryptoError(
        "rine's post-quantum encryption needs the `rine-mls` wheel, which is not "
        "importable. Install `rine-mls` for this platform (linux x64/arm64 "
        "glibc+musl, macOS arm64/x64; Windows is not published yet)."
    ) from exc

PUBLIC_KEY_SIZE: int = rine_mls.ML_KEM768_PUBLIC_KEY_SIZE
PRIVATE_KEY_SIZE: int = rine_mls.ML_KEM768_PRIVATE_KEY_SIZE
CIPHERTEXT_SIZE: int = rine_mls.ML_KEM768_CIPHERTEXT_SIZE
SHARED_SECRET_SIZE: int = rine_mls.ML_KEM768_SHARED_SECRET_SIZE

#: Raised by the wheel for a malformed key or ciphertext. A subclass of the MLS
#: core's base error, so it carries a ``code`` like every other core failure.
MlKemError = rine_mls.MlKemError

generate_key_pair = rine_mls.ml_kem768_generate_key_pair
public_key = rine_mls.ml_kem768_public_key
encapsulate = rine_mls.ml_kem768_encapsulate
decapsulate = rine_mls.ml_kem768_decapsulate

__all__ = [
    "CIPHERTEXT_SIZE",
    "PRIVATE_KEY_SIZE",
    "PUBLIC_KEY_SIZE",
    "SHARED_SECRET_SIZE",
    "MlKemError",
    "decapsulate",
    "encapsulate",
    "generate_key_pair",
    "public_key",
]
