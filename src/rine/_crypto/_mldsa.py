"""The ML-DSA-65 half of the ``rine-mls`` wheel: public keys from seeds, nothing else.

This SDK never stores or uses an ML-DSA private key. The 32-byte seed ``xi``
exists only to derive the public key that the org id and the certificates
commit to, so the wheel's seed-to-public-key export is the whole surface.
Like :mod:`rine._crypto._mlkem`, the module is a thin owner of one slice of the
wheel so a change in the wheel's shape lands in one file.
"""

from __future__ import annotations

from rine.errors import CryptoError

try:
    import rine_mls
except ImportError as exc:  # pragma: no cover - depends on the install platform
    raise CryptoError(
        "rine's post-quantum signing keys need the `rine-mls` wheel, which is not "
        "importable. Install `rine-mls` for this platform (linux x64/arm64 "
        "glibc+musl, macOS arm64/x64; Windows is not published yet)."
    ) from exc

SEED_SIZE: int = rine_mls.ML_DSA65_SEED_SIZE
PUBLIC_KEY_SIZE: int = rine_mls.ML_DSA65_PUBLIC_KEY_SIZE

#: Raised by the wheel for a malformed seed.
MlDsaError = rine_mls.MlDsaError

public_key_from_seed = rine_mls.ml_dsa65_public_key_from_seed

__all__ = ["PUBLIC_KEY_SIZE", "SEED_SIZE", "MlDsaError", "public_key_from_seed"]
