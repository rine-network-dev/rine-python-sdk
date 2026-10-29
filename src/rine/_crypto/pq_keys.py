"""The agent's post-quantum keys: the ML-KEM seed on disk, and both public keys as JWK wrappers.

ML-KEM-768 and ML-DSA-65 have no standard JWK binding, so rine publishes its
own ``{"kty", "alg", "x"}`` wrapper and the server validates it structurally.

On disk the agent keeps only the 64-byte ML-KEM seed ``d || z`` at
``keys/{agent_id}/pq_encryption.key`` (base64url, 0600), exactly where and how
the TypeScript stack writes it; the 2400-byte decapsulation key is expanded from
it on load. No ML-DSA private key is ever stored: the signing half is re-derived
from the org root when it is needed.
"""

from __future__ import annotations

import os

from rine._config import UPGRADE_DETAIL, _write_atomic, keys_dir
from rine._crypto import _mldsa, _mlkem
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

PQ_KEY_FILENAME = "pq_encryption.key"

#: The retired client_secret sign-in left a 2400-byte expanded key in this file.
#: A loader that finds one refuses it with the upgrade detail; there is no
#: dual-format reader.
RETIRED_PQ_KEY_SIZE = _mlkem.PRIVATE_KEY_SIZE

KEM_JWK_KTY = "MLKEM"
KEM_JWK_ALG = "ML-KEM-768"
DSA_JWK_KTY = "MLDSA"
DSA_JWK_ALG = "ML-DSA-65"


def _to_jwk(kty: str, alg: str, public_key: bytes) -> dict[str, str]:
    return {"kty": kty, "alg": alg, "x": to_base64url(public_key)}


def _from_jwk(jwk: dict[str, str], kty: str, alg: str, size: int, label: str) -> bytes:
    if jwk.get("kty") != kty or jwk.get("alg") != alg:
        raise CryptoError(f"{label} wrapper must be kty={kty}, alg={alg}")
    x = jwk.get("x")
    if not x:
        raise CryptoError(f"{label} wrapper missing 'x' field")
    key_bytes = from_base64url(x)
    if len(key_bytes) != size:
        raise CryptoError(f"Invalid {label}: expected {size} bytes, got {len(key_bytes)}")
    return key_bytes


def pq_public_key_to_jwk(public_key: bytes) -> dict[str, str]:
    """Export an ML-KEM-768 public key in rine's published wrapper.

    Args:
        public_key: 1184-byte ML-KEM-768 public key.

    Returns:
        Dict with ``kty``, ``alg`` and ``x`` fields.
    """
    return _to_jwk(KEM_JWK_KTY, KEM_JWK_ALG, public_key)


def jwk_to_pq_public_key(jwk: dict[str, str]) -> bytes:
    """Read an ML-KEM-768 public key out of rine's published wrapper.

    Args:
        jwk: Dict with ``kty``, ``alg`` and an ``x`` field (base64url-encoded).

    Returns:
        1184-byte ML-KEM-768 public key.

    Raises:
        CryptoError: If the wrapper is malformed or the key is the wrong size.
    """
    return _from_jwk(jwk, KEM_JWK_KTY, KEM_JWK_ALG, _mlkem.PUBLIC_KEY_SIZE, "PQ public key")


def pq_signing_public_key_to_jwk(public_key: bytes) -> dict[str, str]:
    """Export an ML-DSA-65 public key in rine's published wrapper.

    Args:
        public_key: 1952-byte ML-DSA-65 public key.

    Returns:
        Dict with ``kty``, ``alg`` and ``x`` fields.
    """
    return _to_jwk(DSA_JWK_KTY, DSA_JWK_ALG, public_key)


def jwk_to_pq_signing_public_key(jwk: dict[str, str]) -> bytes:
    """Read an ML-DSA-65 public key out of rine's published wrapper.

    Args:
        jwk: Dict with ``kty``, ``alg`` and an ``x`` field (base64url-encoded).

    Returns:
        1952-byte ML-DSA-65 public key.

    Raises:
        CryptoError: If the wrapper is malformed or the key is the wrong size.
    """
    return _from_jwk(
        jwk, DSA_JWK_KTY, DSA_JWK_ALG, _mldsa.PUBLIC_KEY_SIZE, "PQ signing public key"
    )


def pq_key_path(config_dir: str, agent_id: str) -> str:
    """Path of an agent's ML-KEM-768 seed file."""
    return os.path.join(keys_dir(config_dir, agent_id), PQ_KEY_FILENAME)


def save_pq_key(config_dir: str, agent_id: str, seed: bytes) -> None:
    """Persist an agent's 64-byte ML-KEM-768 seed.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        seed: 64-byte seed ``d || z``.
    """
    _write_atomic(pq_key_path(config_dir, agent_id), to_base64url(seed))


def load_pq_key(config_dir: str, agent_id: str) -> tuple[bytes, bytes, bytes]:
    """Load an agent's ML-KEM-768 key and expand it from its seed.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        A ``(seed, private_key, public_key)`` triple of 64, 2400 and 1184 bytes.

    Raises:
        CryptoError: If the file is missing or corrupt, the wrong size, or the
            retired 2400-byte format (which carries the upgrade detail).
    """
    path = pq_key_path(config_dir, agent_id)
    try:
        with open(path) as f:
            seed = from_base64url(f.read().strip())
    except FileNotFoundError:
        raise CryptoError(f"Key file not found: {path}. Regenerate keys.") from None
    except Exception as exc:
        raise CryptoError(f"Corrupt PQ key file: {path}. {exc}") from exc

    if len(seed) == RETIRED_PQ_KEY_SIZE:
        raise CryptoError(UPGRADE_DETAIL)
    if len(seed) != _mlkem.SEED_SIZE:
        raise CryptoError(
            f"Invalid PQ key size in {path}: expected {_mlkem.SEED_SIZE}, got {len(seed)}"
        )
    public_key, private_key = _mlkem.key_pair_from_seed(seed)
    return seed, private_key, public_key
