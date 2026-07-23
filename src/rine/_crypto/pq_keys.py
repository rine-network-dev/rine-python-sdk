"""The agent's ML-KEM-768 key: on disk, and on the wire as a JWK.

Kept apart from :mod:`rine._crypto.keys` because a PQ key is optional in a way
the Ed25519 and X25519 keys are not — an agent onboarded before rine published
one has none, reads classical DMs perfectly well, and gains a PQ key the next
time its keys are minted or rotated.

The private key is the full 2400-byte FIPS 203 encoding, base64url at
``keys/{agent_id}/pq_encryption.key`` with 0600 permissions, exactly where and
how the TypeScript stack writes it — one config directory serves both.
"""

from __future__ import annotations

import os

from rine._config import _write_atomic, keys_dir
from rine._crypto import _mlkem
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

PQ_KEY_FILENAME = "pq_encryption.key"

#: The published form. Not an OKP JWK — ML-KEM has no standard JWK binding, so
#: this is rine's own wrapper and the server validates it structurally.
PQ_JWK_KTY = "MLKEM"
PQ_JWK_ALG = "ML-KEM-768"


def pq_public_key_to_jwk(public_key: bytes) -> dict[str, str]:
    """Export an ML-KEM-768 public key in rine's published wrapper.

    Args:
        public_key: 1184-byte ML-KEM-768 public key.

    Returns:
        Dict with ``kty``, ``alg`` and ``x`` fields.
    """
    return {"kty": PQ_JWK_KTY, "alg": PQ_JWK_ALG, "x": to_base64url(public_key)}


def jwk_to_pq_public_key(jwk: dict[str, str]) -> bytes:
    """Read an ML-KEM-768 public key out of rine's published wrapper.

    Args:
        jwk: Dict with an ``x`` field (base64url-encoded).

    Returns:
        1184-byte ML-KEM-768 public key.

    Raises:
        CryptoError: If the wrapper is malformed or the key is the wrong size.
    """
    x = jwk.get("x")
    if not x:
        raise CryptoError("PQ key wrapper missing 'x' field")
    key_bytes = from_base64url(x)
    if len(key_bytes) != _mlkem.PUBLIC_KEY_SIZE:
        raise CryptoError(
            f"Invalid PQ public key: expected {_mlkem.PUBLIC_KEY_SIZE} bytes, "
            f"got {len(key_bytes)}"
        )
    return key_bytes


def generate_pq_keypair() -> tuple[bytes, bytes]:
    """Mint an ML-KEM-768 key pair.

    Returns:
        A ``(private_key, public_key)`` pair of 2400 and 1184 bytes.
    """
    public_key, private_key = _mlkem.generate_key_pair()
    return private_key, public_key


def pq_key_path(config_dir: str, agent_id: str) -> str:
    """Path of an agent's ML-KEM-768 private key file."""
    return os.path.join(keys_dir(config_dir, agent_id), PQ_KEY_FILENAME)


def save_pq_key(config_dir: str, agent_id: str, private_key: bytes) -> None:
    """Persist an agent's ML-KEM-768 private key.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        private_key: 2400-byte ML-KEM-768 private key.
    """
    _write_atomic(pq_key_path(config_dir, agent_id), to_base64url(private_key))


def load_pq_key(config_dir: str, agent_id: str) -> tuple[bytes, bytes] | None:
    """Load an agent's ML-KEM-768 key pair if it has one.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        A ``(private_key, public_key)`` pair, or ``None`` when the agent
        predates PQ keys and has no key file.

    Raises:
        CryptoError: If the file exists but is corrupt or the wrong size — a
            present-but-unusable key is an error, never a silent downgrade to
            classical.
    """
    path = pq_key_path(config_dir, agent_id)
    try:
        with open(path) as f:
            private_key = from_base64url(f.read().strip())
    except FileNotFoundError:
        return None
    except Exception as exc:
        raise CryptoError(f"Corrupt PQ key file: {path}. {exc}") from exc

    if len(private_key) != _mlkem.PRIVATE_KEY_SIZE:
        raise CryptoError(
            f"Invalid PQ key size in {path}: expected {_mlkem.PRIVATE_KEY_SIZE}, "
            f"got {len(private_key)}"
        )
    try:
        return private_key, _mlkem.public_key(private_key)
    except _mlkem.MlKemError as exc:
        raise CryptoError(f"Corrupt PQ key file: {path}. {exc}") from exc
