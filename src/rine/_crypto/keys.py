"""Key generation, JWK serialization, and file persistence.

Generates Ed25519 (signing) + X25519 (encryption) keypairs, plus the ML-KEM-768
post-quantum encryption keypair that makes an agent reachable over
``hpke-hybrid-v1``. The two 32-byte private seeds are stored base64url at
``keys/{agent_id}/signing.key`` and ``encryption.key`` with 0o600 permissions;
the post-quantum key lives beside them and is owned by
:mod:`rine._crypto.pq_keys`.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rine._config import _ensure_dir, keys_dir
from rine._crypto.pq_keys import (
    generate_pq_keypair,
    load_pq_key,
    pq_public_key_to_jwk,
    save_pq_key,
)
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_KID_RE = re.compile(
    r"^rine:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I
)


@dataclass
class KeyPair:
    """A 32-byte private + 32-byte public key pair."""

    private_key: bytes = field(repr=False)
    public_key: bytes


@dataclass
class AgentKeys:
    """Signing + encryption key pairs for an agent.

    ``pq_encryption`` is the agent's ML-KEM-768 key, present for every agent
    onboarded since rine published post-quantum DM keys and absent for older
    ones. Its presence is what decides whether a peer seals ``hpke-hybrid-v1``
    to this agent, and whether this agent self-seals its own sends the same way.
    """

    signing: KeyPair
    encryption: KeyPair
    pq_encryption: KeyPair | None = None


def generate_signing_keypair() -> KeyPair:
    """Generate an Ed25519 signing keypair.

    Returns:
        KeyPair with 32-byte private seed and 32-byte public key.
    """
    sk = Ed25519PrivateKey.generate()
    private_bytes = sk.private_bytes_raw()
    public_bytes = sk.public_key().public_bytes_raw()
    return KeyPair(private_key=private_bytes, public_key=public_bytes)


def generate_encryption_keypair() -> KeyPair:
    """Generate an X25519 encryption keypair.

    Returns:
        KeyPair with 32-byte private key and 32-byte public key.
    """
    sk = X25519PrivateKey.generate()
    private_bytes = sk.private_bytes_raw()
    public_bytes = sk.public_key().public_bytes_raw()
    return KeyPair(private_key=private_bytes, public_key=public_bytes)


def generate_agent_keys() -> AgentKeys:
    """Generate every keypair an agent needs.

    Returns:
        AgentKeys containing Ed25519 signing, X25519 encryption and ML-KEM-768
        post-quantum encryption pairs. The PQ key is minted for every new agent,
        so a peer on either stack seals ``hpke-hybrid-v1`` to it from birth.
    """
    pq_private, pq_public = generate_pq_keypair()
    return AgentKeys(
        signing=generate_signing_keypair(),
        encryption=generate_encryption_keypair(),
        pq_encryption=KeyPair(private_key=pq_private, public_key=pq_public),
    )


def signing_public_key_to_jwk(public_key: bytes) -> dict[str, str]:
    """Export an Ed25519 public key as JWK.

    Args:
        public_key: 32-byte Ed25519 public key.

    Returns:
        JWK dict with ``kty``, ``crv``, ``x`` fields.
    """
    return {"kty": "OKP", "crv": "Ed25519", "x": to_base64url(public_key)}


def encryption_public_key_to_jwk(public_key: bytes) -> dict[str, str]:
    """Export an X25519 public key as JWK.

    Args:
        public_key: 32-byte X25519 public key.

    Returns:
        JWK dict with ``kty``, ``crv``, ``x`` fields.
    """
    return {"kty": "OKP", "crv": "X25519", "x": to_base64url(public_key)}


def public_keys_body(keys: AgentKeys) -> dict[str, dict[str, str]]:
    """The published form of an agent's public keys.

    The one place the key-publishing request body is built, so onboarding, key
    rotation and ``get_agent_public_keys`` cannot drift over which keys an agent
    advertises. ``pq_encryption_public_key`` is present exactly when the agent
    has an ML-KEM key — and its presence is what makes peers seal
    ``hpke-hybrid-v1`` to this agent.

    Args:
        keys: The agent's keys.

    Returns:
        Dict with ``signing_public_key``, ``encryption_public_key`` and
        optionally ``pq_encryption_public_key``.
    """
    body = {
        "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
        "encryption_public_key": encryption_public_key_to_jwk(keys.encryption.public_key),
    }
    if keys.pq_encryption is not None:
        body["pq_encryption_public_key"] = pq_public_key_to_jwk(keys.pq_encryption.public_key)
    return body


def jwk_to_public_key(jwk: dict[str, str], expected_crv: str | None = None) -> bytes:
    """Extract a 32-byte public key from a JWK.

    Args:
        jwk: JWK dict with ``x`` field (base64url-encoded).
        expected_crv: Optional expected curve name (e.g. ``Ed25519``, ``X25519``).

    Returns:
        32-byte public key.

    Raises:
        CryptoError: If JWK format is invalid, key size wrong, or curve mismatch.
    """
    if expected_crv:
        crv = jwk.get("crv")
        if crv != expected_crv:
            raise CryptoError(f"JWK curve mismatch: expected {expected_crv}, got {crv}")
    x = jwk.get("x")
    if not x:
        raise CryptoError("JWK missing 'x' field")
    key_bytes = from_base64url(x)
    if len(key_bytes) != 32:
        raise CryptoError(f"Invalid key size: expected 32, got {len(key_bytes)}")
    return key_bytes


def agent_id_from_kid(kid: str) -> str:
    """Extract the agent UUID from a KID string.

    Args:
        kid: Key ID in format ``rine:{uuid}``.

    Returns:
        UUID string.

    Raises:
        CryptoError: If KID format is invalid.
    """
    m = _KID_RE.match(kid)
    if not m:
        raise CryptoError(f"Invalid KID format: {kid!r}. Expected: rine:{{uuid}}")
    return m.group(1)


def make_kid(agent_id: str) -> str:
    """Build a KID string from an agent UUID.

    Args:
        agent_id: Agent UUID string.

    Returns:
        KID in format ``rine:{uuid}``.
    """
    return f"rine:{agent_id}"


def _validate_path_id(value: str, label: str) -> None:
    """Validate that a string is a UUID (for safe file paths)."""
    if not _UUID_RE.match(value):
        raise CryptoError(f"Invalid {label}: {value!r}. Expected a UUID.")


def save_agent_keys(config_dir: str, agent_id: str, keys: AgentKeys) -> None:
    """Save agent keys to disk at ``keys/{agent_id}/``.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        keys: AgentKeys to save.
    """
    _validate_path_id(agent_id, "agent_id")
    kdir = keys_dir(config_dir, agent_id)
    _ensure_dir(kdir)

    for name, kp in [("signing.key", keys.signing), ("encryption.key", keys.encryption)]:
        path = os.path.join(kdir, name)
        from rine._config import _write_atomic

        _write_atomic(path, to_base64url(kp.private_key))

    if keys.pq_encryption is not None:
        save_pq_key(config_dir, agent_id, keys.pq_encryption.private_key)


def load_agent_keys(config_dir: str, agent_id: str) -> AgentKeys:
    """Load agent keys from disk.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        Loaded AgentKeys. ``pq_encryption`` is set when the agent has a PQ key
        file and ``None`` when it predates them.

    Raises:
        CryptoError: If keys are missing, corrupt, or wrong size.
    """
    _validate_path_id(agent_id, "agent_id")
    kdir = keys_dir(config_dir, agent_id)

    def _load_key(filename: str) -> bytes:
        path = os.path.join(kdir, filename)
        try:
            with open(path) as f:
                b64 = f.read().strip()
            key_bytes = from_base64url(b64)
        except FileNotFoundError:
            raise CryptoError(f"Key file not found: {path}. Regenerate keys.")
        except Exception as exc:
            raise CryptoError(f"Corrupt key file: {path}. {exc}") from exc
        if len(key_bytes) != 32:
            raise CryptoError(f"Invalid key size in {path}: expected 32, got {len(key_bytes)}")
        return key_bytes

    sign_priv = _load_key("signing.key")
    enc_priv = _load_key("encryption.key")

    # Derive public keys from private
    sign_pub = Ed25519PrivateKey.from_private_bytes(sign_priv).public_key().public_bytes_raw()
    enc_pub = X25519PrivateKey.from_private_bytes(enc_priv).public_key().public_bytes_raw()

    pq = load_pq_key(config_dir, agent_id)

    return AgentKeys(
        signing=KeyPair(private_key=sign_priv, public_key=sign_pub),
        encryption=KeyPair(private_key=enc_priv, public_key=enc_pub),
        pq_encryption=None if pq is None else KeyPair(private_key=pq[0], public_key=pq[1]),
    )


def agent_keys_exist(config_dir: str, agent_id: str) -> bool:
    """Check if agent keys exist on disk.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        True if both signing.key and encryption.key exist.
    """
    kdir = keys_dir(config_dir, agent_id)
    return os.path.isfile(os.path.join(kdir, "signing.key")) and os.path.isfile(
        os.path.join(kdir, "encryption.key")
    )
