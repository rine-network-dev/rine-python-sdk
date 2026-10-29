"""The agent's leaf keys: derivation to files, files to keys, and the published form.

An agent holds five keys, all derived from its branch: Ed25519
signing, X25519 encryption, ML-KEM-768 encryption, an Ed25519 MLS leaf signing
key, and the generation (``key_gen``) they were derived at. They live as
base64url text at ``keys/{agent_id}/`` with 0o600 permissions: ``signing.key``,
``encryption.key``, ``pq_encryption.key`` (the 64-byte ML-KEM seed, owned by
:mod:`rine._crypto.pq_keys`), ``mls.key`` and ``key_gen``. The files are a cache:
whoever holds the branch can rebuild them.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NamedTuple

from rine._config import UPGRADE_DETAIL, _ensure_dir, _write_atomic, keys_dir
from rine._crypto import _mlkem
from rine._crypto.derive import UUID_RE, ed25519_public_key, x25519_public_key
from rine._crypto.pq_keys import (
    load_pq_key,
    pq_public_key_to_jwk,
    pq_signing_public_key_to_jwk,
    save_pq_key,
)
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

if TYPE_CHECKING:
    from rine._crypto.derive_nodes import AgentNode

# Path ids accept any spelling of a UUID (sender-key files are looked up case-insensitively).
_PATH_ID_RE = re.compile(UUID_RE.pattern, re.I)
# A key id names its agent in the canonical lower-case spelling every minter emits.
_KID_RE = re.compile(
    r"rine:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})#(0|[1-9][0-9]*)",
)

KEY_GEN_FILENAME = "key_gen"
MLS_KEY_FILENAME = "mls.key"


@dataclass
class KeyPair:
    """A private key and its public key."""

    private_key: bytes = field(repr=False)
    public_key: bytes


@dataclass
class AgentKeys:
    """Every leaf key an agent holds, at one generation.

    ``pq_encryption.private_key`` is the 2400-byte decapsulation key expanded
    from ``pq_seed``, the 64-byte value that is persisted. ``mls`` is the MLS
    leaf signature key: a separate key from ``signing``, so an MLS credential
    and a rine envelope signature are never made by the same key.
    """

    signing: KeyPair
    encryption: KeyPair
    pq_encryption: KeyPair
    pq_seed: bytes = field(repr=False)
    mls: KeyPair
    key_gen: int


class KidRef(NamedTuple):
    """The agent and key generation a message-signature kid names."""

    agent_id: str
    key_gen: int


def agent_keys_from_node(node: AgentNode) -> AgentKeys:
    """Build an agent's leaf keys from its derived node.

    Args:
        node: The agent node derived from its branch.

    Returns:
        The agent's keys at the node's generation.
    """
    _, pq_private = _mlkem.key_pair_from_seed(node.kem_seed)
    return AgentKeys(
        signing=KeyPair(node.ed_seed, node.ed_pk),
        encryption=KeyPair(node.x_sk, node.x_pk),
        pq_encryption=KeyPair(pq_private, node.kem_pk),
        pq_seed=node.kem_seed,
        mls=KeyPair(node.mls_seed, node.mls_pk),
        key_gen=node.gen,
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


def public_keys_body(keys: AgentKeys, pq_signing_public_key: bytes) -> dict[str, dict[str, str]]:
    """The published form of the public keys an agent holds.

    The one place the key-publishing body is built, so onboarding and key
    rotation cannot drift over which keys an agent advertises. The ML-DSA public
    key is not a leaf file (no ML-DSA key is stored), so the caller that creates
    or rotates an agent passes the derived 1952-byte public key.

    Args:
        keys: The agent's keys.
        pq_signing_public_key: 1952-byte ML-DSA-65 public key.

    Returns:
        Dict with ``signing_public_key``, ``encryption_public_key``,
        ``pq_encryption_public_key``, ``pq_signing_public_key`` and
        ``mls_signing_public_key``.
    """
    return {
        "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
        "encryption_public_key": encryption_public_key_to_jwk(keys.encryption.public_key),
        "pq_encryption_public_key": pq_public_key_to_jwk(keys.pq_encryption.public_key),
        "pq_signing_public_key": pq_signing_public_key_to_jwk(pq_signing_public_key),
        "mls_signing_public_key": signing_public_key_to_jwk(keys.mls.public_key),
    }


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


def parse_kid(kid: str) -> KidRef:
    """Split a KID into its agent UUID and key generation.

    Args:
        kid: Key ID in format ``rine:{uuid}#{gen}``.

    Returns:
        The agent UUID and the key generation.

    Raises:
        CryptoError: If KID format is invalid, including a non-canonical (upper-case or
            newline-padded) spelling.
    """
    m = _KID_RE.fullmatch(kid)
    if not m:
        raise CryptoError(f"Invalid KID format: {kid!r}. Expected: rine:{{uuid}}#{{gen}}")
    return KidRef(m.group(1), int(m.group(2)))


def agent_id_from_kid(kid: str) -> str:
    """Extract the agent UUID from a KID string.

    Args:
        kid: Key ID in format ``rine:{uuid}#{gen}``.

    Returns:
        UUID string.

    Raises:
        CryptoError: If KID format is invalid.
    """
    return parse_kid(kid).agent_id


def make_kid(agent_id: str, key_gen: int) -> str:
    """Build a KID string from an agent UUID and the generation that signs.

    Args:
        agent_id: Agent UUID string.
        key_gen: The signing key's generation.

    Returns:
        KID in format ``rine:{uuid}#{gen}``, with the UUID in the lower-case spelling
        every reader requires, whatever case the caller's actor value had.
    """
    return f"rine:{agent_id.lower()}#{key_gen}"


def held_key_gen(config_dir: str, agent_id: str) -> int | None:
    """The generation of the leaf keys already on this device for ``agent_id``, if any."""
    try:
        return load_agent_keys(config_dir, agent_id).key_gen
    except CryptoError:
        return None


def _validate_path_id(value: str, label: str) -> None:
    """Validate that a string is a UUID (for safe file paths).

    ``fullmatch`` for the same reason :func:`rine._resolve.is_uuid` uses it —
    Python's ``$`` matches before a trailing newline, so ``match`` let
    ``"<uuid>\\n"`` through a guard whose entire job is deciding what may become
    a directory name.
    """
    if not _PATH_ID_RE.fullmatch(value):
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
    for name, secret in (
        ("signing.key", keys.signing.private_key),
        ("encryption.key", keys.encryption.private_key),
        (MLS_KEY_FILENAME, keys.mls.private_key),
    ):
        _write_atomic(os.path.join(kdir, name), to_base64url(secret))
    _write_atomic(os.path.join(kdir, KEY_GEN_FILENAME), f"{keys.key_gen}\n")
    save_pq_key(config_dir, agent_id, keys.pq_seed)


def _load_secret(kdir: str, filename: str) -> bytes:
    path = os.path.join(kdir, filename)
    try:
        with open(path) as f:
            key_bytes = from_base64url(f.read().strip())
    except FileNotFoundError:
        if filename == MLS_KEY_FILENAME:
            raise CryptoError(UPGRADE_DETAIL) from None
        raise CryptoError(f"Key file not found: {path}. Regenerate keys.") from None
    except Exception as exc:
        raise CryptoError(f"Corrupt key file: {path}. {exc}") from exc
    if len(key_bytes) != 32:
        raise CryptoError(f"Invalid key size in {path}: expected 32, got {len(key_bytes)}")
    return key_bytes


def _load_key_gen(kdir: str) -> int:
    path = os.path.join(kdir, KEY_GEN_FILENAME)
    try:
        with open(path) as f:
            text = f.read().strip()
    except FileNotFoundError:
        raise CryptoError(UPGRADE_DETAIL) from None
    if not re.fullmatch(r"0|[1-9][0-9]*", text):
        raise CryptoError(f"Corrupt key file: {path}. Expected a decimal key generation.")
    return int(text)


def load_agent_keys(config_dir: str, agent_id: str) -> AgentKeys:
    """Load agent keys from disk.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        Loaded AgentKeys, with the ML-KEM key expanded from its seed.

    Raises:
        CryptoError: If keys are missing, corrupt, wrong size, or the retired
            2400-byte ML-KEM format (which carries the upgrade detail).
    """
    _validate_path_id(agent_id, "agent_id")
    kdir = keys_dir(config_dir, agent_id)
    signing = _load_secret(kdir, "signing.key")
    encryption = _load_secret(kdir, "encryption.key")
    mls = _load_secret(kdir, MLS_KEY_FILENAME)
    pq_seed, pq_private, pq_public = load_pq_key(config_dir, agent_id)
    return AgentKeys(
        signing=KeyPair(signing, ed25519_public_key(signing)),
        encryption=KeyPair(encryption, x25519_public_key(encryption)),
        pq_encryption=KeyPair(pq_private, pq_public),
        pq_seed=pq_seed,
        mls=KeyPair(mls, ed25519_public_key(mls)),
        key_gen=_load_key_gen(kdir),
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
