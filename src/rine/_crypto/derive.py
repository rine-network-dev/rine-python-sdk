"""Deterministic key-derivation tree for org roots, branches and agents.

Every node is HKDF-SHA256 over a labelled parent, so the whole tree is a pure
function of the 32-byte org root. This module holds the primitives and the
public-key helpers; the node dataclasses and their builders live in
:mod:`rine._crypto.derive_nodes`.
"""

from __future__ import annotations

import hashlib
import re
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rine.errors import CryptoError

BRANCH_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_ORG_ID_DOMAIN = b"rine.v1.org-id"


def derive(parent: bytes, label: str, length: int) -> bytes:
    """Derive ``length`` bytes from ``parent`` under an ASCII ``label``."""
    return HKDF(algorithm=SHA256(), length=length, salt=b"", info=label.encode("ascii")).derive(
        parent
    )


def ed25519_public_key(seed: bytes) -> bytes:
    """Return the raw Ed25519 public key for a 32-byte seed."""
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def x25519_public_key(sk: bytes) -> bytes:
    """Return the raw X25519 public key for a 32-byte secret key."""
    return (
        X25519PrivateKey.from_private_bytes(sk)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def check_branch_name(name: str) -> str:
    """Return ``name`` when it is a canonical branch name, else raise."""
    if not BRANCH_NAME_RE.fullmatch(name):
        raise CryptoError("invalid branch name")
    return name


def canonical_uuid(value: str, what: str) -> str:
    """Return ``value`` when it is a canonical lowercase UUID (so NUL-free ASCII), else raise."""
    if not UUID_RE.fullmatch(value):
        raise CryptoError(f"non-canonical {what}")
    return value


def canonical_agent_label_id(agent_id: str) -> str:
    """Return ``agent_id`` when it is a canonical UUID, else raise."""
    return canonical_uuid(agent_id, "agent id")


def org_id_from_keys(ed25519_pk: bytes, ml_dsa_pk: bytes) -> str:
    """Return the lowercase hyphenated org id for an org's public keys."""
    digest = hashlib.sha256(_ORG_ID_DOMAIN + b"\x00" + ed25519_pk + ml_dsa_pk).digest()
    raw = bytearray(digest[:16])
    raw[6] = (raw[6] & 0x0F) | 0x80
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))
