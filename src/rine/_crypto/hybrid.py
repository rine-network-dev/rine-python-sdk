"""``hpke-hybrid-v2``: the post-quantum 1:1 DM envelope.

X25519 and ML-KEM-768 in parallel, their shared secrets combined with SHA3-256
into one AES-256-GCM key. Hybrid means an attacker has to break *both*: X25519
today, or ML-KEM-768 once a quantum computer exists — so a DM harvested now is
not decryptable later by breaking only one of them.

Wire format, byte-for-byte the same as the TypeScript stack's
``rine-core/src/crypto/hybrid.ts``::

    [1 byte: version 0x04]
    [32 bytes: ephemeral X25519 public key]
    [1088 bytes: ML-KEM-768 ciphertext]
    [remaining: AES-256-GCM ciphertext + 16-byte auth tag]

The AEAD nonce is twelve zero bytes and is not on the wire: both KEM halves are
freshly randomized per message, so the derived key is used exactly once. The
AAD is never caller-supplied bytes — it is encoded from a closed
:data:`SealContext` union, so a payload only opens under its own context.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import assert_never

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rine._crypto import _mlkem
from rine._crypto.derive import canonical_uuid, check_branch_name
from rine.errors import CryptoError

VERSION_HYBRID = 0x04
X25519_ENC_SIZE = 32
KEY_SCHEDULE_LABEL = b"rine.v1.hpke-hybrid-v2"

_SEP = b"\x00"
_BRANCH_BUNDLE_LABEL = b"rine.v1.branch-bundle"
_MLS_ESCROW_LABEL = b"rine.v1.mls-escrow"
_FP_SIZE = 16
#: Epochs are bounded by 2**53 so every client stack, JavaScript's safe integers included, agrees.
MAX_EPOCH = 2**53
_GCM_NONCE = b"\x00" * 12
_HEADER_SIZE = 1 + X25519_ENC_SIZE + _mlkem.CIPHERTEXT_SIZE
_MIN_WIRE = _HEADER_SIZE + 16


@dataclass(frozen=True, slots=True)
class AgentMessage:
    """A 1:1 direct message addressed to one agent."""

    recipient_agent_id: str


@dataclass(frozen=True, slots=True)
class BranchBundle:
    """A branch-scoped bundle of org state."""

    org_id: str
    branch: str


@dataclass(frozen=True, slots=True)
class MlsEscrow:
    """An MLS group epoch escrowed for an org branch."""

    org_id: str
    branch: str
    group_id: str
    epoch: int
    uploader_agent_id: str
    fp: bytes


#: The closed set of contexts a hybrid payload can be bound to.
SealContext = AgentMessage | BranchBundle | MlsEscrow


def _aad(*parts: bytes) -> bytes:
    """Join AAD parts behind the version byte, separated by ``SEP``."""
    return bytes([VERSION_HYBRID]) + _SEP.join(parts)


def seal_context_aad(ctx: SealContext) -> bytes:
    """Encode a :data:`SealContext` into its canonical associated data.

    Args:
        ctx: The typed context the payload is bound to.

    Raises:
        CryptoError: If an id or branch is not canonical, or an ``MlsEscrow``
            fingerprint or epoch is out of range.
    """
    match ctx:
        case AgentMessage():
            return _aad(canonical_uuid(ctx.recipient_agent_id, "recipient agent id").encode())
        case BranchBundle():
            return _aad(
                _BRANCH_BUNDLE_LABEL,
                canonical_uuid(ctx.org_id, "org id").encode(),
                check_branch_name(ctx.branch).encode(),
            )
        case MlsEscrow():
            if len(ctx.fp) != _FP_SIZE:
                raise CryptoError(f"MlsEscrow fp must be {_FP_SIZE} bytes, got {len(ctx.fp)}")
            if not 0 <= ctx.epoch < MAX_EPOCH:
                raise CryptoError(f"MlsEscrow epoch out of range: {ctx.epoch}")
            return _aad(
                _MLS_ESCROW_LABEL,
                canonical_uuid(ctx.org_id, "org id").encode(),
                check_branch_name(ctx.branch).encode(),
                canonical_uuid(ctx.group_id, "group id").encode(),
                ctx.epoch.to_bytes(8, "big"),
                canonical_uuid(ctx.uploader_agent_id, "uploader agent id").encode(),
                ctx.fp,
            )
        case _ as unreachable:
            assert_never(unreachable)


def derive_key(
    ss_mlkem: bytes,
    ss_x25519: bytes,
    ephemeral_pk: bytes,
    recipient_x25519_pk: bytes,
) -> bytes:
    """Derive the AES-256-GCM key from both KEM halves and both public keys.

    The label, the order of the four inputs and the hash are all wire format:
    change any of them and the two stacks derive different keys.
    """
    return hashlib.sha3_256(
        KEY_SCHEDULE_LABEL + ss_mlkem + ss_x25519 + ephemeral_pk + recipient_x25519_pk
    ).digest()


def seal(
    recipient_x25519_pk: bytes,
    recipient_mlkem_pk: bytes,
    plaintext: bytes | bytearray,
    ctx: SealContext,
) -> bytes:
    """Encrypt a plaintext to a recipient's classical + PQ public keys.

    Args:
        recipient_x25519_pk: Recipient's 32-byte X25519 public key.
        recipient_mlkem_pk: Recipient's 1184-byte ML-KEM-768 public key.
        plaintext: Plaintext bytes to encrypt, read in place.
        ctx: The typed context the payload is bound to.

    Raises:
        CryptoError: If either recipient key is malformed, or encryption fails.
    """
    try:
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes_raw()
        x25519_shared = eph_sk.exchange(X25519PublicKey.from_public_bytes(recipient_x25519_pk))
        mlkem_ct, mlkem_shared = _mlkem.encapsulate(recipient_mlkem_pk)
        key = derive_key(mlkem_shared, x25519_shared, eph_pk, recipient_x25519_pk)
        ciphertext = AESGCM(key).encrypt(_GCM_NONCE, plaintext, seal_context_aad(ctx))
    except Exception as exc:
        raise CryptoError(f"hpke-hybrid-v2 seal failed: {exc}") from exc
    return bytes([VERSION_HYBRID]) + eph_pk + mlkem_ct + ciphertext


def open(  # noqa: A001 - module-level `open` pairs with `seal`
    recipient_x25519_sk: bytes,
    recipient_mlkem_sk: bytes,
    payload: bytes,
    ctx: SealContext,
) -> bytes:
    """Decrypt an ``hpke-hybrid-v2`` payload.

    Args:
        recipient_x25519_sk: Recipient's 32-byte X25519 private key.
        recipient_mlkem_sk: Recipient's 2400-byte ML-KEM-768 private key.
        payload: Encrypted bytes from :func:`seal`.
        ctx: The typed context the payload was sealed under.

    Raises:
        CryptoError: If the payload is malformed, its version is unsupported,
            or decryption fails (including a mismatched context).
    """
    if len(payload) < _MIN_WIRE:
        raise CryptoError(
            f"hpke-hybrid-v2 payload too short: {len(payload)} bytes (min {_MIN_WIRE})"
        )
    version = payload[0]
    if version != VERSION_HYBRID:
        raise CryptoError(
            f"hpke-hybrid-v2 unsupported version byte 0x{version:02x} "
            f"(expected 0x{VERSION_HYBRID:02x})"
        )
    eph_pk = payload[1 : 1 + X25519_ENC_SIZE]
    mlkem_ct = payload[1 + X25519_ENC_SIZE : _HEADER_SIZE]
    ciphertext = payload[_HEADER_SIZE:]
    try:
        recipient_sk = X25519PrivateKey.from_private_bytes(recipient_x25519_sk)
        recipient_pk = recipient_sk.public_key().public_bytes_raw()
        x25519_shared = recipient_sk.exchange(X25519PublicKey.from_public_bytes(eph_pk))
        mlkem_shared = _mlkem.decapsulate(mlkem_ct, recipient_mlkem_sk)
        key = derive_key(mlkem_shared, x25519_shared, eph_pk, recipient_pk)
        return AESGCM(key).decrypt(_GCM_NONCE, ciphertext, seal_context_aad(ctx))
    except Exception as exc:
        raise CryptoError(
            f"hpke-hybrid-v2 decryption failed — wrong recipient key or context? {exc}"
        ) from exc
