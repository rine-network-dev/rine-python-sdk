"""MLS read escrow: seal one epoch's read secrets and open them.

An escrow is an ``EpochReadSecrets`` v1 plaintext sealed (``hpke-hybrid-v2``,
:class:`~rine._crypto.hybrid.MlsEscrow` context) to the uploader's own branch
escrow key, with the uploader's Ed25519 signature over the slot it belongs to.
Sealing and signing are separate steps: the signature is made at upload, under the
uploader's key generation of that moment.

The open half is what the fleet reader calls. It checks the uploader signature
before anything else, so a row the uploader did not sign is never attributed to
it: a bad signature is :class:`EscrowForgedError` and names nobody, while a
signed copy that will not open is :class:`EscrowInvalidError` and names its
uploader.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rine._crypto import hybrid
from rine._crypto.certs import signed_within_validity
from rine._crypto.derive import canonical_uuid, check_branch_name
from rine._crypto.ed25519_strict import verify_ed25519_strict
from rine._crypto.hybrid import MAX_EPOCH, MlsEscrow
from rine._mls.binding import DEFAULT_CIPHER_SUITE
from rine.errors import CryptoError

if TYPE_CHECKING:
    from datetime import datetime

    from rine._crypto.certs import VerifiedAgentKeys
    from rine._crypto.escrow_key import VerifiedEscrowKey

ESCROW_CIPHER_SUITE = DEFAULT_CIPHER_SUITE
EPOCH_READ_SECRETS_VERSION = 1
MAX_ESCROW_CONTEXT_LENGTH = 1024
MAX_ESCROW_LEAVES = 1000
#: Twice the power of two holding ``MAX_ESCROW_LEAVES``: the widest tree a reader will size.
MAX_ESCROW_TREE_LEAVES = 2048
_TREE_LEAF_COUNT_OFFSET = 3

_SIG_DOMAIN = b"rine.v1.mls-escrow-sig"
_SEP = b"\x00"
_KEY_GEN_LIMIT = 2**32
_LEAF_ENTRY_SIZE = 36
# version(1) + cipher_suite(2) + leaf_count(4) + sender_data_secret(32) + encryption_secret(32)
_FIXED_PART_SIZE = 71


class EscrowForgedError(CryptoError):
    """The uploader signature over an escrow row does not verify; nobody is named."""


class EscrowInvalidError(CryptoError):
    """A correctly signed escrow copy that does not open; its uploader is named."""

    def __init__(self, uploader_agent_id: str, detail: str) -> None:
        super().__init__(f"escrow from {uploader_agent_id} is invalid: {detail}")
        self.uploader_agent_id = uploader_agent_id


@dataclass(frozen=True, slots=True)
class EscrowSlot:
    """The slot an escrow belongs to: group, epoch and fork fingerprint."""

    group_id: str
    epoch: int
    fp: bytes


@dataclass(frozen=True, slots=True)
class EscrowUploader:
    """The agent that signed an escrow, at the key generation it signed with."""

    agent_id: str
    key_gen: int


@dataclass(frozen=True, slots=True)
class SealedEscrow:
    """A sealed escrow and the uploader's signature over its slot."""

    sealed: bytes
    uploader_sig: bytes


def escrow_seal_context(
    org_id: str, branch: str, slot: EscrowSlot, uploader_agent_id: str
) -> MlsEscrow:
    """The context binding org, branch, group, epoch, uploader and ``fp``."""
    return MlsEscrow(
        org_id=org_id,
        branch=branch,
        group_id=slot.group_id,
        epoch=slot.epoch,
        uploader_agent_id=uploader_agent_id,
        fp=slot.fp,
    )


def uploader_signature_input(
    org_id: str, branch: str, slot: EscrowSlot, uploader: EscrowUploader, sealed: bytes
) -> bytes:
    """The bytes the uploader signs: every identifier as its canonical ASCII text.

    Raises:
        CryptoError: If an id, branch, epoch, ``fp`` or key generation is out of range.
    """
    if not 0 <= slot.epoch < MAX_EPOCH or not 0 <= uploader.key_gen < _KEY_GEN_LIMIT:
        raise CryptoError("escrow epoch or key generation out of range")
    return b"".join(
        (
            _SIG_DOMAIN,
            _SEP,
            canonical_uuid(org_id, "org id").encode(),
            _SEP,
            check_branch_name(branch).encode(),
            _SEP,
            canonical_uuid(slot.group_id, "group id").encode(),
            _SEP,
            slot.epoch.to_bytes(8, "big"),
            slot.fp,
            canonical_uuid(uploader.agent_id, "uploader agent id").encode(),
            _SEP,
            uploader.key_gen.to_bytes(4, "big"),
            hashlib.sha256(sealed).digest(),
        )
    )


def check_epoch_read_secrets(plaintext: bytes | bytearray) -> None:
    """Accept only EpochReadSecrets v1, suite 0xF057, with a well-formed length.

    Raises:
        CryptoError: On any other version or suite, a tree size that is not a power
            of two up to 2048 leaves, or a context or leaf tail
            that does not fit the plaintext exactly.
    """
    if len(plaintext) < _FIXED_PART_SIZE + 4:
        raise CryptoError("escrow plaintext too short")
    if plaintext[0] != EPOCH_READ_SECRETS_VERSION:
        raise CryptoError("unsupported EpochReadSecrets version")
    if int.from_bytes(plaintext[1:3], "big") != ESCROW_CIPHER_SUITE:
        raise CryptoError("unsupported escrow cipher suite")
    tree_leaves = int.from_bytes(
        plaintext[_TREE_LEAF_COUNT_OFFSET : _TREE_LEAF_COUNT_OFFSET + 4], "big"
    )
    if not 0 < tree_leaves <= MAX_ESCROW_TREE_LEAVES or tree_leaves & (tree_leaves - 1):
        raise CryptoError("escrow tree size is not a power of two within the limit")
    context_len = int.from_bytes(plaintext[_FIXED_PART_SIZE : _FIXED_PART_SIZE + 4], "big")
    if context_len > MAX_ESCROW_CONTEXT_LENGTH:
        raise CryptoError("escrow group context too long")
    after_context = _FIXED_PART_SIZE + 4 + context_len
    if after_context + 4 > len(plaintext):
        raise CryptoError("escrow group context runs past the end")
    leaf_count = int.from_bytes(plaintext[after_context : after_context + 4], "big")
    if leaf_count > MAX_ESCROW_LEAVES:
        raise CryptoError("escrow lists too many leaves")
    tail = after_context + 4 + _LEAF_ENTRY_SIZE * leaf_count
    if tail != len(plaintext):
        raise CryptoError("escrow leaf count does not match the plaintext length")


def seal_escrow(
    key: VerifiedEscrowKey,
    slot: EscrowSlot,
    uploader: EscrowUploader,
    plaintext: bytes | bytearray,
) -> bytes:
    """Seal read secrets to the branch escrow key.

    The plaintext is read in place, so a caller holding it in a ``bytearray`` can
    zero its only copy afterwards.

    Args:
        key: The uploader's own branch escrow key, chain-verified.
        slot: Group, epoch and fork fingerprint.
        uploader: The sealing agent and its key generation.
        plaintext: An EpochReadSecrets v1 plaintext.

    Raises:
        CryptoError: If the plaintext is not EpochReadSecrets v1 or the seal fails.
    """
    check_epoch_read_secrets(plaintext)
    ctx = escrow_seal_context(key.org_id, key.branch, slot, uploader.agent_id)
    return hybrid.seal(key.x25519_public_key, key.ml_kem_public_key, plaintext, ctx)


def sign_escrow(
    key: VerifiedEscrowKey,
    slot: EscrowSlot,
    uploader: EscrowUploader,
    signing_private_key: bytes,
    sealed: bytes,
) -> bytes:
    """The uploader's Ed25519 signature over the slot a sealed escrow fills.

    Args:
        key: The uploader's own branch escrow key; it names the org and branch.
        slot: Group, epoch and fork fingerprint.
        uploader: The signing agent and the key generation it signs under.
        signing_private_key: The uploader's 32-byte Ed25519 seed.
        sealed: The bytes :func:`seal_escrow` returned.

    Raises:
        CryptoError: If an id, branch, epoch or key generation is out of range.
    """
    return Ed25519PrivateKey.from_private_bytes(signing_private_key).sign(
        uploader_signature_input(key.org_id, key.branch, slot, uploader, sealed)
    )


def open_escrow(
    escrow_x25519_sk: bytes,
    escrow_ml_kem_sk: bytes,
    org_id: str,
    branch: str,
    slot: EscrowSlot,
    uploader: EscrowUploader,
    uploader_keys: VerifiedAgentKeys,
    stored_at: datetime,
    escrow: SealedEscrow,
    *,
    current_key_gen: int,
) -> bytes:
    """Verify the uploader's signature, then open one escrow copy.

    Args:
        escrow_x25519_sk: The branch escrow X25519 private key.
        escrow_ml_kem_sk: The branch escrow ML-KEM-768 private key.
        org_id: The org the row belongs to.
        branch: The branch the row was sealed to.
        slot: Group, epoch and fork fingerprint of the row.
        uploader: The row's uploader and the generation it signed with.
        uploader_keys: The chain-verified keys of that generation, read with
            ``?gen=`` so a superseded one carries its ``superseded_at``, and a
            revoked agent's carries its ``revoked_at``.
        stored_at: When the server stored the row (its ``created_at``). A row
            signed under a generation since superseded is accepted only when it
            was stored at or before that generation's ``superseded_at``, and one
            signed by a revoked agent only at or before its ``revoked_at``.
        escrow: The sealed bytes and signature as the server returned them.
        current_key_gen: The uploader's current generation. A row signed under a
            lower one has a window to check, so ``uploader_keys`` must carry its
            ``superseded_at``: a history read that omits it opens nothing.

    Returns:
        The EpochReadSecrets v1 plaintext.

    Raises:
        EscrowForgedError: The signature does not verify, the keys are not the
            uploader's generation, or the row was stored after that generation
            was superseded or its agent revoked.
        EscrowInvalidError: The uploader's chain-verified keys name another org
            or branch, or the copy is signed but does not open, or opens to
            anything other than EpochReadSecrets v1.
    """
    if (uploader_keys.agent_id, uploader_keys.key_gen) != (uploader.agent_id, uploader.key_gen):
        raise EscrowForgedError("keys are not the uploader's signing generation")
    historical = uploader.key_gen < current_key_gen
    if not signed_within_validity(uploader_keys, stored_at, historical=historical):
        raise EscrowForgedError(
            "escrow is not shown to be stored before its uploader key was superseded or revoked"
        )
    signed = uploader_signature_input(org_id, branch, slot, uploader, escrow.sealed)
    if not verify_ed25519_strict(uploader_keys.signing_public_key, signed, escrow.uploader_sig):
        raise EscrowForgedError("escrow uploader signature does not verify")
    if (uploader_keys.org_id, uploader_keys.branch) != (org_id, branch):
        raise EscrowInvalidError(
            uploader.agent_id, "uploader is not an agent of the branch the escrow names"
        )
    ctx = escrow_seal_context(org_id, branch, slot, uploader.agent_id)
    try:
        plaintext = hybrid.open(escrow_x25519_sk, escrow_ml_kem_sk, escrow.sealed, ctx)
        check_epoch_read_secrets(plaintext)
    except CryptoError as exc:
        raise EscrowInvalidError(uploader.agent_id, str(exc)) from exc
    return plaintext
