"""Sender-verification verdicts and the key-generation steps that lead to them.

The shared, I/O-free half of :mod:`rine._crypto._sender_verify`: the verdict a
check produces, how a key id's generation steers the key read, and how a failed
read maps to a verdict. The sync and async twins only perform the reads.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

import httpx

from rine._crypto.certs import ChainError, signed_within_validity
from rine._crypto.keys import KidRef, parse_kid
from rine._crypto.sign import SigScope, verify_message_signature
from rine._logging import logger
from rine.errors import (
    APIConnectionError,
    APITimeoutError,
    CryptoError,
    RineApiError,
)
from rine.types import SenderKeyChange, VerificationStatus

if TYPE_CHECKING:
    from datetime import datetime

    from rine._crypto.certs import VerifiedAgentKeys


@dataclass(frozen=True)
class SenderVerification:
    """The outcome of verifying one envelope's sender signature.

    ``key_changed`` is set only when the rotation refetch returned a *different*
    signing key, whichever way the re-verification then fell.
    """

    verified: bool
    verification_status: VerificationStatus
    key_changed: SenderKeyChange | None = None


def signing_key_fingerprint(keys: VerifiedAgentKeys) -> str:
    """Return a stable short identity for a published signing key.

    Hex SHA-256 over the raw 32-byte Ed25519 key, so one key fingerprints
    identically on every rine client whatever language it is written in.

    Args:
        keys: An agent's chain-verified keys.

    Returns:
        Lowercase hex digest.
    """
    return hashlib.sha256(keys.signing_public_key).hexdigest()


def verify_with_keys(
    keys: VerifiedAgentKeys,
    scope: SigScope,
    payload: bytes,
    signature: bytes,
    created_at: datetime | None,
    *,
    historical: bool = False,
) -> bool:
    """Verify a message signature against a verified agent's signing key.

    The signature holds only while the row's server ``created_at`` falls inside the
    generation's validity: not after it was superseded, nor after its agent was revoked.
    """
    return signed_within_validity(
        keys, created_at, historical=historical
    ) and verify_message_signature(keys.signing_public_key, scope, payload, signature)


def verdict(verified: bool) -> SenderVerification:
    """Wrap a plain verify outcome, with no key change to report."""
    return SenderVerification(verified, "verified" if verified else "invalid")


def is_authenticity_failure(status: VerificationStatus) -> bool:
    """True when the status is a finding against the message, not a gap.

    ``"invalid"`` and ``"sender-mismatch"`` are both refusals: one says these
    bytes were not signed, the other says they were signed by somebody other
    than the sender. ``"unverifiable"`` is neither — the key could not be read.
    """
    return status in ("invalid", "sender-mismatch")


def sender_matches(agent_id: str, expected_sender_agent_id: str) -> bool:
    """Compare an envelope's signer to the server-authenticated sender.

    Both sides are server-issued UUIDs, so they are compared trimmed and
    lowercased: a caller that carries the id through a surface which upper-cases
    it must not have a legitimate message refused over spelling.
    """
    return agent_id.strip().lower() == expected_sender_agent_id.strip().lower()


def rotation_verdict(
    agent_id: str,
    cached: VerifiedAgentKeys,
    fresh: VerifiedAgentKeys,
    scope: SigScope,
    payload: bytes,
    signature: bytes,
    created_at: datetime | None,
) -> SenderVerification:
    """Decide the outcome of a rotation refetch, and report a real rotation.

    A refetch that returns the SAME key is not re-verified — same key, same
    payload, same signature, same verdict — which keeps the one-refetch budget
    explicit rather than incidental. A different key is re-verified and reported
    either way: the signal is about the key, not about the outcome, and a
    rotation that does not rescue the signature is the more interesting one.
    """
    previous = signing_key_fingerprint(cached)
    current = signing_key_fingerprint(fresh)
    if previous == current:
        return verdict(False)
    verified = verify_with_keys(fresh, scope, payload, signature, created_at)
    return SenderVerification(
        verified,
        "verified" if verified else "invalid",
        SenderKeyChange(
            agent_id=agent_id,
            previous_fingerprint=previous,
            current_fingerprint=current,
        ),
    )


class GenStep(Enum):
    """What a key id's generation asks of the key read that follows."""

    VERIFY = auto()
    REFRESH = auto()
    HISTORY = auto()
    INVALID = auto()


def gen_step(ref_gen: int, keys: VerifiedAgentKeys, from_cache: bool) -> GenStep:
    """Decide how to reach the generation a key id names.

    A key id naming an older generation is read from history. One naming a newer
    generation than a cached answer may mean the peer rotated since: one
    cache-bypassing read settles it, and a fresh read that is still behind names
    a generation that does not exist, so the signature is refused.
    """
    if ref_gen == keys.key_gen:
        return GenStep.VERIFY
    if ref_gen < keys.key_gen:
        return GenStep.HISTORY
    return GenStep.REFRESH if from_cache else GenStep.INVALID


def signer_ref(kid: str, expected_sender_agent_id: str) -> KidRef | None:
    """Parse the key id and hold it against the server-authenticated sender.

    Returns ``None`` on a mismatch, before any key is read. A key id that cannot
    be parsed names nobody, so it is a mismatch too and never a gap in the
    verdict: no honest client emits one.
    """
    try:
        ref = parse_kid(kid)
    except CryptoError:
        return None
    return ref if sender_matches(ref.agent_id, expected_sender_agent_id) else None


def failure_verdict(kid: str, error: Exception) -> SenderVerification:
    """Map a failed key read to a verdict: a broken chain or pin is a finding.

    A chain or pin refusal means the answer contradicted what this client
    verified, so it is ``"invalid"`` and withholds the content. Only transport
    and malformed-input failures are a gap (``"unverifiable"``).
    """
    if isinstance(error, ChainError):
        logger.debug("Refused sender %s (chain or pin)", kid, exc_info=True)
        return SenderVerification(False, "invalid")
    logger.debug("Could not verify sender %s", kid, exc_info=True)
    return SenderVerification(False, "unverifiable")


KEY_READ_ERRORS = (
    KeyError,
    ValueError,
    CryptoError,
    httpx.HTTPError,
    APIConnectionError,
    APITimeoutError,
    RineApiError,
)
