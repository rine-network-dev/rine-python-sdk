"""Sender-signature verification, including the one-shot rotation refetch.

A message's inner envelope is signed with the sender's Ed25519 key, and the copy
of that key this client holds may be a cached one. So a failure here has two
readings — a forged signature, or a peer that rotated its key mid-TTL — and this
module tells them apart with exactly one cache-bypassing refetch, reporting a
genuine rotation to the caller instead of absorbing it silently.

A good signature is also checked against the sender the SERVER authenticated for
the message: the envelope names its own signer, and that name only means
something once it is held against a fact the sender could not choose.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from rine._crypto._agent_keys import get_agent_keys_async, get_agent_keys_sync
from rine._crypto.keys import agent_id_from_kid, jwk_to_public_key
from rine._crypto.sign import verify_signature
from rine._logging import logger
from rine.errors import (
    APIConnectionError,
    APITimeoutError,
    CryptoError,
    RineApiError,
    SenderMismatchError,
    SignatureVerificationError,
)
from rine.types import SenderKeyChange, VerificationStatus

if TYPE_CHECKING:
    from rine._http import AsyncHttpClient, SyncHttpClient

__all__ = [
    "SenderVerification",
    "VerificationStatus",
    "is_authenticity_failure",
    "refuse_if_inauthentic",
    "refuse_if_sender_differs",
    "signing_key_fingerprint",
    "verify_envelope_sender_async",
    "verify_envelope_sender_sync",
]

_SENDER_MISMATCH_DETAIL = "Envelope sender does not match the message sender"


@dataclass(frozen=True)
class SenderVerification:
    """The outcome of verifying one envelope's sender signature.

    ``key_changed`` is set only when the rotation refetch returned a *different*
    signing key, whichever way the re-verification then fell.
    """

    verified: bool
    verification_status: VerificationStatus
    key_changed: SenderKeyChange | None = None


def signing_key_fingerprint(keys_resp: dict[str, Any]) -> str:
    """Return a stable short identity for a published signing key.

    Hex SHA-256 over the raw 32-byte Ed25519 key, so one key fingerprints
    identically on every rine client whatever language it is written in.

    Args:
        keys_resp: A raw ``/agents/{id}/keys`` response.

    Returns:
        Lowercase hex digest.
    """
    raw = jwk_to_public_key(keys_resp["signing_public_key"], expected_crv="Ed25519")
    return hashlib.sha256(raw).hexdigest()


def _verify_with_keys(keys_resp: dict[str, Any], payload: bytes, signature: bytes) -> bool:
    """Verify a signature against the signing key in a keys response."""
    sender_pk = jwk_to_public_key(keys_resp["signing_public_key"], expected_crv="Ed25519")
    return verify_signature(sender_pk, payload, signature)


def _verdict(verified: bool) -> SenderVerification:
    """Wrap a plain verify outcome, with no key change to report."""
    return SenderVerification(verified, "verified" if verified else "invalid")


def is_authenticity_failure(status: VerificationStatus) -> bool:
    """True when the status is a finding against the message, not a gap.

    ``"invalid"`` and ``"sender-mismatch"`` are both refusals: one says these
    bytes were not signed, the other says they were signed by somebody other
    than the sender. ``"unverifiable"`` is neither — the key could not be read.
    """
    return status in ("invalid", "sender-mismatch")


def refuse_if_inauthentic(verification: SenderVerification) -> None:
    """Raise when a verdict is a refusal, so every decrypt path fails alike.

    The single place the refusal is spelled out: a status added to
    :data:`~rine.types.VerificationStatus` is refused everywhere at once instead
    of slipping past one path's equality check.

    Raises:
        SenderMismatchError: The signature is good but belongs to another agent.
        SignatureVerificationError: The signature does not cover these bytes.
    """
    if verification.verification_status == "sender-mismatch":
        raise SenderMismatchError(_SENDER_MISMATCH_DETAIL)
    if verification.verification_status == "invalid":
        raise SignatureVerificationError("Sender signature verification failed")


def refuse_if_sender_differs(sender_kid: str, expected_sender_agent_id: str) -> None:
    """Refuse an envelope whose key id names an agent other than the row's sender.

    The binding comparison on its own, for the path that cannot re-derive a
    verdict: a group decrypt replayed from the memo, whose one-time ratchet key
    the first read already spent. Whom a row is attributed to is decided per
    read, so a row served again under a different sender is refused here rather
    than handed back carrying the earlier read's verdict. A key id that cannot be
    read names nobody and is refused too.

    Args:
        sender_kid: The key id the envelope carried.
        expected_sender_agent_id: The sender the server authenticated for the row
            being read now.

    Raises:
        SenderMismatchError: The key id names a different agent.
    """
    try:
        matches = _sender_matches(agent_id_from_kid(sender_kid), expected_sender_agent_id)
    except CryptoError:
        matches = False
    if not matches:
        raise SenderMismatchError(_SENDER_MISMATCH_DETAIL)


def _sender_matches(agent_id: str, expected_sender_agent_id: str) -> bool:
    """Compare an envelope's signer to the server-authenticated sender.

    Both sides are server-issued UUIDs, so they are compared trimmed and
    lowercased: a caller that carries the id through a surface which upper-cases
    it must not have a legitimate message refused over spelling.
    """
    return agent_id.strip().lower() == expected_sender_agent_id.strip().lower()


def _rotation_verdict(
    agent_id: str,
    cached: dict[str, Any],
    fresh: dict[str, Any],
    payload: bytes,
    signature: bytes,
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
        return _verdict(False)
    verified = _verify_with_keys(fresh, payload, signature)
    return SenderVerification(
        verified,
        "verified" if verified else "invalid",
        SenderKeyChange(
            agent_id=agent_id,
            previous_fingerprint=previous,
            current_fingerprint=current,
        ),
    )


def verify_envelope_sender_sync(
    kid: str,
    payload: bytes,
    signature: bytes,
    client: SyncHttpClient,
    expected_sender_agent_id: str,
) -> SenderVerification:
    """Verify an envelope's sender signature synchronously.

    The envelope's key id is held against ``expected_sender_agent_id`` first, and
    a mismatch returns ``"sender-mismatch"`` without reading any key: whose
    signature this is has already been decided by then, and no answer from the
    key endpoint can change it. A signature stays valid wherever it is carried,
    so this comparison is what ties one to the message it arrived in.

    If a CACHED key yields a verify failure the sender may have rotated keys
    mid-TTL, so refetch once bypassing the cache before declaring the signature
    invalid. Exactly one refetch per call — whoever answers the key endpoint
    chooses the second answer, so retrying until something verifies would hand
    them an oracle. A genuinely fresh fetch that fails is not re-fetched.

    Args:
        kid: The envelope's key id, naming the sending agent.
        payload: The signed bytes.
        signature: The envelope's Ed25519 signature.
        client: HTTP client used to read the sender's published keys.
        expected_sender_agent_id: The sender the server authenticated for this
            message (its ``from_agent_id``). Never a value read off the envelope
            or the payload, which the sender chooses.

    Returns:
        The verdict, carrying a key change when the refetch found one.
    """
    try:
        agent_id = agent_id_from_kid(kid)
        if not _sender_matches(agent_id, expected_sender_agent_id):
            return SenderVerification(False, "sender-mismatch")
        keys, from_cache = get_agent_keys_sync(client, agent_id)
        verified = _verify_with_keys(keys, payload, signature)
        if verified or not from_cache:
            return _verdict(verified)
        fresh, _ = get_agent_keys_sync(client, agent_id, bypass=True)
        return _rotation_verdict(agent_id, keys, fresh, payload, signature)
    except (KeyError, ValueError, CryptoError):
        logger.debug("Could not verify sender %s (malformed key)", kid, exc_info=True)
        return SenderVerification(False, "unverifiable")
    except (httpx.HTTPError, APIConnectionError, APITimeoutError, RineApiError):
        logger.debug("Could not verify sender %s (network)", kid, exc_info=True)
        return SenderVerification(False, "unverifiable")


async def verify_envelope_sender_async(
    kid: str,
    payload: bytes,
    signature: bytes,
    client: AsyncHttpClient,
    expected_sender_agent_id: str,
) -> SenderVerification:
    """Verify an envelope's sender signature asynchronously.

    Mirrors :func:`verify_envelope_sender_sync`, including the sender comparison
    that precedes every key read and the cache-gated verify-failure refetch: only
    a CACHED key that fails is re-fetched.

    Args:
        kid: The envelope's key id, naming the sending agent.
        payload: The signed bytes.
        signature: The envelope's Ed25519 signature.
        client: Async HTTP client used to read the sender's published keys.
        expected_sender_agent_id: The sender the server authenticated for this
            message (its ``from_agent_id``).

    Returns:
        The verdict, carrying a key change when the refetch found one.
    """
    try:
        agent_id = agent_id_from_kid(kid)
        if not _sender_matches(agent_id, expected_sender_agent_id):
            return SenderVerification(False, "sender-mismatch")
        keys, from_cache = await get_agent_keys_async(client, agent_id)
        verified = _verify_with_keys(keys, payload, signature)
        if verified or not from_cache:
            return _verdict(verified)
        fresh, _ = await get_agent_keys_async(client, agent_id, bypass=True)
        return _rotation_verdict(agent_id, keys, fresh, payload, signature)
    except (KeyError, ValueError, CryptoError):
        logger.debug("Could not verify sender %s (malformed key)", kid, exc_info=True)
        return SenderVerification(False, "unverifiable")
    except (httpx.HTTPError, APIConnectionError, APITimeoutError, RineApiError):
        logger.debug("Could not verify sender %s (network)", kid, exc_info=True)
        return SenderVerification(False, "unverifiable")
