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

from typing import TYPE_CHECKING

from rine._crypto._agent_keys import (
    get_agent_keys_async,
    get_agent_keys_sync,
)
from rine._crypto._sender_verdict import (
    KEY_READ_ERRORS,
    GenStep,
    SenderVerification,
    failure_verdict,
    gen_step,
    is_authenticity_failure,
    rotation_verdict,
    sender_matches,
    signer_ref,
    signing_key_fingerprint,
    verdict,
    verify_with_keys,
)
from rine.errors import SenderMismatchError, SignatureVerificationError
from rine.types import VerificationStatus

if TYPE_CHECKING:
    from datetime import datetime

    from rine._crypto.sign import SigScope
    from rine._http import AsyncHttpClient, SyncHttpClient

__all__ = [
    "SenderVerification",
    "VerificationStatus",
    "is_authenticity_failure",
    "refuse_if_inauthentic",
    "refuse_if_sender_differs",
    "refuse_if_state_not_owned_by",
    "signing_key_fingerprint",
    "verify_envelope_sender_async",
    "verify_envelope_sender_sync",
]

_SENDER_MISMATCH_DETAIL = "Envelope sender does not match the message sender"


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
    if signer_ref(sender_kid, expected_sender_agent_id) is None:
        raise SenderMismatchError(_SENDER_MISMATCH_DETAIL)


def refuse_if_state_not_owned_by(state_owner_agent_id: str, expected_sender_agent_id: str) -> None:
    """Refuse a sender-key state that its owner did not file for this message's sender.

    Every member of an open group holds every member's chain key, so a message
    can open under a key that is not its signer's. Whoever posts it is verified
    as itself, but the ratchet it would advance and persist is another agent's:
    that would spend or skip the owner's next indexes. A state belongs only to
    the sender the server authenticated for the message that opened it.

    Raises:
        SenderMismatchError: The state is another agent's.
    """
    if not sender_matches(state_owner_agent_id, expected_sender_agent_id):
        raise SenderMismatchError(_SENDER_MISMATCH_DETAIL)


def verify_envelope_sender_sync(
    kid: str,
    payload: bytes,
    signature: bytes,
    scope: SigScope,
    client: SyncHttpClient,
    expected_sender_agent_id: str,
    created_at: datetime | None = None,
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
        scope: The recipient agent or group the signature must be addressed to.
        client: HTTP client used to read the sender's published keys.
        expected_sender_agent_id: The sender the server authenticated for this
            message (its ``from_agent_id``). Never a value read off the envelope
            or the payload, which the sender chooses.
        created_at: The message's server ``created_at``. A signature under a generation
            the sender has since rotated away verifies only for a row stamped at or before
            that generation's ``superseded_at``, and one by a revoked agent only for a
            row stamped at or before its ``revoked_at``; without it such a signature
            is ``"invalid"``.

    Returns:
        The verdict, carrying a key change when the refetch found one.
    """
    try:
        ref = signer_ref(kid, expected_sender_agent_id)
        if ref is None:
            return SenderVerification(False, "sender-mismatch")
        agent_id = ref.agent_id
        keys, from_cache = get_agent_keys_sync(client, agent_id)
        step = gen_step(ref.key_gen, keys, from_cache)
        if step is GenStep.REFRESH:
            fresh, _ = get_agent_keys_sync(client, agent_id, bypass=True)
            step = gen_step(ref.key_gen, fresh, False)
            if step is GenStep.VERIFY:
                return rotation_verdict(
                    agent_id, keys, fresh, scope, payload, signature, created_at
                )
            keys, from_cache = fresh, False
        if step is GenStep.INVALID:
            return verdict(False)
        historical = step is GenStep.HISTORY
        if historical:
            keys, _ = get_agent_keys_sync(client, agent_id, gen=ref.key_gen)
            from_cache = False
        verified = verify_with_keys(
            keys, scope, payload, signature, created_at, historical=historical
        )
        if verified or not from_cache:
            return verdict(verified)
        fresh, _ = get_agent_keys_sync(client, agent_id, bypass=True)
        return rotation_verdict(agent_id, keys, fresh, scope, payload, signature, created_at)
    except KEY_READ_ERRORS as error:
        return failure_verdict(kid, error)


async def verify_envelope_sender_async(
    kid: str,
    payload: bytes,
    signature: bytes,
    scope: SigScope,
    client: AsyncHttpClient,
    expected_sender_agent_id: str,
    created_at: datetime | None = None,
) -> SenderVerification:
    """Verify an envelope's sender signature asynchronously.

    Mirrors :func:`verify_envelope_sender_sync`, including the sender comparison
    that precedes every key read and the cache-gated verify-failure refetch: only
    a CACHED key that fails is re-fetched.

    Args:
        kid: The envelope's key id, naming the sending agent.
        payload: The signed bytes.
        signature: The envelope's Ed25519 signature.
        scope: The recipient agent or group the signature must be addressed to.
        client: Async HTTP client used to read the sender's published keys.
        expected_sender_agent_id: The sender the server authenticated for this
            message (its ``from_agent_id``).
        created_at: The message's server ``created_at`` (see the sync twin).

    Returns:
        The verdict, carrying a key change when the refetch found one.
    """
    try:
        ref = signer_ref(kid, expected_sender_agent_id)
        if ref is None:
            return SenderVerification(False, "sender-mismatch")
        agent_id = ref.agent_id
        keys, from_cache = await get_agent_keys_async(client, agent_id)
        step = gen_step(ref.key_gen, keys, from_cache)
        if step is GenStep.REFRESH:
            fresh, _ = await get_agent_keys_async(client, agent_id, bypass=True)
            step = gen_step(ref.key_gen, fresh, False)
            if step is GenStep.VERIFY:
                return rotation_verdict(
                    agent_id, keys, fresh, scope, payload, signature, created_at
                )
            keys, from_cache = fresh, False
        if step is GenStep.INVALID:
            return verdict(False)
        historical = step is GenStep.HISTORY
        if historical:
            keys, _ = await get_agent_keys_async(client, agent_id, gen=ref.key_gen)
            from_cache = False
        verified = verify_with_keys(
            keys, scope, payload, signature, created_at, historical=historical
        )
        if verified or not from_cache:
            return verdict(verified)
        fresh, _ = await get_agent_keys_async(client, agent_id, bypass=True)
        return rotation_verdict(agent_id, keys, fresh, scope, payload, signature, created_at)
    except KEY_READ_ERRORS as error:
        return failure_verdict(kid, error)
