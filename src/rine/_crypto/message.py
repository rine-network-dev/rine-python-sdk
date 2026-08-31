"""High-level message encrypt/decrypt orchestration.

Wires together key loading, signing, envelope encoding, and HPKE/Sender Key
encryption, then hands each decrypted envelope to
:mod:`rine._crypto._sender_verify` and persists the sender key state.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from rine._constants import EncryptionVersion
from rine._crypto._sender_verify import (
    refuse_if_inauthentic,
    verify_envelope_sender_async,
    verify_envelope_sender_sync,
)
from rine._crypto.dm_envelope import (
    RecipientKeys,
    open_dm,
    seal_to_recipient,
    seal_to_self,
)
from rine._crypto.envelope import decode_envelope, encode_envelope
from rine._crypto.group_read_cache import lookup_group_read, record_group_read
from rine._crypto.keys import load_agent_keys, make_kid, public_keys_body
from rine._crypto.sender_keys import (
    SenderKeyState,
    derive_message_key,
    open_group,
    seal_group,
)
from rine._crypto.sender_keys_helpers import (
    load_sender_key_states,
    save_sender_key_state,
    sender_keys_retired,
)
from rine._crypto.sign import sign_payload
from rine._utils import from_base64url, to_base64url

if TYPE_CHECKING:
    from rine._http import AsyncHttpClient, SyncHttpClient
    from rine._mls.sync import MlsSyncResult
    from rine.types import SenderKeyChange, VerificationStatus


class EncryptResult:
    """Result of encrypting a message.

    ``self_encrypted_payload`` is a second ciphertext of the same envelope sealed
    to the SENDER's own key, set only for 1:1 sends (``encrypt_message``) so the
    sender can later self-read its own message via ``thread()``. It is ``None``
    for group sends (groups self-read via the sender-key cache, not a self-blob).
    The self-blob follows the SENDER's own post-quantum capability — hybrid when
    the sender has an ML-KEM key, classical otherwise — independent of the
    version negotiated for the recipient.
    """

    __slots__ = (
        "encrypted_payload",
        "encryption_version",
        "sender_signing_kid",
        "self_encrypted_payload",
    )

    def __init__(
        self,
        encrypted_payload: str,
        encryption_version: str,
        kid: str,
        self_encrypted_payload: str | None = None,
    ) -> None:
        self.encrypted_payload = encrypted_payload
        self.encryption_version = encryption_version
        self.sender_signing_kid = kid
        self.self_encrypted_payload = self_encrypted_payload


class DecryptResult:
    """Result of decrypting a message.

    ``key_changed`` carries the sender's key rotation when verification found
    one, so every receive surface can pass it on instead of dropping it.

    ``catch_up`` carries what reading this row did to the group's local MLS
    state. It is set by the MLS read path alone — the sender-key regime has no
    epochs to advance — and it is present whenever that read ran a sync, which
    includes the ordinary case of a current member with nothing to apply:
    ``processed`` is then ``0``, and that is a report, not an absence. ``None``
    means no sync ran at all — the one-minute floor declined it
    (:data:`~rine._mls.catchup.MLS_CATCHUP_MIN_INTERVAL_S`), it failed, or this
    was never an MLS read — so ``None`` is "nothing was done", never "you are
    current".
    """

    __slots__ = (
        "catch_up",
        "key_changed",
        "plaintext",
        "sender_kid",
        "verified",
        "verification_status",
    )

    def __init__(
        self,
        plaintext: str,
        sender_kid: str,
        verified: bool,
        verification_status: VerificationStatus,
        key_changed: SenderKeyChange | None = None,
        catch_up: MlsSyncResult | None = None,
    ) -> None:
        self.plaintext = plaintext
        self.sender_kid = sender_kid
        self.verified = verified
        self.verification_status = verification_status
        self.key_changed = key_changed
        self.catch_up = catch_up

    def as_replay(self) -> DecryptResult:
        """This result as a *later* read of the same row must report it.

        Same plaintext, same verdict, no catch-up: a read answered from the
        memo applied no commits and advanced no epoch, and reporting the first
        read's work again would make the field a lie the second time it is
        read. Used where the memo stores a result, not where it returns one —
        the read that did the work still reports it.
        """
        return DecryptResult(
            self.plaintext,
            self.sender_kid,
            self.verified,
            self.verification_status,
            self.key_changed,
        )


def encrypt_message(
    config_dir: str,
    sender_agent_id: str,
    recipient: RecipientKeys,
    payload: object,
) -> EncryptResult:
    """Encrypt a 1:1 message, post-quantum when the recipient allows it.

    Args:
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        recipient: Recipient's published encryption keys. A recipient that
            publishes an ML-KEM key gets ``hpke-hybrid-v1``; one that does not
            gets ``hpke-v1``.
        payload: JSON-serializable message payload.

    Returns:
        EncryptResult with base64url-encoded encrypted payload and a
        ``self_encrypted_payload`` copy sealed to the sender's own keys so the
        sender can self-read its own message later.
    """
    keys = load_agent_keys(config_dir, sender_agent_id)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    kid = make_kid(sender_agent_id)
    signature = sign_payload(keys.signing.private_key, plaintext)
    envelope = encode_envelope(kid, signature, plaintext)

    encrypted, version = seal_to_recipient(recipient, envelope)
    self_sealed = seal_to_self(keys, envelope)

    return EncryptResult(
        encrypted_payload=to_base64url(encrypted),
        encryption_version=version,
        kid=kid,
        self_encrypted_payload=to_base64url(self_sealed),
    )


def decrypt_message_sync(
    config_dir: str,
    recipient_agent_id: str,
    encrypted_payload_b64: str,
    client: SyncHttpClient,
    from_agent_id: str,
) -> DecryptResult:
    """Decrypt a 1:1 message, classical or post-quantum (sync).

    The payload's own version byte picks the envelope, so the same call reads
    ``hpke-v1`` and ``hpke-hybrid-v1``.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: HTTP client for fetching sender's public keys.
        from_agent_id: The sender the server authenticated for this message
            (its ``from_agent_id``). The envelope's own key id is refused unless
            it names this agent.

    Returns:
        DecryptResult with plaintext and verification status.

    Raises:
        SignatureVerificationError: The signature is forged, or the envelope
            names a signer other than the message's sender.
    """
    keys = load_agent_keys(config_dir, recipient_agent_id)
    encrypted = from_base64url(encrypted_payload_b64)
    envelope_bytes = open_dm(keys, encrypted)
    decoded = decode_envelope(envelope_bytes)
    plaintext = decoded.payload.decode("utf-8")

    verification = verify_envelope_sender_sync(
        decoded.kid, decoded.payload, decoded.signature, client, from_agent_id
    )
    refuse_if_inauthentic(verification)
    return DecryptResult(
        plaintext,
        decoded.kid,
        verification.verified,
        verification.verification_status,
        verification.key_changed,
    )


async def decrypt_message_async(
    config_dir: str,
    recipient_agent_id: str,
    encrypted_payload_b64: str,
    client: AsyncHttpClient,
    from_agent_id: str,
) -> DecryptResult:
    """Decrypt a 1:1 message, classical or post-quantum (async).

    Mirrors :func:`decrypt_message_sync`, including the version-byte dispatch and
    the sender comparison.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: Async HTTP client for fetching sender's public keys.
        from_agent_id: The sender the server authenticated for this message
            (its ``from_agent_id``). The envelope's own key id is refused unless
            it names this agent.

    Returns:
        DecryptResult with plaintext and verification status.

    Raises:
        SignatureVerificationError: The signature is forged, or the envelope
            names a signer other than the message's sender.
    """
    keys = load_agent_keys(config_dir, recipient_agent_id)
    encrypted = from_base64url(encrypted_payload_b64)
    envelope_bytes = open_dm(keys, encrypted)
    decoded = decode_envelope(envelope_bytes)
    plaintext = decoded.payload.decode("utf-8")

    verification = await verify_envelope_sender_async(
        decoded.kid, decoded.payload, decoded.signature, client, from_agent_id
    )
    refuse_if_inauthentic(verification)
    return DecryptResult(
        plaintext,
        decoded.kid,
        verification.verified,
        verification.verification_status,
        verification.key_changed,
    )


def encrypt_group_message(
    config_dir: str,
    sender_agent_id: str,
    group_id: str,
    sender_key_state: SenderKeyState,
    payload: object,
) -> tuple[EncryptResult, SenderKeyState]:
    """Encrypt a group message with sender keys.

    Caches the message key for sender self-read before advancing the ratchet.

    Args:
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        group_id: Group UUID.
        sender_key_state: Current sender key state.
        payload: JSON-serializable message payload.

    Returns:
        Tuple of (EncryptResult, updated SenderKeyState).
    """
    keys = load_agent_keys(config_dir, sender_agent_id)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    kid = make_kid(sender_agent_id)

    # Pre-derive message key for self-read cache
    self_read_key, _ = derive_message_key(sender_key_state.chain_key)
    self_read_index = sender_key_state.message_index

    encrypted_payload, updated = seal_group(
        keys.signing.private_key, kid, sender_key_state, plaintext
    )

    # Cache for sender self-read
    updated.skipped_keys[self_read_index] = to_base64url(self_read_key)

    # Persist state
    all_states = load_sender_key_states(config_dir, sender_agent_id, group_id)
    other_states = [s for s in all_states if s.sender_key_id != updated.sender_key_id]
    save_sender_key_state(config_dir, sender_agent_id, group_id, [*other_states, updated])

    return (
        EncryptResult(
            encrypted_payload=to_base64url(encrypted_payload),
            encryption_version=EncryptionVersion.SENDER_KEY_V1,
            kid=kid,
        ),
        updated,
    )


def _assert_sender_key_regime(config_dir: str, recipient_agent_id: str, group_id: str) -> None:
    """Refuse a sender-key row for a group this agent holds MLS state for.

    A ``sender-key-v1`` row IS the server saying this group is not MLS, so the
    guard takes ``False`` for that claim. Holding no state is not evidence of
    anything — a billboard group, a member whose Welcome has not landed and a
    fresh install all hold none, and all decrypt. It runs before the ratchet is
    touched AND before the read cache is consulted, so a replay can never answer
    a row the guard would have refused.
    """
    # Imported here, not at module scope: this module also serves the 1:1 DM
    # path, which must not pull in the compiled group stack.
    from rine._mls.downgrade import assert_no_mls_downgrade

    assert_no_mls_downgrade(config_dir, recipient_agent_id, group_id, False)


def _replayed_envelope(
    config_dir: str, recipient_agent_id: str, group_id: str, encrypted_payload_b64: str
) -> Any:
    """The envelope this agent already opened out of these bytes, or ``None``.

    🔴 A retirement marker closes the cache with everything else. A leave
    already deletes it, so this is the case where the two disagree: a message
    opened while the marker was absent must stop opening when it is back, or
    the marker would be a thing that cannot be re-armed.
    """
    if sender_keys_retired(config_dir, recipient_agent_id, group_id):
        return None
    cached = lookup_group_read(
        config_dir, recipient_agent_id, group_id, from_base64url(encrypted_payload_b64)
    )
    return None if cached is None else decode_envelope(cached)


def _record_read(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    decoded: Any,
) -> None:
    """Keep the envelope so the next read of this row needs no ratchet step."""
    record_group_read(
        config_dir,
        recipient_agent_id,
        group_id,
        from_base64url(encrypted_payload_b64),
        encode_envelope(decoded.kid, decoded.signature, decoded.payload),
    )


def _group_result(decoded: Any, verification: Any) -> DecryptResult:
    """One decrypt result, whether the envelope came from the ratchet or the cache."""
    return DecryptResult(
        decoded.payload.decode("utf-8"),
        decoded.kid,
        verification.verified,
        verification.verification_status,
        verification.key_changed,
    )


def _decrypt_group_core(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
) -> tuple[Any, str, int, SenderKeyState, dict[str, SenderKeyState]]:
    """Common group decryption logic (parse + decrypt, before verification)."""
    states = load_sender_key_states(config_dir, recipient_agent_id, group_id)
    state_map = {s.sender_key_id: s for s in states}

    encrypted = from_base64url(encrypted_payload_b64)
    inner_envelope, sender_key_id, message_index, updated = open_group(state_map, encrypted)
    decoded = decode_envelope(inner_envelope)

    state_map[sender_key_id] = updated
    return decoded, sender_key_id, message_index, updated, state_map


def decrypt_group_message_sync(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    client: SyncHttpClient,
    from_agent_id: str,
) -> DecryptResult:
    """Decrypt a group message (sync).

    Verifies the sender before persisting ratchet state, so a refused message
    leaves the ratchet where it was.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        group_id: Group UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: HTTP client for fetching sender's public keys.
        from_agent_id: The sender the server authenticated for this message
            (its ``from_agent_id``). The envelope's own key id is refused unless
            it names this agent.

    Returns:
        DecryptResult with plaintext and verification status.

    Raises:
        SignatureVerificationError: The signature is forged, or the envelope
            names a signer other than the message's sender (state NOT persisted).
    """
    _assert_sender_key_regime(config_dir, recipient_agent_id, group_id)

    # A row this agent has already opened is answered from its own read cache:
    # the ratchet spends the message key at the first decrypt and cannot be
    # asked twice. The envelope is verified here exactly as a first read is.
    replay = _replayed_envelope(config_dir, recipient_agent_id, group_id, encrypted_payload_b64)
    if replay is not None:
        verification = verify_envelope_sender_sync(
            replay.kid, replay.payload, replay.signature, client, from_agent_id
        )
        refuse_if_inauthentic(verification)
        return _group_result(replay, verification)

    decoded, sender_key_id, message_index, updated, state_map = _decrypt_group_core(
        config_dir, recipient_agent_id, group_id, encrypted_payload_b64
    )

    verification = verify_envelope_sender_sync(
        decoded.kid, decoded.payload, decoded.signature, client, from_agent_id
    )

    refuse_if_inauthentic(verification)

    # Preserve self-read keys for own sender key
    if updated.sender_agent_id == recipient_agent_id:
        prev = {
            s.sender_key_id: s
            for s in load_sender_key_states(config_dir, recipient_agent_id, group_id)
        }.get(updated.sender_key_id)
        if prev and message_index in (prev.skipped_keys or {}):
            cached = prev.skipped_keys[message_index]
            if message_index not in updated.skipped_keys:
                updated.skipped_keys[message_index] = cached

    save_sender_key_state(config_dir, recipient_agent_id, group_id, list(state_map.values()))
    _record_read(config_dir, recipient_agent_id, group_id, encrypted_payload_b64, decoded)
    return _group_result(decoded, verification)


async def decrypt_group_message_async(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    client: AsyncHttpClient,
    from_agent_id: str,
) -> DecryptResult:
    """Decrypt a group message (async).

    Mirrors :func:`decrypt_group_message_sync`, verifying the sender before
    persisting ratchet state.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        group_id: Group UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: Async HTTP client for fetching sender's public keys.
        from_agent_id: The sender the server authenticated for this message
            (its ``from_agent_id``). The envelope's own key id is refused unless
            it names this agent.

    Returns:
        DecryptResult with plaintext and verification status.

    Raises:
        SignatureVerificationError: The signature is forged, or the envelope
            names a signer other than the message's sender (state NOT persisted).
    """
    _assert_sender_key_regime(config_dir, recipient_agent_id, group_id)

    replay = _replayed_envelope(config_dir, recipient_agent_id, group_id, encrypted_payload_b64)
    if replay is not None:
        verification = await verify_envelope_sender_async(
            replay.kid, replay.payload, replay.signature, client, from_agent_id
        )
        refuse_if_inauthentic(verification)
        return _group_result(replay, verification)

    decoded, sender_key_id, message_index, updated, state_map = _decrypt_group_core(
        config_dir, recipient_agent_id, group_id, encrypted_payload_b64
    )

    verification = await verify_envelope_sender_async(
        decoded.kid, decoded.payload, decoded.signature, client, from_agent_id
    )

    refuse_if_inauthentic(verification)

    if updated.sender_agent_id == recipient_agent_id:
        prev_states = load_sender_key_states(config_dir, recipient_agent_id, group_id)
        prev = {s.sender_key_id: s for s in prev_states}.get(updated.sender_key_id)
        if prev and message_index in (prev.skipped_keys or {}):
            cached = prev.skipped_keys[message_index]
            if message_index not in updated.skipped_keys:
                updated.skipped_keys[message_index] = cached

    save_sender_key_state(config_dir, recipient_agent_id, group_id, list(state_map.values()))
    _record_read(config_dir, recipient_agent_id, group_id, encrypted_payload_b64, decoded)
    return _group_result(decoded, verification)


def get_agent_public_keys(config_dir: str, agent_id: str) -> dict[str, dict[str, str]]:
    """Get an agent's public keys in their published form.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        Dict with ``signing_public_key`` and ``encryption_public_key``, plus
        ``pq_encryption_public_key`` when the agent has a post-quantum key.
    """
    return public_keys_body(load_agent_keys(config_dir, agent_id))
