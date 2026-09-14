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
from rine._crypto.sender_keys_store import (
    merge_sender_key_states,
    states_from_sender,
    with_sender_key_states,
    with_sender_key_states_sync,
)
from rine._crypto.sign import sign_payload
from rine._utils import from_base64url, to_base64url
from rine.errors import UnpersistedSenderKeyStateError

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

    # 🔴 The THIRD read-modify-write of this group's state file, and it is HELD:
    # the load and the save below sit in one
    # :func:`rine._crypto.sender_keys_store.with_sender_key_states_sync` region,
    # the thread tier, because this whole function runs on the worker thread the
    # async send hands it to and an :class:`asyncio.Lock` cannot reach a thread.
    # "No ``await`` between the load and the save" was never the argument that
    # made this safe — it excludes other COROUTINES and nothing else, and the
    # writer this site actually races is another thread. Do not put an await
    # between them even so: this is a sync function, and making it async would
    # reopen the coroutine half against a lock this side cannot poll for.
    #
    # 🔴 The reverse direction is a KNOWN RESIDUAL and is not closed: a decrypt of
    # this agent's own past post holds the file's lock across its network verify
    # and merges under this same ``sender_key_id``, so a send landing in that
    # window is overwritten by the holder's pre-network copy — a message index
    # re-used across two posts, and the sender's own self-read key for one of them
    # gone. Taking the lock here would order the two writes and still not fix it:
    # ``seal_group`` has already consumed the chain key from the snapshot this
    # function was handed. Closing it means the send re-deriving under the lock,
    # which is a design change to the send path, not a lock placement.
    #
    # 🔴 Written back IN PLACE, and NOT written back at all if the row is gone.
    # ``rine._sender_key_ops.get_or_create_sender_key_sync`` reads the LAST own
    # entry as the current key, so position here is not cosmetic — it decides what
    # the next send seals under. This used to filter the row out and re-append it
    # last, which is wrong in both directions once a concurrent rotation lands
    # during a send:
    #
    # * The rotation retains the state it superseded BELOW the new one, so
    #   re-appending this row moved a SUPERSEDED key back to last and the next
    #   send sealed under a key this agent had already rotated away from.
    # * Where the rotation did not retain it, the re-append RESURRECTED a row the
    #   rotation had deliberately dropped, with the same result, and it re-created
    #   the state file of a group this agent had already left.
    #
    # Both are fixed by the same move: find the row by id and replace it where it
    # already sits, and if it is not there, do nothing. A key that was rotated away
    # or retired mid-send has nothing worth recording — the message it sealed is
    # already out, and its chain advance is only meaningful to a key nobody will
    # send under again. Absent therefore means retired, never new: the state was
    # saved by ``get_or_create_sender_key_sync`` before this function ever saw it.
    # This is the shape
    # :func:`rine._crypto.sender_keys_store.merge_sender_key_states` takes for an
    # own row too — it skips one whose (sender, key) pair is not already on disk,
    # for exactly this reason. The two agree only since that fix; the merge used
    # to re-add.
    # Twin: ``crypto/message.ts``, which carried the identical defect.
    #
    # 🔴 "Absent means retired" is a claim about WHICH absence, and the three
    # cases are told apart rather than collapsed. A row gone from a file that
    # still names other keys of this agent's was dropped by a rotation; a group
    # with no file and a retirement marker was left. Both are silent, because
    # both are the state file correctly having moved on. Absent with NO own row
    # anywhere and NO retirement is neither: nothing ever persisted the state
    # this call was handed, so the ratchet advance and the self-read key are
    # about to be discarded for a message that is already sealed. Every in-tree
    # caller comes through ``get_or_create_sender_key_sync``, which saves before
    # it returns — but this function is reachable from outside that path, and a
    # silent discard there is a real, transmittable message whose sender can
    # never read it back. It is refused instead.
    with with_sender_key_states_sync(config_dir, sender_agent_id, group_id):
        all_states = load_sender_key_states(config_dir, sender_agent_id, group_id)
        # 🔴 By the (sender, key) pair, never the key id alone: a peer may legitimately
        # hold a row under an id this agent also uses, and a write that matched on the id
        # would overwrite THAT peer's chain key with this agent's own state — losing the
        # peer's key for good, on an ordinary send.
        own = states_from_sender(all_states, sender_agent_id)
        target = next((s for s in own if s.sender_key_id == updated.sender_key_id), None)
        if target is not None:
            save_sender_key_state(
                config_dir,
                sender_agent_id,
                group_id,
                [updated if s is target else s for s in all_states],
            )
        elif not own and not sender_keys_retired(config_dir, sender_agent_id, group_id):
            raise UnpersistedSenderKeyStateError(updated.sender_key_id, group_id)

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


def _replay_result_sync(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    client: SyncHttpClient,
    from_agent_id: str,
) -> DecryptResult | None:
    """The cached answer for a row this agent already opened, or ``None`` (sync).

    The synchronous twin of :func:`_replay_result_async`, and it exists as a
    function for the same reason that one does: the cache is consulted twice per
    decrypt — once before the state file's lock and once inside it — and the two
    consultations must be the same check, including the signature verify.
    """
    replay = _replayed_envelope(config_dir, recipient_agent_id, group_id, encrypted_payload_b64)
    if replay is None:
        return None
    verification = verify_envelope_sender_sync(
        replay.kid, replay.payload, replay.signature, client, from_agent_id
    )
    refuse_if_inauthentic(verification)
    return _group_result(replay, verification)


async def _replay_result_async(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    client: AsyncHttpClient,
    from_agent_id: str,
) -> DecryptResult | None:
    """The cached answer for a row this agent already opened, or ``None``.

    A row this agent has already opened is answered from its own read cache: the
    ratchet spends the message key at the first decrypt and cannot be asked twice.
    The envelope is verified here exactly as a first read is, so the cache decides
    only whether the ratchet is touched — never whether the signer is checked.
    """
    replay = _replayed_envelope(config_dir, recipient_agent_id, group_id, encrypted_payload_b64)
    if replay is None:
        return None
    verification = await verify_envelope_sender_async(
        replay.kid, replay.payload, replay.signature, client, from_agent_id
    )
    refuse_if_inauthentic(verification)
    return _group_result(replay, verification)


def _group_result(decoded: Any, verification: Any) -> DecryptResult:
    """One decrypt result, whether the envelope came from the ratchet or the cache."""
    return DecryptResult(
        decoded.payload.decode("utf-8"),
        decoded.kid,
        verification.verified,
        verification.verification_status,
        verification.key_changed,
    )


def _own_row(
    config_dir: str, agent_id: str, group_id: str, sender_key_id: str
) -> SenderKeyState | None:
    """This agent's own row for one key, re-read from disk, or ``None``.

    Scoped to the agent as well as the key: the self-read cache spliced out of the
    row found here is message-key material, and a peer holding a row under the same
    id would otherwise hand this decrypt a cached key for a message it never sent.
    """
    states = load_sender_key_states(config_dir, agent_id, group_id)
    return next(
        (s for s in states_from_sender(states, agent_id) if s.sender_key_id == sender_key_id),
        None,
    )


def _decrypt_group_core(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    from_agent_id: str,
) -> tuple[Any, str, int, SenderKeyState]:
    """Common group decryption logic (parse + decrypt, before verification).

    🔴 A row from *from_agent_id* — the sender the SERVER stamped on this message —
    WINS any sender key id it shares. The file may legitimately hold two rows under
    one id, because the distribution ingest scopes its already-held check to the
    (sender, key) pair so that claiming a peer's id first cannot take its slot; a
    map built over the whole array in one pass then keeps whichever landed last,
    which is an attacker's row by construction. The honest peer's posts open against
    the wrong chain key and stop rendering, and re-planting after every decrypt makes
    it permanent — a refusal that reads as a crypto regression.

    Expressed as a preference rather than a filter, and both halves are deliberate.
    Preferring rather than keying the map on the pair keeps
    :func:`rine._crypto.sender_keys.open_group`'s contract, which sees only the key
    id the wire carries. Preferring rather than FILTERING keeps the refusals this
    path already gives: a message whose key belongs to an agent other than the one
    the server named still opens far enough to be refused as a sender mismatch,
    which is the true sentence about it, instead of becoming an absent-key refusal
    that invites the reader to ask the sender to post again.

    *from_agent_id* is already this path's trusted authority — it is what the
    envelope's own kid is refused against — and a reader's own posts name the
    reader, so self-read is unaffected.
    """
    on_disk = load_sender_key_states(config_dir, recipient_agent_id, group_id)
    state_map = {s.sender_key_id: s for s in on_disk}
    state_map.update({s.sender_key_id: s for s in states_from_sender(on_disk, from_agent_id)})

    encrypted = from_base64url(encrypted_payload_b64)
    inner_envelope, sender_key_id, message_index, updated = open_group(state_map, encrypted)
    decoded = decode_envelope(inner_envelope)

    return decoded, sender_key_id, message_index, updated


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
    replayed = _replay_result_sync(
        config_dir, recipient_agent_id, group_id, encrypted_payload_b64, client, from_agent_id
    )
    if replayed is not None:
        return replayed

    # 🔴 Everything below is ONE read-modify-write across a network verify, and it
    # runs under this file's THREAD lock — the tier a sync caller can take, since
    # this function is reached both from the sync client's own thread and from the
    # worker thread the async client hands its group send to. The region, the
    # in-region cache recheck and the merge are the async twin's below, for the
    # reasons documented there; the only difference is which tier of the lock a
    # sync caller is entitled to take. The read cache is consulted a SECOND time
    # inside the region because the ratchet spends a message key exactly once, so
    # a caller that lost the race must be shown the winner's recorded read rather
    # than a spent-key ``CryptoError`` the render path does not recover.
    with with_sender_key_states_sync(config_dir, recipient_agent_id, group_id):
        replayed = _replay_result_sync(
            config_dir, recipient_agent_id, group_id, encrypted_payload_b64, client, from_agent_id
        )
        if replayed is not None:
            return replayed

        decoded, _sender_key_id, message_index, updated = _decrypt_group_core(
            config_dir, recipient_agent_id, group_id, encrypted_payload_b64, from_agent_id
        )

        verification = verify_envelope_sender_sync(
            decoded.kid, decoded.payload, decoded.signature, client, from_agent_id
        )

        refuse_if_inauthentic(verification)

        # Preserve self-read keys for own sender key
        if updated.sender_agent_id == recipient_agent_id:
            prev = _own_row(config_dir, recipient_agent_id, group_id, updated.sender_key_id)
            if prev and message_index in (prev.skipped_keys or {}):
                cached = prev.skipped_keys[message_index]
                if message_index not in updated.skipped_keys:
                    updated.skipped_keys[message_index] = cached

        # Merge rather than assert an array built from a pre-network read, exactly
        # as the async twin below and ``crypto/message.ts`` do. The map this path
        # used to write back was keyed by sender key id over the WHOLE file, so a
        # second row legitimately sharing an id — see :func:`_decrypt_group_core` —
        # was collapsed away by the load and then deleted by the save. The merge
        # asserts the one row this decrypt knows about and says nothing about the
        # rest of the file, which also stops an ingest that landed during the
        # verify from being rolled back.
        merge_sender_key_states(config_dir, recipient_agent_id, group_id, [updated])
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

    replayed = await _replay_result_async(
        config_dir, recipient_agent_id, group_id, encrypted_payload_b64, client, from_agent_id
    )
    if replayed is not None:
        return replayed

    # 🔴 Everything below is ONE read-modify-write of this group's state file
    # across a network verify, so it runs under that file's lock and loads INSIDE
    # it. A transcript render opens many rows against one ratchet, and a
    # background SSE listener decrypts in the same event loop as the foreground
    # render: without the lock each row loads the same array, advances its own
    # copy and writes the whole array back, so every advance but the last is
    # discarded — and a peer key an ingest installed during the verify goes with
    # it. What the reader is then shown is the sealed-message refusal, which
    # claims no later message reopens the row; the next render opens it, so the
    # refusal is a falsehood the product hands its own user.
    #
    # The lock is taken HERE and not by the caller because it is not reentrant
    # and ``_self_heal_group_decrypt`` re-enters this function — from outside,
    # after the first attempt's exception has escaped.
    async with with_sender_key_states(config_dir, recipient_agent_id, group_id):
        # 🔴 The read cache is consulted a SECOND time, inside the region. The
        # ratchet spends a message key exactly once, so two tasks decrypting the
        # same row — a background SSE listener and a foreground render, the shape
        # this lock exists for — both miss the cache outside it and then serialise
        # here. Without this the loser reloads the advanced state, finds no skipped
        # key for an index the winner consumed, and raises "Message key expired or
        # already consumed": a plain ``CryptoError``, which the render path does
        # NOT spend recovery on (``_decrypt_thread_row`` recovers
        # ``NoSenderKeyStateError`` only), so the row renders as the sealed-message
        # refusal — the very symptom the lock is here to remove. The winner records
        # its read inside this region, so the loser is guaranteed to see it.
        replayed = await _replay_result_async(
            config_dir, recipient_agent_id, group_id, encrypted_payload_b64, client, from_agent_id
        )
        if replayed is not None:
            return replayed

        decoded, _sender_key_id, message_index, updated = _decrypt_group_core(
            config_dir, recipient_agent_id, group_id, encrypted_payload_b64, from_agent_id
        )

        verification = await verify_envelope_sender_async(
            decoded.kid, decoded.payload, decoded.signature, client, from_agent_id
        )

        refuse_if_inauthentic(verification)

        if updated.sender_agent_id == recipient_agent_id:
            prev = _own_row(config_dir, recipient_agent_id, group_id, updated.sender_key_id)
            if prev and message_index in (prev.skipped_keys or {}):
                cached = prev.skipped_keys[message_index]
                if message_index not in updated.skipped_keys:
                    updated.skipped_keys[message_index] = cached

        # Merge rather than assert the map: the distribution ingest
        # (``rine._client.RineClient._scan_pending_sk_distributions``) takes no
        # lock, so it can install a peer's key while the verify above awaits.
        # This row knows about one sender key and says so; it says nothing about
        # the rest of the file.
        merge_sender_key_states(config_dir, recipient_agent_id, group_id, [updated])
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
