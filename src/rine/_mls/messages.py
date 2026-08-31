"""``mls-v1`` application messages: one sent, one read.

The MLS ciphertext carries rine's ordinary signed inner envelope (kid + Ed25519
signature + plaintext), exactly as the sender-key path does, so a group moving
from Sender Keys to MLS changes what wraps a message and nothing about what a
message *is*. MLS authenticates the sending leaf; the inner signature is what
binds the message to a rine agent, because the MLS credential layer is
accept-all.

Local state is keyed by the rine group UUID — never the server's ``mls_group_id``
latch — which is what lets one key serve joining, sending and reading.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from rine._constants import EncryptionVersion
from rine._crypto._sender_verify import refuse_if_inauthentic, verify_envelope_sender_sync
from rine._crypto.envelope import decode_envelope, encode_envelope
from rine._crypto.group_read_cache import lookup_group_read, record_group_read
from rine._crypto.keys import load_agent_keys, make_kid
from rine._crypto.message import DecryptResult, EncryptResult
from rine._crypto.sender_keys_helpers import sender_keys_retired
from rine._crypto.sign import sign_payload
from rine._logging import logger
from rine._mls.api import read_group
from rine._mls.catchup import catch_up_mls_group
from rine._mls.failures import group_failures, is_recoverable_mls_failure, mls_boundary
from rine._mls.group_access import open_mls_group
from rine._mls.join import install_mls_state
from rine._mls.sync import MlsSyncResult, sync_mls_group
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

if TYPE_CHECKING:
    from rine.types import GroupRead


@mls_boundary
def encrypt_mls_group_message(
    client: Any, config_dir: str, agent_id: str, group: GroupRead, payload: object
) -> EncryptResult:
    """Encrypt a payload for an MLS group, recovering once if state is missing.

    The group is synced to its current epoch first: a member that joined at a
    later epoch never held the earlier epochs' secrets, so a message sent from a
    stale epoch is one the newest members cannot read.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The sending agent's UUID.
        group: The group, carrying its own MLS latch and ciphersuite.
        payload: JSON-serializable message payload.

    Returns:
        The ``mls-v1`` ciphertext and the sender's signing kid.
    """
    with group_failures(str(group.id)):
        _sync_quietly(client, config_dir, agent_id, group)
        try:
            return _encrypt(config_dir, agent_id, group, payload)
        except Exception as err:
            if not is_recoverable_mls_failure(err):
                raise
            logger.debug("MLS send recovery for group %s", group.id, exc_info=True)
        _recover(client, config_dir, agent_id, group)
        return _encrypt(config_dir, agent_id, group, payload)


@mls_boundary
def decrypt_mls_group_message(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str | None,
    encrypted_payload_b64: str,
    from_agent_id: str,
) -> DecryptResult:
    """Decrypt an ``mls-v1`` message, recovering once if this agent is behind.

    A message this agent sent comes back from the core's self-read cache, which
    is what makes a sender able to read its own thread at all under forward
    secrecy. That cache lives in the Rust core and is shared with the TypeScript
    stack; there is no second Python-side mechanism.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The reading agent's UUID.
        group_id: The rine group the message was sent to. ``None`` is a refusal,
            not a guess: MLS state is keyed by group and there is no other key.
        encrypted_payload_b64: The message's ``encrypted_payload``.
        from_agent_id: The sender the server authenticated for this message (its
            ``from_agent_id``). MLS authenticates the sending leaf; this is what
            ties the inner envelope's signature to a rine agent.

    Raises:
        CryptoError: When the message names no group.
        NoMlsGroupStateError: When recovery could not establish state.
        MlsError: For every other refusal from the core, carrying its stable
            ``code`` — including ``RINE_MLS_SELF_MESSAGE_NOT_CACHED``, this
            agent's own message whose plaintext has aged out, which no sync can
            bring back and which is therefore not retried.
        SignatureVerificationError: When the inner envelope's signature is
            forged, or names a signer other than the message's sender.
    """
    if group_id is None:
        raise CryptoError(
            "An mls-v1 message names no group, so there is no MLS state to open "
            "it with. This is a malformed message, not a missing key."
        )
    payload = from_base64url(encrypted_payload_b64)
    with group_failures(group_id):
        try:
            result = _decrypt(
                client, config_dir, agent_id, group_id, payload, from_agent_id, cipher_suite=None
            )
        except Exception as err:
            if not is_recoverable_mls_failure(err):
                raise
            logger.debug("MLS read recovery for group %s", group_id, exc_info=True)
        else:
            # A read that worked is the ordinary case, and it is the one that
            # used to leave a member drifting: nothing here ever advanced the
            # epoch unless a decrypt had already failed. The catch-up is
            # rate-limited and never raises, so the answer above is returned
            # either way — carrying what the catch-up did, when it did anything.
            result.catch_up = catch_up_mls_group(client, config_dir, agent_id, group_id)
            return result

        # One-shot recovery: install any pending Welcome (which establishes state
        # for a group just joined), self-join if that left none, then apply the
        # commits posted since our epoch. It is what makes a re-invited agent's
        # first read work: the eviction is only final once this has run.
        group = read_group(client, agent_id, group_id)
        recovered = _recover(client, config_dir, agent_id, group)
        result = _decrypt(
            client,
            config_dir,
            agent_id,
            group_id,
            payload,
            from_agent_id,
            cipher_suite=group.mls_cipher_suite,
        )
        result.catch_up = recovered
        return result


def _encrypt(config_dir: str, agent_id: str, group: GroupRead, payload: object) -> EncryptResult:
    mls = open_mls_group(config_dir, agent_id, str(group.id), cipher_suite=group.mls_cipher_suite)
    keys = load_agent_keys(config_dir, agent_id)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    kid = make_kid(agent_id)
    envelope = encode_envelope(kid, sign_payload(keys.signing.private_key, plaintext), plaintext)

    # The core frames the payload with its own version tag and records the
    # envelope in its self-read cache, so the sender can read back a message its
    # own ratchet has already advanced past.
    ciphertext = mls.encrypt_application_message(envelope)
    mls.save()
    return EncryptResult(
        encrypted_payload=to_base64url(ciphertext),
        encryption_version=EncryptionVersion.MLS_V1,
        kid=kid,
    )


def _decrypt(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    payload: bytes,
    from_agent_id: str,
    *,
    cipher_suite: int | None,
) -> DecryptResult:
    # A row this agent has already opened is answered from its own read cache.
    # MLS consumes the secret-tree entry at the first decrypt and will not hand
    # the message back, so without this the second read of an inbox entry is an
    # error about a key that is simply gone. The envelope is verified below
    # exactly as a first read is, and no MLS state is opened at all.
    #
    # 🔴 A retirement marker closes the cache with everything else. A
    # leave already deletes it, so this is the case where the two disagree: a
    # message opened while the marker was absent must stop opening when it is
    # back, or the marker would be a thing that cannot be re-armed. The gate is
    # regime-independent — the sender-key twin is ``_crypto.message``'s
    # ``_replayed_envelope`` and the TypeScript twin gates both regimes in one
    # place (``crypto/message.ts``) — so the MLS path may not be the one hole.
    replay = (
        None
        if sender_keys_retired(config_dir, agent_id, group_id)
        else lookup_group_read(config_dir, agent_id, group_id, payload)
    )
    if replay is not None:
        return _authenticate(decode_envelope(replay), client, from_agent_id)

    mls = open_mls_group(config_dir, agent_id, group_id, cipher_suite=cipher_suite)
    app = mls.decrypt_application_message(payload)
    envelope = decode_envelope(app.envelope)

    # Persist only once the plaintext is known to be extractable. The receiving
    # ratchet advanced in memory the moment the decrypt returned, and saving that
    # advance is what makes forward secrecy real — but saving it before the steps
    # above would spend the message's one-time key on a read that then threw the
    # plaintext away, and MLS has no way to hand it back. Persisting BEFORE the
    # refusal inside ``_authenticate`` keeps a forged message from being a retry
    # oracle: it burns its key exactly like an honest one.
    mls.save()

    result = _authenticate(envelope, client, from_agent_id)
    record_group_read(config_dir, agent_id, group_id, payload, app.envelope)
    return result


def _authenticate(envelope: Any, client: Any, from_agent_id: str) -> DecryptResult:
    """Turn a signed inner envelope into a result, refusing what its sender did not sign.

    Shared by the live decrypt and the cache replay so a re-read is verified
    against the sender the server names on the row being read NOW, rather than
    answered from the first read's verdict.
    """
    verification = verify_envelope_sender_sync(
        envelope.kid, envelope.payload, envelope.signature, client, from_agent_id
    )
    refuse_if_inauthentic(verification)
    return DecryptResult(
        envelope.payload.decode("utf-8"),
        envelope.kid,
        verification.verified,
        verification.verification_status,
        verification.key_changed,
    )


def _recover(client: Any, config_dir: str, agent_id: str, group: GroupRead) -> MlsSyncResult:
    """Establish state and catch up — the one answer to "this agent is behind"."""
    install_mls_state(client, config_dir, agent_id, group)
    return sync_mls_group(
        client, config_dir, agent_id, str(group.id), cipher_suite=group.mls_cipher_suite
    )


def _sync_quietly(client: Any, config_dir: str, agent_id: str, group: GroupRead) -> None:
    """Advance to the group's current epoch, swallowing every failure.

    A send must not fail because a pre-sync did: having no local state at all is
    what the recovery below it answers, and any other failure leaves the send
    exactly where it would have been without this call.
    """
    try:
        sync_mls_group(
            client, config_dir, agent_id, str(group.id), cipher_suite=group.mls_cipher_suite
        )
    except Exception:
        logger.debug("MLS pre-send sync failed for group %s", group.id, exc_info=True)
