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
from rine._crypto.envelope import decode_envelope, encode_envelope
from rine._crypto.keys import load_agent_keys, make_kid
from rine._crypto.message import DecryptResult, EncryptResult, _verify_envelope_sender_sync
from rine._crypto.sign import sign_payload
from rine._logging import logger
from rine._mls.api import read_group
from rine._mls.failures import is_recoverable_mls_failure
from rine._mls.group_access import open_mls_group
from rine._mls.join import install_mls_state
from rine._mls.sync import sync_mls_group
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError, SignatureVerificationError

if TYPE_CHECKING:
    from rine.types import GroupRead


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
    _sync_quietly(client, config_dir, agent_id, group)
    try:
        return _encrypt(config_dir, agent_id, group, payload)
    except Exception as err:
        if not is_recoverable_mls_failure(err):
            raise
        logger.debug("MLS send recovery for group %s", group.id, exc_info=True)
    _recover(client, config_dir, agent_id, group)
    return _encrypt(config_dir, agent_id, group, payload)


def decrypt_mls_group_message(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str | None,
    encrypted_payload_b64: str,
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

    Raises:
        CryptoError: When the message names no group.
        NoMlsGroupStateError: When recovery could not establish state.
        SelfMessageNotCachedError: For this agent's own message whose plaintext
            has aged out — no sync can bring it back, so it is not retried.
        SignatureVerificationError: When the inner envelope's signature is forged.
    """
    if group_id is None:
        raise CryptoError(
            "An mls-v1 message names no group, so there is no MLS state to open "
            "it with. This is a malformed message, not a missing key."
        )
    payload = from_base64url(encrypted_payload_b64)
    try:
        return _decrypt(client, config_dir, agent_id, group_id, payload, cipher_suite=None)
    except Exception as err:
        if not is_recoverable_mls_failure(err):
            raise
        logger.debug("MLS read recovery for group %s", group_id, exc_info=True)

    # One-shot recovery: install any pending Welcome (which establishes state for
    # a group just joined), self-join if that left none, then apply the commits
    # posted since our epoch.
    group = read_group(client, agent_id, group_id)
    _recover(client, config_dir, agent_id, group)
    return _decrypt(
        client, config_dir, agent_id, group_id, payload, cipher_suite=group.mls_cipher_suite
    )


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
    *,
    cipher_suite: int | None,
) -> DecryptResult:
    mls = open_mls_group(config_dir, agent_id, group_id, cipher_suite=cipher_suite)
    app = mls.decrypt_application_message(payload)
    # Persist immediately: the receiving ratchet advanced, and MLS has already
    # authenticated the sending leaf. The inner-signature check below is a second
    # layer over that — unlike the sender-key path, whose ONLY sender
    # authentication is that signature, so there it must gate persistence.
    mls.save()

    envelope = decode_envelope(app.envelope)
    plaintext = envelope.payload.decode("utf-8")
    verified, status = _verify_envelope_sender_sync(
        envelope.kid, envelope.payload, envelope.signature, client
    )
    if status == "invalid":
        raise SignatureVerificationError("Sender signature verification failed")
    return DecryptResult(plaintext, envelope.kid, verified, status)


def _recover(client: Any, config_dir: str, agent_id: str, group: GroupRead) -> None:
    """Establish state and catch up — the one answer to "this agent is behind"."""
    install_mls_state(client, config_dir, agent_id, group)
    sync_mls_group(
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
