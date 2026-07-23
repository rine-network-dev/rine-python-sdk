"""High-level message encrypt/decrypt orchestration.

Wires together key loading, signing, envelope encoding, and HPKE/Sender Key
encryption. Handles signature verification and sender key state persistence.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Literal

import httpx

from rine._constants import EncryptionVersion
from rine._crypto.dm_envelope import (
    RecipientKeys,
    open_dm,
    recipient_keys_from_response,
    seal_to_recipient,
    seal_to_self,
)
from rine._crypto.envelope import decode_envelope, encode_envelope
from rine._crypto.keys import (
    agent_id_from_kid,
    jwk_to_public_key,
    load_agent_keys,
    make_kid,
    public_keys_body,
)
from rine._crypto.sender_keys import (
    SenderKeyState,
    derive_message_key,
    open_group,
    seal_group,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._crypto.sign import sign_payload, verify_signature
from rine._logging import logger
from rine._utils import from_base64url, to_base64url
from rine.errors import (
    APIConnectionError,
    APITimeoutError,
    CryptoError,
    RineApiError,
    SignatureVerificationError,
)

if TYPE_CHECKING:
    from rine._http import AsyncHttpClient, SyncHttpClient

VerificationStatus = Literal["verified", "invalid", "unverifiable"]


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
    """Result of decrypting a message."""

    __slots__ = ("plaintext", "sender_kid", "verified", "verification_status")

    def __init__(
        self,
        plaintext: str,
        sender_kid: str,
        verified: bool,
        verification_status: VerificationStatus,
    ) -> None:
        self.plaintext = plaintext
        self.sender_kid = sender_kid
        self.verified = verified
        self.verification_status = verification_status


def get_agent_keys_sync(
    client: SyncHttpClient, agent_id: str, *, bypass: bool = False
) -> tuple[dict[str, Any], bool]:
    """Fetch an agent's public keys through the client's TTL cache (sync).

    Args:
        client: HTTP client owning the per-instance key cache.
        agent_id: Agent UUID.
        bypass: Skip the cache read (forces a network fetch) but still refresh
            the cache with the result — used by the verify-failure refetch.

    Returns:
        A ``(keys, from_cache)`` pair: the raw ``/agents/{id}/keys`` response
        (signing + encryption keys) and whether it was served from the cache.
        Callers use ``from_cache`` to gate the verify-failure refetch so a fresh
        miss is not re-fetched (parity with rine-core ``fetchAgentKeys``).
    """
    if not bypass:
        cached = client._keys_cache.get(agent_id)
        if cached is not None:
            return cached, True
    data: dict[str, Any] = client.get(f"/agents/{agent_id}/keys")
    client._keys_cache.set(agent_id, data)
    return data, False


async def get_agent_keys_async(
    client: AsyncHttpClient, agent_id: str, *, bypass: bool = False
) -> tuple[dict[str, Any], bool]:
    """Fetch an agent's public keys through the client's TTL cache (async).

    Returns a ``(keys, from_cache)`` pair; see :func:`get_agent_keys_sync`.
    """
    if not bypass:
        cached = client._keys_cache.get(agent_id)
        if cached is not None:
            return cached, True
    data: dict[str, Any] = await client.get(f"/agents/{agent_id}/keys")
    client._keys_cache.set(agent_id, data)
    return data, False


def _verify_with_keys(keys_resp: dict[str, Any], payload: bytes, signature: bytes) -> bool:
    """Verify a signature against the signing key in a keys response."""
    sender_pk = jwk_to_public_key(keys_resp["signing_public_key"], expected_crv="Ed25519")
    return verify_signature(sender_pk, payload, signature)


def _verify_envelope_sender_sync(
    kid: str, payload: bytes, signature: bytes, client: SyncHttpClient
) -> tuple[bool, VerificationStatus]:
    """Verify envelope sender signature synchronously.

    If a CACHED key yields a verify failure the sender may have rotated keys
    mid-TTL, so refetch once bypassing the cache and re-verify before declaring
    the signature invalid. A genuinely fresh fetch that fails is not
    re-fetched (parity with rine-core ``verifyEnvelopeSender``).
    """
    try:
        agent_id = agent_id_from_kid(kid)
        keys, from_cache = get_agent_keys_sync(client, agent_id)
        verified = _verify_with_keys(keys, payload, signature)
        if not verified and from_cache:
            fresh, _ = get_agent_keys_sync(client, agent_id, bypass=True)
            verified = _verify_with_keys(fresh, payload, signature)
        return verified, "verified" if verified else "invalid"
    except (KeyError, ValueError, CryptoError):
        logger.debug("Could not verify sender %s (malformed key)", kid, exc_info=True)
        return False, "unverifiable"
    except (httpx.HTTPError, APIConnectionError, APITimeoutError, RineApiError):
        logger.debug("Could not verify sender %s (network)", kid, exc_info=True)
        return False, "unverifiable"


async def _verify_envelope_sender_async(
    kid: str, payload: bytes, signature: bytes, client: AsyncHttpClient
) -> tuple[bool, VerificationStatus]:
    """Verify envelope sender signature asynchronously.

    Mirrors :func:`_verify_envelope_sender_sync`, including the cache-gated
    verify-failure refetch: only a CACHED key that fails is re-fetched.
    """
    try:
        agent_id = agent_id_from_kid(kid)
        keys, from_cache = await get_agent_keys_async(client, agent_id)
        verified = _verify_with_keys(keys, payload, signature)
        if not verified and from_cache:
            fresh, _ = await get_agent_keys_async(client, agent_id, bypass=True)
            verified = _verify_with_keys(fresh, payload, signature)
        return verified, "verified" if verified else "invalid"
    except (KeyError, ValueError, CryptoError):
        logger.debug("Could not verify sender %s (malformed key)", kid, exc_info=True)
        return False, "unverifiable"
    except (httpx.HTTPError, APIConnectionError, APITimeoutError, RineApiError):
        logger.debug("Could not verify sender %s (network)", kid, exc_info=True)
        return False, "unverifiable"


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
) -> DecryptResult:
    """Decrypt a 1:1 message, classical or post-quantum (sync).

    The payload's own version byte picks the envelope, so the same call reads
    ``hpke-v1`` and ``hpke-hybrid-v1``.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: HTTP client for fetching sender's public keys.

    Returns:
        DecryptResult with plaintext and verification status.
    """
    keys = load_agent_keys(config_dir, recipient_agent_id)
    encrypted = from_base64url(encrypted_payload_b64)
    envelope_bytes = open_dm(keys, encrypted)
    decoded = decode_envelope(envelope_bytes)
    plaintext = decoded.payload.decode("utf-8")

    verified, status = _verify_envelope_sender_sync(
        decoded.kid, decoded.payload, decoded.signature, client
    )
    if status == "invalid":
        raise SignatureVerificationError("Sender signature verification failed")
    return DecryptResult(plaintext, decoded.kid, verified, status)


async def decrypt_message_async(
    config_dir: str,
    recipient_agent_id: str,
    encrypted_payload_b64: str,
    client: AsyncHttpClient,
) -> DecryptResult:
    """Decrypt a 1:1 message, classical or post-quantum (async).

    Mirrors :func:`decrypt_message_sync`, including the version-byte dispatch.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: Async HTTP client for fetching sender's public keys.

    Returns:
        DecryptResult with plaintext and verification status.
    """
    keys = load_agent_keys(config_dir, recipient_agent_id)
    encrypted = from_base64url(encrypted_payload_b64)
    envelope_bytes = open_dm(keys, encrypted)
    decoded = decode_envelope(envelope_bytes)
    plaintext = decoded.payload.decode("utf-8")

    verified, status = await _verify_envelope_sender_async(
        decoded.kid, decoded.payload, decoded.signature, client
    )
    if status == "invalid":
        raise SignatureVerificationError("Sender signature verification failed")
    return DecryptResult(plaintext, decoded.kid, verified, status)


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
) -> DecryptResult:
    """Decrypt a group message (sync).

    Verifies signature before persisting ratchet state. Rejects invalid signatures.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        group_id: Group UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: HTTP client for fetching sender's public keys.

    Returns:
        DecryptResult with plaintext and verification status.

    Raises:
        CryptoError: If sender signature is invalid (state NOT persisted).
    """
    decoded, sender_key_id, message_index, updated, state_map = _decrypt_group_core(
        config_dir, recipient_agent_id, group_id, encrypted_payload_b64
    )
    plaintext = decoded.payload.decode("utf-8")

    verified, status = _verify_envelope_sender_sync(
        decoded.kid, decoded.payload, decoded.signature, client
    )

    if status == "invalid":
        raise SignatureVerificationError("Sender signature verification failed")

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
    return DecryptResult(plaintext, decoded.kid, verified, status)


async def decrypt_group_message_async(
    config_dir: str,
    recipient_agent_id: str,
    group_id: str,
    encrypted_payload_b64: str,
    client: AsyncHttpClient,
) -> DecryptResult:
    """Decrypt a group message (async).

    Verifies signature before persisting ratchet state. Rejects invalid signatures.

    Args:
        config_dir: Config directory path.
        recipient_agent_id: Recipient agent UUID.
        group_id: Group UUID.
        encrypted_payload_b64: Base64url-encoded encrypted payload.
        client: Async HTTP client for fetching sender's public keys.

    Returns:
        DecryptResult with plaintext and verification status.

    Raises:
        CryptoError: If sender signature is invalid (state NOT persisted).
    """
    decoded, sender_key_id, message_index, updated, state_map = _decrypt_group_core(
        config_dir, recipient_agent_id, group_id, encrypted_payload_b64
    )
    plaintext = decoded.payload.decode("utf-8")

    verified, status = await _verify_envelope_sender_async(
        decoded.kid, decoded.payload, decoded.signature, client
    )

    if status == "invalid":
        raise SignatureVerificationError("Sender signature verification failed")

    if updated.sender_agent_id == recipient_agent_id:
        prev_states = load_sender_key_states(config_dir, recipient_agent_id, group_id)
        prev = {s.sender_key_id: s for s in prev_states}.get(updated.sender_key_id)
        if prev and message_index in (prev.skipped_keys or {}):
            cached = prev.skipped_keys[message_index]
            if message_index not in updated.skipped_keys:
                updated.skipped_keys[message_index] = cached

    save_sender_key_state(config_dir, recipient_agent_id, group_id, list(state_map.values()))
    return DecryptResult(plaintext, decoded.kid, verified, status)


def fetch_recipient_keys_sync(client: SyncHttpClient, agent_id: str) -> RecipientKeys:
    """Fetch a recipient's published encryption keys (sync).

    Args:
        client: HTTP client.
        agent_id: Agent UUID.

    Returns:
        The recipient's X25519 key and, when published, its ML-KEM-768 key —
        which is what decides whether the message is sealed post-quantum.
    """
    data, _ = get_agent_keys_sync(client, agent_id)
    return recipient_keys_from_response(data)


async def fetch_recipient_keys_async(client: AsyncHttpClient, agent_id: str) -> RecipientKeys:
    """Fetch a recipient's published encryption keys (async).

    Mirrors :func:`fetch_recipient_keys_sync`.

    Args:
        client: Async HTTP client.
        agent_id: Agent UUID.

    Returns:
        The recipient's X25519 key and, when published, its ML-KEM-768 key.
    """
    data, _ = await get_agent_keys_async(client, agent_id)
    return recipient_keys_from_response(data)


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
