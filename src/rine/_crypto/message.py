"""High-level message encrypt/decrypt orchestration.

Wires together key loading, signing, envelope encoding, and HPKE/Sender Key
encryption. Handles signature verification and sender key state persistence.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Literal

import httpx

from rine._constants import EncryptionVersion
from rine._crypto.envelope import decode_envelope, encode_envelope
from rine._crypto.hpke import open as hpke_open
from rine._crypto.hpke import seal as hpke_seal
from rine._crypto.keys import (
    agent_id_from_kid,
    jwk_to_public_key,
    load_agent_keys,
    make_kid,
    signing_public_key_to_jwk,
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
from rine.errors import APIConnectionError, APITimeoutError, CryptoError, RineApiError

if TYPE_CHECKING:
    from rine._http import AsyncHttpClient, SyncHttpClient

VerificationStatus = Literal["verified", "invalid", "unverifiable"]


class EncryptResult:
    """Result of encrypting a message."""

    __slots__ = ("encrypted_payload", "encryption_version", "sender_signing_kid")

    def __init__(self, encrypted_payload: str, encryption_version: str, kid: str) -> None:
        self.encrypted_payload = encrypted_payload
        self.encryption_version = encryption_version
        self.sender_signing_kid = kid


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


def _verify_envelope_sender_sync(
    kid: str, payload: bytes, signature: bytes, client: SyncHttpClient
) -> tuple[bool, VerificationStatus]:
    """Verify envelope sender signature synchronously."""
    try:
        agent_id = agent_id_from_kid(kid)
        keys_resp: Any = client.get(f"/agents/{agent_id}/keys")
        sender_pk = jwk_to_public_key(keys_resp["signing_public_key"], expected_crv="Ed25519")
        verified = verify_signature(sender_pk, payload, signature)
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
    """Verify envelope sender signature asynchronously."""
    try:
        agent_id = agent_id_from_kid(kid)
        keys_resp: Any = await client.get(f"/agents/{agent_id}/keys")
        sender_pk = jwk_to_public_key(keys_resp["signing_public_key"], expected_crv="Ed25519")
        verified = verify_signature(sender_pk, payload, signature)
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
    recipient_encryption_pk: bytes,
    payload: object,
) -> EncryptResult:
    """Encrypt a 1:1 message with HPKE.

    Args:
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        recipient_encryption_pk: Recipient's 32-byte X25519 public key.
        payload: JSON-serializable message payload.

    Returns:
        EncryptResult with base64url-encoded encrypted payload.
    """
    keys = load_agent_keys(config_dir, sender_agent_id)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    kid = make_kid(sender_agent_id)
    signature = sign_payload(keys.signing.private_key, plaintext)
    envelope = encode_envelope(kid, signature, plaintext)
    encrypted = hpke_seal(recipient_encryption_pk, envelope)

    return EncryptResult(
        encrypted_payload=to_base64url(encrypted),
        encryption_version=EncryptionVersion.HPKE_V1,
        kid=kid,
    )


def decrypt_message_sync(
    config_dir: str,
    recipient_agent_id: str,
    encrypted_payload_b64: str,
    client: SyncHttpClient,
) -> DecryptResult:
    """Decrypt a 1:1 HPKE message (sync).

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
    envelope_bytes = hpke_open(keys.encryption.private_key, encrypted)
    decoded = decode_envelope(envelope_bytes)
    plaintext = decoded.payload.decode("utf-8")

    verified, status = _verify_envelope_sender_sync(
        decoded.kid, decoded.payload, decoded.signature, client
    )
    if status == "invalid":
        raise CryptoError("Sender signature verification failed")
    return DecryptResult(plaintext, decoded.kid, verified, status)


async def decrypt_message_async(
    config_dir: str,
    recipient_agent_id: str,
    encrypted_payload_b64: str,
    client: AsyncHttpClient,
) -> DecryptResult:
    """Decrypt a 1:1 HPKE message (async).

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
    envelope_bytes = hpke_open(keys.encryption.private_key, encrypted)
    decoded = decode_envelope(envelope_bytes)
    plaintext = decoded.payload.decode("utf-8")

    verified, status = await _verify_envelope_sender_async(
        decoded.kid, decoded.payload, decoded.signature, client
    )
    if status == "invalid":
        raise CryptoError("Sender signature verification failed")
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
        raise CryptoError("Sender signature verification failed")

    # Preserve self-read keys for own sender key
    if updated.sender_agent_id == recipient_agent_id:
        prev = {s.sender_key_id: s for s in load_sender_key_states(
            config_dir, recipient_agent_id, group_id
        )}.get(updated.sender_key_id)
        if prev and message_index in (prev.skipped_keys or {}):
            cached = prev.skipped_keys[message_index]
            if message_index not in updated.skipped_keys:
                updated.skipped_keys[message_index] = cached

    save_sender_key_state(
        config_dir, recipient_agent_id, group_id, list(state_map.values())
    )
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
        raise CryptoError("Sender signature verification failed")

    if updated.sender_agent_id == recipient_agent_id:
        prev_states = load_sender_key_states(config_dir, recipient_agent_id, group_id)
        prev = {s.sender_key_id: s for s in prev_states}.get(updated.sender_key_id)
        if prev and message_index in (prev.skipped_keys or {}):
            cached = prev.skipped_keys[message_index]
            if message_index not in updated.skipped_keys:
                updated.skipped_keys[message_index] = cached

    save_sender_key_state(
        config_dir, recipient_agent_id, group_id, list(state_map.values())
    )
    return DecryptResult(plaintext, decoded.kid, verified, status)


def fetch_recipient_encryption_key_sync(client: SyncHttpClient, agent_id: str) -> bytes:
    """Fetch recipient's encryption public key (sync).

    Args:
        client: HTTP client.
        agent_id: Agent UUID.

    Returns:
        32-byte X25519 public key.
    """
    data: Any = client.get(f"/agents/{agent_id}/keys")
    return jwk_to_public_key(data["encryption_public_key"], expected_crv="X25519")


async def fetch_recipient_encryption_key_async(
    client: AsyncHttpClient, agent_id: str
) -> bytes:
    """Fetch recipient's encryption public key (async).

    Args:
        client: Async HTTP client.
        agent_id: Agent UUID.

    Returns:
        32-byte X25519 public key.
    """
    data: Any = await client.get(f"/agents/{agent_id}/keys")
    return jwk_to_public_key(data["encryption_public_key"], expected_crv="X25519")


def get_agent_public_keys(
    config_dir: str, agent_id: str
) -> dict[str, dict[str, str]]:
    """Get an agent's public keys as JWK dicts.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.

    Returns:
        Dict with ``signing_public_key`` and ``encryption_public_key`` JWK dicts.
    """
    keys = load_agent_keys(config_dir, agent_id)
    return {
        "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
        "encryption_public_key": {
            "kty": "OKP",
            "crv": "X25519",
            "x": to_base64url(keys.encryption.public_key),
        },
    }
