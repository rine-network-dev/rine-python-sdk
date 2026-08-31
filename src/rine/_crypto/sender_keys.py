"""Sender Key encryption for group messages — HMAC-SHA256 chain ratchet + AES-256-GCM.

Wire format::

    [1 byte: version 0x02]
    [16 bytes: sender_key_id (UUID binary)]
    [4 bytes: message_index (big-endian uint32)]
    [12 bytes: random nonce]
    [remaining: AES-256-GCM ciphertext + 16-byte auth tag]
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import uuid
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rine._crypto.envelope import encode_envelope
from rine._crypto.sign import sign_payload
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError, NoSenderKeyStateError
from rine.sender_key_words import no_sender_key_state_detail

VERSION_SENDER_KEY = 0x02
SENDER_KEY_ID_SIZE = 16
MESSAGE_INDEX_SIZE = 4
NONCE_SIZE = 12
MAX_SKIP = 1000
ROTATION_MESSAGE_LIMIT = 100
ROTATION_AGE_MS = 7 * 24 * 60 * 60 * 1000


@dataclass
class SenderKeyState:
    """State for a sender key ratchet."""

    sender_key_id: str
    group_id: str
    sender_agent_id: str
    chain_key: bytes = field(repr=False)  # 32 bytes
    message_index: int = 0
    skipped_keys: dict[int, str] = field(default_factory=dict)  # idx -> b64url(key)
    distributed_to: list[str] = field(default_factory=list)
    created_at: int | None = None


def generate_sender_key(group_id: str, sender_agent_id: str) -> SenderKeyState:
    """Generate a new sender key for a group.

    Args:
        group_id: Group UUID.
        sender_agent_id: Sender agent UUID.

    Returns:
        Fresh SenderKeyState with random chain key.
    """
    return SenderKeyState(
        sender_key_id=str(uuid.uuid4()),
        group_id=group_id,
        sender_agent_id=sender_agent_id,
        chain_key=os.urandom(32),
        message_index=0,
        created_at=int(__import__("time").time() * 1000),
    )


def derive_message_key(chain_key: bytes) -> tuple[bytes, bytes]:
    """Derive message key and next chain key via HMAC-SHA256.

    Args:
        chain_key: Current 32-byte chain key.

    Returns:
        Tuple of (message_key, next_chain_key), both 32 bytes.
    """
    message_key = hmac_mod.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac_mod.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def _uuid_to_bytes(u: str) -> bytes:
    """Convert UUID string to 16-byte binary."""
    return uuid.UUID(u).bytes


def _bytes_to_uuid(b: bytes) -> str:
    """Convert 16-byte binary to UUID string."""
    return str(uuid.UUID(bytes=b))


def _build_aad(sender_key_id_bytes: bytes, message_index: int) -> bytes:
    """Build AAD: sender_key_id (16B) + message_index (4B big-endian)."""
    return sender_key_id_bytes + message_index.to_bytes(4, "big")


def _advance_chain(
    state: SenderKeyState, target_index: int
) -> tuple[SenderKeyState, dict[int, bytes]]:
    """Advance chain to target index, caching skipped keys.

    Returns:
        Tuple of (updated state at target_index, skipped keys map).
    """
    skip_count = target_index - state.message_index
    if skip_count > MAX_SKIP:
        raise CryptoError(f"Too many skipped messages: {skip_count} (max {MAX_SKIP})")

    skipped: dict[int, bytes] = {}
    chain_key = state.chain_key
    index = state.message_index

    while index < target_index:
        mk, chain_key = derive_message_key(chain_key)
        skipped[index] = mk
        index += 1

    updated = SenderKeyState(
        sender_key_id=state.sender_key_id,
        group_id=state.group_id,
        sender_agent_id=state.sender_agent_id,
        chain_key=chain_key,
        message_index=index,
        skipped_keys=dict(state.skipped_keys),
        distributed_to=list(state.distributed_to),
        created_at=state.created_at,
    )
    return updated, skipped


def seal_group(
    sender_signing_private_key: bytes,
    sender_signing_kid: str,
    state: SenderKeyState,
    plaintext: bytes,
) -> tuple[bytes, SenderKeyState]:
    """Encrypt a group message with sender keys.

    Args:
        sender_signing_private_key: 32-byte Ed25519 private seed.
        sender_signing_kid: Key ID for signing (``rine:{uuid}``).
        state: Current sender key state.
        plaintext: Raw payload bytes.

    Returns:
        Tuple of (encrypted_payload bytes, updated SenderKeyState).
    """
    signature = sign_payload(sender_signing_private_key, plaintext)
    inner_envelope = encode_envelope(sender_signing_kid, signature, plaintext)

    message_key, next_chain_key = derive_message_key(state.chain_key)

    nonce = os.urandom(NONCE_SIZE)
    id_bytes = _uuid_to_bytes(state.sender_key_id)
    aad = _build_aad(id_bytes, state.message_index)

    ciphertext = AESGCM(message_key).encrypt(nonce, inner_envelope, aad)

    # Build wire format
    out = bytearray()
    out.append(VERSION_SENDER_KEY)
    out.extend(id_bytes)
    out.extend(state.message_index.to_bytes(MESSAGE_INDEX_SIZE, "big"))
    out.extend(nonce)
    out.extend(ciphertext)

    updated = SenderKeyState(
        sender_key_id=state.sender_key_id,
        group_id=state.group_id,
        sender_agent_id=state.sender_agent_id,
        chain_key=next_chain_key,
        message_index=state.message_index + 1,
        skipped_keys=dict(state.skipped_keys),
        distributed_to=list(state.distributed_to),
        created_at=state.created_at,
    )
    return bytes(out), updated


def require_sender_key_state(
    sender_key_states: dict[str, SenderKeyState],
    sender_key_id: str,
) -> SenderKeyState:
    """The state for a sender key, or a refusal that says how to get one.

    Placed here, at the only lookup that can miss, rather than at the read paths
    that call it. There are three of them — ``inbox()``, ``read()`` and the
    stream — and the one thing they share is that by the time they see this
    failure they have already ingested every pending distribution the server
    holds. A remedy written at any of them would either repeat that dead advice
    or be written three times and drift.

    The refusal is deliberately *not* the message-key wording a few lines below
    it. Nothing was consumed here: this agent never had the key, or retired it
    on the way out of the group.

    The refusal carries the key id as a field as well as in its sentence: a
    render that never ran the recovery has to re-say this refusal in weaker words
    and needs the id to do it, and reading it back out of the paragraph would
    make the wording load-bearing.

    Raises:
        NoSenderKeyStateError: When no state is held for that sender key.
    """
    state = sender_key_states.get(sender_key_id)
    if state is None:
        raise NoSenderKeyStateError(no_sender_key_state_detail(sender_key_id), sender_key_id)
    return state


def open_group(
    sender_key_states: dict[str, SenderKeyState],
    encrypted_payload: bytes,
) -> tuple[bytes, str, int, SenderKeyState]:
    """Decrypt a group message.

    Args:
        sender_key_states: Map of sender_key_id to SenderKeyState.
        encrypted_payload: Encrypted wire-format bytes.

    Returns:
        Tuple of (inner_envelope, sender_key_id, message_index, updated_state).

    Raises:
        NoSenderKeyStateError: When this agent holds no state for the sender key
            the message names — a :class:`~rine.errors.CryptoError`, so the read
            paths' self-heal still selects it.
        CryptoError: If the message key expired or decryption fails.
    """
    min_len = 1 + SENDER_KEY_ID_SIZE + MESSAGE_INDEX_SIZE + NONCE_SIZE
    if len(encrypted_payload) < min_len:
        raise CryptoError("Sender key payload too short")

    version = encrypted_payload[0]
    if version != VERSION_SENDER_KEY:
        raise CryptoError(
            f"Unknown sender key version: 0x{version:02x} (expected 0x{VERSION_SENDER_KEY:02x})"
        )

    offset = 1
    sender_key_id = _bytes_to_uuid(encrypted_payload[offset : offset + SENDER_KEY_ID_SIZE])
    offset += SENDER_KEY_ID_SIZE
    message_index = int.from_bytes(encrypted_payload[offset : offset + MESSAGE_INDEX_SIZE], "big")
    offset += MESSAGE_INDEX_SIZE
    nonce = encrypted_payload[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = encrypted_payload[offset:]

    state = require_sender_key_state(sender_key_states, sender_key_id)

    if message_index < state.message_index:
        # Past message — look up in skipped key cache
        cached = state.skipped_keys.get(message_index)
        if cached is None:
            raise CryptoError("Message key expired or already consumed")
        message_key = from_base64url(cached)
        new_skipped = dict(state.skipped_keys)
        del new_skipped[message_index]
        updated = SenderKeyState(
            sender_key_id=state.sender_key_id,
            group_id=state.group_id,
            sender_agent_id=state.sender_agent_id,
            chain_key=state.chain_key,
            message_index=state.message_index,
            skipped_keys=new_skipped,
            distributed_to=list(state.distributed_to),
            created_at=state.created_at,
        )
    elif message_index == state.message_index:
        # Current message — derive key
        message_key, next_chain_key = derive_message_key(state.chain_key)
        updated = SenderKeyState(
            sender_key_id=state.sender_key_id,
            group_id=state.group_id,
            sender_agent_id=state.sender_agent_id,
            chain_key=next_chain_key,
            message_index=state.message_index + 1,
            skipped_keys=dict(state.skipped_keys),
            distributed_to=list(state.distributed_to),
            created_at=state.created_at,
        )
    else:
        # Future message — advance chain, cache skipped keys
        advanced, new_skipped_keys = _advance_chain(state, message_index)
        message_key, next_chain_key = derive_message_key(advanced.chain_key)

        merged = dict(state.skipped_keys)
        for idx, key in new_skipped_keys.items():
            merged[idx] = to_base64url(key)

        # Enforce cap
        if len(merged) > MAX_SKIP:
            sorted_keys = sorted(merged.keys())
            excess = len(merged) - MAX_SKIP
            for k in sorted_keys[:excess]:
                del merged[k]

        updated = SenderKeyState(
            sender_key_id=state.sender_key_id,
            group_id=state.group_id,
            sender_agent_id=state.sender_agent_id,
            chain_key=next_chain_key,
            message_index=message_index + 1,
            skipped_keys=merged,
            distributed_to=list(state.distributed_to),
            created_at=state.created_at,
        )

    # Decrypt
    id_bytes = encrypted_payload[1 : 1 + SENDER_KEY_ID_SIZE]
    aad = _build_aad(id_bytes, message_index)
    try:
        inner_envelope = AESGCM(message_key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise CryptoError(f"Sender key decryption failed: {exc}") from exc

    return inner_envelope, sender_key_id, message_index, updated


def needs_rotation(state: SenderKeyState) -> bool:
    """Check if a sender key should be rotated.

    Args:
        state: Current sender key state.

    Returns:
        True if message limit or age threshold exceeded.
    """
    if state.message_index >= ROTATION_MESSAGE_LIMIT:
        return True
    if state.created_at is not None:
        import time

        age_ms = int(time.time() * 1000) - state.created_at
        if age_ms > ROTATION_AGE_MS:
            return True
    return False
