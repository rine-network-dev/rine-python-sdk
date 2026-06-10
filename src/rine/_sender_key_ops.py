"""Sender key distribution, rotation, and auto-recovery.

Ports rine-core's ``sender-key-ops.ts`` — handles distributing sender keys
to group members via encrypted 1:1 messages.
"""

from __future__ import annotations

from typing import Any

from rine._constants import MessageType
from rine._crypto.message import encrypt_message, fetch_recipient_encryption_key_sync
from rine._crypto.sender_keys import (
    SenderKeyState,
    generate_sender_key,
    needs_rotation,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._logging import logger
from rine._utils import to_base64url


def distribute_sender_key_sync(
    client: Any,
    config_dir: str,
    sender_agent_id: str,
    state: SenderKeyState,
    group_id: str,
    recipient_ids: list[str],
) -> tuple[list[str], list[str]]:
    """Distribute a sender key to recipients via encrypted 1:1 DMs.

    Args:
        client: SyncHttpClient for API calls.
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        state: SenderKeyState to distribute.
        group_id: Group UUID.
        recipient_ids: List of recipient agent UUIDs.

    Returns:
        Tuple of (succeeded agent IDs, failed agent IDs).
    """
    distribution_payload = {
        "group_id": group_id,
        "sender_key_id": state.sender_key_id,
        "chain_key": to_base64url(state.chain_key),
        "message_index": state.message_index,
        "sender_agent_id": sender_agent_id,
    }

    succeeded: list[str] = []
    failed: list[str] = []

    for recipient_id in recipient_ids:
        try:
            recipient_pk = fetch_recipient_encryption_key_sync(client, recipient_id)
            result = encrypt_message(
                config_dir, sender_agent_id, recipient_pk, distribution_payload
            )
            client.post(
                "/messages",
                json_body={
                    "to_agent_id": recipient_id,
                    "type": MessageType.SENDER_KEY_DISTRIBUTION,
                    "encrypted_payload": result.encrypted_payload,
                    "encryption_version": result.encryption_version,
                    "sender_signing_kid": result.sender_signing_kid,
                },
            )
            succeeded.append(recipient_id)
        except Exception:
            logger.warning("Failed to distribute SK to %s", recipient_id, exc_info=True)
            failed.append(recipient_id)

    return succeeded, failed


def get_or_create_sender_key_sync(
    client: Any,
    config_dir: str,
    sender_agent_id: str,
    group_handle: str,
) -> tuple[SenderKeyState, str]:
    """Get or create a sender key for a group, distributing as needed.

    Handles rotation triggers (message limit, age, member changes).

    Args:
        client: SyncHttpClient for API calls.
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        group_handle: Group handle (with or without ``#`` prefix).

    Returns:
        Tuple of (SenderKeyState, group_id).
    """
    # Resolve group — targeted handle lookup
    from rine.errors import MlsUnsupportedError, NotFoundError

    target_handle = group_handle if group_handle.startswith("#") else f"#{group_handle}"
    group_data = client.get("/groups", params={"handle": target_handle})
    items = group_data.get("items", []) if isinstance(group_data, dict) else group_data
    if not items:
        raise NotFoundError(f"Group not found: {group_handle}")
    group = items[0]
    group_id = str(group["id"])

    # MLS latch: a non-null mls_group_id means the group uses MLS encryption,
    # and mls_pending means the server has frozen the group during MLS init.
    # The Python SDK has no MLS crypto, and the server rejects sender-key-v1
    # sends to MLS (or MLS-initializing) groups (409), so fail loudly BEFORE
    # attempting sender-key crypto rather than silently producing an
    # undeliverable message.
    if group.get("mls_group_id") is not None or group.get("mls_pending"):
        raise MlsUnsupportedError()

    # Get members
    members_data = client.get(f"/groups/{group_id}/members")
    member_items = (
        members_data.get("items", members_data) if isinstance(members_data, dict) else members_data
    )
    member_ids = [
        str(m["agent_id"]) for m in member_items if str(m["agent_id"]) != sender_agent_id
    ]

    # Load existing states
    states = load_sender_key_states(config_dir, sender_agent_id, group_id)
    own_state = next((s for s in states if s.sender_agent_id == sender_agent_id), None)

    should_rotate = own_state is None or needs_rotation(own_state)

    # Check member changes
    if own_state and not should_rotate:
        distributed_set = set(own_state.distributed_to)
        current_set = set(member_ids)
        if not current_set.issubset(distributed_set):
            # New members need the key
            undistributed = list(current_set - distributed_set)
            if undistributed:
                succeeded, _ = distribute_sender_key_sync(
                    client, config_dir, sender_agent_id, own_state, group_id, undistributed
                )
                own_state.distributed_to.extend(succeeded)
                save_sender_key_state(config_dir, sender_agent_id, group_id, states)

        # Check if members were removed (triggers rotation)
        if distributed_set and not distributed_set.issubset(current_set | {sender_agent_id}):
            should_rotate = True

    if should_rotate:
        new_state = generate_sender_key(group_id, sender_agent_id)
        succeeded, _ = distribute_sender_key_sync(
            client, config_dir, sender_agent_id, new_state, group_id, member_ids
        )
        new_state.distributed_to = succeeded

        # Replace or append state
        other_states = [
            s for s in states if s.sender_key_id != (own_state.sender_key_id if own_state else "")
        ]
        other_states.append(new_state)
        save_sender_key_state(config_dir, sender_agent_id, group_id, other_states)
        return new_state, group_id

    assert own_state is not None
    return own_state, group_id
