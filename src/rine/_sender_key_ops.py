"""Sender key distribution, rotation, retirement, and auto-recovery.

Ports rine-core's ``sender-key-ops.ts`` — handles distributing sender keys
to group members via encrypted 1:1 messages.
"""

from __future__ import annotations

import os
from typing import Any

from rine._actor import AGENT_HEADER
from rine._config import sender_keys_dir
from rine._constants import MessageType
from rine._crypto._agent_keys import fetch_recipient_keys_sync
from rine._crypto.keys import _validate_path_id
from rine._crypto.message import encrypt_message
from rine._crypto.sender_keys import (
    SenderKeyState,
    generate_sender_key,
    needs_rotation,
)
from rine._crypto.sender_keys_helpers import (
    lift_retirement_if_member,
    load_sender_key_states,
    mark_sender_keys_retired,
    save_sender_key_state,
)
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
            recipient = fetch_recipient_keys_sync(client, recipient_id)
            result = encrypt_message(config_dir, sender_agent_id, recipient, distribution_payload)
            client.post(
                "/messages",
                json_body={
                    "to_agent_id": recipient_id,
                    "type": MessageType.SENDER_KEY_DISTRIBUTION,
                    "encrypted_payload": result.encrypted_payload,
                    "encryption_version": result.encryption_version,
                    "sender_signing_kid": result.sender_signing_kid,
                },
                # The distribution DM is sent BY the sender-key owner. Without
                # this the server cannot pick a sender in a multi-agent org and
                # 422s, so every recipient silently misses the key.
                extra_headers={AGENT_HEADER: sender_agent_id},
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
    group: dict[str, Any],
) -> SenderKeyState:
    """Get or create a sender key for a group, distributing as needed.

    Handles rotation triggers (message limit, age, member changes).

    Args:
        client: SyncHttpClient for API calls.
        config_dir: Config directory path.
        sender_agent_id: Sender agent UUID.
        group: The resolved group, as ``rine._group_send`` read it. Whether the
            group is on Sender Keys at all is decided there, so reaching here
            means it is.

    Returns:
        The sender key to encrypt with.
    """
    group_id = str(group["id"])

    # Get members
    members_data = client.get(f"/groups/{group_id}/members")
    member_items = (
        members_data.get("items", members_data) if isinstance(members_data, dict) else members_data
    )
    member_ids = [
        str(m["agent_id"]) for m in member_items if str(m["agent_id"]) != sender_agent_id
    ]

    # A retirement this agent left behind on a previous departure is spent once
    # the server's own member list names it again. The read path lifts
    # it on the same fact — see ``lift_retirement_if_member`` — because a
    # re-admitted agent that reads before it sends, or never sends at all, would
    # otherwise refuse every distribution its new peers make it, forever.
    lift_retirement_if_member(
        config_dir,
        sender_agent_id,
        group_id,
        (str(m["agent_id"]) for m in member_items),
    )

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
        return new_state

    assert own_state is not None
    return own_state


def _state_paths(config_dir: str, agent_id: str, group_id: str) -> list[str]:
    """Every path this agent's sender-key state for one group could be at.

    The group id is a FILENAME here, and ``_validate_path_id`` accepts a UUID in
    either case while every writer takes the id from the server, which spells it
    lower-case. A caller that upper-cases the same group — the SDK passes an
    ``is_uuid`` argument straight through without normalising it — would
    otherwise read or unlink a path that does not exist and report that there
    was nothing to retire, while all of it is still on disk. Both spellings,
    always; the one that is not there costs nothing.
    """
    _validate_path_id(agent_id, "agent_id")
    _validate_path_id(group_id, "group_id")
    directory = sender_keys_dir(config_dir, agent_id)
    return [
        os.path.join(directory, f"{spelling}.json")
        for spelling in dict.fromkeys([group_id, group_id.lower()])
    ]


def sender_key_state_exists(config_dir: str, agent_id: str, group_id: str) -> bool:
    """Whether this agent holds any local sender-key material for one group.

    The sender-key twin of :func:`rine._mls.group_access.holds_mls_state`, and
    it exists for the same reason: a leave has to say which encryption's
    material it just retired, and these two answers are what tell a closed
    group's leave from an open one's without reading the group back.

    Args:
        config_dir: Config directory path.
        agent_id: The agent whose material is in question.
        group_id: The rine group UUID.

    Returns:
        True when a state file exists under either spelling of the group id.
    """
    return any(os.path.exists(path) for path in _state_paths(config_dir, agent_id, group_id))


def delete_sender_key(config_dir: str, agent_id: str, group_id: str) -> None:
    """Retire this agent's local sender-key material for one group.

    The key it sends under, every peer key it ingested for that group, and the
    cached message keys both left behind — all of which live in the single
    ``keys/{agent}/sender_keys/{group}.json`` state file, so retiring the group
    is removing that file. Retiring a group this agent holds no material for is
    **not an error**: a member of a closed group has none, and leaving must not
    fail on account of what it did not have to clean up.

    The wipe alone was point-in-time, so it no longer travels alone. Every peer
    key it deletes still sits in this agent's inbox as a
    ``rine.v1.sender_key_distribution`` DM and used to be re-ingested by the next
    group read that missed (``rine._sync_client._fetch_pending_sk_distributions``).
    So this also writes a RETIREMENT MARKER
    (:func:`rine._crypto.sender_keys_helpers.mark_sender_keys_retired`) and every
    later ingest of a sender key for this group is refused. The marker is written
    whether or not there was anything to delete: a distribution DM this agent
    never opened is material the wipe never saw, and it is in the same inbox.

    What does not come back is the cached message keys, so a message delivered
    before the wipe and never OPENED does not open afterwards.

    What the marker buys is LOCAL and it is not an eviction. Membership in an
    open group is enforced by the server's delivery filter; the marker binds
    this client's own future behaviour and nothing else, and no surface may
    describe it as putting the material beyond a departed member's reach — a
    client that never had the marker, or an operator who deletes it, is
    unaffected. What bounds a departed member's reach into later traffic is each
    remaining member ROTATING on their next send (see
    :func:`get_or_create_sender_key_sync`). Deleting one's own state on the way
    out is neither a rekey nor a cryptographic removal. The TypeScript twin is
    ``deleteSenderKey`` (``rine-core/src/sender-key-ops.ts``), with the same
    semantics.

    Args:
        config_dir: Config directory path.
        agent_id: The departing agent's UUID.
        group_id: The rine group UUID.
    """
    for path in _state_paths(config_dir, agent_id, group_id):
        try:
            os.remove(path)
        except FileNotFoundError:
            # Nothing held under this spelling. The point of the call is the
            # end state, not that it did any work.
            continue
    mark_sender_keys_retired(config_dir, agent_id, group_id)
