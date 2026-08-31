"""Sender key state persistence — load/save from JSON files.

State stored at ``keys/{agent_id}/sender_keys/{group_id}.json``, and the
retirement marker that outlives it at ``{group_id}.retired.json`` beside it.
"""

from __future__ import annotations

import contextlib
import json
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from rine._config import _ensure_dir, sender_keys_dir
from rine._crypto.keys import _validate_path_id
from rine._crypto.sender_keys import SenderKeyState
from rine._utils import from_base64url, to_base64url

if TYPE_CHECKING:
    from collections.abc import Iterable


def _state_to_json(state: SenderKeyState) -> dict[str, Any]:
    """Serialize SenderKeyState to JSON-compatible dict."""
    d: dict[str, Any] = {
        "senderKeyId": state.sender_key_id,
        "groupId": state.group_id,
        "senderAgentId": state.sender_agent_id,
        "chainKey": to_base64url(state.chain_key),
        "messageIndex": state.message_index,
    }
    if state.skipped_keys:
        d["skippedKeys"] = {str(k): v for k, v in state.skipped_keys.items()}
    if state.distributed_to:
        d["distributedTo"] = state.distributed_to
    if state.created_at is not None:
        d["createdAt"] = state.created_at
    return d


def _state_from_json(d: dict[str, Any]) -> SenderKeyState:
    """Deserialize SenderKeyState from JSON dict."""
    skipped: dict[int, str] = {}
    raw_skipped = d.get("skippedKeys", {})
    if isinstance(raw_skipped, dict):
        skipped = {int(k): v for k, v in raw_skipped.items()}

    return SenderKeyState(
        sender_key_id=d["senderKeyId"],
        group_id=d["groupId"],
        sender_agent_id=d["senderAgentId"],
        chain_key=from_base64url(d["chainKey"]),
        message_index=d.get("messageIndex", 0),
        skipped_keys=skipped,
        distributed_to=d.get("distributedTo", []),
        created_at=d.get("createdAt"),
    )


def load_sender_key_states(config_dir: str, agent_id: str, group_id: str) -> list[SenderKeyState]:
    """Load all sender key states for a group.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        group_id: Group UUID.

    Returns:
        List of SenderKeyState. Empty list if file doesn't exist.
    """
    _validate_path_id(agent_id, "agent_id")
    _validate_path_id(group_id, "group_id")
    path = os.path.join(sender_keys_dir(config_dir, agent_id), f"{group_id}.json")
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return [_state_from_json(d) for d in data]
        return []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_sender_key_state(
    config_dir: str, agent_id: str, group_id: str, states: list[SenderKeyState]
) -> None:
    """Save sender key states for a group.

    Args:
        config_dir: Config directory path.
        agent_id: Agent UUID.
        group_id: Group UUID.
        states: List of SenderKeyState to persist.
    """
    _validate_path_id(agent_id, "agent_id")
    _validate_path_id(group_id, "group_id")
    sk_dir = sender_keys_dir(config_dir, agent_id)
    _ensure_dir(sk_dir)
    path = os.path.join(sk_dir, f"{group_id}.json")
    content = json.dumps([_state_to_json(s) for s in states], indent=2)
    from rine._config import _write_atomic

    _write_atomic(path, content)


def _retirement_path(config_dir: str, agent_id: str, group_id: str) -> str:
    """Where the retirement marker for one (agent, group) pair lives.

    Beside the state file it retires: ``{group}.retired.json`` next to
    ``{group}.json``. The pair IS the path — the agent owns the directory, the
    group names the file — so the marker needs no contents to be keyed
    correctly, and nothing that reads it has to parse anything.

    The group id is lower-cased on the way in. ``_validate_path_id`` accepts a
    UUID in either case and every writer takes the id from the server, which
    spells it lower-case; without one canonical spelling a retirement written
    from an upper-cased id would be invisible to the reader that matters.
    """
    _validate_path_id(agent_id, "agent_id")
    _validate_path_id(group_id, "group_id")
    return os.path.join(sender_keys_dir(config_dir, agent_id), f"{group_id.lower()}.retired.json")


def mark_sender_keys_retired(config_dir: str, agent_id: str, group_id: str) -> None:
    """Retire this agent's sender-key material for one group, permanently.

    :func:`rine._sender_key_ops.delete_sender_key` removes the material; this is
    what stops it coming back. Every peer key that wipe removes arrived as a
    ``rine.v1.sender_key_distribution`` DM which is still in this agent's inbox
    — leaving a group takes nothing out of an inbox — so without a marker the
    next group read that misses its key re-ingests all of them and the wipe
    holds only until then.

    The refusal is per GROUP, not per (group, peer) pair, and deliberately so: a
    distribution DM this agent never opened carries a sender the wipe never saw,
    so refusing only the pairs that were on disk would let exactly those through.

    It is a LOCAL refusal by this client and no surface may describe it as
    putting a departed member beyond reach: nothing cryptographic keeps a leaver
    out of an open group, and what bounds their reach into later traffic is each
    remaining member ROTATING on their next send. The TypeScript twin is
    ``markSenderKeysRetired`` (``rine-core/src/crypto/sender-keys-helpers.ts``).

    The timestamp is written for a human reading the config dir; the mechanism
    keys on the file existing.

    Args:
        config_dir: Config directory path.
        agent_id: The departing agent's UUID.
        group_id: The rine group UUID.
    """
    from rine._config import _write_atomic

    _write_atomic(
        _retirement_path(config_dir, agent_id, group_id),
        json.dumps({"retiredAt": datetime.now(UTC).isoformat()}),
    )


def sender_keys_retired(config_dir: str, agent_id: str, group_id: str) -> bool:
    """Whether this agent has retired one group's sender keys.

    Answers from the marker's existence and never parses it: this is on the
    ingest path and runs once per distribution DM considered.

    Args:
        config_dir: Config directory path.
        agent_id: The agent whose material is in question.
        group_id: The rine group UUID.

    Returns:
        True when this agent has retired that group's sender keys.
    """
    return os.path.exists(_retirement_path(config_dir, agent_id, group_id))


def unretire_sender_keys(config_dir: str, agent_id: str, group_id: str) -> None:
    """Lift a retirement, because this agent is a member of the group again.

    Callers reach this only through :func:`lift_retirement_if_member`, and only
    after the server's own member list has been read and found to contain this
    agent — that gate is what keeps the retirement permanent for the case it
    exists for, since a departed agent is not on that list.

    The cost, stated rather than softened: re-admission also makes the
    distribution DMs still sitting in this agent's inbox ingestible again, so
    traffic sent during the gap can be opened by a member who was re-admitted.
    The alternative is a rejoined member whose client can never read the group
    again, with no way for its operator to see why.

    Args:
        config_dir: Config directory path.
        agent_id: The re-admitted agent's UUID.
        group_id: The rine group UUID.
    """
    # Nothing retired is a valid end state; the point of the call is that state.
    with contextlib.suppress(FileNotFoundError):
        os.remove(_retirement_path(config_dir, agent_id, group_id))


def lift_retirement_if_member(
    config_dir: str,
    agent_id: str,
    group_id: str,
    member_ids: Iterable[str],
) -> bool:
    """Whether this agent may take delivery of one group's sender keys.

    🔴 **A retirement is lifted by MEMBERSHIP, never by sending.** It used to be
    lifted inside :func:`rine._sender_key_ops.get_or_create_sender_key_sync`
    alone, which every surface reaches only from a group **send** — so a
    re-admitted agent that reads before it sends refused every distribution its
    new peers made it, forever, with nothing naming the cause; and a read-only
    member (a monitor, a connector that only replies to what it could decrypt)
    never sends at all and was wedged permanently. That is why this takes the
    member list rather than an intention to send: both the send path and the read
    path pass through it. The TypeScript twin is ``liftRetirementIfMember``
    (``rine-core/src/crypto/sender-keys-helpers.ts``).

    The list is passed in rather than fetched, so this module keeps doing no I/O
    beyond the config dir and each caller reuses the read it already makes.

    Args:
        config_dir: Config directory path.
        agent_id: The agent whose material is in question.
        group_id: The rine group UUID.
        member_ids: Agent ids the server currently names as members of the group
            — ``GET /groups/{id}/members``, and nothing derived locally.

    Returns:
        True when the group's keys may be ingested.
    """
    if not sender_keys_retired(config_dir, agent_id, group_id):
        return True
    lowered = agent_id.lower()
    if not any(str(member).lower() == lowered for member in member_ids):
        return False
    unretire_sender_keys(config_dir, agent_id, group_id)
    return True
