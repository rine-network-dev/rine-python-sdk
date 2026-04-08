"""Sender key state persistence — load/save from JSON files.

State stored at ``keys/{agent_id}/sender_keys/{group_id}.json``.
"""

from __future__ import annotations

import json
import os
from typing import Any

from rine._config import _ensure_dir, sender_keys_dir
from rine._crypto.keys import _validate_path_id
from rine._crypto.sender_keys import SenderKeyState
from rine._utils import from_base64url, to_base64url


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


def load_sender_key_states(
    config_dir: str, agent_id: str, group_id: str
) -> list[SenderKeyState]:
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
