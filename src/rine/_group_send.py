"""Which encryption a group send uses, decided once.

A rine group is either MLS-active or on Sender Keys, and the server enforces the
choice: it refuses a ``sender-key-v1`` send to an MLS group, and vice versa. The
group is therefore resolved once here and the branch taken from what it says,
rather than each client guessing and retrying.

``mls_pending`` counts as MLS: the group is frozen mid-init and the MLS commit
that unfreezes it is already in flight.
"""

from __future__ import annotations

from typing import Any

from rine._crypto.message import EncryptResult, encrypt_group_message
from rine._sender_key_ops import get_or_create_sender_key_sync
from rine.errors import NotFoundError
from rine.types import GroupRead


def resolve_group_for_send(client: Any, group_handle: str) -> dict[str, Any]:
    """The group a ``#handle`` send targets, as the server returns it.

    Args:
        client: Sync HTTP client.
        group_handle: Group handle, with or without the leading ``#``.

    Raises:
        NotFoundError: When no group carries that handle.
    """
    target = group_handle if group_handle.startswith("#") else f"#{group_handle}"
    data = client.get("/groups", params={"handle": target})
    items = data.get("items", []) if isinstance(data, dict) else data
    if not items:
        raise NotFoundError(f"Group not found: {group_handle}")
    group: dict[str, Any] = items[0]
    return group


def is_mls_group(group: dict[str, Any]) -> bool:
    """Whether a group's messages are MLS-encrypted."""
    return group.get("mls_group_id") is not None or bool(group.get("mls_pending"))


def encrypt_for_group_sync(
    client: Any, config_dir: str, agent_id: str, group_handle: str, payload: object
) -> tuple[EncryptResult, str]:
    """Encrypt one payload for a group, whichever encryption the group uses.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The sending agent's UUID — the identity the sender key is
            ratcheted under and the MLS leaf belongs to.
        group_handle: Group handle, with or without the leading ``#``.
        payload: JSON-serializable message payload.

    Returns:
        The ciphertext (carrying its own ``encryption_version``) and the group's
        UUID.
    """
    raw = resolve_group_for_send(client, group_handle)
    if is_mls_group(raw):
        # Imported here, not at module scope: a send to a Sender Keys group then
        # never loads the compiled MLS core it has no use for.
        from rine._mls.messages import encrypt_mls_group_message

        group = GroupRead.model_validate(raw)
        return (
            encrypt_mls_group_message(client, config_dir, agent_id, group, payload),
            str(group.id),
        )

    state = get_or_create_sender_key_sync(client, config_dir, agent_id, raw)
    group_id = str(raw["id"])
    result, _ = encrypt_group_message(config_dir, agent_id, group_id, state, payload)
    return result, group_id
