"""Reaching this agent's local state for one group.

Local MLS state is keyed by the **rine group UUID** a user sees — never the
server's opaque ``mls_group_id`` latch, which is a different value with a
confusingly similar name. Keying it here, once, is what lets joining, sending
and reading all find the same state.
"""

from __future__ import annotations

import uuid

from rine._mls.binding import MlsClient, MlsGroup, MlsProtocolError, open_mls_client
from rine.errors import NoMlsGroupStateError


def mls_group_id_bytes(group_id: str) -> bytes:
    """The 16 raw bytes MLS keys a group by.

    Always the rine group UUID a user sees — never the server's opaque
    ``mls_group_id`` latch, which is a different value with a confusingly
    similar name.
    """
    return uuid.UUID(group_id).bytes


def load_mls_group(client: MlsClient, group_id: str) -> MlsGroup | None:
    """This agent's local state for one group, or ``None`` when it holds none.

    ``None`` means the agent was never added, its Welcome has not been processed
    yet, or the group's state was retired — the three cases a caller answers the
    same way, by installing state. A store I/O failure is a different thing
    entirely and propagates rather than masquerading as "never joined".
    """
    try:
        return client.load_group(mls_group_id_bytes(group_id))
    except MlsProtocolError:
        return None


def open_mls_group(
    config_dir: str,
    agent_id: str,
    group_id: str,
    *,
    cipher_suite: int | None = None,
) -> MlsGroup:
    """This agent's local state for a group, or a typed refusal when it has none.

    The one entry point for every operation that needs an established group —
    sending, reading, syncing — so "this agent is not in the group's MLS state"
    is one answer with one remedy rather than a different failure per surface.

    Raises:
        NoMlsGroupStateError: When this agent holds no state for the group.
    """
    group = load_mls_group(
        open_mls_client(config_dir, agent_id, cipher_suite=cipher_suite), group_id
    )
    if group is None:
        raise NoMlsGroupStateError(group_id)
    return group


__all__ = ["load_mls_group", "mls_group_id_bytes", "open_mls_group"]
