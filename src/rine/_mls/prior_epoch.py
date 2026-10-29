"""Admitting a sender's history before a message from an older epoch is opened."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.allowed import admit_peers
from rine._mls.header import MlsHeaderError, parse_header

if TYPE_CHECKING:
    from rine._mls.binding import MlsGroup
    from rine._mls.heartbeat import MlsActor


def admit_prior_epoch_sender(
    actor: MlsActor, group: MlsGroup, payload: bytes, from_agent_id: str
) -> None:
    """Admit the sender's history before a message from an older epoch is opened.

    The leaf the sender held when it sealed the message may have moved on since, and
    the core opens such a message only when the leaf's current key is a verified
    successor of the one that sealed it. A process that never synced holds neither
    generation, so the admission comes first: the open consumes the message's
    ratchet key before the identity check, which makes a retry after a refusal
    useless. A payload that is not an MLS message, or one at the group's current
    epoch, admits nothing.

    Args:
        actor: The reading agent and its client.
        group: The reader's open group, whose epoch is the current one.
        payload: The message's ``mls-v1`` payload bytes.
        from_agent_id: The sender the server named for the message.

    Raises:
        Exception: Any failure reading the sender's keys; nothing has been opened yet.
    """
    try:
        sealed_at = parse_header(payload).epoch
    except MlsHeaderError:
        return
    if sealed_at < group.epoch():
        admit_peers(actor, [from_agent_id])


__all__ = ["admit_prior_epoch_sender"]
