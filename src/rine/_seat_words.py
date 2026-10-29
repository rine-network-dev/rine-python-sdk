"""What a recovery says about where the agent's own leaf stands.

A rotation moves the agent's leaf to its new key; a group sync reports the
outcome in one appended sentence. The sentences are the TypeScript twin's, byte
for byte (``rine-core/src/mls-recovery-format.ts``). This module imports no MLS
code, because :mod:`rine.format` must stay importable where the wheel is not.
"""

from __future__ import annotations

from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdate,
    SeatUpdateStatus,
)

RECOVERY_EVICTED = (
    "This agent was removed from the group by a commit it just replayed: messages that "
    "already arrived still open, and nothing committed after the Remove ever will."
)

_DEFERRED: dict[SeatDeferReason, str] = {
    SeatDeferReason.EPOCH_RACE: (
        "Its leaf still carries an earlier key: another commit landed first; "
        "the next sync retries."
    ),
    SeatDeferReason.UNREACHABLE: (
        "Its leaf still carries an earlier key: the update could not be posted; "
        "the next sync retries."
    ),
    SeatDeferReason.AWAITING_ACK: (
        "Its leaf moves to the agent's current key once a member acknowledges the update "
        "(epoch {epoch}); until then it carries the earlier key."
    ),
    SeatDeferReason.ROLLED_BACK: (
        "Its leaf still carries an earlier key: the group rolled the update back before "
        "a member acknowledged it; the next sync retries."
    ),
}

_FAILED: dict[SeatFailReason, str] = {
    SeatFailReason.EVICTED: RECOVERY_EVICTED,
    SeatFailReason.SEAT_UNHEALABLE: (
        "Its leaf carries a key this agent cannot sign for; a member must remove the agent "
        "and invite it again."
    ),
    SeatFailReason.KEY_NOT_CURRENT: (
        "Its leaf was not moved: this device holds an earlier key generation than the "
        "agent's current one."
    ),
    SeatFailReason.REFUSED: "Its leaf was not moved: the update was refused: {detail}",
}


def seat_update_line(seat: SeatUpdate | None) -> str:
    """The sentence a recovery appends about the agent's leaf, or ``""`` when it has none.

    Silent for a leaf that already carries the current key and for a recovery that
    ran no self-update, so an unchanged group prints exactly what it printed before.
    """
    if seat is None or seat.status is SeatUpdateStatus.CURRENT:
        return ""
    if seat.status is SeatUpdateStatus.UPDATED:
        return f"Its leaf now carries the agent's current key (epoch {seat.epoch})."
    if seat.status is SeatUpdateStatus.DEFERRED and isinstance(seat.reason, SeatDeferReason):
        return _DEFERRED[seat.reason].format(epoch=seat.epoch)
    if isinstance(seat.reason, SeatFailReason):
        return _FAILED[seat.reason].format(detail=seat.detail or "no reason was reported")
    return ""


__all__ = ["RECOVERY_EVICTED", "seat_update_line"]
