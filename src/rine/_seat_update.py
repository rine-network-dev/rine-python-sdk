"""The outcome of moving one agent's leaf: a status, and a reason when it is not clean.

Shared by the sweep that moves every group's leaf (:mod:`rine._mls.seat_sweep`),
the single-group update (:mod:`rine._mls.self_update`) and the recovery result
(:class:`rine._mls.resync.MlsRecoveryResult`). The strings are the wire vocabulary
of the TypeScript twin (``rine-core/src/mls-self-update.ts``), byte for byte.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SeatUpdateStatus(StrEnum):
    """Where one group's seat stands after a self-update was tried."""

    UPDATED = "updated"
    CURRENT = "current"
    DEFERRED = "deferred"
    FAILED = "failed"


class SeatDeferReason(StrEnum):
    """Why a seat was not moved this time; a later sweep tries again."""

    EPOCH_RACE = "epoch_race"
    AWAITING_ACK = "awaiting_ack"
    ROLLED_BACK = "rolled_back"
    UNREACHABLE = "unreachable"


class SeatFailReason(StrEnum):
    """Why a seat cannot be moved from this host; trying again changes nothing."""

    EVICTED = "evicted"
    SEAT_UNHEALABLE = "seat_unhealable"
    KEY_NOT_CURRENT = "key_not_current"
    REFUSED = "refused"


@dataclass(frozen=True)
class SeatUpdate:
    """The outcome for one group, or (``group_id`` ``None``) for the whole sweep."""

    group_id: str | None
    status: SeatUpdateStatus
    reason: SeatDeferReason | SeatFailReason | None = None
    detail: str | None = None
    """The error message, for ``refused``, ``seat_unhealable`` and ``unreachable``."""

    epoch: int | None = None
    """The epoch the update landed at, or awaits confirmation at."""

    escrow_pending: bool = False
    """The drain left this epoch's escrow queued; the send gate covers it."""


def deferred(
    group_id: str | None,
    reason: SeatDeferReason,
    *,
    detail: str | None = None,
    epoch: int | None = None,
) -> SeatUpdate:
    """A seat that was not moved this time; a later sweep tries again."""
    return SeatUpdate(group_id, SeatUpdateStatus.DEFERRED, reason, detail, epoch)


def failed(group_id: str | None, reason: SeatFailReason, detail: str | None = None) -> SeatUpdate:
    """A seat that cannot be moved from this host."""
    return SeatUpdate(group_id, SeatUpdateStatus.FAILED, reason, detail)


__all__ = [
    "SeatDeferReason",
    "SeatFailReason",
    "SeatUpdate",
    "SeatUpdateStatus",
    "deferred",
    "failed",
]
