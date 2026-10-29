"""The typed escrow outcome a drain, a settle or a sweep hands back.

This is the single typed record those operations return, merged into the sync,
join, admission and reseat results so a caller sees the escrow work done on its
behalf without reading prose: the epochs that have no escrow, why sealing was
not attempted when it was not, and what still waits unsealed. The TypeScript
twin is ``rine-core/src/mls-escrow-report.ts`` — same names.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from rine._mls.escrow_gap import (
    DrainGap,  # noqa: TC001 - pydantic resolves result fields
    EscrowLoss,
)
from rine._mls.escrow_revoked import revoked_loss

if TYPE_CHECKING:
    from rine._mls.binding import EscrowBacklog

__all__ = [
    "EscrowDeferral",
    "EscrowReport",
    "deferral_for",
    "report_from_backlog",
]


class EscrowDeferral(StrEnum):
    """Why sealing was not attempted, if it was not."""

    KEY_UNAVAILABLE = "key_unavailable"
    """No verified escrow key could be read; exports stay queued."""

    BRANCH_REVOKED = "branch_revoked"
    """The branch is revoked (the key read answers 410, or a bearer route names it); the
    drain keeps its exports queued, and the sweep records a gap for every parked one and
    discards it."""

    AGENT_REVOKED = "agent_revoked"
    """The agent itself is revoked (a bearer route or the token mint names it); the drain keeps
    its exports queued, and the sweep records a gap for every parked one and discards it."""


@dataclass(frozen=True, slots=True)
class EscrowReport:
    """What a result reports of the escrow work done on its behalf."""

    gaps: tuple[DrainGap, ...] = ()
    """Epochs with no escrow."""

    deferral: EscrowDeferral | None = None
    """Why sealing was not attempted, if it was not."""

    queued: int = 0
    """Exports still waiting unsealed: in the group's snapshot queue, or in a parked state."""

    dropped: int = 0
    """Exports the native queue dropped (overflow)."""

    backlogged: int = 0
    """Old-state snapshots parked in ``escrow-backlog/`` awaiting the sweep."""

    def merge(self, other: EscrowReport) -> EscrowReport:
        """Fold in a report about different group state: gaps concatenate, counts sum.

        The deferral is this report's when it has one, else ``other``'s: the
        first reason sealing was skipped is the one that explains the queue.
        """
        return EscrowReport(
            gaps=(*self.gaps, *other.gaps),
            deferral=self.deferral if self.deferral is not None else other.deferral,
            queued=self.queued + other.queued,
            dropped=self.dropped + other.dropped,
            backlogged=self.backlogged + other.backlogged,
        )

    def advance(self, later: EscrowReport) -> EscrowReport:
        """Fold in a later report about the SAME group's state: the newer reading wins.

        The native queue and drop counters are cumulative, so a later drain's
        ``queued`` and ``dropped`` already include what an earlier one counted, and
        summing them would report the same exports twice. Gaps and parked
        snapshots are new work each time and accumulate. The deferral is the later
        one's: a drain that sealed what an earlier one had to leave queued is not
        deferred any more.
        """
        return EscrowReport(
            gaps=(*self.gaps, *later.gaps),
            deferral=later.deferral,
            queued=later.queued,
            dropped=later.dropped,
            backlogged=self.backlogged + later.backlogged,
        )


_DEFERRAL_BY_LOSS: dict[EscrowLoss, EscrowDeferral] = {
    EscrowLoss.BRANCH_REVOKED: EscrowDeferral.BRANCH_REVOKED,
    EscrowLoss.AGENT_REVOKED: EscrowDeferral.AGENT_REVOKED,
}


def deferral_for(exc: Exception) -> EscrowDeferral:
    """The deferral an exception that stopped sealing names."""
    loss = revoked_loss(exc)
    return EscrowDeferral.KEY_UNAVAILABLE if loss is None else _DEFERRAL_BY_LOSS[loss]


def report_from_backlog(backlog: EscrowBacklog | None) -> EscrowReport:
    """The report of what a snapshot backlog holds; empty for ``None``."""
    if backlog is None:
        return EscrowReport()
    return EscrowReport(queued=backlog.queued, dropped=backlog.dropped)
