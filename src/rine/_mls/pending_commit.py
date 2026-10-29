"""Settling a self-update this member built and has not applied yet.

In an open-enrollment group the server accepts a commit as *tentative*: it
advances the compare-and-swap latch but not the confirmed epoch, and rolls the
commit back unless a member acknowledges it in time. A self-update cannot be
recovered from a fork onto a rolled-back epoch, because the only way back is an
external-commit resync and that refuses to change the key a leaf carries. So the
committer never applies a self-update before the server confirms it. The commit
stays an mls-rs *pending commit* on the handle, saved to disk, and the live state
stays the pre-commit state. This module decides, on every sync, what became of it.

Settling is not a self-update: it never posts, so the implicit sync behind every
read and send may apply or clear a pending commit and never builds one.

The TypeScript twin is ``settlePendingCommit`` (``rine-core/src/mls-pending-commit.ts``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
from rine._mls.group_access import note_mls_state_changed, open_mls_group
from rine._mls.sync_api import OwnCommitStanding

if TYPE_CHECKING:
    from rine._mls.binding import MlsGroup
    from rine._mls.heartbeat import MlsActor


class PendingCommitOutcome(StrEnum):
    """What a sync found out about this member's pending commit."""

    APPLIED = "applied"
    """The group confirmed it; it is now this member's state."""

    HELD = "held"
    """Still tentative: waiting for a member to acknowledge it."""

    LOST = "lost"
    """A peer's commit took the pending epoch; ours is dead."""

    ROLLED_BACK = "rolled_back"
    """The group rolled our tentative commit back after accepting it."""

    NOT_POSTED = "not_posted"
    """The server never accepted our commit."""


@dataclass(frozen=True)
class PendingCommitSettlement:
    """The verdict on one pending commit, and the epoch it concerns."""

    epoch: int
    """Applied: the epoch now held. Held: the epoch the commit awaits confirmation at.
    Every other outcome: the epoch the handle is at."""

    outcome: PendingCommitOutcome
    escrow: EscrowReport = field(default_factory=EscrowReport)
    """Set with ``applied``: what the drain of the applied epoch could not do. The sync
    merges it into its own escrow report."""


def drop_pending_commit(actor: MlsActor, group_id: str, group: MlsGroup) -> None:
    """Drop the handle's pending commit and save it, unless the store moved past it.

    Two processes of one agent can sweep the same group. The one whose post lost the
    epoch race clears and saves its handle at the old epoch; if the winner has applied
    and saved the next epoch meanwhile, that save would put the store back one epoch,
    and the server never serves an agent its own commit again. The store is read just
    before the save, so the window is microseconds rather than a network round trip.
    """
    if open_mls_group(actor.config_dir, actor.agent_id, group_id).epoch() > group.epoch():
        return
    group.clear_pending_commit()
    group.save()
    note_mls_state_changed(actor.config_dir, actor.agent_id, group_id)


def settle_pending_commit(
    actor: MlsActor,
    group_id: str,
    group: MlsGroup,
    standing: OwnCommitStanding | None,
) -> PendingCommitSettlement | None:
    """Apply, hold or drop this member's pending commit, whichever the group decided.

    With nothing pending it returns ``None`` and makes no request, so a sync of a
    handle that holds nothing is exactly what it was before. A holding handle needs
    the server's ``standing``, read with the handshakes under the same lock as the
    feed; the settle makes no read of its own:

    - ``confirmed``: a member acknowledged it. Apply it, then drain the escrow of
      the epoch it created.
    - ``tentative``: still waiting. Hold, and save nothing: a peer's commit at the
      pending epoch or later may be built on ours.
    - ``rolled_back``: the server quarantined it or orphaned it. Drop it.
    - ``superseded``: a peer's commit holds the pending epoch. Ours is dead; applying
      the peer's commit later is what the sync does next.
    - ``absent``: the server never accepted it. Drop it.

    Args:
        actor: Who is acting, and through which client.
        group_id: The rine group UUID.
        group: The open handle; its pending commit is the subject.
        standing: What the handshakes read answered, or ``None`` when it said nothing.

    Returns:
        The verdict, or ``None`` when the handle holds no pending commit.

    Raises:
        RuntimeError: When the handle holds a commit and the server named no standing.
            A caller that cannot tell "still tentative" from an old server would drop
            a commit the server may be holding.
    """
    pending = group.pending_commit_epoch()
    if pending is None:
        return None
    if standing is OwnCommitStanding.CONFIRMED:
        group.apply_pending_commit()
        drained = drain_escrow(actor, group_id, group).report()
        note_mls_state_changed(actor.config_dir, actor.agent_id, group_id)
        return PendingCommitSettlement(group.epoch(), PendingCommitOutcome.APPLIED, drained)
    if standing is OwnCommitStanding.TENTATIVE:
        return PendingCommitSettlement(pending, PendingCommitOutcome.HELD)
    dead = _DEAD.get(standing) if standing is not None else None
    if dead is None:
        raise RuntimeError(
            f"The handshakes read for group {group_id} did not say where the pending commit stands."
        )
    drop_pending_commit(actor, group_id, group)
    return PendingCommitSettlement(group.epoch(), dead)


_DEAD = {
    OwnCommitStanding.ROLLED_BACK: PendingCommitOutcome.ROLLED_BACK,
    OwnCommitStanding.SUPERSEDED: PendingCommitOutcome.LOST,
    OwnCommitStanding.ABSENT: PendingCommitOutcome.NOT_POSTED,
}

__all__ = [
    "PendingCommitOutcome",
    "PendingCommitSettlement",
    "drop_pending_commit",
    "settle_pending_commit",
]
