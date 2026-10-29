"""How a self-update that did not land is reported: the seat result for each way it stops.

Split from :mod:`rine._mls.self_update`, which builds and posts the commit; these map what the
sync, the core or the server answered onto a ``deferred`` or ``failed`` :class:`SeatUpdate`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.binding import CommitPendingError, MlsCoreError, SignerLeafMismatchError
from rine._mls.failures import is_epoch_conflict
from rine._mls.pending_commit import (
    PendingCommitOutcome,
    PendingCommitSettlement,
    drop_pending_commit,
)
from rine._seat_update import SeatDeferReason, SeatFailReason, SeatUpdate, deferred, failed
from rine.errors import RineApiError

if TYPE_CHECKING:
    from rine._mls.binding import MlsGroup
    from rine._mls.heartbeat import MlsActor


def unsettled(group_id: str, held: PendingCommitSettlement) -> SeatUpdate:
    """The deferral for a pending commit the sync did not apply, by where the server left it."""
    match held.outcome:
        case PendingCommitOutcome.HELD:
            return deferred(group_id, SeatDeferReason.AWAITING_ACK, epoch=held.epoch)
        case PendingCommitOutcome.ROLLED_BACK:
            return deferred(group_id, SeatDeferReason.ROLLED_BACK)
        case PendingCommitOutcome.LOST:
            return deferred(group_id, SeatDeferReason.EPOCH_RACE)
        case _:
            return deferred(group_id, SeatDeferReason.UNREACHABLE)


def build_failure(group: MlsGroup, group_id: str, err: Exception) -> SeatUpdate:
    """The seat a failed commit build reports, by what failed.

    Only a failure no retry can change is final. A commit another process of this agent
    still has pending waits for that commit to settle, and a build that died on the network
    (admitting a peer reads it) may succeed on the next beat: both stay deferred, so the
    rotation marker waits and the sweep tries again. The core refusing the build, or a leaf
    this device cannot sign for, answers the same way next time.
    """
    if isinstance(err, CommitPendingError):
        epoch = group.pending_commit_epoch()
        return deferred(
            group_id,
            SeatDeferReason.AWAITING_ACK,
            epoch=group.epoch() + 1 if epoch is None else epoch,
        )
    if isinstance(err, SignerLeafMismatchError):
        return failed(group_id, SeatFailReason.SEAT_UNHEALABLE, str(err))
    if isinstance(err, MlsCoreError):
        return failed(group_id, SeatFailReason.REFUSED, str(err))
    return deferred(group_id, SeatDeferReason.UNREACHABLE, detail=str(err))


def post_refused(
    actor: MlsActor, group: MlsGroup, group_id: str, err: Exception
) -> SeatUpdate | None:
    """Map a refused or lost post. Only a post the server answered may be dropped."""
    answered = isinstance(err, RineApiError) and err.status < 500
    if answered:
        drop_pending_commit(actor, group_id, group)
    if is_epoch_conflict(err):
        return None
    # A transport failure, a timeout or a 5xx is ambiguous: the server may have
    # accepted the commit. The pending commit stays saved and the next sync
    # settles it either way.
    return deferred(group_id, SeatDeferReason.UNREACHABLE, detail=str(err))
