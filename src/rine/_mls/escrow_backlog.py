"""Reopening the old-state snapshots a settle parked, and sealing what they hold.

The sweep reopens each snapshot (:mod:`rine._mls.escrow_snapshots`) in a scratch
store, takes and seals its exports into pending files, and deletes it. A snapshot
that cannot be processed is retried on the schedule of
:mod:`rine._mls.escrow_retry`. Only a failure that is the snapshot's own is
counted: a full disk or a permission error says nothing about it, so it is reported
and tried again at the next pass without using up an attempt.

A snapshot stays until its exports are sealed, except two kinds that can never be:
one that failed sixteen times, and any when the branch is revoked. Each is deleted
only after a gap marker (:mod:`rine._mls.escrow_gap`) records every epoch it held, so
the loss is named and never silent. A crash between the marker and the delete leaves
the snapshot, and the next pass finishes the job.

The TypeScript twin is ``rine-core/src/mls-escrow-backlog.ts``, with the same layout.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from rine._logging import logger
from rine._mls.escrow_gap import DrainGap, EscrowLoss, LocatedGap, lost_gaps, write_gap
from rine._mls.escrow_queued import lost_epochs, recorded_forks
from rine._mls.escrow_reopen import SnapshotUnreadableError, reopened
from rine._mls.escrow_retry import is_due, is_exhausted, note_failure, read_attempts
from rine._mls.escrow_seal import zero
from rine._mls.escrow_snapshots import BacklogSnapshot, delete_snapshot, list_snapshots
from rine._mls.escrow_take import take_and_seal

if TYPE_CHECKING:
    from rine._crypto.escrow_key import VerifiedEscrowKey
    from rine._crypto.keys import AgentKeys
    from rine._mls.heartbeat import MlsActor

#: Logged when a parked snapshot is deleted without being sealed.
LOST_LOG = (
    "MLS escrow backlog: snapshot for group %s epoch %d deleted (%s); epochs recorded as lost"
)


@dataclass(frozen=True, slots=True)
class BacklogResult:
    """What one pass over the backlog did."""

    sealed: int
    """Pending files written."""

    located: tuple[LocatedGap, ...]
    """Gaps the reopened states reported and epochs lost with a deleted snapshot, each
    already filed as a marker, with its group."""

    failures: tuple[Exception, ...]
    """Snapshots that could not be processed this pass; each stays for the next one."""

    @property
    def gaps(self) -> tuple[DrainGap, ...]:
        """The gaps, without their groups."""
        return tuple(located.gap for located in self.located)


def _process(
    actor: MlsActor, snapshot: BacklogSnapshot, key: VerifiedEscrowKey, keys: AgentKeys
) -> tuple[int, tuple[LocatedGap, ...]]:
    """Seal one snapshot's exports into pending files and delete it.

    The sealed files are on disk before the snapshot goes.
    """
    with reopened(actor, snapshot) as group:
        taken = take_and_seal(actor, snapshot.group_id, key, keys, group)
    delete_snapshot(snapshot)
    return taken.sealed, tuple(LocatedGap(snapshot.group_id, gap) for gap in taken.gaps)


def _lost_gaps(actor: MlsActor, snapshot: BacklogSnapshot, loss: EscrowLoss) -> list[DrainGap]:
    """The epochs a snapshot holds that nobody has sealed, as gaps for ``loss``.

    Each gap carries the fork it is lost for. A snapshot that cannot be reopened is known
    by the epoch range recorded when it was parked (:func:`rine._mls.escrow_queued.lost_epochs`)
    and by the forks recorded with it, so an epoch with no recorded fork is lost for none.
    The reopened state's export plaintexts are overwritten with zeros: nobody will seal them.

    Raises:
        OSError: The scratch store could not be made, which says nothing about the snapshot.
    """
    try:
        with reopened(actor, snapshot) as group:
            take = group.take_escrow_exports()
    except OSError:
        raise
    except Exception:
        epochs = lost_epochs(
            actor.config_dir, actor.agent_id, snapshot.group_id, snapshot.path, snapshot.epoch
        )
        forks = recorded_forks(snapshot.path, snapshot.epoch)
        return [replace(gap, fp=forks.get(gap.epoch)) for gap in lost_gaps(epochs, loss)]
    gaps = [DrainGap(gap.epoch, gap.reason, gap.fp) for gap in take.gaps]
    gaps.extend(DrainGap(export.epoch, loss, export.fp) for export in take.exports)
    for export in take.exports:
        zero(export.plaintext)
    return gaps


def _give_up(
    actor: MlsActor, snapshot: BacklogSnapshot, loss: EscrowLoss, failures: list[Exception]
) -> tuple[LocatedGap, ...]:
    """File the loss of a snapshot's epochs, then delete it.

    A failure to make the marker durable keeps the snapshot for the next pass.
    """
    try:
        filed = [
            replace(
                gap,
                reason=write_gap(actor.config_dir, actor.agent_id, snapshot.group_id, gap, gap.fp),
            )
            for gap in _lost_gaps(actor, snapshot, loss)
        ]
    except Exception as exc:
        failures.append(exc)
        return ()
    delete_snapshot(snapshot)
    logger.warning(LOST_LOG, snapshot.group_id, snapshot.epoch, loss.value)
    return tuple(LocatedGap(snapshot.group_id, gap) for gap in dict.fromkeys(filed))


def give_up_snapshots(actor: MlsActor, loss: EscrowLoss) -> BacklogResult:
    """Give up on every parked snapshot of this agent, as when its branch is revoked."""
    located: list[LocatedGap] = []
    failures: list[Exception] = []
    for snapshot in list_snapshots(actor.config_dir, actor.agent_id):
        located.extend(_give_up(actor, snapshot, loss, failures))
    return BacklogResult(0, tuple(located), tuple(failures))


def process_backlog(
    actor: MlsActor, key: VerifiedEscrowKey, keys: AgentKeys, *, now: float | None = None
) -> BacklogResult:
    """Seal every due snapshot's exports into the pending store and delete the snapshot.

    Oldest group and epoch first. One snapshot's failure never stops the pass:
    it is recorded, and the sweep still uploads what is pending. A snapshot whose
    attempts are used up is given up on. This function does no network I/O.
    """
    instant = time.time() if now is None else now
    sealed = 0
    located: list[LocatedGap] = []
    failures: list[Exception] = []
    for snapshot in list_snapshots(actor.config_dir, actor.agent_id):
        record = read_attempts(snapshot.path)
        if is_exhausted(record):
            located.extend(_give_up(actor, snapshot, EscrowLoss.UNREADABLE, failures))
            continue
        if not is_due(record, instant):
            continue
        try:
            written, reported = _process(actor, snapshot, key, keys)
        except Exception as exc:
            failures.append(exc)
            if isinstance(exc, SnapshotUnreadableError) and is_exhausted(
                note_failure(snapshot.path, str(exc), now=instant)
            ):
                located.extend(_give_up(actor, snapshot, EscrowLoss.UNREADABLE, failures))
            continue
        sealed += written
        located.extend(reported)
    return BacklogResult(sealed, tuple(located), tuple(failures))
