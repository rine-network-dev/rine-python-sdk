"""Settle a group's escrow before its local state is discarded.

A deferred drain leaves untaken exports only in the stored snapshot, so a resync,
a self-join, a Welcome re-join or a reseat that saves a new group over it, and a
leave that wipes it, would make the epochs the old snapshot still holds unreadable
after a recovery. The old state is settled first, and settling is local and
lossless; it never waits on the network and never refuses the caller:

* with the verified escrow key cached, the old state's exports are taken and
  sealed into pending files, and its gaps are filed as markers;
* without it, the old snapshot is parked under ``escrow-backlog/`` with the live
  snapshot's own at-rest protection (:mod:`rine._mls.escrow_snapshots`), and the
  sweep reopens, seals and uploads it later.

Best effort: no stored state means nothing to settle, and a failure here must
not block the replacement or the leave the caller is making. A sealing failure
falls back to parking, because parking copies bytes and needs no key.

Call it only after the replacement is certain (the server accepted the commit,
the Welcome opened) and before the replacement group is saved. The old state is
finished with and released before this returns, so no two handles to one group's
state are live when the new one is saved.

The TypeScript twin is ``settleEscrow`` in ``rine-core/src/mls-escrow-settle.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._crypto.keys import load_agent_keys
from rine._logging import logger
from rine._mls.binding import open_mls_client
from rine._mls.escrow_keys import cached_escrow_key
from rine._mls.escrow_report import EscrowDeferral, EscrowReport
from rine._mls.escrow_snapshots import park_snapshot
from rine._mls.escrow_take import take_and_seal
from rine._mls.group_access import load_mls_group

if TYPE_CHECKING:
    from rine._mls.binding import EscrowBacklog
    from rine._mls.heartbeat import MlsActor


def settle_escrow(actor: MlsActor, group_id: str) -> EscrowReport:
    """Seal the stored state's exports, or park the state for the sweep; never raises.

    What the state still holds is read before the take: ``take_escrow_exports``
    drains the queue, so a sealing failure after it leaves only the parked copy of
    the stored state, which still holds every export, and the counts to report.
    The forks of those exports are read only when the state is parked, from the
    stored state, which the take never touched.
    """
    try:
        group = load_mls_group(open_mls_client(actor.config_dir, actor.agent_id), group_id)
    except Exception:
        # Unreadable state is discarded anyway; pending files stay on disk.
        logger.debug("MLS escrow settle skipped for group %s", group_id, exc_info=True)
        return EscrowReport()
    if group is None:
        return EscrowReport()
    held = group.escrow_backlog()
    epoch = group.epoch()
    key = cached_escrow_key(actor)
    if key is not None:
        try:
            keys = load_agent_keys(actor.config_dir, actor.agent_id)
            return EscrowReport(gaps=take_and_seal(actor, group_id, key, keys, group).gaps)
        except Exception:
            logger.warning("MLS escrow settle could not seal group %s", group_id, exc_info=True)
    return _park(actor, group_id, epoch, held)


def _forks(actor: MlsActor, group_id: str) -> dict[int, bytes]:
    """The fork of each queued export and of the current epoch, from the stored state.

    The stored state is read afresh because the handle ``settle_escrow`` holds may
    have been drained by a take that failed to seal. Advisory, like the record it
    feeds: a failure to read them parks the state with none.
    """
    try:
        group = load_mls_group(open_mls_client(actor.config_dir, actor.agent_id), group_id)
        if group is None:
            return {}
        forks = dict(group.queued_escrow_fingerprints())
        forks[group.epoch()] = group.epoch_fingerprint()
    except Exception:
        logger.warning(
            "MLS escrow settle could not read the forks of a parked state", exc_info=True
        )
        return {}
    return forks


def _park(
    actor: MlsActor,
    group_id: str,
    epoch: int,
    held: EscrowBacklog,
) -> EscrowReport:
    """Set the stored snapshot aside when it still holds exports (or lost some)."""
    if not (held.queued or held.dropped):
        return EscrowReport(deferral=EscrowDeferral.KEY_UNAVAILABLE)
    parked = False
    try:
        parked = park_snapshot(
            actor.config_dir,
            actor.agent_id,
            group_id,
            epoch,
            held.queued,
            held.dropped,
            _forks(actor, group_id),
        )
    except Exception:
        logger.warning("MLS escrow settle could not park group %s", group_id, exc_info=True)
    return EscrowReport(
        deferral=EscrowDeferral.KEY_UNAVAILABLE,
        queued=held.queued,
        dropped=held.dropped,
        backlogged=int(parked),
    )
