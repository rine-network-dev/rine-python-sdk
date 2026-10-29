"""The MLS read-escrow drain: seal, persist, save, upload.

This replaces a bare ``group.save()`` at every epoch-install site. The order is
the crash-safety argument: take the exports and seal them to disk BEFORE
``group.save()``, so a crash in between re-yields them on the next load; only
then save, which makes the take durable; only then upload, so a network failure
leaves the sealed bytes on disk for the next drain rather than losing them. The
pending files of every other group, held or not, are the sweep's
(:mod:`rine._mls.escrow_sweep`), which runs on the heartbeat and at start-up, not here.

It never raises for a key or network problem: those are reported in the outcome.
A sealing or write failure DOES propagate — nothing was saved, so nothing is
lost, and the caller must not treat the epoch as installed.

The TypeScript twin is ``rine-core/src/mls-escrow-drain.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from rine._crypto.keys import load_agent_keys
from rine._logging import logger
from rine._mls.escrow_gap import DrainGap
from rine._mls.escrow_handoff import take_unreported
from rine._mls.escrow_head import EscrowHead, read_head, write_head
from rine._mls.escrow_keys import resolve_escrow_key
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_report import EscrowReport, deferral_for, report_from_backlog
from rine._mls.escrow_store import list_pending
from rine._mls.escrow_take import take_and_seal
from rine._mls.escrow_upload import upload_files
from rine.errors import CryptoError, EscrowGapError, RineError

if TYPE_CHECKING:
    from rine._mls.binding import EscrowBacklog, MlsGroup
    from rine._mls.heartbeat import MlsActor

#: Logged when sealing is skipped because no verified escrow key could be read.
DEFERRED_LOG = "MLS escrow drain deferred: no verified branch escrow key"

#: The refusal a sender gets for an epoch whose escrow has not been drained yet.
NO_DRAINED_ESCROW = (
    "group {group_id} epoch {epoch} has no drained escrow yet, so a send would be "
    "unreadable to the org; drain the escrow for this epoch first"
)


@dataclass(frozen=True, slots=True)
class DrainOutcome:
    """What one drain did, and what it could not do."""

    sealed: int
    """New pending files written by this call."""

    uploaded: int
    """Pending files the server now holds, uploaded or already stored, and deleted by this call."""

    failures: tuple[Exception, ...]
    """Upload failures. A file the server may yet accept stays for the next drain; one it
    refused for good is deleted and listed here once."""

    deferred: Exception | None
    """Set when sealing was not attempted (no verified escrow key, or a revoked branch). The
    exports stay queued in the saved snapshot, up to the group's cap; the drain never discards
    them (the sweep gives up the snapshots of a revoked branch)."""

    gaps: tuple[DrainGap, ...] = ()
    """Epochs that have no escrow, each filed as a local gap marker: the ones the core reported
    before the group was saved, and the ones an upload gave up on."""

    backlog: EscrowBacklog | None = None
    """Set with ``deferred`` when the exports were kept: what waits in the snapshot."""

    def report(self) -> EscrowReport:
        """This outcome as the typed record the sync, join, admission and reseat results carry."""
        return EscrowReport(
            gaps=self.gaps,
            deferral=deferral_for(self.deferred) if self.deferred is not None else None,
        ).merge(report_from_backlog(self.backlog))


def upload_pending_escrow(actor: MlsActor, group_id: str) -> DrainOutcome:
    """Upload this group's pending escrows without taking or saving anything.

    Raises:
        RineError: The branch escrow key could not be resolved or verified.
    """
    key = resolve_escrow_key(actor)
    keys = load_agent_keys(actor.config_dir, actor.agent_id)
    up = upload_files(actor, list_pending(actor.config_dir, actor.agent_id, group_id), key, keys)
    return DrainOutcome(
        sealed=0, uploaded=up.uploaded, failures=up.failures, deferred=None, gaps=up.gaps
    )


def drain_escrow(
    actor: MlsActor,
    group_id: str,
    group: MlsGroup,
    *,
    upload: bool = True,
    carry_unreported: bool = False,
) -> DrainOutcome:
    """Seal, persist, save and upload one group's escrow exports.

    With ``carry_unreported`` the epochs a background sweep lost in THIS group since the
    last report join the outcome's gaps (:mod:`rine._mls.escrow_handoff`) and are cleared,
    so each is reported once. Pass it only where the outcome reaches a caller: a call whose
    outcome is dropped would take the news and throw it away.

    ``upload=False`` stops after the save: the sealed files stay pending for the
    next drain of this group, which uploads them. Only this group's files are
    sent, and each only when its own retry schedule says it is due.

    A key or network problem is reported in the outcome, never raised; a sealing
    or write failure propagates, because nothing was saved and so nothing is lost.
    A revoked branch or agent defers like any other missing key: the exports stay queued.
    """
    outcome = _drain(actor, group_id, group, upload=upload)
    if not carry_unreported:
        return outcome
    carried = take_unreported(actor.config_dir, actor.agent_id, group_id)
    return replace(outcome, gaps=(*carried, *outcome.gaps)) if carried else outcome


def _drain(actor: MlsActor, group_id: str, group: MlsGroup, *, upload: bool) -> DrainOutcome:
    """:func:`drain_escrow` without the handoff."""
    try:
        key = resolve_escrow_key(actor)
    except RineError as exc:
        logger.warning(DEFERRED_LOG, exc_info=True)
        # No verified key: save WITHOUT taking, so the exports stay in the
        # snapshot and the next drain yields them again.
        backlog = group.escrow_backlog()
        group.save()
        return DrainOutcome(0, 0, (), exc, backlog=backlog)

    keys = load_agent_keys(actor.config_dir, actor.agent_id)
    taken = take_and_seal(actor, group_id, key, keys, group)
    if taken.newest is not None:
        live = taken.newest.epoch == group.epoch() and taken.newest.fp == group.epoch_fingerprint()
        write_head(actor.config_dir, actor.agent_id, group_id, taken.newest, live=live)

    # Everything is on disk: this is the line a crash before it re-yields the
    # exports, and the line a crash after it would lose them.
    group.save()
    if not upload:
        return DrainOutcome(taken.sealed, 0, (), None, gaps=taken.gaps)

    pending = list_pending(actor.config_dir, actor.agent_id, group_id)
    up = upload_files(actor, pending, key, keys, due_only=True)
    return DrainOutcome(taken.sealed, up.uploaded, up.failures, None, gaps=(*taken.gaps, *up.gaps))


def escrow_fp_for(actor: MlsActor, group_id: str, group: MlsGroup) -> bytes:
    """The fork fingerprint a sender must carry for the group's CURRENT epoch.

    The fork is the group's live one. The drain's head vouches for the epoch only when it
    names that fork, and only that fork's gap marker, or a fork-less one, speaks for it:
    another fork's loss never blocks a send on the live fork.

    Raises:
        EscrowGapError: The live fork of the current epoch is a recorded gap: it has no
            escrow and never will.
        CryptoError: The live fork of the current epoch has no drained escrow yet, so a
            send would be unreadable to the org.
    """
    epoch = group.epoch()
    fp = group.epoch_fingerprint()
    head = read_head(actor.config_dir, actor.agent_id, group_id)
    if head == EscrowHead(epoch, fp):
        return fp
    reason = read_gap(actor.config_dir, actor.agent_id, group_id, epoch, fp)
    if reason is not None:
        raise EscrowGapError(group_id, epoch, reason)
    raise CryptoError(NO_DRAINED_ESCROW.format(group_id=group_id, epoch=epoch))
