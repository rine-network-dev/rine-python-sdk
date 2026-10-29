"""Catching a group's local state up with the commits its members published.

An MLS group advances by commits, and a member that has not applied them is at
the wrong epoch: it cannot read what peers send, and what it sends is readable
only by members that kept the older epoch's secrets. So every send and every
read passes through here first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import Any

from rine._actor import AGENT_HEADER
from rine._mls.allowed import admit_group_peers
from rine._mls.binding import PeerNotAdmittedError
from rine._mls.commit_admission import admit_refused_peers
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_handoff import take_unreported
from rine._mls.escrow_report import EscrowReport
from rine._mls.failures import is_unprocessable_commit
from rine._mls.group_access import open_mls_group
from rine._mls.heartbeat import MlsActor, mls_heartbeat
from rine._mls.pending_commit import (
    PendingCommitOutcome,
    PendingCommitSettlement,
    settle_pending_commit,
)
from rine._mls.sync_api import fetch_handshake_feed
from rine._mls.sync_signals import emit_ack, emit_nack, reconcile_if_orphaned


@dataclass(frozen=True)
class MlsSyncResult:
    """Where a sync left the group."""

    epoch: int
    processed: int

    evicted: bool
    """True when the member is no longer in the group's ratchet tree.

    Eviction is the correct outcome of a valid Remove commit, not an error: the
    group keeps decrypting the backlog it already holds secrets for, but can no
    longer send or commit. In-session only — the core does not persist it, so a
    later process reloads the group as active and learns otherwise from the first
    operation that refuses.
    """

    escrow: EscrowReport = field(default_factory=EscrowReport)
    """What the drains of the applied commits (or of a re-bootstrap) could not do:
    epochs with no escrow, a deferral, and what waits queued."""

    pending_commit: PendingCommitSettlement | None = None
    """What became of a self-update this member built and had not applied, when it
    held one: applied, still held, or lost. ``None`` when nothing was pending."""


def sync_mls_group(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    *,
    carry_unreported: bool = False,
) -> MlsSyncResult:
    """Apply every commit posted to the group since this agent's current epoch.

    With ``carry_unreported`` the result also reports the epochs a background sweep lost in
    this group since the last report (:mod:`rine._mls.escrow_handoff`). Pass it only where
    the result reaches a caller: a sync whose result is dropped would take the news and
    throw it away.

    Carries the acting agent's key-package heartbeat, which is what covers the
    verbs that post no commit — the catch-up behind an ordinary read, the replay
    rung of a recovery, and the retries behind a removal or a reclamation. It
    beats BEFORE the group handle is opened, so only one MLS handle for this
    store root is ever live at a time.

    Raises:
        NoMlsGroupStateError: When this agent holds no local state for the group.
        MlsStoreError: When the local store cannot be read or written — a failure
            of this process, which the next sync retries rather than blaming on
            the commit.
    """
    headers = {AGENT_HEADER: agent_id}
    mls_heartbeat(MlsActor(client=client, config_dir=config_dir, agent_id=agent_id), "gated")
    group = open_mls_group(config_dir, agent_id, group_id)
    # A holding handle names its pending epoch, and the answer says where its own
    # commit stands. A handle with nothing pending sends the plain request.
    feed = fetch_handshake_feed(
        client, group_id, group.epoch(), headers, group.pending_commit_epoch()
    )
    handshakes = feed.handshakes
    actor = MlsActor(client=client, config_dir=config_dir, agent_id=agent_id)

    settled = settle_pending_commit(actor, group_id, group, feed.pending_commit)
    escrow = settled.escrow if settled is not None else EscrowReport()
    if settled is not None and settled.outcome is PendingCommitOutcome.HELD:
        # Our own commit is not confirmed yet, so a commit built on it cannot be
        # told from a commit built on a rolled-back epoch. Applying or NACKing
        # anything past it would be a guess.
        return _idle(config_dir, agent_id, group_id, group, escrow, carry_unreported, settled)

    # Applying a peer's commit meets its leaves for the first time, so the
    # chain-verified peers must be admitted first. An idle sync has no handshakes
    # and stays free of the extra reads.
    if handshakes:
        admit_group_peers(actor, group_id)

    epoch = group.epoch()
    processed = 0

    for handshake in handshakes:
        # The feed was read before the pending commit was applied, so a handshake at
        # or below the epoch now held is already in this handle.
        if handshake.epoch is not None and handshake.epoch <= epoch:
            continue
        try:
            epoch = admit_refused_peers(actor, group, partial(group.apply_commit, handshake.blob))
        except Exception as err:
            # Three causes must be told apart. A local failure (store I/O, a
            # retired handle) is not the commit's fault. Our OWN state may be
            # orphaned — our tentative self-join was rolled back, so no peer
            # commit can ever apply to our stale branch, and NACK-looping that
            # is a permanent per-member denial of participation. Only what is
            # left is a genuinely un-processable commit, which earns one NACK.
            if not is_unprocessable_commit(err):
                raise
            reconciled = reconcile_if_orphaned(
                client, config_dir, agent_id, group_id, epoch, headers, carry_unreported
            )
            if reconciled is not None:
                return MlsSyncResult(
                    epoch=reconciled.epoch,
                    processed=processed,
                    evicted=False,
                    escrow=escrow.merge(reconciled.escrow),
                    pending_commit=settled,
                )
            emit_nack(client, group_id, handshake, err, headers)
            # A refused peer is a typed outcome, not a quiet stop: the recovery
            # ladder reads it and climbs to the resync that seats us past it.
            if isinstance(err, PeerNotAdmittedError):
                raise
            break
        processed += 1
        # Persist the advance BEFORE ACKing, so a crash mid-ACK never confirms an
        # epoch we did not save locally.
        escrow = escrow.advance(
            drain_escrow(actor, group_id, group, carry_unreported=carry_unreported).report()
        )
        emit_ack(client, group_id, handshake.id, headers)
        if not group.is_active():
            return MlsSyncResult(
                epoch=epoch,
                processed=processed,
                evicted=True,
                escrow=escrow,
                pending_commit=settled,
            )

    return _idle(
        config_dir, agent_id, group_id, group, escrow, carry_unreported, settled, processed
    )


def _idle(
    config_dir: str,
    agent_id: str,
    group_id: str,
    group: Any,
    escrow: EscrowReport,
    carry_unreported: bool,
    settled: PendingCommitSettlement | None,
    processed: int = 0,
) -> MlsSyncResult:
    """The result of a sync that applied what it was going to.

    An idle sync drains nothing, so it takes the news of a background loss itself.
    """
    if carry_unreported:
        escrow = escrow.merge(EscrowReport(gaps=take_unreported(config_dir, agent_id, group_id)))
    return MlsSyncResult(
        epoch=group.epoch(),
        processed=processed,
        evicted=not group.is_active(),
        escrow=escrow,
        pending_commit=settled,
    )
