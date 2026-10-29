"""Moving this agent's own leaf in one group to the key it rotated to.

Rotating an agent's key changes what the agent signs with, and nothing else: every
group it sits in still holds a leaf under the old key. A self-update is one
commit whose UpdatePath carries the new key, so the leaf moves in place and the
seat is kept. Only a host that holds the group's local MLS state can build one.

The commit is built as a pending commit and applied only when the server confirms
it. A closed group confirms on the post and the commit applies at once; an
open-enrollment group answers ``confirmed: false`` and the commit stays pending
until a member acknowledges it, or is dropped if the group rolls it back
(:mod:`rine._mls.pending_commit`). The pending commit is saved before the post
leaves, so no exit point leaves the server holding a commit this host cannot
account for.

Nothing here raises for a group's own refusal: the result is a :class:`SeatUpdate`
the caller reports. The TypeScript twin is ``selfUpdateGroup``
(``rine-core/src/mls-self-update.ts``); the status and reason strings are the same.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._actor import AGENT_HEADER
from rine._crypto.keys import load_agent_keys
from rine._mls.allowed import admit_group_peers
from rine._mls.api import MlsCommit
from rine._mls.binding import (
    DEFAULT_CIPHER_SUITE,
    GroupInactiveError,
    LeafAlreadyCurrentError,
)
from rine._mls.commit import post_mls_commit_bundle
from rine._mls.commit_admission import admit_refused_peers
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_stored import epoch_escrow_pending
from rine._mls.group_access import note_mls_state_changed, open_mls_group
from rine._mls.pending_commit import PendingCommitOutcome
from rine._mls.rotated_leaf import MlsRotatedLeafError
from rine._mls.self_update_outcome import build_failure, post_refused, unsettled
from rine._mls.sync import sync_mls_group
from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdate,
    SeatUpdateStatus,
    deferred,
    failed,
)

if TYPE_CHECKING:
    from rine._mls.binding import MlsGroup
    from rine._mls.commit_wire import MlsCommitAccepted
    from rine._mls.heartbeat import MlsActor


def self_update_group(actor: MlsActor, group_id: str) -> SeatUpdate:
    """Move the acting agent's leaf in ``group_id`` to the key on disk.

    Catches the local state up first, since a commit built on a stale epoch loses
    the server's compare-and-swap. A lost race clears the pending commit, syncs
    and builds once more; a second loss is ``deferred``.

    Args:
        actor: The agent whose leaf moves, and the client it acts through.
        group_id: A group this host holds local state for.

    Returns:
        The outcome. Never raises for a refusal of the group's or the server's.
    """
    try:
        for attempt in (1, 2):
            synced = sync_mls_group(actor.client, actor.config_dir, actor.agent_id, group_id)
            if synced.evicted:
                return failed(group_id, SeatFailReason.EVICTED)
            held = synced.pending_commit
            if held is not None and held.outcome is not PendingCommitOutcome.APPLIED:
                return unsettled(group_id, held)
            built = _build_and_post(actor, group_id)
            if built is not None:
                return built
            if attempt == 2:
                return deferred(group_id, SeatDeferReason.EPOCH_RACE)
    except GroupInactiveError:
        return failed(group_id, SeatFailReason.EVICTED)
    except MlsRotatedLeafError as err:
        return failed(group_id, SeatFailReason.SEAT_UNHEALABLE, str(err))
    except Exception as err:
        return deferred(group_id, SeatDeferReason.UNREACHABLE, detail=str(err))
    raise AssertionError("unreachable")  # pragma: no cover - the loop returns on attempt 2


def _build_and_post(actor: MlsActor, group_id: str) -> SeatUpdate | None:
    """Build the pending commit, save it, post it, and settle on the answer.

    Returns:
        The outcome, or ``None`` when the commit lost the epoch race.
    """
    keys = load_agent_keys(actor.config_dir, actor.agent_id)
    admit_group_peers(actor, group_id)
    group = open_mls_group(actor.config_dir, actor.agent_id, group_id)
    if group.own_leaf_signature_key() == keys.mls.public_key:
        return SeatUpdate(group_id, SeatUpdateStatus.CURRENT, epoch=group.epoch())
    try:
        bundle = admit_refused_peers(
            actor, group, lambda: group.commit_update(keys.mls.private_key)
        )
    except LeafAlreadyCurrentError:
        return SeatUpdate(group_id, SeatUpdateStatus.CURRENT, epoch=group.epoch())
    except GroupInactiveError:
        return failed(group_id, SeatFailReason.EVICTED)
    except Exception as err:
        return build_failure(group, group_id, err)
    # Write-ahead. An applied commit cannot be taken back, which is why the other
    # commits save after the server accepts; a pending one can (``clear``), and it
    # leaves the live state untouched. Saving first is what leaves no exit point
    # with the server holding a commit this host has forgotten.
    group.save()
    commit = MlsCommit(
        commit=bundle.commit,
        group_info=bundle.group_info,
        epoch=bundle.epoch,
        cipher_suite=DEFAULT_CIPHER_SUITE,
    )
    try:
        accepted = post_mls_commit_bundle(actor, group_id, commit, {AGENT_HEADER: actor.agent_id})
    except Exception as err:
        return post_refused(actor, group, group_id, err)
    return _settle_accepted(actor, group, group_id, accepted)


def _settle_accepted(
    actor: MlsActor, group: MlsGroup, group_id: str, accepted: MlsCommitAccepted
) -> SeatUpdate:
    if not accepted.confirmed:
        group.save()
        return deferred(group_id, SeatDeferReason.AWAITING_ACK, epoch=accepted.epoch)
    group.apply_pending_commit()
    # Not carrying the sweep's unreported losses: a seat has no gap list to hand them
    # to, so a later result that does must still find them.
    drain_escrow(actor, group_id, group)
    note_mls_state_changed(actor.config_dir, actor.agent_id, group_id)
    return SeatUpdate(
        group_id,
        SeatUpdateStatus.UPDATED,
        epoch=accepted.epoch,
        escrow_pending=epoch_escrow_pending(actor, group_id, group.epoch()),
    )


__all__ = ["self_update_group"]
