"""Step 6 of recovery: put a restored agent back into its closed groups.

Ports rine-core's ``recover-reseat.ts``. A fresh device holds no MLS state, so
each seat is retaken with ``resync_from_group_info``: one external commit that
replaces the leaf found by the agent's credential, needing nothing but the
published GroupInfo. Local state is adopted only after the server accepts the
commit, and the resync epoch is escrowed. A commit that loses the epoch
race (the group advanced between the GroupInfo fetch and the post) is rebuilt once
from a fresh GroupInfo; a second loss is reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from typing import TYPE_CHECKING

from rine._actor import AGENT_HEADER
from rine._mls.allowed import admit_group_peers
from rine._mls.api import MlsCommit, fetch_group_info
from rine._mls.binding import DEFAULT_CIPHER_SUITE, NoSeatToReplaceError, open_mls_client
from rine._mls.commit import post_mls_commit
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
from rine._mls.escrow_settle import settle_escrow
from rine._mls.escrow_stored import epoch_escrow_pending
from rine._mls.failures import is_epoch_conflict
from rine._mls.group_access import note_mls_state_changed
from rine._mls.heartbeat import MlsActor
from rine._mls.rotated_leaf import MlsRotatedLeafError, admit_refused_peers_for_resync
from rine._mls.seated_groups import seated_mls_groups
from rine.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rine._http import SyncHttpClient


class ReseatStatus(StrEnum):
    """What recovery did with one closed group."""

    RESEATED = "reseated"
    NO_GROUP_INFO = "no_group_info"
    NOT_SEATED = "not_seated"
    NEEDS_READD = "needs_readd"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class GroupReseat:
    """One agent's outcome in one closed group. ``reason`` says why it was not reseated."""

    agent_id: str
    group_id: str | None
    status: ReseatStatus
    reason: str | None = None
    escrow_pending: bool = False
    """True when the seat was retaken but the resync epoch's escrow is not stored yet:
    the agent's first send into the group is refused until a later drain uploads it."""

    escrow: EscrowReport = field(default_factory=EscrowReport)
    """What settling the replaced state and draining the resync epoch could not do:
    gaps, a deferral, and what waits queued or backlogged."""


def _resync_once(actor: MlsActor, group_id: str, headers: dict[str, str]) -> GroupReseat:
    """Take one GroupInfo, post one external commit, adopt and escrow the epoch."""
    client, config_dir, agent_id = actor.client, actor.config_dir, actor.agent_id
    info = fetch_group_info(client, group_id, headers)
    if info.blob is None:
        return GroupReseat(
            agent_id, group_id, ReseatStatus.NO_GROUP_INFO, "the group has published no GroupInfo"
        )
    admit_group_peers(actor, group_id)
    mls = open_mls_client(config_dir, agent_id)
    group = admit_refused_peers_for_resync(
        actor, mls, partial(mls.resync_from_group_info, info.blob), group_id
    )
    bundle = group.last_commit()
    if bundle is None:
        raise CryptoError("the resync produced no commit")
    post_mls_commit(
        actor,
        group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=DEFAULT_CIPHER_SUITE,
        ),
        headers,
    )
    settled = settle_escrow(actor, group_id)
    drained = drain_escrow(actor, group_id, group, carry_unreported=True)
    note_mls_state_changed(config_dir, agent_id, group_id)
    pending = epoch_escrow_pending(actor, group_id, group.epoch())
    return GroupReseat(
        agent_id,
        group_id,
        ReseatStatus.RESEATED,
        escrow_pending=pending,
        escrow=settled.merge(drained.report()),
    )


def retake_seat(
    client: SyncHttpClient, config_dir: str, agent_id: str, group_id: str
) -> GroupReseat:
    """Retake one agent's own seat, rebuilding once on an epoch conflict.

    Raises:
        NoSeatToReplaceError: The tree holds no leaf under this agent's credential.
        MlsRotatedLeafError: The leaf is under a key this agent rotated away from.
        PeerNotAdmittedError: The tree holds another member the core cannot verify.
        Exception: Whatever the GroupInfo read, the commit post or the core raised.
    """
    headers = {AGENT_HEADER: agent_id}
    actor = MlsActor(client=client, config_dir=config_dir, agent_id=agent_id)
    try:
        return _resync_once(actor, group_id, headers)
    except Exception as err:
        if not is_epoch_conflict(err):
            raise
    return _resync_once(actor, group_id, headers)


def reseat_group(
    client: SyncHttpClient, config_dir: str, agent_id: str, group_id: str
) -> GroupReseat:
    """Reseat one agent in one group; every failure becomes a reported outcome."""
    try:
        return retake_seat(client, config_dir, agent_id, group_id)
    except NoSeatToReplaceError:
        reason = "the group's roster no longer holds this agent"
        return GroupReseat(agent_id, group_id, ReseatStatus.NOT_SEATED, reason)
    except MlsRotatedLeafError as err:
        return GroupReseat(agent_id, group_id, ReseatStatus.NEEDS_READD, str(err))
    except Exception as err:
        return GroupReseat(agent_id, group_id, ReseatStatus.FAILED, str(err))


def reseat_closed_groups(
    client: SyncHttpClient, config_dir: str, agent_ids: Iterable[str]
) -> list[GroupReseat]:
    """Reseat each restored agent in every closed group the server lists it in.

    A group that cannot be reseated is reported, never retried. An agent whose
    group list cannot be read is reported once, with no group id.
    """
    reseats: list[GroupReseat] = []
    for agent_id in agent_ids:
        try:
            groups = seated_mls_groups(client, agent_id)
        except Exception as err:
            reseats.append(GroupReseat(agent_id, None, ReseatStatus.FAILED, str(err)))
            continue
        reseats.extend(reseat_group(client, config_dir, agent_id, str(g.id)) for g in groups)
    return reseats


__all__ = ["GroupReseat", "ReseatStatus", "reseat_closed_groups", "reseat_group", "retake_seat"]
