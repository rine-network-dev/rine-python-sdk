"""Take a group's escrow exports and put them on disk, without saving or uploading.

The one place the three callers that hold a native group do the same thing: the
drain (:mod:`rine._mls.escrow_drain`), the local settle that runs before a state
is discarded (:mod:`rine._mls.escrow_settle`) and the reopening of a parked
snapshot (:mod:`rine._mls.escrow_backlog`). The caller owns what comes next:
``group.save()`` for a state that stays, nothing for one that is about to go.

Only the live drain records the group's head: the head says which fork the
group's CURRENT epoch is pinned to, and a settled or reopened old state is not
the live one. The drain writes it from :attr:`Taken.newest`.

The TypeScript twin is ``takeAndSeal`` in ``rine-core/src/mls-escrow-drain.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._mls.escrow_gap import DrainGap, file_gaps
from rine._mls.escrow_head import EscrowHead
from rine._mls.escrow_seal import seal_taken

if TYPE_CHECKING:
    from rine._crypto.escrow_key import VerifiedEscrowKey
    from rine._crypto.keys import AgentKeys
    from rine._mls.binding import MlsGroup
    from rine._mls.heartbeat import MlsActor


@dataclass(frozen=True, slots=True)
class Taken:
    """What taking a group's exports put on disk."""

    sealed: int
    """New pending files written."""

    gaps: tuple[DrainGap, ...]
    """Epochs the core reported as having no escrow, each already filed as a marker."""

    newest: EscrowHead | None
    """The newest epoch taken and its fork fingerprint; ``None`` when nothing was taken."""


def take_and_seal(
    actor: MlsActor, group_id: str, key: VerifiedEscrowKey, keys: AgentKeys, group: MlsGroup
) -> Taken:
    """Seal every pending export of ``group`` to disk and file its gap markers.

    Raises:
        CryptoError: Sealing or a write failed. Nothing was saved, so the exports
            re-yield the next time the state is loaded.
    """
    take = group.take_escrow_exports()
    sealed = seal_taken(actor, group_id, key, keys, take.exports)
    newest = None
    if take.exports:
        latest = max(take.exports, key=lambda e: e.epoch)
        newest = EscrowHead(latest.epoch, latest.fp)
    gaps = tuple(DrainGap(g.epoch, g.reason, g.fp) for g in take.gaps)
    file_gaps(actor.config_dir, actor.agent_id, group_id, gaps)
    return Taken(sealed, gaps, newest)
