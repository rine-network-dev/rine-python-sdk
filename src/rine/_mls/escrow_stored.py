"""Whether one epoch's read escrow is stored.

The TypeScript twin is ``epochEscrowStored`` (``rine-core/src/mls-escrow-stored.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.escrow_head import read_head
from rine._mls.escrow_store import list_pending

if TYPE_CHECKING:
    from rine._mls.actor import MlsActor


def epoch_escrow_pending(actor: MlsActor, group_id: str, epoch: int) -> bool:
    """Whether the epoch just adopted still lacks a stored escrow.

    Decided from this epoch alone: it is pending until the drain's head names it
    (sealed) and no sealed file for it is left waiting (uploaded). A failure on an
    older epoch of the group, or a gap, does not decide it.
    """
    head = read_head(actor.config_dir, actor.agent_id, group_id)
    if head is None or head.epoch != epoch:
        return True
    waiting = list_pending(actor.config_dir, actor.agent_id, group_id)
    return any(p.epoch == epoch for p in waiting)


__all__ = ["epoch_escrow_pending"]
