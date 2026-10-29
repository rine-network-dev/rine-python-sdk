"""One orphan reclamation when a group's tree outgrew the escrow bound.

The native core cannot escrow an epoch whose ratchet tree holds more leaves than
the bound, and files it as a ``too_many_leaves`` gap. Orphaned leaves (members
who left without committing their own removal) are the usual reason a tree is
larger than its roster, so a send that meets such a gap runs the reclamation
once for the group, then drains the epoch it produced and looks again.

Once per (config dir, agent, group, gap epoch) per process: a reclamation is one
O(N) commit per orphan, billed to every member, so it is never repeated to see
whether the gap went away. A later, distinct gap is a new case and gets its own;
a failed attempt counts as the one for its gap. The TypeScript twin is
``reclaimOnceForGap`` in ``rine-core/src/mls-escrow-leaves.ts``.
"""

from __future__ import annotations

from typing import Any

from rine._logging import logger
from rine._mls.orphans import reclaim_orphan_leaves

_attempted: set[tuple[str, str, str, int]] = set()


def reclaim_once_for_gap(
    client: Any, config_dir: str, agent_id: str, group_id: str, epoch: int
) -> bool:
    """Run the orphan reclamation unless this process already did for the gap at ``epoch``.

    Best effort: a reclamation that fails or declines leaves the gap standing, and
    the send reports it.

    Returns:
        True when a reclamation ran now, so the caller should drain and look again.
    """
    gate = (config_dir, agent_id, group_id, epoch)
    if gate in _attempted:
        return False
    _attempted.add(gate)
    try:
        reclaim_orphan_leaves(client, config_dir, agent_id, group_id)
    except Exception:
        logger.debug("MLS orphan reclamation for a too_many_leaves gap failed", exc_info=True)
    return True


def reset_gap_reclamation() -> None:
    """Forget every attempt. Test-only: a process boundary is what clears it in life."""
    _attempted.clear()
