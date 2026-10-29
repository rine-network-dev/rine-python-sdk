"""Every gap marker on disk for an agent.

The markers (:mod:`rine._mls.escrow_gap`) are what remembers an epoch with no escrow, so a
surface that reports a recovery lists them from here rather than relying on news a
background sweep kept in memory: a process that exits before a result carried that news
loses only the memory, never the marker.

The TypeScript twin is ``rine-core/src/mls-escrow-gap-list.ts``: the same listing, with the same
markers in the same order, under camelCase field names and an absent ``fork`` where this one
has ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass

from rine._mls.escrow_gap import GapReason
from rine._mls.escrow_markers import group_markers
from rine._mls.escrow_store import group_dirs


@dataclass(frozen=True, slots=True)
class GapMarker:
    """One marker: an epoch of a group with no escrow, and why."""

    agent_id: str
    group_id: str
    epoch: int
    fork: str | None
    """The fork's fingerprint (32 hex), when the marker names one."""
    reason: GapReason


def list_gap_markers(config_dir: str, agent_id: str) -> list[GapMarker]:
    """Every gap marker on disk for ``agent_id``, across its groups, sorted by group then name.

    A marker whose text names no known reason is left out, as :func:`read_gap` leaves it out.
    """
    return [
        GapMarker(agent_id, group_id, found.epoch, found.fork, found.reason)
        for group_id, directory in group_dirs(config_dir, agent_id)
        for found in group_markers(directory)
    ]
