"""Reading the gap markers back.

It answers which of a group's epochs have no escrow, and whether the fork a sender is on is
one of them. The markers themselves, and how they are written, are in
:mod:`rine._mls.escrow_gap`. The TypeScript twin is ``rine-core/src/mls-escrow-markers.ts``.
"""

from __future__ import annotations

import os
from typing import NamedTuple

from rine._mls.binding import EscrowGapReason
from rine._mls.escrow_gap import EscrowLoss, marker_reason, parse_gap_name
from rine._mls.escrow_store import pending_dir


class GroupMarker(NamedTuple):
    """One readable marker of a group: the epoch and fork its name gives, and its reason."""

    epoch: int
    fork: str | None
    reason: EscrowGapReason | EscrowLoss


def group_markers(directory: str) -> list[GroupMarker]:
    """The readable markers in one group's pending dir, in name order.

    A torn file, one whose text names no known reason and one whose name is not a marker's
    are left out.
    """
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    markers: list[GroupMarker] = []
    for name in names:
        parsed = parse_gap_name(name)
        reason = None if parsed is None else marker_reason(os.path.join(directory, name))
        if parsed is not None and reason is not None:
            markers.append(GroupMarker(parsed[0], parsed[1], reason))
    return markers


def read_gap(
    config_dir: str, agent_id: str, group_id: str, epoch: int, fp: bytes
) -> EscrowGapReason | EscrowLoss | None:
    """The recorded reason the fork ``fp`` of an epoch has no escrow, or ``None``.

    The fork's own marker and the fork-less one speak for it, the first in name order; a
    marker of another fork never does. The native take files its gaps fork-less, so dropping
    them would turn a permanent loss of the live epoch into a retryable one. A marker whose
    text names no known reason reads as ``None``, as does an unreadable one.
    """
    forks = {None, fp.hex()}
    directory = pending_dir(config_dir, agent_id, group_id)
    return next(
        (m.reason for m in group_markers(directory) if m.epoch == epoch and m.fork in forks), None
    )
