"""The epochs a background sweep lost that no result has told the caller about yet.

The sweep runs on the heartbeat and at start-up, and nothing there hands a result back:
it files a gap marker for every epoch it gives up on and moves on. The caller learns of a
loss from the next result that carries an escrow report, so the sweep leaves the gaps it
filed here, per (config dir, agent, group), and the next drain or sync result of THAT group
takes them and clears them: a result never reports another group's loss. Each loss is
reported once. Only a call that hands its result to a caller takes them; a drain or a sync
whose result is dropped (a send's pre-sync, a retry) leaves them for one that does not.

The markers on disk are the durable record; this handoff is only the news of them, held in
the process, and a process that ends before a result carries it loses the news and keeps the
markers. The TypeScript twin is ``rine-core/src/mls-escrow-handoff.ts``.
"""

from __future__ import annotations

from threading import Lock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rine._mls.escrow_gap import DrainGap, LocatedGap

_unreported: dict[tuple[str, str, str], list[DrainGap]] = {}
_lock = Lock()


def note_unreported(config_dir: str, agent_id: str, gaps: Iterable[LocatedGap]) -> None:
    """Remember gaps no result has reported yet, each under its own group."""
    with _lock:
        for located in gaps:
            key = (config_dir, agent_id, located.group_id)
            _unreported.setdefault(key, []).append(located.gap)


def take_unreported(config_dir: str, agent_id: str, group_id: str) -> tuple[DrainGap, ...]:
    """One group's gaps waiting to be reported, in the order they were noted; they are cleared."""
    with _lock:
        return tuple(_unreported.pop((config_dir, agent_id, group_id), ()))


def reset_escrow_handoff() -> None:
    """Forget every handoff. Test-only: a process boundary is what clears it in life."""
    with _lock:
        _unreported.clear()
