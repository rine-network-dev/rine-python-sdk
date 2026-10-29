"""The settlement guard: a process-wide hold on the agents whose rotation is settling.

A settlement opens every group the agent is seated in and moves its leaf. Opening a
group runs a sync, and a sync runs a gated heartbeat, which is the very call that
would start the settlement again; the hold is what ends that recursion. The
heartbeat's own stamp cannot serve, because a failed top-up deletes it.

A commit's own heartbeat takes the hold too (:mod:`rine._mls.commit`): the caller has
not applied its commit yet, so a settlement opening the same group there would read
that commit as a peer's.

The async client runs MLS work on ``asyncio.to_thread`` workers, so taking the hold
is one atomic step under a lock. The TypeScript twin is
``rine-core/src/mls-settle-guard.ts``.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rine._mls.actor import MlsActor

#: Agents whose settlement is running in this process, keyed ``(config dir, agent)``.
_settling: set[tuple[str, str]] = set()
_lock = threading.Lock()


@contextmanager
def hold_settlement(actor: MlsActor) -> Iterator[bool]:
    """Mark this agent as settling for the duration of the block.

    The hold is released only by the call that took it, so a nested call for an
    agent already settling leaves the outer hold standing.

    Yields:
        ``True`` when this call took the hold, ``False`` when the agent was already
        settling.
    """
    key = (actor.config_dir, actor.agent_id)
    with _lock:
        taken = key not in _settling
        if taken:
            _settling.add(key)
    try:
        yield taken
    finally:
        if taken:
            with _lock:
                _settling.discard(key)


__all__ = ["hold_settlement"]
