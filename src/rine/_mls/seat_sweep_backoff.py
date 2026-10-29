"""How long a background seat sweep waits after leaving a seat deferred.

A group that cannot take a self-update (a commit held for acknowledgement, a peer that
cannot be reached) stays that way for a while, and the heartbeat that settles a rotation
runs on every MLS operation. Without a wait, each beat would retry it. A sweep that left a
seat deferred doubles the wait before the next background one, from a minute up to an hour;
one that settled everything forgets the wait.

Per process and deliberately not persisted: a restart gets a fresh try, which is what a
stuck group needs most. The TypeScript twin is ``noteSweep`` in ``rine-core/src/mls-seat-sweep.ts``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rine._mls.actor import MlsActor

BACKOFF_BASE_S = 60.0
BACKOFF_MAX_S = 60.0 * 60.0


@dataclass(frozen=True)
class _Stuck:
    failures: int
    not_before: float


_stuck: dict[tuple[str, str], _Stuck] = {}


def _now() -> float:
    return time.monotonic()


def sweep_must_wait(actor: MlsActor) -> bool:
    """True while a background sweep for this agent is inside its backoff."""
    stuck = _stuck.get((actor.config_dir, actor.agent_id))
    return stuck is not None and _now() < stuck.not_before


def note_sweep(actor: MlsActor, *, deferred: bool) -> None:
    """Record how a background-eligible sweep ended, doubling the wait when it deferred."""
    key = (actor.config_dir, actor.agent_id)
    if not deferred:
        _stuck.pop(key, None)
        return
    failures = (_stuck[key].failures if key in _stuck else 0) + 1
    wait = min(BACKOFF_MAX_S, BACKOFF_BASE_S * 2 ** (failures - 1))
    _stuck[key] = _Stuck(failures, _now() + wait)


def reset_seat_sweep_backoff() -> None:
    """Forget every backoff. Test-only: a process boundary is what clears it in life."""
    _stuck.clear()


__all__ = ["note_sweep", "reset_seat_sweep_backoff", "sweep_must_wait"]
