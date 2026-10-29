"""Cross-process lock file, for a short read-modify-write of a shared file.

Mirror of ``rine-core/src/file-lock.ts``; a lock written by one language is read
for staleness by the other. The lock is created content-atomically
(:func:`rine._atomic_file.create_atomic_exclusive`), and a crashed holder's lock is taken over by
**rename-steal**: ``rename`` has exactly one winner, so two processes that both
judge a lock stale cannot both take it. Never held across network I/O.

The body is ``{"pid": <int>, "acquired_at": <ms>, "token": <hex>}`` plus a newline, mode
0600. The token is the acquire's own, so a release removes the lock only while it is still
the holder's.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from rine._atomic_file import create_atomic_exclusive
from rine._config import _ensure_dir

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@dataclass(frozen=True)
class FileLockTiming:
    """When a lock counts as stale, how long to try before giving up, and how often to retry."""

    stale_ms: int
    timeout_ms: int
    poll_ms: int


class _LockState(Enum):
    """What a failed (EEXIST) create found.

    ``MISSING`` is not stealable: a lock that already vanished is a normal
    release, and stealing on ENOENT could evict a holder that re-created it
    fresh between the read and the steal.
    """

    MISSING = "missing"
    FRESH = "fresh"
    STALE = "stale"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _lock_state(path: str, now_ms: int, stale_ms: int) -> _LockState:
    try:
        with open(path) as f:
            raw = f.read()
        # An empty lock is a holder between its in-place create and its write, so
        # its age is the file's own.
        acquired_at = (
            os.stat(path).st_mtime * 1000 if raw == "" else int(json.loads(raw)["acquired_at"])
        )
    except FileNotFoundError:
        return _LockState.MISSING
    except (OSError, ValueError, KeyError, TypeError):
        return _LockState.STALE  # unreadable or garbage: a crashed writer's leftovers
    # A stamp from the future (a wall clock stepped back) reads as fresh: it may be a
    # live holder's, and stealing it would give the lock two holders.
    return _LockState.FRESH if now_ms - acquired_at < stale_ms else _LockState.STALE


def _try_create(path: str, now_ms: int, token: str) -> bool:
    """Create the lock with its body already present; ``False`` if someone holds it."""
    body = {"pid": os.getpid(), "acquired_at": now_ms, "token": token}
    encoded = (json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8")
    return create_atomic_exclusive(path, encoded)


def _steal_stale(path: str) -> None:
    """Rename-steal a stale lock; a rename that fails lost the race, and the caller retries."""
    stolen = f"{path}.stale-{os.urandom(8).hex()}"
    try:
        os.rename(path, stolen)
    except OSError:
        return
    with suppress(OSError):
        os.unlink(stolen)


def _acquire(path: str, timing: FileLockTiming, busy: Callable[[], Exception], token: str) -> None:
    _ensure_dir(os.path.dirname(path))
    deadline = _now_ms() + timing.timeout_ms
    while True:
        now_ms = _now_ms()
        if _try_create(path, now_ms, token):
            return
        state = _lock_state(path, now_ms, timing.stale_ms)
        if state is _LockState.STALE:
            _steal_stale(path)
            continue
        if now_ms >= deadline:
            raise busy()
        if state is _LockState.FRESH:
            time.sleep(timing.poll_ms / 1000)
        # MISSING: released between the create and the read; retry at once.


@contextmanager
def file_lock(path: str, timing: FileLockTiming, busy: Callable[[], Exception]) -> Iterator[None]:
    """Hold the lock at ``path`` for the ``with`` block, always releasing it.

    Raises ``busy()`` when a live holder keeps the lock past ``timing.timeout_ms``.
    The release is best-effort: a stranded lock self-heals once it is stale.
    """
    token = os.urandom(8).hex()
    _acquire(path, timing, busy, token)
    try:
        yield
    finally:
        _release(path, token)


def _release(path: str, token: str) -> None:
    """Remove the lock if it still carries ``token``.

    A holder that overran the stale age may have been stolen from; the lock it finds
    then is the new holder's, and stays.
    """
    with suppress(OSError, ValueError):
        with open(path, encoding="utf-8") as handle:
            held = json.load(handle)
        if held.get("token") == token:
            os.unlink(path)
