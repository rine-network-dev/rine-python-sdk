"""Cross-process spend-reservation lock (mirror of ``x402/spend-lock.ts``).

A file lock held across the read → enforce → write of the daily-spend journal so
two processes of the same agent cannot both slip a payment past the daily cap
(the S2 cross-process TOCTOU fix). Byte-compatible with the TypeScript lock: same
path (``keys/{agent_id}/wallet-spend.lock``), same JSON body (``{"pid": <int>,
"acquired_at": <ms>}`` + newline, 0600), same ``STALE_MS``/``ACQUIRE_TIMEOUT_MS``/
``POLL_MS`` constants, and the same **rename-steal** protocol — so a Python and a
Node payer of one agent serialize against each other on a shared config dir.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager, suppress
from typing import TYPE_CHECKING

from rine._config import _ensure_dir, keys_dir
from rine._crypto.keys import _validate_path_id
from rine.x402.errors import X402Error, X402ErrorCode

if TYPE_CHECKING:
    from collections.abc import Iterator

# Must match the TypeScript side EXACTLY — cross-language contention depends on it.
STALE_MS = 5000  # a lock older than this is treated as abandoned (holder crashed)
ACQUIRE_TIMEOUT_MS = 10000  # > STALE_MS so one call rides through a crashed holder
POLL_MS = 50  # sleep between retries while a fresh lock is held


def _lock_path(config_dir: str, agent_id: str) -> str:
    _validate_path_id(agent_id, "agent_id")
    return os.path.join(keys_dir(config_dir, agent_id), "wallet-spend.lock")


def _now_ms() -> int:
    return int(time.time() * 1000)


# Lock states observed after a failed (EEXIST) create.
_MISSING = "missing"  # vanished between our create attempt and the read (a release)
_FRESH = "fresh"  # a live sibling holds it — wait
_STALE = "stale"  # exists but crashed (age ≥ STALE_MS) or garbage content — steal


def _lock_state(path: str, now_ms: int) -> str:
    """Classify the lock at ``path`` — ``_MISSING`` / ``_FRESH`` / ``_STALE``.

    ``_MISSING`` (ENOENT) is deliberately NOT stale: a lock that already vanished is
    a normal release, not a crashed holder. Stealing on ENOENT is a TOCTOU trap —
    the file could have been re-created fresh by a new holder between the read and
    the steal, so a rename-steal would evict a LIVE process (two holders). Only an
    *existing* lock that is genuinely old or has unparseable content is stolen.
    """
    try:
        with open(path) as f:
            raw = f.read()
    except FileNotFoundError:
        return _MISSING
    except OSError:
        return _STALE
    try:
        acquired_at = int(json.loads(raw)["acquired_at"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return _STALE  # exists but garbage — a crashed writer's leftovers
    return _FRESH if now_ms - acquired_at < STALE_MS else _STALE


def _try_create(path: str, now_ms: int) -> bool:
    """Atomically create the lock with its body already present.

    Returns ``True`` on success, ``False`` if it already exists (someone holds it).
    Content-atomic: a plain ``O_EXCL`` create then ``write`` leaves an EMPTY file for
    a moment, and a racing acquirer would read that as unparseable → steal a LIVE
    holder → two holders (a lost update). Writing the body to a per-pid temp first,
    then ``os.link``-ing it into place, keeps the exclusive-create guarantee while
    making the lock non-empty the instant it exists.
    """
    body = json.dumps({"pid": os.getpid(), "acquired_at": now_ms}, separators=(",", ":")) + "\n"
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.link(tmp, path)  # atomic exclusive create — EEXIST if a holder exists
        return True
    except FileExistsError:
        return False
    finally:
        with suppress(OSError):
            os.unlink(tmp)


def _steal_stale(path: str) -> None:
    """Rename-steal a stale/unparseable lock.

    ``rename`` has exactly one winner, so two processes that both judge the lock
    stale cannot both take it (unlike an in-place overwrite). The rename winner
    unlinks the renamed file; a rename ENOENT means the steal race was lost.
    """
    stolen = f"{path}.stale-{os.getpid()}"
    try:
        os.rename(path, stolen)
    except OSError:
        return  # lost the steal race — caller retries the exclusive create
    with suppress(OSError):
        os.unlink(stolen)


def _acquire(path: str) -> None:
    _ensure_dir(os.path.dirname(path))
    deadline = _now_ms() + ACQUIRE_TIMEOUT_MS
    while True:
        now_ms = _now_ms()
        if _try_create(path, now_ms):
            return
        state = _lock_state(path, now_ms)
        if state == _STALE:
            _steal_stale(path)  # crashed holder — steal, then loop to re-create
            continue
        if now_ms >= deadline:  # _FRESH (live sibling) or _MISSING (churning release)
            raise X402Error(
                X402ErrorCode.WALLET_BUSY,
                "Wallet spend lock is held by another process",
                {"path": path},
            )
        if state == _FRESH:
            time.sleep(POLL_MS / 1000)  # a live sibling holds it — back off
        # _MISSING: released between our attempt and read — retry create at once


@contextmanager
def spend_lock(config_dir: str, agent_id: str) -> Iterator[None]:
    """Hold the agent's spend lock for the duration of the ``with`` block.

    Raises :class:`rine.x402.errors.X402Error` ``wallet-busy`` if a live sibling
    keeps the lock past ``ACQUIRE_TIMEOUT_MS``. Always releases in ``finally``
    (best-effort unlink; a stranded lock self-heals via staleness).
    """
    path = _lock_path(config_dir, agent_id)
    _acquire(path)
    try:
        yield
    finally:
        # best-effort: a stranded lock self-heals via staleness after STALE_MS
        with suppress(OSError):
            os.unlink(path)
