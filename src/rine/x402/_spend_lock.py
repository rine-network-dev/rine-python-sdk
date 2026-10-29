"""Cross-process spend-reservation lock (mirror of ``x402/spend-lock.ts``).

A file lock held across the read → enforce → write of the daily-spend journal so
two processes of the same agent cannot both slip a payment past the daily cap
(the cross-process TOCTOU fix). Byte-compatible with the TypeScript lock: same
path (``keys/{agent_id}/wallet-spend.lock``), same body and protocol
(:mod:`rine._file_lock`), and the same ``STALE_MS``/``ACQUIRE_TIMEOUT_MS``/
``POLL_MS`` constants — so a Python and a Node payer of one agent serialize
against each other on a shared config dir.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import TYPE_CHECKING

from rine._config import keys_dir
from rine._crypto.keys import _validate_path_id
from rine._file_lock import FileLockTiming, file_lock
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


@contextmanager
def spend_lock(config_dir: str, agent_id: str) -> Iterator[None]:
    """Hold the agent's spend lock for the duration of the ``with`` block.

    Raises :class:`rine.x402.errors.X402Error` ``wallet-busy`` if a live sibling
    keeps the lock past ``ACQUIRE_TIMEOUT_MS``. Always releases in ``finally``
    (best-effort unlink; a stranded lock self-heals via staleness).
    """
    path = _lock_path(config_dir, agent_id)

    def busy() -> X402Error:
        return X402Error(
            X402ErrorCode.WALLET_BUSY,
            "Wallet spend lock is held by another process",
            {"path": path},
        )

    with file_lock(path, FileLockTiming(STALE_MS, ACQUIRE_TIMEOUT_MS, POLL_MS), busy):
        yield
