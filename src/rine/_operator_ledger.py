"""The durable record of operator statements an agent has accepted.

It remembers which row carried each nonce, whether its text has been shown to a model, and
the digest of the ciphertext that was classified. One small JSON file per agent in the config
dir, written under a cross-process lock because the wake path and a tool path can run in
different processes on the same dir. Twin of ``rine-core/src/operator-ledger.ts``: both read
and write the same file. Losing it weakens replay protection only, because the freshness
window still bounds how old a replayed statement can be. A file that is there but cannot be
read is a different case and fails closed: it is never read as empty and overwritten, so the
caller treats the row as data until someone looks.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from rine._config import _write_atomic
from rine._file_lock import FileLockTiming, file_lock
from rine.errors import ConfigError
from rine.operator_statement import OPERATOR_FUTURE_SKEW_MS, OPERATOR_WINDOW_MS

if TYPE_CHECKING:
    from collections.abc import Callable

_T = TypeVar("_T")
#: The critical section is one small read and one atomic write, so a holder older than
#: ``stale_ms`` is dead. ``stale_ms`` is longer than ``timeout_ms`` on purpose: a waiter gives up
#: (and the row is treated as data) before it would take a live holder's lock and let two
#: writers lose each other's entries.
_LEDGER_LOCK = FileLockTiming(stale_ms=30000, timeout_ms=10000, poll_ms=50)
_MAX_STEM = 128


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """What the ledger remembers about one nonce."""

    row_id: str
    #: Hex SHA-256 of the row's ``encrypted_payload`` as it was classified.
    digest: str
    #: True once a model has been shown the text. A wake alone never sets it.
    rendered: bool
    #: The statement's ``issued_at`` in epoch milliseconds, for expiry.
    issued_at_ms: int


@dataclass(frozen=True, slots=True)
class LedgerLoc:
    """Whose ledger, and where it lives."""

    config_dir: str
    agent_id: str


def _ledger_path(loc: LedgerLoc) -> str:
    """The ledger file of an agent; the name is lower-cased because ids compare without case."""
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", (loc.agent_id or "default").lower())[:_MAX_STEM]
    return os.path.join(loc.config_dir, f"operator_ledger_{stem}.json")


def _entry_from(raw: Any) -> LedgerEntry | None:
    if not isinstance(raw, dict):
        return None
    row_id, digest = raw.get("row_id"), raw.get("digest")
    rendered, issued = raw.get("rendered"), raw.get("issued_ms")
    if (
        not isinstance(row_id, str)
        or not isinstance(digest, str)
        or not isinstance(rendered, bool)
    ):
        return None
    if isinstance(issued, bool) or not isinstance(issued, int | float):
        return None
    if isinstance(issued, float) and not issued.is_integer():
        return None
    return LedgerEntry(row_id, digest, rendered, int(issued))


def _unreadable(path: str) -> ConfigError:
    return ConfigError(
        f"{path} is not a readable operator ledger; move it aside to start a new one"
    )


def _read_entries(path: str) -> dict[str, LedgerEntry]:
    """The stored entries; a missing file reads as empty, a present but malformed one raises."""
    try:
        with open(path, encoding="utf-8") as handle:
            parsed = json.load(handle)
    except FileNotFoundError:
        return {}
    except ValueError as err:
        raise _unreadable(path) from err
    stored = parsed.get("entries") if isinstance(parsed, dict) else None
    if not isinstance(stored, dict):
        raise _unreadable(path)
    entries: dict[str, LedgerEntry] = {}
    for nonce, raw in stored.items():
        entry = _entry_from(raw)
        if entry is None:
            raise _unreadable(path)
        entries[nonce] = entry
    return entries


def _serialise(entries: dict[str, LedgerEntry]) -> str:
    stored = {
        nonce: {
            "row_id": e.row_id,
            "digest": e.digest,
            "rendered": e.rendered,
            "issued_ms": e.issued_at_ms,
        }
        for nonce, e in entries.items()
    }
    return json.dumps({"v": 1, "entries": stored}, separators=(",", ":"))


def update_ledger(
    loc: LedgerLoc, now_ms: int, change: Callable[[dict[str, LedgerEntry]], _T]
) -> _T:
    """Read the ledger, run ``change`` on it and write it back when it altered it, under the lock.

    Entries whose statement is older than the window can no longer be replayed as a new
    instruction, so they are dropped on the way in. Raises when the lock or the write fails:
    the caller decides what that means.
    """
    path = _ledger_path(loc)
    lock = f"{path}.lock"
    busy = lambda: ConfigError(f"{lock} is held by another process; retry when it finishes")  # noqa: E731
    with file_lock(lock, _LEDGER_LOCK, busy):
        entries = _read_entries(path)
        horizon = now_ms - OPERATOR_WINDOW_MS - OPERATOR_FUTURE_SKEW_MS
        entries = {nonce: e for nonce, e in entries.items() if e.issued_at_ms >= horizon}
        before = _serialise(entries)
        result = change(entries)
        after = _serialise(entries)
        if after != before:
            _write_atomic(path, after)
        return result
