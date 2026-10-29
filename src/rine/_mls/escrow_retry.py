"""The per-file retry schedule for an escrow file the server has not yet taken.

The schedule is per file and wall-clock: each retryable failure pushes the file's
next try out by an exponential delay, and the state is persisted next to the file
so a restart keeps it rather than hammering the server from zero. A file is a
pending escrow (``.bin``) or a backlog snapshot (``.snapshot``); the sidecar is its
own path with the extension swapped::

    <file stem>.attempts   {"attempts": 3, "next_try": <unix s>, "last": "403 escrow_no_seat"}

The TypeScript twin is ``rine-core/src/mls-escrow-retry.ts``; the two read each
other's sidecars, so the key names and the unit (seconds) are shared.
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass

from rine._constants import MLS_HEARTBEAT_MIN_INTERVAL_S
from rine._mls.escrow_atomic import write_atomic

ATTEMPTS_SUFFIX = ".attempts"

#: After this many failures the file is given up on: its epochs are recorded as lost and it
#: is deleted.
MAX_ATTEMPTS = 16

#: Cap of the exponential delay: one day.
MAX_BACKOFF_S = 24 * 60 * 60.0


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """One file's retry state: how many failures, when to try again, and the last answer."""

    attempts: int
    """Failures so far."""

    next_try: float
    """Unix seconds; the file is not tried before this."""

    last: str
    """The last answer, e.g. ``"403"`` or ``"403 escrow_no_seat"``."""


def attempts_path(file_path: str) -> str:
    """The sidecar path holding one file's retry state."""
    return os.path.splitext(file_path)[0] + ATTEMPTS_SUFFIX


def read_attempts(file_path: str) -> AttemptRecord | None:
    """The file's retry state, or ``None`` when absent, unreadable or malformed."""
    try:
        with open(attempts_path(file_path), encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    attempts = raw.get("attempts")
    next_try = raw.get("next_try")
    last = raw.get("last")
    if not isinstance(attempts, int) or isinstance(attempts, bool):
        return None
    if not isinstance(next_try, (int, float)) or isinstance(next_try, bool):
        return None
    if not isinstance(last, str):
        return None
    return AttemptRecord(attempts=attempts, next_try=float(next_try), last=last)


def is_due(record: AttemptRecord | None, now: float) -> bool:
    """Whether the file may be tried now: a file with no record always is."""
    return record is None or now >= record.next_try


def is_exhausted(record: AttemptRecord | None) -> bool:
    """Whether the file has used every attempt. It is never due again: it is given up on."""
    return record is not None and record.attempts >= MAX_ATTEMPTS


def retry_delay(attempts: int, base_s: float) -> float:
    """The delay after ``attempts`` retryable refusals, capped at :data:`MAX_BACKOFF_S`."""
    return min(MAX_BACKOFF_S, base_s * 2.0 ** (attempts - 1))


def _write(file_path: str, record: AttemptRecord) -> None:
    body = json.dumps(
        {"attempts": record.attempts, "next_try": record.next_try, "last": record.last}
    ).encode("utf-8")
    write_atomic(attempts_path(file_path), body)


def note_failure(file_path: str, last: str, *, now: float) -> AttemptRecord:
    """Record one failure and push the file's next try out."""
    previous = read_attempts(file_path)
    attempts = (previous.attempts if previous is not None else 0) + 1
    record = AttemptRecord(
        attempts=attempts,
        next_try=now + retry_delay(attempts, MLS_HEARTBEAT_MIN_INTERVAL_S),
        last=last,
    )
    _write(file_path, record)
    return record


def clear_attempts(file_path: str) -> None:
    """Drop the file's retry state; none is success."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(attempts_path(file_path))
