"""The cross-THREAD half of one group's sender-key state lock.

:mod:`rine._crypto.sender_keys_store` serialises coroutines against each other
with an :class:`asyncio.Lock` per running loop. That tier cannot see a thread,
and on this stack the group SEND path is a thread: the async client runs the
whole synchronous read-modify-write on a worker
(:meth:`rine._client.RineClient.send` -> ``rine._mls.bridge.with_sync_http`` ->
:func:`asyncio.to_thread` -> ``rine._group_send.encrypt_for_group_sync``), and
:class:`asyncio.Lock` binds to the loop that first contends it, so a thread has
no loop to contend from. A :class:`threading.Lock` is the one primitive both a
coroutine and a worker thread can hold, which is why the exclusion is built in
two tiers rather than one: together they make "exclusive access to one state
file" a property of the PROCESS, not of one event loop.

This module owns the thread tier alone. Both context managers key on the string
:func:`rine._crypto.sender_keys_store._file_key` derives, so the two tiers agree
about which file they are guarding without either one building a path.

🔴 Lock order is fixed: a coroutine takes the loop tier FIRST and this one
second; a synchronous caller takes only this one. No caller takes them in the
other order, so the pair cannot invert. Do not add a site that acquires the
loop tier from inside a region held here.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


class _ThreadLock:
    """One state file's cross-thread lock, and how many callers hold or await it."""

    __slots__ = ("holders", "lock", "owner")

    def __init__(self) -> None:
        """Mint an unheld lock for a file nothing is queued on yet."""
        self.lock = threading.Lock()
        self.holders = 0
        #: The :func:`threading.get_ident` of whoever holds the lock right now,
        #: written by BOTH tiers and read by the blocking one alone — which is
        #: what turns a fatal re-entry into a refusal instead of a hang. See
        #: :func:`_refuse_reentry` for why only the blocking side may act on it.
        #:
        #: Read WITHOUT ``_thread_locks_guard`` on purpose, and sound because of
        #: what it is compared against: an acquirer only ever tests it for
        #: equality with its own ident, and the sole thread that can write that
        #: particular value is the acquirer itself. A stale or torn read can
        #: therefore miss a re-entry, never invent one.
        self.owner: int | None = None


# Locks per state file, shared by every thread and every event loop in the
# process — and deliberately NOT keyed per loop, which is the whole point of it.
#
# An entry is dropped when its last holder leaves, so the table holds only what
# is in flight. ``_thread_locks_guard`` is what makes mint-or-find atomic: the
# store's per-loop table gets that for free from the loop being single-threaded,
# and this one has no such luxury — two threads first touching the same group
# would otherwise mint two locks over one file, which is no lock at all.
_thread_locks: dict[str, _ThreadLock] = {}
_thread_locks_guard = threading.Lock()

#: How long a coroutine waits between attempts at a state file's cross-thread
#: lock. It polls rather than blocking because a blocking acquire from the event
#: loop thread stops every other task in the process, including the ones that
#: would let the holder finish.
#:
#: 🔴 **The wait is network-bounded in BOTH directions, and the asymmetry a
#: reader might expect here does not exist.** A coroutine holds the region across
#: its peer-key verify, and so does a synchronous one:
#: :func:`rine._crypto.message.decrypt_group_message_sync` calls
#: ``verify_envelope_sender_sync`` inside the region, which is a real
#: ``GET /agents/{id}/keys`` whenever the signing-key cache misses — first sight
#: of each sender, which is precisely where the lost update this lock exists for
#: concentrates. The region has to cover it: the ratchet spends its message key
#: before the verify and cannot be asked twice, so the load and the save are one
#: indivisible step with a round-trip in the middle. So do NOT size this constant
#: by counting the wakeups of a disk-bounded wait, and do not "restore" a sentence
#: claiming a sync region reaches no network — one does, deliberately.
#:
#: What the value is chosen for is LATENCY AFTER RELEASE: 2 ms is how long a
#: queued coroutine can sit on an already-free lock. The cost of a long wait is
#: paid in wakeups (a 500 ms fetch on a cold key is ~250 of them, which is a
#: cheap way to spend half a second), not in throughput, and lengthening the poll
#: to save those wakeups buys nothing a caller can measure. A
#: :class:`threading.Event` handed to :meth:`asyncio.loop.run_in_executor` would
#: remove them, at the price of a thread per waiter; that trade has not been
#: worth making at this contention.
POLL_SECONDS = 0.002


def _claim(key: str) -> _ThreadLock:
    """Claim one file's entry, minting it on first use, before any wait."""
    with _thread_locks_guard:
        entry = _thread_locks.get(key)
        if entry is None:
            entry = _ThreadLock()
            _thread_locks[key] = entry
        entry.holders += 1
        return entry


def _refuse_reentry(key: str, entry: _ThreadLock) -> None:
    """Refuse a BLOCKING acquire from the thread that already holds the file.

    The non-reentrancy of this lock used to be prose alone, and a violation of it
    is a blocking acquire against a lock the caller itself holds: the thread
    stops forever, taking the whole ``pytest`` run — and therefore the publish
    train, which runs it inside a ``set -e`` subshell — with it. A hang carries no
    traceback and names no file; this raises, so the offending pair of regions is
    in the report.

    Two shapes reach it, and both are unrecoverable rather than merely slow:

    * a synchronous region entered from inside another synchronous region over
      the same file — calling :func:`rine._sender_key_ops._record_distribution`
      from inside the rotation's own region would be exactly it;
    * a synchronous region entered on the event loop thread while a coroutine on
      that loop holds the file. The loop cannot advance while its own thread is
      parked in :meth:`threading.Lock.acquire`, so the holder can never reach its
      release: refusing is the only answer that terminates.

    🔴 The polling acquirer must NOT call this, and the asymmetry is the whole
    reason ``owner`` is written by both tiers and read by one. Every coroutine on
    a single loop shares that loop's ident, so a same-ident *async* acquire is
    the ordinary case of two tasks wanting one file — it waits, and the loop
    stays live while it does. It is also already excluded upstream, by the
    per-loop :class:`asyncio.Lock` in
    :mod:`rine._crypto.sender_keys_store`; acting on the ident there would turn a
    correct wait into a spurious failure the moment anything reached this module
    without that tier.

    A coroutine that hands synchronous work over the same file to
    :func:`asyncio.to_thread` from inside its own region still deadlocks, on two
    different idents, and is not caught — residual 2 of
    :mod:`rine._crypto.sender_keys_store`.

    :class:`RuntimeError` rather than a :mod:`rine.errors` type on purpose: no
    caller can handle this, and nothing should catch it. It is the same class of
    answer :class:`asyncio.Lock` gives for its own misuse.
    """
    if entry.owner == threading.get_ident():
        raise RuntimeError(
            "sender-key state region re-entered on the thread already holding"
            f" {key} — this lock is not reentrant, and the acquire would block"
            " forever. Leave the outer region before reaching this one."
        )


def _release(key: str, entry: _ThreadLock) -> None:
    """Drop one claim, and the entry itself when the last holder leaves."""
    with _thread_locks_guard:
        entry.holders -= 1
        if entry.holders > 0:
            return
        if _thread_locks.get(key) is entry:
            del _thread_locks[key]


@contextmanager
def held_across_threads(key: str) -> Iterator[None]:
    """Hold one state file's cross-thread lock, blocking until it is free.

    For SYNCHRONOUS callers only, which on this stack means a worker thread. A
    coroutine must use :func:`held_across_threads_async` — a blocking acquire
    from the event loop thread stops every task in the process, including the
    ones that would let the holder finish.

    🔴 Not reentrant, in either direction. Nothing inside the region may reach
    another region over the same file, and a synchronous caller must not be
    reached from inside :func:`rine._crypto.sender_keys_store.with_sender_key_states`.
    Both of those are same-thread and both now raise :class:`RuntimeError` here
    instead of hanging — see :func:`_refuse_reentry`, which also names the one
    cross-thread shape that still deadlocks.
    """
    entry = _claim(key)
    try:
        _refuse_reentry(key, entry)
        with entry.lock:
            entry.owner = threading.get_ident()
            try:
                yield
            finally:
                entry.owner = None
    finally:
        _release(key, entry)


@asynccontextmanager
async def held_across_threads_async(key: str) -> AsyncIterator[None]:
    """Hold one state file's cross-thread lock from a coroutine, polling for it.

    The event loop stays live while it waits — see :data:`POLL_SECONDS` for why
    the wait is a poll and what bounds it.

    It records the holder for :func:`_refuse_reentry`'s benefit and deliberately
    never consults it: on one loop every task shares the loop thread's ident, so
    a same-ident wait here is two tasks queueing for one file, not a deadlock.
    """
    entry = _claim(key)
    try:
        while not entry.lock.acquire(blocking=False):
            await asyncio.sleep(POLL_SECONDS)
        entry.owner = threading.get_ident()
        try:
            yield
        finally:
            entry.owner = None
            entry.lock.release()
    finally:
        _release(key, entry)


__all__ = ["POLL_SECONDS", "held_across_threads", "held_across_threads_async"]
