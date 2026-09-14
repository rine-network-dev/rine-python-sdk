"""Serialised, merge-safe access to ONE group's sender-key state file.

Every sender-key operation is a read-modify-write of a single JSON array, and a
group decrypt spans a network call: it verifies the envelope's signer between
loading the ratchet and saving it. A whole-array write taken from a pre-network
snapshot therefore discards everything that landed in the file while the network
was in flight — another row's ratchet advance, or a peer's key an ingest had just
installed. The reader is then told the group is sealed and that no later message
reopens it, which is false in every clause: the next render reads the lot.

The three halves below close different holes and no one of them subsumes another:

- :func:`with_sender_key_states` serialises COROUTINE holders against each other,
  which is the only thing that can make two decrypts of the same sender key
  advance the ratchet twice instead of once. No merge can recover that.
- :func:`with_sender_key_states_sync` extends the same exclusion to a SYNCHRONOUS
  holder, which on this stack means a worker thread. The TypeScript stack needs
  no such half — its runtime is single-threaded — and this one cannot do without
  it, because the group send is sync and the async client runs it on a thread. The
  tier itself lives in :mod:`rine._crypto.sender_keys_thread_lock`, which
  documents why an :class:`asyncio.Lock` cannot serve it.
- :func:`merge_sender_key_states` keeps entries the holder never touched, so a
  holder asserts only what it actually derived. It is what survives a writer no
  region can reach — a SECOND PROCESS over the same config dir (residual 1
  below), which is the only unserialised writer left, on either stack.

The TypeScript twin is ``rine-core/src/crypto/sender-keys-store.ts``, and this is
a port of it, with the thread tier added. Every read-modify-write of a state file
this package owns is inside a region — all seven of them, which is the claim, not
a summary of most of them:

- :func:`rine._crypto.message.decrypt_group_message_async` (both tiers),
- :func:`rine._crypto.message.decrypt_group_message_sync`,
- the tail of :func:`rine._crypto.message.encrypt_group_message`,
- the rotation in :func:`rine._sender_key_ops.get_or_create_sender_key_sync`,
- :func:`rine._sender_key_ops._record_distribution`,
- the distribution ingest ``rine._client.RineClient._scan_pending_sk_distributions``,
- its sync twin in ``rine._sync_client.SyncRineClient``.

🔴 Three of the seven ASSERT a whole array rather than merging — the encrypt
tail, the rotation, and both ingests, which is four of the seven counting the
pair as two. So "the holders merge, so an unlocked writer cannot hurt them" was
never a property of a region here, and must not be written down as one: it is a
property of the three sites that call :func:`merge_sender_key_states`. An
asserting writer outside a region erases whatever landed in the file while it
worked, and the two ingests were exactly that until they took the region.

🔴 **"No ``await`` between the load and the save" is not a soundness argument on
this stack.** It is one on the TypeScript stack, whose runtime is single-threaded.
Here it excludes other COROUTINES and nothing else: the group send runs its whole
read-modify-write on a WORKER THREAD, and Python threads preempt between
bytecodes — the load is file I/O, which releases the GIL outright. Read every "no
await between them" below and at the sites as "no coroutine interleaves with it",
never as "nothing else in this process runs". It is why the exclusion here has a
tier the TypeScript twin does not.

Residuals this module does NOT close, each named because a later reader will
otherwise take "the file's writes are serialised" for more than it says:

1. **Two-process concurrency.** The exclusion is a property of the PROCESS: no
   ``flock`` is taken, so a ``rine stream`` and a ``rine thread`` against one
   config dir in two terminals still race, on either stack.
2. **A region entered from a thread the holder is waiting on.** The thread tier
   is not reentrant and detects same-thread re-entry only
   (:func:`rine._crypto.sender_keys_thread_lock.held_across_threads`), so a
   coroutine that holds a region and then hands synchronous work over the same
   file to :func:`asyncio.to_thread` deadlocks rather than raising. No in-tree
   site does it; nothing stops one being added.
3. The Python renderer is already sequential
   (``rine._client.RineClient._transcript_rows`` iterates rows with a plain
   ``for``), so the TypeScript fix's other half — making the render sequential —
   has no counterpart to port. The loss here comes from a SECOND decrypt site in
   the same event loop (a background SSE listener), which a sequential renderer is
   no defence against.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING

from rine._config import sender_keys_dir
from rine._crypto.sender_keys_helpers import (
    load_sender_key_states,
    save_sender_key_state,
    sender_keys_retired,
)
from rine._crypto.sender_keys_thread_lock import (
    held_across_threads,
    held_across_threads_async,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Iterator, Sequence

    from rine._crypto.sender_keys import SenderKeyState


class _FileLock:
    """One state file's lock, and how many callers hold or await it."""

    __slots__ = ("holders", "lock")

    def __init__(self) -> None:
        """Mint an unheld lock for a file nothing is queued on yet."""
        self.lock = asyncio.Lock()
        self.holders = 0


# Locks per running event loop, per state file. Both levels are load-bearing.
#
# 🔴 An `asyncio.Lock` binds itself to a loop the first time it is CONTENDED —
# CPython's uncontended `acquire` returns without ever touching the loop — and a
# contended acquire from any other loop then raises "... is bound to a different
# event loop". One process runs many loops: successive ones (`asyncio.run()` per
# CLI command, one per test here) and concurrent ones (a host running a loop per
# worker thread). A table keyed by file identity alone hands the second loop the
# first loop's lock, and for a concurrent pair nothing repairs that afterwards.
#
# An entry is dropped when its last holder leaves, so the table holds only what is
# in flight. Not tidiness: a contended `asyncio.Lock` holds its loop STRONGLY, so a
# table that never releases pins every loop it ever served. It is also what makes
# `id()` safe as the key — the entry holds the loop object, so that id cannot be
# recycled while the entry exists. `weakref` is deliberately not used for it: a
# running loop need not be weakref-able (`uvloop.Loop` is a Cython class, and
# uvicorn selects it by default), and a `TypeError` there would fail every group
# decrypt on that runtime. Two loops in two threads touch different keys of this
# dict, and each key's own read-modify-write has no await in it.
_locks: dict[int, tuple[asyncio.AbstractEventLoop, dict[str, _FileLock]]] = {}


def _file_key(config_dir: str, agent_id: str, group_id: str) -> str:
    """The lock identity for one group's state file.

    The ``(config_dir, agent_id, group_id)`` triple IS the file path — the agent
    owns the directory and the group names the file — so no path has to be built
    to key on it. The directory is absolutised first because it is the one
    component a caller supplies verbatim: :class:`rine._client.RineClient` stores
    the config dir it was constructed with, so ``.rine`` and ``/abs/path/.rine``
    reach one file through two keys — two locks over one file, which is no lock at
    all, and it fails silently.
    """
    return json.dumps([os.path.abspath(config_dir), agent_id, group_id])


def _enter(config_dir: str, agent_id: str, group_id: str) -> tuple[int, str, _FileLock]:
    """Claim this loop's lock for one state file, minting the entry on first use.

    The holder count is taken here, before any await, so an entry can never be
    dropped out from under a caller still queued behind it.
    """
    loop = asyncio.get_running_loop()
    loop_id = id(loop)
    table = _locks.get(loop_id)
    if table is None:
        table = (loop, {})
        _locks[loop_id] = table
    key = _file_key(config_dir, agent_id, group_id)
    file_lock = table[1].get(key)
    if file_lock is None:
        file_lock = _FileLock()
        table[1][key] = file_lock
    file_lock.holders += 1
    return loop_id, key, file_lock


def _leave(loop_id: int, key: str, file_lock: _FileLock) -> None:
    """Release one claim, dropping the entry — and the loop — when the last goes."""
    file_lock.holders -= 1
    if file_lock.holders > 0:
        return
    table = _locks.get(loop_id)
    if table is None:
        return
    if table[1].get(key) is file_lock:
        del table[1][key]
    if not table[1]:
        del _locks[loop_id]


@asynccontextmanager
async def with_sender_key_states(
    config_dir: str, agent_id: str, group_id: str
) -> AsyncIterator[None]:
    """Hold exclusive in-process access to one group's sender-key state.

    The body must load the state file INSIDE this block: entering it with an
    array read before the wait is the very snapshot the lock exists to retire.

    🔴 The lock is NOT reentrant. Nothing inside the block may reach another
    ``with_sender_key_states`` for the same file, directly or through anything it
    calls, or it waits on itself forever. The recovery path is the case to keep in
    mind — ``rine._client.RineClient._self_heal_group_decrypt`` re-enters
    :func:`rine._crypto.message.decrypt_group_message_async` — and it may only do
    so from OUTSIDE this block. It does: the first attempt's exception has already
    escaped the decrypt, and ``_fetch_pending_sk_distributions`` runs between the
    two attempts. That is why the decrypt takes the lock inside itself rather than
    the recovery taking it around both.

    Two coroutines re-entering here still wait on themselves forever —
    :class:`asyncio.Lock` gives no diagnostic for that and neither does the tier
    below it, on purpose (:func:`rine._crypto.sender_keys_thread_lock._refuse_reentry`
    says why). Reaching :func:`with_sender_key_states_sync` for the same file from
    inside this block DOES now raise rather than hang.

    🔴 It is in-process only: two processes over one config dir still race (see
    this module's own docstring for that residual and the others).

    Args:
        config_dir: Config directory path.
        agent_id: The reading agent's UUID.
        group_id: The rine group UUID.

    Yields:
        Nothing; the block is entered for the exclusion alone.
    """
    loop_id, key, file_lock = _enter(config_dir, agent_id, group_id)
    try:
        async with file_lock.lock, held_across_threads_async(key):
            yield
    finally:
        _leave(loop_id, key, file_lock)


@contextmanager
def with_sender_key_states_sync(config_dir: str, agent_id: str, group_id: str) -> Iterator[None]:
    """Hold exclusive in-process access to one group's sender-key state, from a thread.

    The synchronous counterpart to :func:`with_sender_key_states`, and the reason
    the exclusion has a thread tier at all: the group SEND path is synchronous,
    and the async client runs it on a worker thread where no
    :class:`asyncio.Lock` reaches it. A caller of this and a caller of
    :func:`with_sender_key_states` over the same file exclude each other.

    Everything the async version's docstring says about entering the block with
    an already-loaded array, and about the block not being reentrant, holds here
    unchanged. The one rule specific to this side: it must never be called from
    a coroutine. It acquires blocking, so the event loop would stop until the
    holder — possibly a worker thread waiting on that same loop — finished.

    Both of those refusals are enforced rather than merely documented: this side
    raises :class:`RuntimeError` when the thread reaching it is the one already
    holding the file, which covers the nested-region case and the call-from-a-
    coroutine case alike. It is the only re-entry either tier can catch; see
    :func:`rine._crypto.sender_keys_thread_lock._refuse_reentry`.

    Args:
        config_dir: Config directory path.
        agent_id: The sending agent's UUID.
        group_id: The rine group UUID.

    Yields:
        Nothing; the block is entered for the exclusion alone.
    """
    with held_across_threads(_file_key(config_dir, agent_id, group_id)):
        yield


def sender_key_identity(state: SenderKeyState) -> tuple[str, str]:
    """The pair that names one row of a state file: its sender, then its key id.

    🔴 A ``sender_key_id`` is NOT unique within the file, and keying anything by it
    alone silently deletes a row. The id is minted by whoever sends it, so
    :func:`rine._crypto.sk_distribution.already_held` admits a distribution carrying
    an id this agent already holds when it comes from a DIFFERENT sender — scoped to
    the pair precisely so that claiming a genuine peer's id first cannot take its
    slot. Two rows sharing one id is therefore the intended state of a file under
    attack, and a dict built over ``sender_key_id`` keeps whichever landed last:
    rebuilding the array from that dict's values writes the honest peer's key out of
    existence, permanently, with no error anywhere.

    Agent ids compare case-insensitively, exactly as ``already_held`` compares them:
    :func:`rine._crypto.keys.agent_id_from_kid` preserves whatever case the signer
    put in its kid, and the ingest files the row under that spelling. Key ids need no
    folding — the ingest canonicalises them and every local mint is a lower-case
    ``uuid4`` — but a pair is only as good as its weaker half, so both halves are
    decided here and nowhere else.
    """
    return (state.sender_agent_id.lower(), state.sender_key_id)


def states_from_sender(states: Iterable[SenderKeyState], agent_id: str) -> list[SenderKeyState]:
    """Only the rows *agent_id* filed, out of a whole group's state file.

    The counterpart to :func:`sender_key_identity` for the sites that already know
    whose row they want: a search by key id alone answers with whatever row landed
    last under that id, which is not necessarily the one this caller means.
    """
    sender = agent_id.lower()
    return [s for s in states if s.sender_agent_id.lower() == sender]


def merge_sender_key_states(
    config_dir: str, agent_id: str, group_id: str, touched: Sequence[SenderKeyState]
) -> None:
    """Write back only the states this caller derived, leaving the rest as found.

    A holder that saves ``list(its_own_map.values())`` asserts the whole file,
    including the parts it never looked at — which is how one peer's key
    disappears when two arrive at once. Replacing by ``sender_key_id`` asserts
    only what the caller actually knows.

    Insertion order is preserved for ids already on disk, because a dict keeps an
    existing key's position when it is reassigned: the merge disturbs no reader's
    assumption about position, whatever that assumption is. The reader that has one
    here is :func:`rine._sender_key_ops.get_or_create_sender_key_sync`, which takes
    the LAST own entry — the same end of the array that the rotation appends the
    fresh key to, and the same end the TypeScript twin's ``sender-key-ops.ts``
    reads. The rotation retains the ONE state it superseded, below the new one, so
    a self-read decrypt that merges its own pre-rotation row back finds that id
    already on disk and updates it IN PLACE: position kept, last own still the
    fresh key. Do not "correct" the ordering to first-wins, and do not make this
    merge append what it touches — either one hands the next send a retired key.

    🔴 **An OWN row whose id is not already on disk is DROPPED, not added**, and
    that asymmetry is the whole of the protection for the last-own reader. A peer
    row is added, because installing a key this agent did not have is what the
    merge is for. An own row is different in kind: every own row on disk was put
    there by :func:`rine._sender_key_ops.get_or_create_sender_key_sync`, which is
    also the only writer that removes one, so an own id the file no longer holds
    is one a rotation RETIRED — the same "absent means retired, never new" rule
    :func:`rine._crypto.message.encrypt_group_message`'s tail applies. Adding it
    back appends it at the END, where the reader takes it as current, and the next
    send seals the group under a key the group has already moved on from.

    The argument that used to stand here — that a resurrected row is harmless
    because "every rotation trigger is a pure function of the row itself", so the
    next send re-fires whatever retired it and pays one spurious fan-out — is
    REFUTED and must not be restored. A row is also dropped by the rotation's own
    RETENTION, which keeps exactly one superseded own row and drops the rest, and
    that drop is not a trigger: the dropped row's ``message_index``,
    ``created_at`` and ``distributed_to`` are exactly what they were while it was
    current, so :func:`rine._crypto.sender_keys.needs_rotation` says no. And where
    a trigger does fire, the rotation retains the RESURRECTED row (it is
    positionally last) and drops the row the agent was actually sending under, so
    the cost is not a spurious fan-out but the loss of the self-read the retention
    exists to provide. Both halves were reproduced live, on both stacks, before
    this rule was written; the ordering half is pinned by ``TestMergeOrdering``.

    Nothing legitimate needs the merge to CREATE an own row. Its three callers all
    pass a row they read from this very file — :func:`rine._sender_key_ops._record_distribution`
    looks its row up on disk and returns on a miss, and
    :func:`rine._crypto.message.decrypt_group_message_sync` and
    :func:`rine._crypto.message.decrypt_group_message_async` each merge the state
    they loaded from it — and the writer that mints own rows
    (``get_or_create_sender_key_sync``) asserts its whole array through
    :func:`rine._crypto.sender_keys_helpers.save_sender_key_state`, never through
    this.

    The own/peer test HERE folds case (``sender_agent_id.lower()``, the same fold
    :func:`sender_key_identity` applies), while the last-own reader in
    :func:`rine._sender_key_ops.get_or_create_sender_key_sync` compares the strings
    as they stand. The asymmetry is deliberate and both sides are right, for
    different reasons. The rotation compares the caller's own string against rows
    whose ``sender_agent_id`` came from that same string — the state file lives in
    a directory keyed by it — so a case-sensitive compare there cannot miss an own
    row; and no peer row can fold INTO it either, because agent ids are UUIDs, so
    two spellings differing only in case name the same agent rather than two.
    Folding is what this side needs, because :func:`states_from_sender` is also
    handed the SERVER's spelling of a sender (``from_agent_id`` in
    :func:`rine._crypto.message._decrypt_group_core`) to match against rows written
    with the CALLER's, and a sensitive compare there would lose the self-read
    whenever the two spellings differ. Matching the reader is still the point, but
    it is about which ROWS the two agree are own, not about which operator they
    reach for — a row the merge calls a peer and the reader calls own is exactly
    the hole this closes, and on UUID ids the two tests never disagree about that.

    A caller that must genuinely drop states re-derives its whole array from a
    fresh read instead, inside a region: :func:`with_sender_key_states` for a
    coroutine, :func:`with_sender_key_states_sync` for a synchronous one.
    :func:`rine._sender_key_ops.get_or_create_sender_key_sync`'s rotation is the
    asserting caller, and it holds the second of those — being sync and run on a
    worker thread is what decides WHICH tier it is entitled to, not whether it
    can have one, and the sentence that said it could not predates that tier. It
    re-reads inside the region regardless: the fresh read is the half of the fix
    that keeps what another writer had already committed, and it is worth having
    on its own, because the region excludes no second PROCESS.

    🔴 A merge never RE-CREATES a retired group's file.
    :func:`rine._sender_key_ops.delete_sender_key` unlinks it and marks the group
    retired in one synchronous step, so a holder that entered before the leave and
    resumes after it always sees the marker — and without this check its merge
    re-reads nothing, appends the state it is still holding, and puts live chain
    material back on disk that the leave had just removed. The marker survives, so
    no NEW distribution is ingested; what comes back is the very key the in-flight
    decrypt was using, which goes on opening that peer's later traffic. "Retiring
    the group is removing that file" has to hold for the writer already running.

    The refusal is deliberately narrow — retired AND no file. A retired group whose
    file exists again was re-created by a writer that is not this one
    (``get_or_create_sender_key_sync`` lifts a retirement for a current member and
    saves either way), and silently dropping that writer's updates would be a
    second bug rather than a fix for this one. The existence check reads the ONE
    path this function's own load and save use: ``sender_key_state_exists`` probes
    both spellings of the group id and would answer for a file this merge neither
    reads nor writes.

    Args:
        config_dir: Config directory path.
        agent_id: The reading agent's UUID.
        group_id: The rine group UUID.
        touched: The states this caller derived and is entitled to assert. Every
            other entry in the file is left exactly as it is on disk. An own row
            the file no longer holds is dropped rather than re-added.
    """
    state_file = os.path.join(sender_keys_dir(config_dir, agent_id), f"{group_id}.json")
    if sender_keys_retired(config_dir, agent_id, group_id) and not os.path.exists(state_file):
        return
    on_disk = load_sender_key_states(config_dir, agent_id, group_id)
    merged = {sender_key_identity(s): s for s in on_disk}
    self_id = agent_id.lower()
    applicable = [
        s
        for s in touched
        if sender_key_identity(s) in merged or s.sender_agent_id.lower() != self_id
    ]
    # Nothing to assert is not the same as asserting the file as it stands: a
    # save here would CREATE an empty state file for a group this agent holds no
    # material for, and ``sender_key_state_exists`` — which a leave reads to say
    # which encryption it just retired — answers off that file's existence.
    if not applicable:
        return
    for state in applicable:
        merged[sender_key_identity(state)] = state
    save_sender_key_state(config_dir, agent_id, group_id, list(merged.values()))


__all__ = [
    "merge_sender_key_states",
    "sender_key_identity",
    "states_from_sender",
    "with_sender_key_states",
    "with_sender_key_states_sync",
]
