"""Reaching this agent's local state for one group.

Local MLS state is keyed by the **rine group UUID** a user sees — never the
server's opaque ``mls_group_id`` latch, which is a different value with a
confusingly similar name. Keying it here, once, is what lets joining, sending
and reading all find the same state.

This module also owns the memoized "does this agent hold state?" answer
(:func:`holds_mls_state`) and its invalidation (:func:`note_mls_state_changed`),
because the memo and the state it remembers have to be retired together. The
TypeScript mirror is ``rine-core/src/crypto/mls-state.ts``, with the same names
and the same per-key semantics: a memo whose staleness differs per stack is the
same defect class as a guard whose input differs per stack.
"""

from __future__ import annotations

import os
import uuid

from rine._config import mls_store_dir
from rine._mls.binding import MlsClient, MlsGroup, MlsProtocolError, open_mls_client
from rine.errors import NoMlsGroupStateError


def mls_group_id_bytes(group_id: str) -> bytes:
    """The 16 raw bytes MLS keys a group by.

    Always the rine group UUID a user sees — never the server's opaque
    ``mls_group_id`` latch, which is a different value with a confusingly
    similar name.
    """
    return uuid.UUID(group_id).bytes


def load_mls_group(client: MlsClient, group_id: str) -> MlsGroup | None:
    """This agent's local state for one group, or ``None`` when it holds none.

    ``None`` means the agent was never added, its Welcome has not been processed
    yet, or the group's state was retired — the three cases a caller answers the
    same way, by installing state. A store I/O failure is a different thing
    entirely and propagates rather than masquerading as "never joined".
    """
    try:
        return client.load_group(mls_group_id_bytes(group_id))
    except MlsProtocolError:
        return None


def open_mls_group(
    config_dir: str,
    agent_id: str,
    group_id: str,
    *,
    cipher_suite: int | None = None,
) -> MlsGroup:
    """This agent's local state for a group, or a typed refusal when it has none.

    The one entry point for every operation that needs an established group —
    sending, reading, syncing — so "this agent is not in the group's MLS state"
    is one answer with one remedy rather than a different failure per surface.

    Raises:
        NoMlsGroupStateError: When this agent holds no state for the group.
    """
    group = load_mls_group(
        open_mls_client(config_dir, agent_id, cipher_suite=cipher_suite), group_id
    )
    if group is None:
        raise NoMlsGroupStateError(group_id)
    return group


#: What one memo entry remembers: the fingerprint the group's state file had
#: when the answer was taken, and the answer. ``None`` is the fingerprint of a
#: group this agent has no state file for at all.
_StateStamp = tuple[int, int, int] | None

#: The remembered answer to :func:`holds_mls_state`, per
#: ``(config_dir, agent_id, group_id)``. ``config_dir`` is part of the key
#: because one process can serve two config directories, and they are two
#: different agents' key material rather than two views of one. Bounded by the
#: number of distinct groups the process has asked about.
_HELD: dict[tuple[str, str, str], tuple[_StateStamp, bool]] = {}


def _state_stamp(config_dir: str, agent_id: str, group_id: str) -> _StateStamp:
    """Fingerprint the on-disk state file behind one memo entry, or ``None``.

    The native core keeps one directory per group under the agent's store and
    writes the group's current state to ``state.bin`` inside it; establishing
    creates that file and retiring removes the directory. So its presence is the
    same fact the memo remembers, readable with a single ``stat`` — which is
    emphatically not a store open: it loads no compiled core, reads no
    signing key and deserializes nothing.

    ``None`` versus not-``None`` is the exact, timing-free half of the check:
    the fail-open direction — a remembered "holds none" outliving the join that
    made it false — always turns the file from absent to present. Size and mtime
    cover the rarer case of a state file rewritten in place.

    A missing file is an answer; anything else is a store I/O failure and
    propagates, exactly as :func:`load_mls_group` refuses to let one
    masquerade as "never joined".
    """
    path = os.path.join(
        mls_store_dir(config_dir, agent_id),
        "groups",
        mls_group_id_bytes(group_id).hex(),
        "state.bin",
    )
    try:
        stat = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return (stat.st_mtime_ns, stat.st_size, stat.st_ino)


def holds_mls_state(config_dir: str, agent_id: str, group_id: str) -> bool:
    """Whether this agent holds local MLS state for a group.

    Memoized because the downgrade guard asks it once per row on a group read,
    and answering it from the native store means opening that store per row.
    An entry is served only while the group's state file still looks exactly as
    it did when the answer was taken, so the memo cannot outlive the thing it
    remembers:

    * **Another process.** The state is on disk and shared — ``rine-cli`` and a
      long-running ``rine-mcp`` routinely hold the same config dir — and no
      in-process invalidation can reach across that. A join taken on the command
      line changes the file, so the server's next read re-asks the store instead
      of answering "holds none" until it restarts.
    * **Another thread.** The stamp is sampled BEFORE the store read and stored
      with the answer, so a mutation landing in the window between the read and
      the write-back leaves an entry whose stamp no longer matches — the next
      caller discards it. That is what makes the write-back safe without a lock:
      an entry is self-invalidating rather than mutually excluded, and every
      entry is internally consistent (its answer was taken after its stamp).
      Nothing here is asyncio-sensitive: this function and everything it calls
      are synchronous, so a coroutine cannot be suspended inside the window.

    :func:`note_mls_state_changed` remains the in-process contract, enforced
    over the source by ``rine-sdk/tests/test_mls_downgrade.py``. It is the
    tighter of the two — it needs no filesystem evidence at all — and it is what
    covers a state file rewritten so fast that its size and mtime are unchanged.
    """
    key = (config_dir, agent_id, group_id)
    stamp = _state_stamp(config_dir, agent_id, group_id)
    cached = _HELD.get(key)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    held = load_mls_group(open_mls_client(config_dir, agent_id), group_id) is not None
    _HELD[key] = (stamp, held)
    return held


def note_mls_state_changed(config_dir: str, agent_id: str, group_id: str) -> None:
    """Forget the remembered answer for one group, whose state just changed.

    Per-key on purpose: a mutating path always knows its own
    ``(config_dir, agent_id, group_id)``, and a blunt process-wide clear invites
    "reset it somewhere afterwards" in place of invalidating at the mutation.
    """
    _HELD.pop((config_dir, agent_id, group_id), None)


__all__ = [
    "holds_mls_state",
    "load_mls_group",
    "mls_group_id_bytes",
    "note_mls_state_changed",
    "open_mls_group",
]
