"""How a member reads a group message it has ALREADY read.

Both of rine's group regimes spend a one-time key at the first successful
decrypt, and neither can be asked twice. Sender Keys derives the message key
from a ratchet step and discards it (:mod:`rine._crypto.sender_keys` answers
"Message key expired or already consumed"); MLS consumes the secret-tree entry
inside ``process_incoming_message``. Nothing kept the plaintext, so re-reading
an inbox entry — the most ordinary thing an operator does — was an error.

This cache is the plaintext being kept, and it is the receiving counterpart of
the native core's ``self_read.bin``, which has always kept the plaintext of a
member's OWN sends for the same reason. It copies that file's shape on purpose:
keyed on a digest of the framed ciphertext, bounded by entry count and by bytes,
one file per group, written 0600. Its TypeScript twin is
``rine-core/src/crypto/group-read-cache.ts``; the two never share a file, so
they need only agree on behaviour.

🔴 **This is plaintext at rest, and it widens what a stolen config dir yields.**
The dir already holds group state in the clear under 0600, and MLS group state
is itself enough to decrypt the traffic of every epoch it retains — but before
this, a message whose key had been spent was not recoverable from disk by
anyone, including an attacker. It is now, for the newest
:data:`GROUP_READ_MAX_ENTRIES` messages per group. The bound is what keeps it a
re-read buffer rather than an archive, and leaving the group deletes it with the
rest of that group's material — a SELF-leave only: the departing client is what
calls :func:`delete_group_read_cache`, so a removed or evicted agent keeps its
copy until the config dir goes.

What is cached is what the row's bytes SAID: the signed inner envelope, never a
verdict about it. Every replay re-runs the signature check against the sender
the server names on the row being read now, so a row served again under a
different sender is refused rather than answered from the first read's
verification. :class:`rine._crypto._decrypt_memo.DecryptMemo` remains the
in-process half of the same job — it answers without touching disk, for a
long-lived client re-polling its own inbox.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from typing import Any

from rine._config import _ensure_dir, _write_atomic
from rine._crypto.keys import _validate_path_id
from rine._utils import from_base64url, to_base64url

#: Newest messages one group's read cache holds, matching the native core's
#: ``SELF_READ_MAX_ENTRIES``. The two caches answer the same question from the
#: two sides of a send.
GROUP_READ_MAX_ENTRIES = 256

#: Plaintext budget per group, on top of the entry count, matching the native
#: core's ``SELF_READ_MAX_BYTES``: a handful of large envelopes must not turn
#: the cache into megabytes of retained plaintext.
GROUP_READ_MAX_BYTES = 1024 * 1024


def _cache_path(config_dir: str, agent_id: str, group_id: str) -> str:
    """Where one agent's read cache for one group lives.

    Both ids are path segments — the agent names the directory, the group names
    the file — so both are validated here rather than at every caller.
    """
    _validate_path_id(agent_id, "agent_id")
    _validate_path_id(group_id, "group_id")
    return os.path.join(config_dir, "keys", agent_id, "group_reads", f"{group_id.lower()}.json")


def _digest(ciphertext: bytes) -> str:
    """The key: a digest of the ciphertext, so no caller needs a message id."""
    return to_base64url(hashlib.sha256(ciphertext).digest())


def _load(path: str) -> list[dict[str, Any]]:
    """Entries oldest-first.

    An absent file is an empty cache, and so is one that does not parse: this
    holds no authority and no key material, so a damaged re-read buffer must
    degrade into "decrypt it again" rather than fail a read the ratchet could
    still answer.
    """
    try:
        with open(path) as fh:
            entries = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict) and "k" in e and "e" in e]


def _evict(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Trim to the newest entries within both bounds. Oldest go first."""
    kept = entries[-GROUP_READ_MAX_ENTRIES:]
    total = sum(len(e["e"]) for e in kept)
    while len(kept) > 1 and total > GROUP_READ_MAX_BYTES:
        total -= len(kept[0]["e"])
        kept = kept[1:]
    return kept


def lookup_group_read(
    config_dir: str, agent_id: str, group_id: str, ciphertext: bytes
) -> bytes | None:
    """The signed inner envelope this agent already opened out of ``ciphertext``.

    Args:
        config_dir: Config directory path.
        agent_id: The reading agent's UUID.
        group_id: The rine group UUID.
        ciphertext: The framed payload the row carried, version tag included.

    Returns:
        The cached inner envelope, or ``None`` when this agent never opened
        those bytes (or the entry has aged out).
    """
    key = _digest(ciphertext)
    for entry in _load(_cache_path(config_dir, agent_id, group_id)):
        if entry["k"] == key:
            return from_base64url(entry["e"])
    return None


def record_group_read(
    config_dir: str, agent_id: str, group_id: str, ciphertext: bytes, inner_envelope: bytes
) -> None:
    """Record what a successful decrypt produced, for the next read of that row.

    A write failure is swallowed: the caller is holding the plaintext and is
    about to return it, and failing a read that worked because a re-read buffer
    could not be written would trade a real answer for a convenience.

    Args:
        config_dir: Config directory path.
        agent_id: The reading agent's UUID.
        group_id: The rine group UUID.
        ciphertext: The framed payload the row carried, version tag included.
        inner_envelope: The signed envelope that came out of it.
    """
    with contextlib.suppress(Exception):
        path = _cache_path(config_dir, agent_id, group_id)
        _ensure_dir(os.path.dirname(path))
        key = _digest(ciphertext)
        entries = [e for e in _load(path) if e["k"] != key]
        entries.append({"k": key, "e": to_base64url(inner_envelope)})
        _write_atomic(path, json.dumps(_evict(entries), separators=(",", ":")))


def delete_group_read_cache(config_dir: str, agent_id: str, group_id: str) -> None:
    """Drop everything this agent kept of one group's traffic.

    Called by every leave, beside the MLS wipe and the sender-key delete: the
    sentence a leave prints says the group's messages no longer open, and a
    plaintext cache that outlived the keys would make that false.

    Args:
        config_dir: Config directory path.
        agent_id: The departing agent's UUID.
        group_id: The rine group UUID.
    """
    with contextlib.suppress(Exception):
        os.remove(_cache_path(config_dir, agent_id, group_id))


__all__ = [
    "GROUP_READ_MAX_BYTES",
    "GROUP_READ_MAX_ENTRIES",
    "delete_group_read_cache",
    "lookup_group_read",
    "record_group_read",
]
