"""Which sender keys a scan has already failed to find.

A reader that knows this does not list the whole distribution inbox again for
every post that needs one.

A group post whose sender key never arrives (the sender's org refuses our keys,
or its distribution was never sent) makes every read of that sender's posts run
one list call plus a GET and a decrypt per pending distribution. An agent
reading twenty such posts paid the scan twenty times. One empty scan is the
answer for all of them until something could have changed it.

In memory and per process, on purpose: no on-disk state and no file lock. A
long-running agent scans once per :data:`NEGATIVE_TTL_SECONDS` per missing key;
a one-shot call scans once, as it always did. A lock guards the map because the
send path runs on a worker thread while a read may run on the caller's.

Keyed by (agent, group, sender, key id), never by a group's ``refused_members``:
the cache records what a scan found, not what a group rule says. The twin is
``rine-core/src/sender-key-negative-cache.ts``. Only the readers' retry arm
consults it; the explicit ``group_sync`` always scans.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, NamedTuple

from rine.errors import NoSenderKeyStateError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rine.types import DecryptedMessage

#: How long an empty scan stays the answer.
NEGATIVE_TTL_SECONDS = 15 * 60

#: The oldest entries go first once the map is this full.
NEGATIVE_MAX_ENTRIES = 1000


class MissingSenderKey(NamedTuple):
    """One missing key: the reader, where the post lives, who sent it, and which key."""

    agent_id: str
    group_id: str
    sender_agent_id: str
    key_id: str


def _folded(key: MissingSenderKey) -> MissingSenderKey:
    """Ids compare case-insensitively, as the ingest guard does."""
    return MissingSenderKey(
        key.agent_id.lower(), key.group_id.lower(), key.sender_agent_id.lower(), key.key_id
    )


class SenderKeyNegativeCache:
    """A bounded, expiring set of sender keys a scan found missing."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Start empty. ``clock`` is injectable so a test can move time."""
        self._clock = clock
        self._lock = threading.Lock()
        # Entry to the moment it stops being the answer. Insertion order is age.
        self._expiries: dict[MissingSenderKey, float] = {}

    def is_cached(self, key: MissingSenderKey) -> bool:
        """Whether a scan already found this key missing within the last 15 minutes."""
        entry = _folded(key)
        with self._lock:
            expiry = self._expiries.get(entry)
            if expiry is None:
                return False
            if expiry > self._clock():
                return True
            del self._expiries[entry]
            return False

    def record_missing(self, key: MissingSenderKey) -> None:
        """Remember that a scan ran and did not bring this key."""
        entry = _folded(key)
        with self._lock:
            # Re-insert so a repeat entry counts as the newest.
            self._expiries.pop(entry, None)
            if len(self._expiries) >= NEGATIVE_MAX_ENTRIES:
                del self._expiries[next(iter(self._expiries))]
            self._expiries[entry] = self._clock() + NEGATIVE_TTL_SECONDS

    def clear_sender(self, agent_id: str, sender_agent_id: str) -> None:
        """Forget every entry for this sender as seen by this agent.

        A distribution from them was just ingested, so what was missing may be
        here now.
        """
        agent, sender = agent_id.lower(), sender_agent_id.lower()
        with self._lock:
            for entry in [
                e for e in self._expiries if e.agent_id == agent and e.sender_agent_id == sender
            ]:
                del self._expiries[entry]


#: The process-wide cache both clients share.
SENDER_KEY_NEGATIVE_CACHE = SenderKeyNegativeCache()

#: How many scans in a row one distribution row may fail before it stops vetoing a recorded
#: miss. A transient failure (a dropped GET) heals inside this many scans and keeps the scan
#: incomplete meanwhile; a row that never opens (a garbled or badly signed distribution, which
#: stays in the listing for good) would otherwise keep the cache off for the whole process.
ROW_FAILURE_LIMIT = 3


class RowFailureLedger:
    """Consecutive failed scans per (agent, message), bounded like the cache."""

    def __init__(self) -> None:
        """Start empty."""
        self._lock = threading.Lock()
        # (agent, message id) to the scans in a row that row has failed. Insertion order is age.
        self._streaks: dict[tuple[str, str], int] = {}

    def settle(self, agent_id: str, opened_ids: Sequence[str], failed_ids: Sequence[str]) -> int:
        """Fold one scan's per-row outcome in; return how many failed rows still count.

        A row that opened loses its count, a row that raised gains one, and a row past
        :data:`ROW_FAILURE_LIMIT` consecutive failures is no longer counted. The twin is
        ``settleRowFailures`` in ``rine-core/src/sender-key-negative-cache.ts``.
        """
        agent = agent_id.lower()
        failed = {i.lower() for i in failed_ids}
        counted = 0
        with self._lock:
            for row_id in opened_ids:
                if row_id.lower() not in failed:
                    self._streaks.pop((agent, row_id.lower()), None)
            for row_id in failed:
                entry = (agent, row_id)
                streak = self._streaks.pop(entry, 0) + 1
                if len(self._streaks) >= NEGATIVE_MAX_ENTRIES:
                    del self._streaks[next(iter(self._streaks))]
                self._streaks[entry] = streak
                if streak <= ROW_FAILURE_LIMIT:
                    counted += 1
        return counted


#: The process-wide ledger both clients share.
SENDER_KEY_ROW_FAILURES = RowFailureLedger()


def missing_sender_key(
    agent_id: str, msg: DecryptedMessage, error: Exception
) -> MissingSenderKey | None:
    """The key a failed group read is missing, or ``None`` when the cache cannot speak for it.

    Only a decrypt that named an absent key, on a row that names its group and
    its sender, has a cache entry to ask about.
    """
    if (
        not isinstance(error, NoSenderKeyStateError)
        or msg.group_id is None
        or msg.from_agent_id is None
    ):
        return None
    return MissingSenderKey(
        agent_id, str(msg.group_id), str(msg.from_agent_id), error.sender_key_id
    )
