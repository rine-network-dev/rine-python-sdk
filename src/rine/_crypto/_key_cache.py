"""Per-client TTL + LRU cache for agents' chain-verified keys, and their pins.

This cache serves the inbound-verify path alone. Sending reads a recipient's
keys fresh every time — see ``_agent_keys.py`` for why the two paths differ. The
cache is bounded in both time (``ttl``) and size (``max_entries``, LRU eviction)
and is pure in-memory, so one instance is shared by the sync and async paths of
a single client — including the worker threads the async client runs MLS on,
which is why every read and write is taken under a lock.

Keys rotate rarely; the TTL bounds both the rotation staleness window and the
revocation window (a cached view of a revoked agent verifies until it expires,
which the server-honest revocation model accepts), and the verify-failure
refetch (see ``_sender_verify.py``) closes any mid-TTL rotation hole. No row
stamp ever bypasses an entry: a live message must not cost a key read.
"""

from __future__ import annotations

from collections import OrderedDict
from threading import Lock
from time import monotonic
from typing import TYPE_CHECKING

from rine._crypto._key_pins import KeyPins

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._crypto.certs import VerifiedAgentKeys


class KeyCache:
    """A bounded TTL + LRU cache keyed by agent id.

    Only keys that passed the whole chain check are ever stored (see
    :mod:`rine._crypto.certs`), and ``pins`` carries what the client has
    committed to about each agent. It lives here so every client sharing a
    cache shares its pins.

    Args:
        ttl: Seconds an entry stays valid after insertion.
        max_entries: Maximum number of entries before least-recently-used
            eviction.
        time_fn: Monotonic clock source (injectable for deterministic tests).
    """

    def __init__(
        self,
        ttl: float,
        max_entries: int,
        time_fn: Callable[[], float] = monotonic,
    ) -> None:
        self._ttl = ttl
        self._max_entries = max_entries
        self._time_fn = time_fn
        self._entries: OrderedDict[str, tuple[float, VerifiedAgentKeys]] = OrderedDict()
        self._lock = Lock()
        self.pins = KeyPins()

    def get(self, key: str) -> VerifiedAgentKeys | None:
        """Return a live cached value, or ``None`` if missing or expired.

        A live read refreshes recency (LRU); an expired entry is evicted.

        Args:
            key: Agent id.

        Returns:
            The cached verified keys, or ``None``.
        """
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self._time_fn() >= expires_at:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return value

    def set(self, key: str, value: VerifiedAgentKeys) -> None:
        """Insert or refresh an entry, evicting the LRU entry if over capacity.

        Args:
            key: Cache key: the agent id, or ``<agent id>#<gen>`` for a
                superseded generation.
            value: Verified keys to cache.
        """
        with self._lock:
            self._entries[key] = (self._time_fn() + self._ttl, value)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def invalidate(self, key: str) -> None:
        """Drop a cached entry if present.

        Args:
            key: Agent id.
        """
        with self._lock:
            self._entries.pop(key, None)
