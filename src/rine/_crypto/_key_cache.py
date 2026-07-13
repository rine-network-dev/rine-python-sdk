"""Per-client TTL + LRU cache for agents' public keys.

A single ``GET /agents/{id}/keys`` response carries both an agent's signing and
encryption public keys, so one cached entry serves send (recipient encryption
key) and inbound-verify (sender signing key) alike. The cache is bounded in both
time (``ttl``) and size (``max_entries``, LRU eviction) and is pure in-memory, so
one instance is shared by the sync and async paths of a single client.

Keys rotate rarely; the TTL bounds the staleness window and the verify-failure
refetch (see ``message.py``) closes any mid-TTL rotation hole.
"""

from __future__ import annotations

from collections import OrderedDict
from time import monotonic
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


class KeyCache:
    """A bounded TTL + LRU cache keyed by agent id.

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
        self._entries: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()

    def get(self, key: str) -> dict[str, Any] | None:
        """Return a live cached value, or ``None`` if missing or expired.

        A live read refreshes recency (LRU); an expired entry is evicted.

        Args:
            key: Agent id.

        Returns:
            The cached keys response, or ``None``.
        """
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._time_fn() >= expires_at:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return value

    def set(self, key: str, value: dict[str, Any]) -> None:
        """Insert or refresh an entry, evicting the LRU entry if over capacity.

        Args:
            key: Agent id.
            value: Keys response to cache.
        """
        self._entries[key] = (self._time_fn() + self._ttl, value)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def invalidate(self, key: str) -> None:
        """Drop a cached entry if present.

        Args:
            key: Agent id.
        """
        self._entries.pop(key, None)
