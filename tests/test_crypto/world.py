"""Stand-in key servers over the shared test world (:mod:`rine.testing`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from rine._crypto._key_cache import KeyCache
from rine.testing import WORLD, World

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._crypto._key_pins import KeyPins

#: When a :class:`KeyServer` says a superseded generation stopped being valid.
SUPERSEDED_AT = datetime(2026, 1, 1, tzinfo=UTC)


class KeyServer:
    """A stand-in HTTP client serving ``GET /agents/{id}/keys`` from a :class:`World`.

    It owns a real key cache (and so real pins), counts every read, and serves
    each agent at the generation set with :meth:`publish` (default 0). A
    ``?gen=N`` read is answered with that generation. ``tamper`` may rewrite a
    response on its way out, which is how a broken chain is simulated.
    """

    def __init__(self, world: World = WORLD) -> None:
        """Serve agents of one world, from cold."""
        self.world = world
        self._keys_cache = KeyCache(600.0, 256)
        self.published: dict[str, int] = {}
        self.tamper: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.superseded_at: datetime | None = SUPERSEDED_AT
        self.revoked_at: datetime | None = None
        self.reads = 0

    @property
    def key_pins(self) -> KeyPins:
        """The pins every read through this server is admitted to."""
        return self._keys_cache.pins

    def publish(self, agent_id: str, gen: int) -> None:
        """Make ``gen`` the generation served for an agent from now on."""
        self.published[agent_id] = gen

    def _answer(self, path: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        self.reads += 1
        agent_id = path.split("/")[2]
        gen = (kwargs.get("params") or {}).get("gen", self.published.get(agent_id, 0))
        body = self.world.keys_response(agent_id, int(gen))
        if int(gen) < self.published.get(agent_id, 0) and self.superseded_at is not None:
            body["superseded_at"] = self.superseded_at.isoformat()
        if self.revoked_at is not None:
            body["revoked_at"] = self.revoked_at.isoformat()
        return self.tamper(body) if self.tamper else body

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer a key read, counting it."""
        return self._answer(path, kwargs)


class AsyncKeyServer(KeyServer):
    """The async twin of :class:`KeyServer`."""

    async def get(self, path: str, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        """Answer a key read, counting it."""
        return self._answer(path, kwargs)
