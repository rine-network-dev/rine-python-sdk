"""One client's view of who it acts as: the signer, its token cache, its own-org pins.

Resolution reads key files, so it happens once and is remembered; the token
cache is built from it because the cache dir depends on whose key signs (the
owner dir for a principal derived from ``root.key``, the runtime dir otherwise).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._custody import ResolvedAuth, local_agent_ids, resolve_auth
from rine._token_cache import TokenCache
from rine.errors import AuthenticationError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from rine._crypto._key_pins import KeyPins

_NO_IDENTITY = "No identity found. Run: rine onboard"


class ClientAuth:
    """Resolve once, then serve the signer and the token cache from that answer."""

    __slots__ = (
        "_config_dir",
        "_margin",
        "_owner_dir",
        "_profile",
        "_resolved",
        "_time_fn",
        "_tokens",
    )

    def __init__(
        self,
        config_dir: str,
        owner_dir: str | None,
        profile: str | None,
        margin: float,
        time_fn: Callable[[], float],
    ) -> None:
        """Hold nothing yet: the first :meth:`resolved` reads the key files."""
        self._config_dir = config_dir
        self._owner_dir = owner_dir
        self._profile = profile
        self._margin = margin
        self._time_fn = time_fn
        self._resolved: ResolvedAuth | None = None
        self._tokens: TokenCache | None = None

    def _resolve(self) -> ResolvedAuth | None:
        if self._resolved is None:
            self._resolved = resolve_auth(self._config_dir, self._owner_dir, self._profile)
        return self._resolved

    def resolved(self) -> ResolvedAuth:
        """Who this client acts as.

        Raises:
            AuthenticationError: This process holds no identity to act as.
        """
        found = self._resolve()
        if found is None:
            raise AuthenticationError(_NO_IDENTITY)
        return found

    @property
    def tokens(self) -> TokenCache:
        """The token cache of the resolved principal."""
        if self._tokens is None:
            found = self.resolved()
            self._tokens = TokenCache(
                found.cache_dir, str(found.signer.principal), self._margin, self._time_fn
            )
        return self._tokens

    def invalidate(self) -> None:
        """Forget the held token (a no-op before one was ever fetched)."""
        if self._tokens is not None:
            self._tokens.clear()

    def pin_agents(self, pins: KeyPins, agent_ids: Iterable[str]) -> None:
        """Pin these agents to this client's own org, when it has an identity to name one."""
        found = self._resolve()
        if found is None:
            return
        for agent_id in agent_ids:
            pins.pin_own_agent(agent_id, found.org_id)

    def seed_pins(self, pins: KeyPins) -> None:
        """Pin every agent this client holds leaf keys for."""
        self.pin_agents(pins, local_agent_ids(self._config_dir))
