"""One client's OAuth token: the copy it holds, and when it stops trusting it.

Both HTTP clients had their own copy of this — read memory, fall back to the
shared on-disk cache, stamp a freshly minted token into both, clear both on a
401 — in ``rine._http``, which is why ``rine-sdk``'s suite carries a test that
diffs the two ``_get_token`` bodies against each other. That test exists because
the divergence it watches for has already been paid for once: the expiry check
was added to the disk path and missed on the in-memory one, and an always-on
agent then spent one rejected request per token lifetime, forever, with every
suite we owned green. Pinning two copies to each other is a way of living with a
duplication; holding one copy is a way of not having it.

What stays in ``rine._http`` is the part that genuinely differs: the fetch is a
coroutine on one client and a blocking call on the other. Everything either one
does with the ANSWER is here, so the sync and async ``_get_token`` bodies are now
the same three statements.

🔴 The margin is a floor on freshness, never on lifetime. Nothing here may
lengthen a token's life or the server's ``token_lifetime_seconds`` (900 s, a
security control: there is no revocation list and no ``jti``, so the TTL *is* the
containment window for a leaked token). The one adjustment
:meth:`TokenCache.stamp` makes only ever SHORTENS a margin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._config import cache_token, get_cached_token_entry, token_is_fresh
from rine._logging import logger

if TYPE_CHECKING:
    from collections.abc import Callable


class TokenCache:
    """The token one client is holding, and the deadline it is judged against.

    Not shared between clients: the margin is drawn per client so co-located
    clients desynchronize their refreshes, and two clients sharing one instance
    would resynchronize them. The DISK cache underneath *is* shared, and that is
    where a warm start gets its token from.
    """

    __slots__ = (
        "_config_dir",
        "_margin",
        "_principal",
        "_time_fn",
        "_token_margin",
        "expires_at",
        "token",
    )

    def __init__(
        self, config_dir: str, principal: str, margin: float, time_fn: Callable[[], float]
    ) -> None:
        """Hold nothing yet, judged by *margin* seconds against *time_fn*'s clock.

        *principal* keys the entry in the shared disk cache, which lives in
        *config_dir*: one cache file serves every principal that dir signs for.
        """
        self._config_dir = config_dir
        self._principal = principal
        #: The client's own drawn margin. Never reassigned: it is what every disk
        #: lookup is filtered by, and what a cleared cache falls back to.
        self._margin = margin
        #: The margin for the token currently held, which :meth:`stamp` may pull
        #: below ``_margin`` for a short-lived one. Separate so that seeing one
        #: short token does not shorten this client's margin for good — that
        #: would quietly undo the jitter the margin was drawn for.
        self._token_margin = margin
        self._time_fn = time_fn
        self.token: str | None = None
        self.expires_at = 0.0

    def fresh_token(self) -> str | None:
        """The token still usable right now, or ``None`` if one must be minted.

        Memory first, then the shared disk cache — and a hit there is adopted
        WITH its expiry, not just its string. Taking only the string is what left
        a warm-started client blind again from that moment on: the disk path
        checked the deadline and then handed over a token whose deadline the
        client did not know.

        The disk lookup is filtered by the client's own margin rather than by a
        clamped one, because the entry on disk does not say what lifetime it was
        granted. The cost of that is bounded and small: a warm start against a
        token shorter than the margin gets no hit and mints once. It cannot storm
        — the token it then stamps carries the clamp.
        """
        now = self._time_fn()
        if self.token and token_is_fresh(self.expires_at, self._token_margin, now):
            return self.token
        cached = get_cached_token_entry(self._config_dir, self._principal, self._margin, now)
        if cached:
            self.token = cached["access_token"]
            self.expires_at = cached["expires_at"]
            self._token_margin = self._margin
            return self.token
        return None

    def stamp(self, token: str, expires_in: float) -> None:
        """Adopt a freshly minted token, and write it to the shared disk cache.

        🔴 The margin is clamped to half this token's own lifetime, and that
        clamp is what keeps a short-lived token from being born stale. The
        per-client margin is 60–180 s; a server issuing a 120 s token would hand
        every client drawn above 120 s a token that fails
        :func:`rine._config.token_is_fresh` on the very next call, so every
        request mints another — a refresh storm, produced by the mechanism that
        exists to prevent needless refreshes. Our own server issues 900 s and
        that number does not move, so the clamp is inert against it; it is the
        client's half of the contract with any conforming OAuth server, and it
        only ever shortens.

        The deadline is sampled AFTER the fetch, matching what ``cache_token``
        writes to disk so the two agree. That errs LATE by one round-trip — the
        server started the clock when it issued the token, not when the response
        landed — so the deadline is optimistic by the RTT. The margin absorbs it,
        which is one of the reasons the margin cannot be cut to zero.

        A pathological ``expires_in`` of zero or less leaves the token stale on
        arrival and every request mints another. Nothing here invents a lifetime
        the server did not grant.
        """
        try:
            cache_token(self._config_dir, self._principal, token, expires_in)
        except Exception:
            logger.warning("Failed to cache token", exc_info=True)
        self.token = token
        self.expires_at = self._time_fn() + expires_in
        self._token_margin = min(self._margin, expires_in / 2)

    def clear(self) -> None:
        """Forget the token, its deadline and its clamped margin together.

        Clearing the token but leaving the deadline behind would leave a stale
        one attached to whatever token is fetched next.
        """
        self.token = None
        self.expires_at = 0.0
        self._token_margin = self._margin


__all__ = ["TokenCache"]
