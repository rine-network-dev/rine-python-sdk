"""Guard: a client held across a token expiry refreshes before it 401s.

The discriminator for this defect is process lifetime, not code path. One client
that outlives a 900 s token, asked for anything after the expiry, used to hand
back the token it had cached on first use — with no expiry comparison anywhere on
that path — and learn it was dead from the server's 401. That cost one rejected
request per token lifetime, per always-on agent, forever: an operator measured
3607 of them at a 905 s cadence. Nothing broke, which is why every suite we owned
was green: the CLI, one-shots and short tests all start with an empty in-memory
cache and fall through to the disk path, which did compare the expiry.

So the property under test is **no 401 ever reaching the wire**, not the presence
of any attribute — a test written around the fix's own shape would survive the
next refactor that loses the behaviour. The mock server here rejects exactly what
a real one rejects: a bearer token issued more than one lifetime ago.
"""

from __future__ import annotations

import inspect
import os
import textwrap
import time
from typing import Any

import httpx
import respx

from rine._http import AsyncHttpClient, SyncHttpClient
from rine.testing import write_agent_identity

API = "https://rine.network"
TOKEN_URL = f"{API}/oauth/token"
AGENTS_URL = f"{API}/agents"
AGENT_ID = "00000000-1111-2222-3333-444444444444"
_TTL = 900  # the server's token lifetime; a security control, it does not move


class _Rig:
    """A token-expiring server plus the clock its clients read.

    ``rejected`` is the whole point: it collects every bearer token the server
    turned away, so an assertion can be made about the absence of that
    round-trip rather than about how the client avoided it.
    """

    def __init__(self, ttl: int = _TTL) -> None:
        self.now = time.time()
        self.ttl = ttl
        self.issued: dict[str, float] = {}
        self.rejected: list[str] = []

    def clock(self) -> float:
        return self.now

    def install(self) -> None:
        respx.post(TOKEN_URL).mock(side_effect=self._token)
        respx.get(AGENTS_URL).mock(side_effect=self._api)

    def _token(self, _request: httpx.Request) -> httpx.Response:
        name = f"tok-{len(self.issued)}"
        self.issued[name] = self.now
        return httpx.Response(200, json={"access_token": name, "expires_in": self.ttl})

    def _api(self, request: httpx.Request) -> httpx.Response:
        presented = request.headers["Authorization"].removeprefix("Bearer ")
        issued_at = self.issued.get(presented)
        if issued_at is None or self.now - issued_at >= self.ttl:
            self.rejected.append(presented)
            return httpx.Response(401, json={"detail": "token expired"})
        return httpx.Response(200, json={"ok": True})


def _sync_client(rig: _Rig, config_dir: str, **kwargs: Any) -> SyncHttpClient:
    return SyncHttpClient(
        config_dir=config_dir, api_url=API, rng=lambda: 0.0, time_fn=rig.clock, **kwargs
    )


def _async_client(rig: _Rig, config_dir: str, **kwargs: Any) -> AsyncHttpClient:
    return AsyncHttpClient(
        config_dir=config_dir, api_url=API, rng=lambda: 0.0, time_fn=rig.clock, **kwargs
    )


class TestOneClientAcrossAnExpiry:
    """The operator's shape: a single long-lived client, two calls, one expiry."""

    @respx.mock
    def test_sync_client_refreshes_without_a_401(self, tmp_config_dir):
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        client = _sync_client(rig, tmp_config_dir)

        assert client.get("/agents") == {"ok": True}
        rig.now += _TTL + 1
        assert client.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 2  # it minted a fresh token, proactively
        client.close()

    @respx.mock
    async def test_async_client_refreshes_without_a_401(self, tmp_config_dir):
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        client = _async_client(rig, tmp_config_dir)

        assert await client.get("/agents") == {"ok": True}
        rig.now += _TTL + 1
        assert await client.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 2
        await client.close()


class TestWarmStartFromDisk:
    """A client that inherits its token from the shared disk cache.

    The disk path always compared the expiry — but it handed back only the token
    string, so the client it seeded was blind again from that moment on. A
    warm-started client has to carry the deadline the disk cache checked.
    """

    @respx.mock
    def test_sync_warm_started_client_refreshes_without_a_401(self, tmp_config_dir):
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        primer = _sync_client(rig, tmp_config_dir)
        assert primer.get("/agents") == {"ok": True}  # writes the disk cache
        primer.close()

        warm = _sync_client(rig, tmp_config_dir)
        assert warm.get("/agents") == {"ok": True}  # served from disk, no fetch
        assert len(rig.issued) == 1
        rig.now += _TTL + 1
        assert warm.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 2
        warm.close()

    @respx.mock
    async def test_async_warm_started_client_refreshes_without_a_401(self, tmp_config_dir):
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        primer = _async_client(rig, tmp_config_dir)
        assert await primer.get("/agents") == {"ok": True}
        await primer.close()

        warm = _async_client(rig, tmp_config_dir)
        assert await warm.get("/agents") == {"ok": True}
        assert len(rig.issued) == 1
        rig.now += _TTL + 1
        assert await warm.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 2
        await warm.close()

    @respx.mock
    def test_sync_warm_start_survives_the_disk_cache_vanishing(self, tmp_config_dir):
        # Seeding the deadline is what makes the in-memory token usable at all
        # for a warm-started client. Without it every request falls back to the
        # file, so a co-located process clearing it costs a needless token mint.
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        primer = _sync_client(rig, tmp_config_dir)
        assert primer.get("/agents") == {"ok": True}
        primer.close()

        warm = _sync_client(rig, tmp_config_dir)
        assert warm.get("/agents") == {"ok": True}
        os.remove(os.path.join(tmp_config_dir, "token_cache.json"))
        assert warm.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 1  # answered from memory, no needless mint
        warm.close()

    @respx.mock
    async def test_async_warm_start_survives_the_disk_cache_vanishing(self, tmp_config_dir):
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        primer = _async_client(rig, tmp_config_dir)
        assert await primer.get("/agents") == {"ok": True}
        await primer.close()

        warm = _async_client(rig, tmp_config_dir)
        assert await warm.get("/agents") == {"ok": True}
        os.remove(os.path.join(tmp_config_dir, "token_cache.json"))
        assert await warm.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 1
        await warm.close()


class TestA401IsNowUnexpected:
    """With the refresh proactive, a 401 means revocation — so it warns."""

    @respx.mock
    def test_revocation_mid_life_is_retried_and_logged_at_warning(self, tmp_config_dir, caplog):
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        client = _sync_client(rig, tmp_config_dir)
        assert client.get("/agents") == {"ok": True}

        rig.issued.clear()  # the server forgets the token: revoked, not expired
        with caplog.at_level("WARNING"):
            assert client.get("/agents") == {"ok": True}

        assert len(rig.rejected) == 1  # the backstop fired, exactly once
        assert any("401 received, refreshing token" in r.message for r in caplog.records)
        client.close()

    @respx.mock
    async def test_async_revocation_mid_life_is_retried_and_logged_at_warning(
        self, tmp_config_dir, caplog
    ):
        """The async client's own copy of the backstop, which nothing asserted.

        The two clients carry independent copies of this code and
        ``TestSyncAndAsyncStayInStep`` pins only ``_get_token`` and
        ``_invalidate_token`` — it reaches neither ``_request`` nor ``_execute``,
        where the 401 retry and its log line live. So the level on this side was
        guarded by nothing: demoting it back to ``debug`` left every suite we own
        green while an always-on async agent lost the only signal that
        distinguishes a revoked token from a merely stale one, which is the
        distinction the whole proactive refresh was built to make legible.
        """
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        rig.install()
        client = _async_client(rig, tmp_config_dir)
        assert await client.get("/agents") == {"ok": True}

        rig.issued.clear()  # the server forgets the token: revoked, not expired
        with caplog.at_level("WARNING"):
            assert await client.get("/agents") == {"ok": True}

        assert len(rig.rejected) == 1
        assert any("401 received, refreshing token" in r.message for r in caplog.records)
        await client.close()

    async def test_invalidating_the_token_clears_its_expiry(self, tmp_config_dir):
        """A tripwire over the pair of writes, and honestly not more than that.

        🔴 No behavioural assertion is available here and it would be misleading
        to dress this up as one. ``TokenCache.fresh_token`` requires
        ``self._auth.tokens.token`` to be truthy, so a deadline an invalidation
        left behind is never read, and the fetch that follows overwrites it
        unconditionally. What this pins is that the two fields are cleared
        TOGETHER: reorder that fast path to consult the deadline first and a
        stale one becomes reachable. Delete it deliberately if the shape changes,
        rather than letting it quietly outlive its reason.
        """
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig()
        sync_client = _sync_client(rig, tmp_config_dir)
        async_client = _async_client(rig, tmp_config_dir)
        try:
            for client in (sync_client, async_client):
                client._auth.tokens.token = "stale"
                client._auth.tokens.expires_at = rig.now + _TTL
                client._invalidate_token()
                assert client._auth.tokens.token is None
                assert client._auth.tokens.expires_at == 0.0
        finally:
            # Both were left open before, which leaks an httpx transport per run
            # and — for the async one — draws an "unclosed client" warning that
            # any future filterwarnings=error would turn into a failure here
            # rather than where the leak is.
            sync_client.close()
            await async_client.close()


class TestAShortLivedTokenIsNotBornStale:
    """A token whose whole life is shorter than the refresh margin.

    Our server issues 900 s and that does not move, so this is the client's half
    of the contract with any conforming OAuth server — and the failure it
    prevents is the exact inverse of the defect this file is about. A margin of
    up to 180 s applied to a 120 s token makes every token stale on arrival, so
    every request mints a new one: a refresh storm produced by the machinery
    that exists to prevent needless refreshes, and a load pattern an operator
    would read as an attack on their own token endpoint.

    🔴 The clamp only ever SHORTENS a margin. Nothing here lengthens a token's
    life, and nothing here may: ``token_lifetime_seconds`` is the containment
    window for a leaked token, not a performance knob.
    """

    @respx.mock
    def test_sync_client_when_the_token_outlives_the_margin_then_it_is_reused(
        self, tmp_config_dir
    ):
        """Two calls, one token — with a lifetime well inside the 180 s margin."""
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig(ttl=120)
        rig.install()
        # rng() == 1.0 draws the widest margin, 60 + 120 = 180 s: longer than the
        # token's entire life, which is what used to make it stale on arrival.
        client = SyncHttpClient(
            config_dir=tmp_config_dir, api_url=API, rng=lambda: 1.0, time_fn=rig.clock
        )

        assert client.get("/agents") == {"ok": True}
        assert client.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 1  # reused, not re-minted per request
        client.close()

    @respx.mock
    async def test_async_client_when_the_token_outlives_the_margin_then_it_is_reused(
        self, tmp_config_dir
    ):
        """The async client shares the cache, so this is the same code path twice."""
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig(ttl=120)
        rig.install()
        client = AsyncHttpClient(
            config_dir=tmp_config_dir, api_url=API, rng=lambda: 1.0, time_fn=rig.clock
        )

        assert await client.get("/agents") == {"ok": True}
        assert await client.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 1
        await client.close()

    @respx.mock
    def test_short_token_when_past_half_its_life_then_it_is_still_refreshed_early(
        self, tmp_config_dir
    ):
        """Clamped, not abandoned: half the lifetime is still a real margin.

        The clamp must not collapse to "use it until it expires" — that would
        put the 401 back on the wire for exactly the tokens least able to absorb
        a round-trip. At 70 s into a 120 s token the clamped 60 s margin has been
        crossed, so the next call refreshes rather than presenting it.
        """
        write_agent_identity(tmp_config_dir, AGENT_ID)
        rig = _Rig(ttl=120)
        rig.install()
        client = SyncHttpClient(
            config_dir=tmp_config_dir, api_url=API, rng=lambda: 1.0, time_fn=rig.clock
        )

        assert client.get("/agents") == {"ok": True}
        rig.now += 70
        assert client.get("/agents") == {"ok": True}

        assert rig.rejected == []
        assert len(rig.issued) == 2
        client.close()


def _normalized_source(fn: Any) -> str:
    """The method's source with the sync/async spelling differences erased."""
    src = textwrap.dedent(inspect.getsource(fn))
    return (
        src.replace("async def ", "def ")
        .replace("await ", "")
        .replace("_fetch_oauth_token_async", "_fetch_oauth_token")
    )


class TestSyncAndAsyncStayInStep:
    """The two clients carry fully independent copies of this logic.

    A fix applied to one and missed on the other is the divergence this project
    has already paid for elsewhere, so pin them to each other. If a legitimate
    difference ever appears, extend the normalizer deliberately — the value here
    is that the difference has to be argued for, not that it can never exist.

    🔴 A tripwire over source text, and it detects DIVERGENCE only. Both clients
    losing the freshness check together — the operator's original symptom, one
    rejected request per token lifetime forever — leaves these two green, so
    never count them toward a mutation proof of the refresh behaviour. The tests
    that can see that symptom are the rig-driven ones above, which count the
    requests the server rejected.
    """

    def test_get_token_bodies_match(self):
        assert _normalized_source(SyncHttpClient._get_token) == _normalized_source(
            AsyncHttpClient._get_token
        )

    def test_invalidate_token_bodies_match(self):
        assert _normalized_source(SyncHttpClient._invalidate_token) == _normalized_source(
            AsyncHttpClient._invalidate_token
        )
