"""A live message never costs a key read: the cache's lifetime is the only bound on a view.

The server stamps every live row after the key view was fetched, so a cache that
refetched for such rows would read the keys once per message. The revocation
window is the cache's TTL; a view read fresh still refuses rows past its
``revoked_at``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from rine._crypto._sender_verify import verify_envelope_sender_async, verify_envelope_sender_sync
from rine._crypto.keys import make_kid
from rine._crypto.sign import MessageSig, sign_message
from rine.testing import WORLD
from tests.test_crypto.world import AsyncKeyServer, KeyServer

AGENT = "00000000-1111-2222-3333-444444444444"
SCOPE = MessageSig("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
PAYLOAD = b"signed by a live agent"
STAMPED = datetime(2026, 6, 1, tzinfo=UTC)
ONE_HOUR = timedelta(hours=1)


def _signature() -> bytes:
    return sign_message(WORLD.keys(AGENT, 0).signing.private_key, SCOPE, PAYLOAD)


def _verify(server: KeyServer, created_at: datetime) -> str | None:
    return verify_envelope_sender_sync(
        make_kid(AGENT, 0),
        PAYLOAD,
        _signature(),
        SCOPE,
        server,  # type: ignore[arg-type]
        AGENT,
        created_at,
    ).verification_status


def test_verify_when_a_later_row_follows_a_cached_view_then_the_cache_serves_it() -> None:
    """A row stamped after the fetch is served from the cache without a second read."""
    server = KeyServer()
    server.publish(AGENT, 0)
    assert _verify(server, STAMPED) == "verified"
    assert _verify(server, STAMPED + ONE_HOUR) == "verified"
    assert server.reads == 1


async def test_verify_async_when_a_later_row_follows_a_cached_view_then_the_cache_serves_it() -> (
    None
):
    """The async twin: still one key read for two rows, the second stamped later."""
    server = AsyncKeyServer()
    server.publish(AGENT, 0)

    async def verify(created_at: datetime) -> str | None:
        verdict = await verify_envelope_sender_async(
            make_kid(AGENT, 0), PAYLOAD, _signature(), SCOPE, server, AGENT, created_at
        )
        return verdict.verification_status

    assert await verify(STAMPED) == "verified"
    assert await verify(STAMPED + ONE_HOUR) == "verified"
    assert server.reads == 1


def test_verify_when_a_fresh_view_carries_revoked_at_then_a_later_row_is_invalid() -> None:
    """The revocation bound still applies to a view read fresh."""
    server = KeyServer()
    server.publish(AGENT, 0)
    server.revoked_at = STAMPED
    assert _verify(server, STAMPED - ONE_HOUR) == "verified"
    server._keys_cache.invalidate(AGENT)
    assert _verify(server, STAMPED + ONE_HOUR) == "invalid"
