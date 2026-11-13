"""``stream()`` under a hold on the agent: a refusal raises and a lift needs no restart.

The client's stream is one connection with no reconnect of its own: the caller's loop reopens it.
These tests pin what that loop meets while the agent is suspended or its org frozen, and what the
client does once the hold is lifted.
"""

# ruff: noqa: D103, F811 - the imported fixture is the one test_stream_refusal defines
from __future__ import annotations

import httpx
import pytest

from rine._config import cache_token, load_token_cache
from rine.errors import AuthenticationError, AuthorizationError
from tests.test_stream_refusal import (
    SSE_BODY,
    _async_client,
    _sync_client,
    stream_route,  # noqa: F401
    stream_router,  # noqa: F401
)

HELD = httpx.Response(403, json={"error": "agent_suspended", "detail": "Agent is suspended"})
OPEN = httpx.Response(200, text=SSE_BODY)


def _ids(events) -> list[str | None]:
    return [e.id for e in events]


def test_sync_stream_when_held_then_lifted_the_same_client_streams_again(
    stream_route,
    tmp_config_dir,
    agent_id,
):
    stream_route.mock(side_effect=[HELD, HELD, OPEN])
    client = _sync_client(tmp_config_dir, agent_id)

    for _ in range(2):
        with pytest.raises(AuthorizationError):
            list(client.stream())
    events = list(client.stream())

    assert _ids(events) == ["7", None]
    assert stream_route.call_count == 3


async def test_async_stream_when_held_then_lifted_the_same_client_streams_again(
    stream_route,
    tmp_config_dir,
    agent_id,
):
    stream_route.mock(side_effect=[HELD, HELD, OPEN])
    client = _async_client(tmp_config_dir, agent_id)

    for _ in range(2):
        with pytest.raises(AuthorizationError):
            [event async for event in client.stream()]
    events = [event async for event in client.stream()]

    assert _ids(events) == ["7", None]
    assert stream_route.call_count == 3


def test_sync_stream_when_held_never_retries_inside_one_call(
    stream_route,
    tmp_config_dir,
    agent_id,
):
    """A refused stream raises at once; the retry pace belongs to the caller's loop."""
    stream_route.mock(return_value=HELD)
    client = _sync_client(tmp_config_dir, agent_id)

    with pytest.raises(AuthorizationError):
        list(client.stream())

    assert stream_route.call_count == 1


def test_sync_stream_when_the_server_closes_it_at_the_suspend_then_it_ends_without_an_error(
    stream_route,
    tmp_config_dir,
    agent_id,
):
    """The server's kill is a clean end with no frame, indistinguishable from any other close."""
    stream_route.mock(return_value=httpx.Response(200, text="event: heartbeat\ndata: {}\n\n"))
    client = _sync_client(tmp_config_dir, agent_id)

    events = list(client.stream())

    assert [e.event for e in events] == ["heartbeat"]
    assert stream_route.call_count == 1


@pytest.fixture
def mints(stream_router):
    """The token endpoint, counted, handing out ``tok1``, ``tok2`` and so on."""
    token_route = stream_router.routes["token"]
    issued: list[str] = []

    def mint(request: httpx.Request) -> httpx.Response:
        issued.append(f"tok{len(issued) + 1}")
        return httpx.Response(200, json={"access_token": issued[-1], "expires_in": 900})

    token_route.mock(side_effect=mint)
    return issued


def _bearers(stream_route) -> list[str]:
    return [call.request.headers["Authorization"] for call in stream_route.calls]


def test_sync_stream_when_the_token_died_at_the_suspend_then_the_next_attempt_mints_once(
    stream_route,
    mints,
    tmp_config_dir,
    agent_id,
):
    """A 401 drops the cached token, so the reconnect after the lift is not sent the dead one."""
    stream_route.mock(
        side_effect=[OPEN, httpx.Response(401, json={"detail": "tokens revoked"}), OPEN, OPEN]
    )
    client = _sync_client(tmp_config_dir, agent_id)

    list(client.stream())
    with pytest.raises(AuthenticationError):
        list(client.stream())
    list(client.stream())
    list(client.stream())

    assert mints == ["tok1", "tok2"]
    assert _bearers(stream_route) == ["Bearer tok1", "Bearer tok1", "Bearer tok2", "Bearer tok2"]


async def test_async_stream_when_the_token_died_at_the_suspend_then_the_next_attempt_mints_once(
    stream_route,
    mints,
    tmp_config_dir,
    agent_id,
):
    stream_route.mock(
        side_effect=[OPEN, httpx.Response(401, json={"detail": "tokens revoked"}), OPEN, OPEN]
    )
    client = _async_client(tmp_config_dir, agent_id)

    [event async for event in client.stream()]
    with pytest.raises(AuthenticationError):
        [event async for event in client.stream()]
    [event async for event in client.stream()]
    [event async for event in client.stream()]

    assert mints == ["tok1", "tok2"]
    assert _bearers(stream_route) == ["Bearer tok1", "Bearer tok1", "Bearer tok2", "Bearer tok2"]


def test_sync_stream_when_a_401_is_followed_by_a_refused_mint_then_each_attempt_asks_again(
    stream_route,
    stream_router,
    tmp_config_dir,
    agent_id,
):
    """While the hold lasts the mint is refused and the error reaches the caller's backoff."""
    token_route = stream_router.routes["token"]
    refused = httpx.Response(
        400, json={"error": "unauthorized_client", "reason": "agent_suspended"}
    )
    token_route.mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "tok1", "expires_in": 900}),
            refused,
            refused,
        ]
    )
    stream_route.mock(side_effect=[OPEN, httpx.Response(401, json={"detail": "tokens revoked"})])
    client = _sync_client(tmp_config_dir, agent_id)

    list(client.stream())
    with pytest.raises(AuthenticationError):
        list(client.stream())
    for _ in range(2):
        with pytest.raises(AuthenticationError):
            list(client.stream())

    assert token_route.call_count == 3
    assert stream_route.call_count == 2


def test_sync_stream_when_another_process_cached_a_newer_token_then_the_401_keeps_it(
    stream_route,
    mints,
    tmp_config_dir,
    agent_id,
):
    """Only the refused token leaves the shared cache: a sibling's newer one is adopted."""
    stream_route.mock(
        side_effect=[OPEN, httpx.Response(401, json={"detail": "tokens revoked"}), OPEN]
    )
    client = _sync_client(tmp_config_dir, agent_id)
    list(client.stream())
    principal = next(iter(load_token_cache(tmp_config_dir)))
    cache_token(tmp_config_dir, principal, "sibling", 900)

    with pytest.raises(AuthenticationError):
        list(client.stream())
    list(client.stream())

    assert mints == ["tok1"]
    assert _bearers(stream_route)[-1] == "Bearer sibling"
