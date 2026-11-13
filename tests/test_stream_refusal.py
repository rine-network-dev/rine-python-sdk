"""``stream()`` on both clients: a server refusal raises, and it never reads as a clean end.

Reading lines from a refusal's body ends quietly, so before this behaviour a revoked agent's
always-on consumer saw one empty stream after another and reconnected without pause.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine import RineClient, SyncRineClient
from rine.errors import (
    AuthenticationError,
    AuthorizationError,
    PrincipalRevokedError,
    RateLimitError,
    RevokedScope,
    RineApiError,
)
from rine.testing import write_agent_identity

API_URL = "https://rine.network"
TOKEN_URL = f"{API_URL}/oauth/token"
REVOKED_BODY = {"error": "agent_revoked", "detail": "Agent is revoked"}
SSE_BODY = 'event: heartbeat\ndata: {"ok":true}\nid: 7\n\nevent: message\ndata: {"id":"m1"}\n\n'

REFUSALS = [
    pytest.param(httpx.Response(401, json=REVOKED_BODY), PrincipalRevokedError, id="revoked"),
    pytest.param(httpx.Response(401, json={"detail": "bad token"}), AuthenticationError, id="401"),
    pytest.param(httpx.Response(403, json={"detail": "no"}), AuthorizationError, id="403"),
    pytest.param(httpx.Response(422, json=REVOKED_BODY), RineApiError, id="422"),
    pytest.param(httpx.Response(503, text="<html>down</html>"), RineApiError, id="503-not-json"),
]


def _agent_row(agent_id: str) -> dict[str, object]:
    return {
        "id": agent_id,
        "name": "bot",
        "handle": "bot@acme.rine.network",
        "human_oversight": True,
        "incoming_policy": "accept_all",
        "outgoing_policy": "send_all",
        "created_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def stream_router(tmp_config_dir, agent_id):
    """A real identity, a token endpoint (route ``token``) that answers, and the agent list."""
    write_agent_identity(tmp_config_dir, agent_id)
    with respx.mock(assert_all_called=False) as router:
        router.post(TOKEN_URL, name="token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        router.get(f"{API_URL}/agents").mock(
            return_value=httpx.Response(200, json={"items": [_agent_row(agent_id)]})
        )
        yield router


@pytest.fixture
def stream_route(stream_router, agent_id):
    """The agent's stream route, on top of :func:`stream_router`."""
    return stream_router.get(f"{API_URL}/agents/{agent_id}/stream")


def _sync_client(config_dir: str, agent_id: str) -> SyncRineClient:
    return SyncRineClient(config_dir=config_dir, api_url=API_URL, agent=agent_id)


def _async_client(config_dir: str, agent_id: str) -> RineClient:
    return RineClient(config_dir=config_dir, api_url=API_URL, agent=agent_id)


@pytest.mark.parametrize(("response", "expected"), REFUSALS)
def test_sync_stream_when_refused_raises_typed_error(
    stream_route, tmp_config_dir, agent_id, response, expected
):
    stream_route.mock(return_value=response)
    client = _sync_client(tmp_config_dir, agent_id)

    with pytest.raises(expected):
        list(client.stream())

    assert stream_route.call_count == 1


@pytest.mark.parametrize(("response", "expected"), REFUSALS)
async def test_async_stream_when_refused_raises_typed_error(
    stream_route, tmp_config_dir, agent_id, response, expected
):
    stream_route.mock(return_value=response)
    client = _async_client(tmp_config_dir, agent_id)

    with pytest.raises(expected):
        [event async for event in client.stream()]

    assert stream_route.call_count == 1


def test_sync_stream_when_revoked_names_the_scope(stream_route, tmp_config_dir, agent_id):
    stream_route.mock(return_value=httpx.Response(401, json=REVOKED_BODY))
    client = _sync_client(tmp_config_dir, agent_id)

    with pytest.raises(PrincipalRevokedError) as caught:
        list(client.stream())

    assert caught.value.scope is RevokedScope.AGENT


async def test_async_stream_when_rate_limited_carries_retry_after(
    stream_route, tmp_config_dir, agent_id
):
    stream_route.mock(
        return_value=httpx.Response(429, json={"detail": "slow"}, headers={"Retry-After": "7"})
    )
    client = _async_client(tmp_config_dir, agent_id)

    with pytest.raises(RateLimitError) as caught:
        [event async for event in client.stream()]

    assert caught.value.retry_after == 7.0


def test_sync_stream_when_accepted_yields_events(stream_route, tmp_config_dir, agent_id):
    stream_route.mock(return_value=httpx.Response(200, text=SSE_BODY))
    client = _sync_client(tmp_config_dir, agent_id)

    events = list(client.stream())

    assert [(e.event, e.data, e.id) for e in events] == [
        ("heartbeat", '{"ok":true}', "7"),
        ("message", '{"id":"m1"}', None),
    ]


async def test_async_stream_when_accepted_yields_events_and_names_the_agent(
    stream_route, tmp_config_dir, agent_id
):
    stream_route.mock(return_value=httpx.Response(200, text=SSE_BODY))
    client = _async_client(tmp_config_dir, agent_id)

    events = [event async for event in client.stream()]

    assert [(e.event, e.data, e.id) for e in events] == [
        ("heartbeat", '{"ok":true}', "7"),
        ("message", '{"id":"m1"}', None),
    ]
    request = stream_route.calls.last.request
    assert request.headers["X-Rine-Agent"] == agent_id
    assert request.headers["Authorization"] == "Bearer tok"
