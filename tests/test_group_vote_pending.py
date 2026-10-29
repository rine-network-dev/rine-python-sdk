"""A vote that leaves the request pending admits nobody, so the async client mints no leaf."""

from __future__ import annotations

import httpx
import respx

from tests.vote_world import (
    _APPROVED,
    _MLS_GROUP,
    GROUP_ID,
    REQUEST_ID,
    _mock_server,
)


@respx.mock
async def test_vote_when_an_async_request_is_still_pending_then_nobody_is_seated(
    async_client,
    agent_id,
    seat_calls,
):
    """The async client admits nobody below the threshold either, so it mints no leaf."""
    pending = {**_APPROVED, "status": "pending"}
    _mock_server(agent_id, _MLS_GROUP, httpx.Response(200, json=pending))

    result = await async_client.groups.vote(GROUP_ID, REQUEST_ID, "approve")

    assert result.status == "pending"
    assert seat_calls == []
    assert result.mls_seated is None
    await async_client.close()
