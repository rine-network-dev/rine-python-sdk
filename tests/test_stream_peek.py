"""``stream()`` peeks by default, and ``peek=False`` restores the old marking stream.

A frame carries no verdict on whether this client can open the message, so the server
must not mark it delivered as it streams it: the caller acknowledges. Every test here
exists in a sync/async pair, because the two clients are independent hand-kept copies.
"""

from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from rine import RineClient, SyncRineClient
from rine._actor import AGENT_HEADER
from rine._constants import PEEK_HEADER

API = "https://rine.network"
FRAME = "event: message\ndata: {}\nid: 7\n\n"


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "test-token", "expires_in": 900})
    )


def _mock_stream(agent_id: str) -> respx.Route:
    return respx.get(f"{API}/agents/{agent_id}/stream").mock(
        return_value=httpx.Response(200, text=FRAME)
    )


class TestStreamPeek:
    @respx.mock
    def test_stream_when_called_bare_then_it_sends_the_peek_header(self, sync_client, agent_id):
        _mock_token()
        route = _mock_stream(agent_id)

        events = list(sync_client.stream(agent=agent_id))

        assert [e.event for e in events] == ["message"]
        headers = route.calls[0].request.headers
        assert headers[PEEK_HEADER] == "1"
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    async def test_stream_when_called_bare_then_it_sends_the_peek_header_async(
        self, async_client, agent_id
    ):
        _mock_token()
        route = _mock_stream(agent_id)

        events = [event async for event in async_client.stream(agent=agent_id)]

        assert [e.event for e in events] == ["message"]
        headers = route.calls[0].request.headers
        assert headers[PEEK_HEADER] == "1"
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    def test_stream_when_peek_is_false_then_it_sends_no_peek_header(self, sync_client, agent_id):
        _mock_token()
        route = _mock_stream(agent_id)

        list(sync_client.stream(agent=agent_id, peek=False))

        headers = route.calls[0].request.headers
        assert PEEK_HEADER not in headers
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    async def test_stream_when_peek_is_false_then_it_sends_no_peek_header_async(
        self, async_client, agent_id
    ):
        _mock_token()
        route = _mock_stream(agent_id)

        _ = [event async for event in async_client.stream(agent=agent_id, peek=False)]

        headers = route.calls[0].request.headers
        assert PEEK_HEADER not in headers
        assert headers[AGENT_HEADER] == agent_id

    @pytest.mark.parametrize("stream", [SyncRineClient.stream, RineClient.stream])
    def test_stream_peek_is_keyword_only_and_defaults_to_true(self, stream):
        """A tripwire on the signature; the wire behaviour is the tests above."""
        peek = inspect.signature(stream).parameters["peek"]

        assert peek.kind is inspect.Parameter.KEYWORD_ONLY
        assert peek.default is True
