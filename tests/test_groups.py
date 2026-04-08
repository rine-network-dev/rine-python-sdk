"""Tests for group operations — SyncGroups and AsyncGroups."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine import RineClient, SyncRineClient
from rine._config import save_credentials
from rine.errors import NotFoundError
from rine.types import GroupRead, JoinResult


AGENT_ID = "00000000-1111-2222-3333-444444444444"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "isolated": False,
    "vote_duration_hours": 72,
    "member_count": 2,
    "created_at": "2024-01-01T00:00:00Z",
}

_AGENT_PAYLOAD = {
    "id": AGENT_ID,
    "name": "test-agent",
    "handle": "test-agent@myorg.rine.network",
    "human_oversight": True,
    "incoming_policy": "accept_all",
    "outgoing_policy": "send_all",
    "created_at": "2024-01-01T00:00:00Z",
}


def _mock_token() -> None:
    respx.post("https://rine.network/oauth/token").mock(
        return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
    )


def _mock_agents() -> None:
    respx.get("https://rine.network/agents").mock(
        return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD]})
    )


class TestSyncGroupsCreate:
    @respx.mock
    def test_create_returns_group_read(self, sync_client):
        _mock_token()
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        result = sync_client.groups.create("test-group")

        assert isinstance(result, GroupRead)
        assert result.name == "test-group"
        assert result.enrollment_policy == "closed"

    @respx.mock
    def test_create_sends_correct_body(self, sync_client):
        _mock_token()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", enrollment="open", visibility="public")

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "my-group"
        assert body["enrollment_policy"] == "open"
        assert body["visibility"] == "public"


class TestSyncGroupsList:
    @respx.mock
    def test_list_returns_group_list(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )

        results = sync_client.groups.list()

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], GroupRead)
        assert results[0].name == "test-group"

    @respx.mock
    def test_list_returns_empty(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        results = sync_client.groups.list()
        assert results == []


class TestSyncGroupsJoin:
    @respx.mock
    def test_join_by_uuid_posts_to_correct_endpoint(self, sync_client):
        _mock_token()
        route = respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json={"status": "joined", "group": _GROUP_PAYLOAD})
        )

        result = sync_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinResult)
        assert result.status == "joined"
        assert route.called

    @respx.mock
    def test_join_by_handle_resolves_first(self, sync_client):
        _mock_token()
        # Mock handle resolution
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json={"status": "pending"})
        )

        result = sync_client.groups.join("#test-group@myorg.rine.network")

        assert isinstance(result, JoinResult)
        assert result.status == "pending"

    @respx.mock
    def test_join_raises_not_found_on_unknown_handle(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.join("nonexistent-group")


class TestAsyncGroupsCreate:
    @respx.mock
    async def test_create_returns_group_read(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        result = await async_client.groups.create("test-group")

        assert isinstance(result, GroupRead)
        assert result.name == "test-group"
        await async_client.close()

    @respx.mock
    async def test_create_sends_correct_body(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create("my-group", enrollment="majority", visibility="public")

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["enrollment_policy"] == "majority"
        assert body["visibility"] == "public"
        await async_client.close()


class TestAsyncGroupsList:
    @respx.mock
    async def test_list_returns_group_list(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )

        results = await async_client.groups.list()

        assert isinstance(results, list)
        assert len(results) == 1
        assert isinstance(results[0], GroupRead)
        await async_client.close()


class TestAsyncGroupsJoin:
    @respx.mock
    async def test_join_by_uuid(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.post(f"https://rine.network/groups/{GROUP_ID}/join").mock(
            return_value=httpx.Response(200, json={"status": "joined", "group": _GROUP_PAYLOAD})
        )

        result = await async_client.groups.join(GROUP_ID)

        assert isinstance(result, JoinResult)
        assert result.status == "joined"
        await async_client.close()

    @respx.mock
    async def test_join_raises_not_found_on_unknown_handle(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.join("ghost-group")
        await async_client.close()
