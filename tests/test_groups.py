"""Tests for group operations — SyncGroups and AsyncGroups."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    generate_agent_keys,
    save_agent_keys,
)
from rine.errors import NotFoundError
from rine.types import GroupRead, JoinRequestRead, JoinResult

AGENT_ID = "00000000-1111-2222-3333-444444444444"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MEMBER_ID = "11111111-2222-3333-4444-555555555555"
REQUEST_ID = "99999999-8888-7777-6666-555555555555"

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


def _mock_groups_serverlike() -> None:
    """Mock ``GET /groups`` the way the real server filters by ``?handle=``.

    The server only matches a *full* ``#name@org`` handle. A bare ``#name`` query
    returns empty (this is the bug the fix works around), while an unfiltered list
    (no ``handle`` param) returns the caller's groups — so a bare name can only be
    resolved by listing and matching the handle's local part.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        handle = request.url.params.get("handle")
        if handle is None:
            return httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        if handle == _GROUP_PAYLOAD["handle"]:
            return httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        return httpx.Response(200, json={"items": []})

    respx.get("https://rine.network/groups").mock(side_effect=_handler)


_INVITE_PAYLOAD = {
    "id": REQUEST_ID,
    "group_id": GROUP_ID,
    "agent_id": AGENT_ID,
    "invited_by": OTHER_AGENT_ID,
    "message": "join us",
    "status": "invited",
    "created_at": "2024-01-01T00:00:00Z",
    "group_handle": "#test-group@myorg.rine.network",
    "group_name": "test-group",
}


def _mock_invitee_keys(tmp_config_dir: str) -> None:
    """Mock the recipient (invitee) key endpoint so ``send`` can seal a DM."""
    keys = generate_agent_keys()
    save_agent_keys(tmp_config_dir, OTHER_AGENT_ID, keys)
    enc_jwk = encryption_public_key_to_jwk(keys.encryption.public_key)
    respx.get(f"https://rine.network/agents/{OTHER_AGENT_ID}/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "agent_id": OTHER_AGENT_ID,
                "encryption_public_key": enc_jwk,
                "signing_public_key": {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
            },
        )
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

        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "my-group"
        assert body["enrollment_policy"] == "open"
        assert body["visibility"] == "public"

    @respx.mock
    def test_create_includes_description_when_set(self, sync_client):
        _mock_token()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group", description="a research group")

        body = json.loads(route.calls[0].request.content)
        assert body["description"] == "a research group"

    @respx.mock
    def test_create_omits_description_when_none(self, sync_client):
        _mock_token()
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.create("my-group")

        body = json.loads(route.calls[0].request.content)
        assert "description" not in body


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

        body = json.loads(route.calls[0].request.content)
        assert body["enrollment_policy"] == "majority"
        assert body["visibility"] == "public"
        await async_client.close()

    @respx.mock
    async def test_create_includes_description_when_set(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create("my-group", description="a research group")

        body = json.loads(route.calls[0].request.content)
        assert body["description"] == "a research group"
        await async_client.close()

    @respx.mock
    async def test_create_omits_description_when_none(self, async_client):
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        route = respx.post("https://rine.network/groups").mock(
            return_value=httpx.Response(201, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.create("my-group")

        body = json.loads(route.calls[0].request.content)
        assert "description" not in body
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


class TestSyncGroupsBareNameResolve:
    """A bare group name (no @, not a UUID) resolves via the caller's group list.

    The server's ``?handle=`` filter only matches a full ``#name@org`` handle, so
    a bare ``test-group`` is resolved by listing the agent's groups and matching the
    handle's local part. Full handles and UUIDs keep their existing fast paths.
    """

    @respx.mock
    def test_invite_with_bare_name_posts_to_resolved_group(self, sync_client):
        _mock_token()
        _mock_groups_serverlike()
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        result = sync_client.groups.invite("test-group", OTHER_AGENT_ID)

        assert result.status == "invited"
        assert invite.called

    @respx.mock
    def test_invite_with_full_handle_uses_handle_query(self, sync_client):
        _mock_token()
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        sync_client.groups.invite("#test-group@myorg.rine.network", OTHER_AGENT_ID)

        # Full handle goes through the ?handle= server filter, not a bare list.
        assert groups.calls[0].request.url.params.get("handle") == (
            "#test-group@myorg.rine.network"
        )
        assert invite.called

    @respx.mock
    def test_invite_with_uuid_skips_group_lookup(self, sync_client):
        _mock_token()
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert not groups.called  # UUID short-circuits — no group lookup
        assert invite.called

    @respx.mock
    def test_remove_member_with_bare_name_deletes_resolved_member(self, sync_client):
        _mock_token()
        _mock_groups_serverlike()
        remove = respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{MEMBER_ID}").mock(
            return_value=httpx.Response(204)
        )

        sync_client.groups.remove_member("test-group", MEMBER_ID)

        assert remove.called

    @respx.mock
    def test_invite_with_unknown_bare_name_raises_not_found(self, sync_client):
        _mock_token()
        _mock_groups_serverlike()

        with pytest.raises(NotFoundError, match="Group not found: ghost"):
            sync_client.groups.invite("ghost", OTHER_AGENT_ID)


class TestAsyncGroupsBareNameResolve:
    """Async parity for bare-name group resolution (see sync counterpart)."""

    @respx.mock
    async def test_invite_with_bare_name_posts_to_resolved_group(self, async_client):
        _mock_token()
        _mock_groups_serverlike()
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        result = await async_client.groups.invite("test-group", OTHER_AGENT_ID)

        assert result.status == "invited"
        assert invite.called
        await async_client.close()

    @respx.mock
    async def test_invite_with_full_handle_uses_handle_query(self, async_client):
        _mock_token()
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        await async_client.groups.invite("#test-group@myorg.rine.network", OTHER_AGENT_ID)

        assert groups.calls[0].request.url.params.get("handle") == (
            "#test-group@myorg.rine.network"
        )
        assert invite.called
        await async_client.close()

    @respx.mock
    async def test_invite_with_uuid_skips_group_lookup(self, async_client):
        _mock_token()
        groups = respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        invite = respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert not groups.called
        assert invite.called
        await async_client.close()

    @respx.mock
    async def test_remove_member_with_bare_name_deletes_resolved_member(self, async_client):
        _mock_token()
        _mock_groups_serverlike()
        remove = respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{MEMBER_ID}").mock(
            return_value=httpx.Response(204)
        )

        await async_client.groups.remove_member("test-group", MEMBER_ID)

        assert remove.called
        await async_client.close()

    @respx.mock
    async def test_invite_with_unknown_bare_name_raises_not_found(self, async_client):
        _mock_token()
        _mock_groups_serverlike()

        with pytest.raises(NotFoundError, match="Group not found: ghost"):
            await async_client.groups.invite("ghost", OTHER_AGENT_ID)
        await async_client.close()


class TestSyncGroupsListInvites:
    """``groups.list_invites()`` lists invites addressed to the calling agent."""

    @respx.mock
    def test_list_invites_returns_join_request_reads(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": [_INVITE_PAYLOAD]})
        )

        results = sync_client.groups.list_invites()

        assert route.called
        assert len(results) == 1
        assert isinstance(results[0], JoinRequestRead)
        assert str(results[0].group_id) == GROUP_ID
        assert results[0].status == "invited"

    @respx.mock
    def test_list_invites_surfaces_enriched_group_fields(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": [_INVITE_PAYLOAD]})
        )

        results = sync_client.groups.list_invites()

        assert results[0].group_handle == "#test-group@myorg.rine.network"
        assert results[0].group_name == "test-group"

    @respx.mock
    def test_list_invites_returns_empty(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        assert sync_client.groups.list_invites() == []

    @respx.mock
    def test_list_invites_sends_agent_header(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        sync_client.groups.list_invites(agent=AGENT_ID)

        assert route.calls[0].request.headers["X-Rine-Agent"] == AGENT_ID


class TestAsyncGroupsListInvites:
    """Async parity for ``groups.list_invites()``."""

    @respx.mock
    async def test_list_invites_returns_join_request_reads(self, async_client):
        _mock_token()
        route = respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": [_INVITE_PAYLOAD]})
        )

        results = await async_client.groups.list_invites()

        assert route.called
        assert len(results) == 1
        assert isinstance(results[0], JoinRequestRead)
        assert results[0].group_handle == "#test-group@myorg.rine.network"
        await async_client.close()

    @respx.mock
    async def test_list_invites_returns_empty(self, async_client):
        _mock_token()
        respx.get("https://rine.network/groups/invites").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        assert await async_client.groups.list_invites() == []
        await async_client.close()


class TestSyncGroupsInviteNotification:
    """``invite()`` best-effort emits a ``rine.v1.group_invite`` DM to the invitee."""

    @respx.mock
    def test_invite_emits_group_invite_notification(self, sync_client, tmp_config_dir):
        _mock_token()
        _mock_agents()
        _mock_invitee_keys(tmp_config_dir)
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        send = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(201, json={"id": REQUEST_ID, "status": "queued"})
        )

        result = sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID, message="join us")

        assert result.status == "invited"
        assert send.called
        body = json.loads(send.calls[0].request.content)
        assert body["type"] == "rine.v1.group_invite"
        assert body["to_agent_id"] == OTHER_AGENT_ID

    @respx.mock
    def test_invite_succeeds_when_notification_fails(self, sync_client, tmp_config_dir):
        _mock_token()
        # No invitee key mock and no /messages mock — the notification send blows up.
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        result = sync_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        # Best-effort: a failed notification must never fail the invite.
        assert result.status == "invited"


class TestAsyncGroupsInviteNotification:
    """Async parity for the best-effort invite notification."""

    @respx.mock
    async def test_invite_emits_group_invite_notification(self, async_client, tmp_config_dir):
        _mock_token()
        _mock_agents()
        _mock_invitee_keys(tmp_config_dir)
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )
        send = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(201, json={"id": REQUEST_ID, "status": "queued"})
        )

        result = await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID, message="join us")

        assert result.status == "invited"
        assert send.called
        body = json.loads(send.calls[0].request.content)
        assert body["type"] == "rine.v1.group_invite"
        assert body["to_agent_id"] == OTHER_AGENT_ID
        await async_client.close()

    @respx.mock
    async def test_invite_succeeds_when_notification_fails(self, async_client, tmp_config_dir):
        _mock_token()
        respx.post(f"https://rine.network/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(200, json={"status": "invited"})
        )

        result = await async_client.groups.invite(GROUP_ID, OTHER_AGENT_ID)

        assert result.status == "invited"
        await async_client.close()
