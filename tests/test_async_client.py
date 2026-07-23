"""Tests for RineClient — async client public API."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine import RineClient
from rine._config import save_credentials
from rine._constants import MessageType
from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    generate_agent_keys,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states
from rine.errors import (
    AuthorizationError,
    ConfigError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from rine.types import (
    AgentCardRead,
    AgentProfile,
    AgentRead,
    AgentSummary,
    ConversationParticipant,
    ConversationRead,
    CursorPage,
    ErasureResult,
    GroupRead,
    JoinRequestRead,
    OrgQuotas,
    OrgRead,
    PollTokenResponse,
    VoteResponse,
    WebhookCreated,
    WebhookJobRead,
    WebhookJobSummary,
    WebhookRead,
    WhoAmI,
)

AGENT_ID = "00000000-1111-2222-3333-444444444444"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MEMBER_AGENT_ID = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"

_AGENT_PAYLOAD = {
    "id": AGENT_ID,
    "name": "test-agent",
    "handle": "test-agent@myorg.rine.network",
    "human_oversight": True,
    "incoming_policy": "accept_all",
    "outgoing_policy": "send_all",
    "created_at": "2024-01-01T00:00:00Z",
}

_ORG_PAYLOAD = {
    "id": "11111111-2222-3333-4444-555555555555",
    "name": "My Org",
    "slug": "myorg",
    "contact_email": "admin@example.com",
    "country_code": "DE",
    "trust_tier": 1,
    "agent_count": 1,
    "created_at": "2024-01-01T00:00:00Z",
}

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}

_MESSAGE_PAYLOAD = {
    "id": "cccccccc-dddd-eeee-ffff-000000000001",
    "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
    "from_agent_id": AGENT_ID,
    "to_agent_id": OTHER_AGENT_ID,
    "type": MessageType.TASK_REQUEST,
    "encrypted_payload": "dGVzdA==",
    "encryption_version": "hpke-v1",
    "sender_signing_kid": f"rine:{AGENT_ID}",
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


class TestWhoami:
    @respx.mock
    async def test_whoami_returns_org_and_agents(self, async_client):
        _mock_token()
        _mock_agents()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )

        result = await async_client.whoami()

        assert isinstance(result, WhoAmI)
        assert result.org.name == "My Org"
        assert len(result.agents) == 1
        assert result.agents[0].name == "test-agent"
        assert result.trust_tier == 1
        await async_client.close()

    @respx.mock
    async def test_whoami_raises_when_no_agents(self, async_client):
        _mock_token()
        respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(ConfigError, match="No agents found"):
            await async_client.whoami()
        await async_client.close()


class TestDiscover:
    @respx.mock
    async def test_discover_returns_cursor_page(self, async_client):
        respx.get("https://rine.network/directory/agents").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": OTHER_AGENT_ID,
                            "name": "Other Agent",
                            "handle": "other@org.rine.network",
                            "verified": False,
                        }
                    ],
                    "total": 1,
                    "next_cursor": None,
                },
            )
        )

        result = await async_client.discover()

        assert isinstance(result, CursorPage)
        assert len(result.items) == 1
        assert isinstance(result.items[0], AgentSummary)
        assert result.items[0].name == "Other Agent"
        await async_client.close()

    @respx.mock
    async def test_discover_unauthenticated(self, async_client):
        """discover() should not include Authorization header."""
        route = respx.get("https://rine.network/directory/agents").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        await async_client.discover()

        assert route.called
        request = route.calls[0].request
        assert "Authorization" not in request.headers
        await async_client.close()


class TestInspect:
    @respx.mock
    async def test_inspect_with_a2a_envelope(self, async_client):
        """inspect() should unwrap the A2A agent card envelope."""
        respx.get(f"https://rine.network/directory/agents/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "card": {
                        "name": "Legal Bot",
                        "description": "An AI legal assistant",
                        "rine": {
                            "agent_id": OTHER_AGENT_ID,
                            "handle": "legal@acme.rine.network",
                            "category": "legal",
                            "verified": True,
                            "human_oversight": False,
                            "trust_tier": 2,
                        },
                    },
                    "directory_metadata": {"registered_at": "2024-01-01T00:00:00Z"},
                },
            )
        )

        result = await async_client.inspect(OTHER_AGENT_ID)

        assert isinstance(result, AgentProfile)
        assert result.name == "Legal Bot"
        assert result.handle == "legal@acme.rine.network"
        assert result.category == "legal"
        assert result.verified is True
        assert result.trust_tier == 2
        await async_client.close()

    @respx.mock
    async def test_inspect_with_raw_response(self, async_client):
        """inspect() falls through to direct parse when no 'card' key."""
        respx.get(f"https://rine.network/directory/agents/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": OTHER_AGENT_ID,
                    "name": "Raw Agent",
                    "handle": "raw@org.rine.network",
                    "verified": False,
                    "human_oversight": True,
                },
            )
        )

        result = await async_client.inspect(OTHER_AGENT_ID)

        assert isinstance(result, AgentProfile)
        assert result.name == "Raw Agent"
        await async_client.close()


class TestPoll:
    @respx.mock
    async def test_poll_returns_count(self, tmp_config_dir, saved_agent_keys, agent_id):
        save_credentials(
            tmp_config_dir,
            {
                "default": {
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "poll_url": "https://rine.network/poll/async-token",
                }
            },
        )

        respx.get("https://rine.network/poll/async-token").mock(
            return_value=httpx.Response(200, json={"count": 3})
        )

        client = RineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
        count = await client.poll()
        await client.close()

        assert count == 3

    async def test_poll_raises_when_no_poll_url(self, async_client):
        with pytest.raises(ConfigError, match="No poll URL"):
            await async_client.poll()
        await async_client.close()


class TestWithOptions:
    async def test_with_options_returns_new_client(self, async_client):
        new_client = async_client.with_options(timeout=5.0)

        assert new_client is not async_client
        assert isinstance(new_client, RineClient)
        await new_client.close()
        await async_client.close()

    async def test_with_options_overrides_timeout(self, async_client):
        new_client = async_client.with_options(timeout=10.0)

        assert new_client._timeout == 10.0
        await new_client.close()
        await async_client.close()

    async def test_with_options_overrides_agent(self, async_client):
        new_client = async_client.with_options(agent="bot-2")

        assert new_client._agent == "bot-2"
        await new_client.close()
        await async_client.close()

    async def test_with_options_inherits_config_dir(self, async_client):
        new_client = async_client.with_options(timeout=1.0)

        assert new_client._config_dir == async_client._config_dir
        await new_client.close()
        await async_client.close()


class TestInbox:
    @respx.mock
    async def test_inbox_returns_cursor_page_empty(self, async_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0, "next_cursor": None})
        )

        from rine.types import CursorPage

        result = await async_client.inbox()

        assert isinstance(result, CursorPage)
        assert result.items == []
        assert result.total == 0
        await async_client.close()

    @respx.mock
    async def test_inbox_passes_limit_param(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        await async_client.inbox(limit=20)

        assert route.called
        assert b"limit=20" in route.calls[0].request.url.query
        await async_client.close()


class TestSendAndWait:
    async def test_send_and_wait_rejects_group_handles(self, async_client):
        """Group handles raise the typed UnsupportedTargetError (sync endpoint is 1:1 only)."""
        from rine.errors import UnsupportedTargetError

        with pytest.raises(UnsupportedTargetError, match="group handles"):
            await async_client.send_and_wait(
                "#team@acme.rine.network",
                {"task": "nope"},
            )
        await async_client.close()


class TestResolveGroupAsync:
    @respx.mock
    async def test_resolve_group_raises_not_found_on_empty_result(self, async_client):
        """_resolve_group_async raises NotFoundError when group not found."""
        _mock_token()
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(NotFoundError, match="Group not found"):
            await async_client._resolve_group_async("no-such-group")
        await async_client.close()

    @respx.mock
    async def test_resolve_group_returns_id_for_uuid(self, async_client):
        """_resolve_group_async passes through UUIDs without network call."""
        group_uuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

        result = await async_client._resolve_group_async(group_uuid)

        assert result == group_uuid
        await async_client.close()


class TestContextManager:
    @respx.mock
    async def test_async_client_async_context_manager(self, tmp_config_dir, saved_agent_keys):
        save_credentials(
            tmp_config_dir, {"default": {"client_id": "cid", "client_secret": "csecret"}}
        )

        async with RineClient(config_dir=tmp_config_dir, api_url="https://rine.network") as client:
            assert client is not None
        # Verify closed without error


# --- P0: Agent lifecycle ---


class TestUpdateAgent:
    @respx.mock
    async def test_update_agent_all_fields(self, async_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_AGENT_PAYLOAD,
                    "name": "renamed",
                    "human_oversight": False,
                    "incoming_policy": "groups_only",
                    "outgoing_policy": "groups_only",
                    "warnings": ["groups_only policy will block all messages"],
                },
            )
        )

        result = await async_client.update_agent(
            AGENT_ID,
            name="renamed",
            human_oversight=False,
            incoming_policy="groups_only",
            outgoing_policy="groups_only",
        )

        assert isinstance(result, AgentRead)
        assert result.name == "renamed"
        assert result.human_oversight is False
        assert result.incoming_policy == "groups_only"
        assert result.outgoing_policy == "groups_only"
        assert result.warnings is not None
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {
            "name": "renamed",
            "human_oversight": False,
            "incoming_policy": "groups_only",
            "outgoing_policy": "groups_only",
        }
        await async_client.close()

    @respx.mock
    async def test_update_agent_partial_sends_only_provided_fields(self, async_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        await async_client.update_agent(AGENT_ID, name="new-name")

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"name": "new-name"}
        await async_client.close()

    @respx.mock
    async def test_update_agent_no_args_sends_empty_body(self, async_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        await async_client.update_agent(AGENT_ID)

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {}
        await async_client.close()

    @respx.mock
    async def test_update_agent_when_revoked_raises_conflict(self, async_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(409, json={"detail": "Agent is already revoked"})
        )

        with pytest.raises(ConflictError, match="already revoked"):
            await async_client.update_agent(AGENT_ID, name="x")
        await async_client.close()

    @respx.mock
    async def test_update_agent_rename_after_handle_raises_conflict(self, async_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(
                409,
                json={"detail": "Cannot rename agent after handle assignment"},
            )
        )

        with pytest.raises(ConflictError, match="Cannot rename"):
            await async_client.update_agent(AGENT_ID, name="x")
        await async_client.close()

    @respx.mock
    async def test_update_agent_when_not_found_raises_not_found(self, async_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.update_agent(AGENT_ID, name="x")
        await async_client.close()

    @respx.mock
    async def test_update_agent_blank_name_raises_validation(self, async_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(422, json={"detail": "Name must not be blank"})
        )

        with pytest.raises(ValidationError):
            await async_client.update_agent(AGENT_ID, name="")
        await async_client.close()


class TestRevokeAgent:
    @respx.mock
    async def test_revoke_agent_returns_agent_with_revoked_at(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_AGENT_PAYLOAD,
                    "revoked_at": "2024-06-01T00:00:00Z",
                },
            )
        )

        result = await async_client.revoke_agent(AGENT_ID)

        assert isinstance(result, AgentRead)
        assert result.revoked_at is not None
        await async_client.close()

    @respx.mock
    async def test_revoke_agent_already_revoked_raises_conflict(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(409, json={"detail": "Agent is already revoked"})
        )

        with pytest.raises(ConflictError, match="already revoked"):
            await async_client.revoke_agent(AGENT_ID)
        await async_client.close()

    @respx.mock
    async def test_revoke_agent_when_not_found_raises_not_found(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.revoke_agent(AGENT_ID)
        await async_client.close()


# --- P0: Org lifecycle ---


class TestUpdateOrg:
    @respx.mock
    async def test_update_org_success(self, async_client):
        _mock_token()
        route = respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_ORG_PAYLOAD,
                    "name": "New Name",
                    "contact_email": "new@example.com",
                },
            )
        )

        result = await async_client.update_org(name="New Name", contact_email="new@example.com")

        assert isinstance(result, OrgRead)
        assert result.name == "New Name"
        assert result.contact_email == "new@example.com"
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"name": "New Name", "contact_email": "new@example.com"}
        await async_client.close()

    @respx.mock
    async def test_update_org_partial_sends_only_provided_fields(self, async_client):
        _mock_token()
        route = respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )

        await async_client.update_org(country_code="IT")

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"country_code": "IT"}
        await async_client.close()

    @respx.mock
    async def test_update_org_no_args_sends_empty_body(self, async_client):
        _mock_token()
        route = respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )

        await async_client.update_org()

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {}
        await async_client.close()

    @respx.mock
    async def test_update_org_slug_immutable_raises_conflict(self, async_client):
        _mock_token()
        respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(409, json={"detail": "Slug is immutable once set"})
        )

        with pytest.raises(ConflictError, match="immutable"):
            await async_client.update_org(slug="new-slug")
        await async_client.close()

    @respx.mock
    async def test_update_org_invalid_email_raises_validation(self, async_client):
        _mock_token()
        respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(422, json={"detail": "Invalid email format"})
        )

        with pytest.raises(ValidationError):
            await async_client.update_org(contact_email="not-an-email")
        await async_client.close()


# --- P0: GDPR compliance ---


class TestEraseOrg:
    @respx.mock
    async def test_erase_org_success(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.delete(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "org_id": _ORG_PAYLOAD["id"],
                    "erased_at": "2024-06-01T00:00:00Z",
                    "messages_deleted": 42,
                    "agents_deleted": 3,
                    "conversations_deleted": 10,
                    "groups_deleted": 1,
                },
            )
        )

        result = await async_client.erase_org(confirm=True)

        assert isinstance(result, ErasureResult)
        assert str(result.org_id) == _ORG_PAYLOAD["id"]
        assert result.messages_deleted == 42
        assert result.agents_deleted == 3
        assert result.conversations_deleted == 10
        assert result.groups_deleted == 1
        await async_client.close()

    async def test_erase_org_without_confirm_raises_value_error(self, async_client):
        with pytest.raises(ValueError, match="confirm=True"):
            await async_client.erase_org()
        await async_client.close()

    @respx.mock
    async def test_erase_org_forbidden_raises_authorization(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.delete(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}").mock(
            return_value=httpx.Response(403, json={"detail": "Permission denied"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.erase_org(confirm=True)
        await async_client.close()


class TestExportOrg:
    @respx.mock
    async def test_export_org_success(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        ndjson_body = (
            '{"type": "manifest", "org_id": "11111111-2222-3333-4444-555555555555"}\n'
            '{"type": "org", "name": "My Org"}\n'
            '{"type": "agent", "name": "test-agent"}\n'
        )
        respx.get(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}/export").mock(
            return_value=httpx.Response(
                200,
                content=ndjson_body.encode(),
                headers={"content-type": "application/x-ndjson"},
            )
        )

        result = await async_client.export_org()

        assert len(result) == 3
        assert result[0]["type"] == "manifest"
        assert result[1]["type"] == "org"
        assert result[2]["type"] == "agent"
        await async_client.close()

    @respx.mock
    async def test_export_org_empty_response(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.get(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}/export").mock(
            return_value=httpx.Response(200, content=b"", headers={})
        )

        result = await async_client.export_org()
        assert result == []
        await async_client.close()

    @respx.mock
    async def test_export_org_rate_limited_raises_rate_limit(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.get(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}/export").mock(
            return_value=httpx.Response(
                429,
                json={"detail": "Export rate limit: one export per hour"},
                headers={"Retry-After": "3200"},
            )
        )

        with pytest.raises(RateLimitError) as exc_info:
            await async_client.export_org()
        assert exc_info.value.retry_after == 3200.0
        await async_client.close()

    @respx.mock
    async def test_export_org_forbidden_raises_authorization(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.get(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}/export").mock(
            return_value=httpx.Response(403, json={"detail": "Permission denied"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.export_org()
        await async_client.close()


# --- P1: Conversations ---

CONVERSATION_ID = "dddddddd-eeee-ffff-0000-111111111111"

_CONVERSATION_PAYLOAD = {
    "id": CONVERSATION_ID,
    "status": "open",
    "created_at": "2024-01-01T00:00:00Z",
    "parent_conversation_id": None,
    "metadata": {},
}

_PARTICIPANT_PAYLOAD = {
    "id": "eeeeeeee-ffff-0000-1111-222222222222",
    "conversation_id": CONVERSATION_ID,
    "agent_id": AGENT_ID,
    "role": "initiator",
    "joined_at": "2024-01-01T00:00:00Z",
}

WEBHOOK_ID = "ffffffff-0000-1111-2222-333333333333"

_WEBHOOK_PAYLOAD = {
    "id": WEBHOOK_ID,
    "agent_id": AGENT_ID,
    "url": "https://example.com/webhook",
    "active": True,
    "created_at": "2024-01-01T00:00:00Z",
}

_AGENT_CARD_PAYLOAD = {
    "id": "11111111-aaaa-bbbb-cccc-dddddddddddd",
    "agent_id": AGENT_ID,
    "name": "Test Card",
    "description": "A test agent card",
    "version": "1.0",
    "is_public": True,
    "skills": [{"id": "s1", "name": "summarize"}],
    "rine": {"handle": "test@myorg.rine.network", "verified": True},
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-06-01T00:00:00Z",
}


class TestUpdateConversationStatus:
    @respx.mock
    async def test_update_conversation_status_success(self, async_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/conversations/{CONVERSATION_ID}/status").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_CONVERSATION_PAYLOAD,
                    "status": "completed",
                },
            )
        )

        result = await async_client.update_conversation_status(CONVERSATION_ID, "completed")

        assert isinstance(result, ConversationRead)
        assert result.status == "completed"
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"status": "completed"}
        await async_client.close()

    @respx.mock
    async def test_update_conversation_status_invalid_transition_raises_conflict(
        self, async_client
    ):
        _mock_token()
        respx.patch(f"https://rine.network/conversations/{CONVERSATION_ID}/status").mock(
            return_value=httpx.Response(409, json={"detail": "Invalid state transition"})
        )

        with pytest.raises(ConflictError, match="Invalid state transition"):
            await async_client.update_conversation_status(CONVERSATION_ID, "open")
        await async_client.close()

    @respx.mock
    async def test_update_conversation_status_not_found(self, async_client):
        _mock_token()
        respx.patch(f"https://rine.network/conversations/{CONVERSATION_ID}/status").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.update_conversation_status(CONVERSATION_ID, "completed")
        await async_client.close()


class TestGetConversation:
    @respx.mock
    async def test_get_conversation_success(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}").mock(
            return_value=httpx.Response(200, json=_CONVERSATION_PAYLOAD)
        )

        result = await async_client.get_conversation(CONVERSATION_ID)

        assert isinstance(result, ConversationRead)
        assert result.status == "open"
        assert str(result.id) == CONVERSATION_ID
        await async_client.close()

    @respx.mock
    async def test_get_conversation_not_found(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.get_conversation(CONVERSATION_ID)
        await async_client.close()


class TestGetConversationParticipants:
    @respx.mock
    async def test_get_conversation_participants_success(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}/participants").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        _PARTICIPANT_PAYLOAD,
                        {**_PARTICIPANT_PAYLOAD, "role": "responder", "agent_id": OTHER_AGENT_ID},
                    ],
                },
            )
        )

        result = await async_client.get_conversation_participants(CONVERSATION_ID)

        assert len(result) == 2
        assert isinstance(result[0], ConversationParticipant)
        assert result[0].role == "initiator"
        assert result[1].role == "responder"
        await async_client.close()

    @respx.mock
    async def test_get_conversation_participants_not_found(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}/participants").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.get_conversation_participants(CONVERSATION_ID)
        await async_client.close()


# --- P1: Agent Cards ---


class TestSetAgentCard:
    @respx.mock
    async def test_set_agent_card_full(self, async_client):
        _mock_token()
        route = respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(200, json=_AGENT_CARD_PAYLOAD)
        )

        result = await async_client.set_agent_card(
            AGENT_ID,
            name="Test Card",
            description="A test agent card",
            version="1.0",
            is_public=True,
            skills=[{"id": "s1", "name": "summarize"}],
            categories=["legal"],
            languages=["en"],
            pricing_model="free",
        )

        assert isinstance(result, AgentCardRead)
        assert result.name == "Test Card"
        assert result.is_public is True
        parsed = json.loads(route.calls[0].request.content)
        assert parsed["name"] == "Test Card"
        assert parsed["skills"] == [{"id": "s1", "name": "summarize"}]
        assert parsed["rine"]["categories"] == ["legal"]
        assert parsed["rine"]["pricing_model"] == "free"
        await async_client.close()

    @respx.mock
    async def test_set_agent_card_minimal(self, async_client):
        _mock_token()
        route = respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(200, json=_AGENT_CARD_PAYLOAD)
        )

        await async_client.set_agent_card(AGENT_ID, name="Test Card", description="desc")

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"name": "Test Card", "description": "desc"}
        await async_client.close()

    @respx.mock
    async def test_set_agent_card_no_signing_key_raises_conflict(self, async_client):
        _mock_token()
        respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(409, json={"detail": "Agent has no signing key"})
        )

        with pytest.raises(ConflictError, match="signing key"):
            await async_client.set_agent_card(AGENT_ID, name="x", description="d")
        await async_client.close()

    @respx.mock
    async def test_set_agent_card_not_found(self, async_client):
        _mock_token()
        respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.set_agent_card(AGENT_ID, name="x", description="d")
        await async_client.close()


class TestGetAgentCard:
    @respx.mock
    async def test_get_agent_card_success(self, async_client):
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(200, json=_AGENT_CARD_PAYLOAD)
        )

        result = await async_client.get_agent_card(AGENT_ID)

        assert isinstance(result, AgentCardRead)
        assert result.name == "Test Card"
        assert result.is_public is True
        assert "Authorization" not in route.calls[0].request.headers
        await async_client.close()

    @respx.mock
    async def test_get_agent_card_not_found(self, async_client):
        respx.get(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.get_agent_card(AGENT_ID)
        await async_client.close()


class TestDeleteAgentCard:
    @respx.mock
    async def test_delete_agent_card_success(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(204)
        )

        result = await async_client.delete_agent_card(AGENT_ID)
        assert result is None
        await async_client.close()

    @respx.mock
    async def test_delete_agent_card_not_found(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.delete_agent_card(AGENT_ID)
        await async_client.close()


# --- P1: Webhooks ---


class TestWebhookCreate:
    @respx.mock
    async def test_webhook_create_success(self, async_client):
        _mock_token()
        respx.post("https://rine.network/webhooks").mock(
            return_value=httpx.Response(
                201,
                json={
                    **_WEBHOOK_PAYLOAD,
                    "secret": "whsec_test123",
                },
            )
        )

        result = await async_client.webhooks.create(AGENT_ID, "https://example.com/webhook")

        assert isinstance(result, WebhookCreated)
        assert result.secret == "whsec_test123"
        assert result.url == "https://example.com/webhook"
        await async_client.close()

    @respx.mock
    async def test_webhook_create_with_events(self, async_client):
        _mock_token()
        route = respx.post("https://rine.network/webhooks").mock(
            return_value=httpx.Response(
                201,
                json={
                    **_WEBHOOK_PAYLOAD,
                    "secret": "whsec_test123",
                },
            )
        )

        await async_client.webhooks.create(
            AGENT_ID,
            "https://example.com/webhook",
            events=["message.received"],
        )

        parsed = json.loads(route.calls[0].request.content)
        assert parsed["events"] == ["message.received"]
        await async_client.close()

    @respx.mock
    async def test_webhook_create_duplicate_raises_conflict(self, async_client):
        _mock_token()
        respx.post("https://rine.network/webhooks").mock(
            return_value=httpx.Response(409, json={"detail": "Duplicate webhook URL"})
        )

        with pytest.raises(ConflictError, match="Duplicate"):
            await async_client.webhooks.create(AGENT_ID, "https://example.com/webhook")
        await async_client.close()

    @respx.mock
    async def test_webhook_create_quota_exceeded_raises_authorization(self, async_client):
        _mock_token()
        respx.post("https://rine.network/webhooks").mock(
            return_value=httpx.Response(403, json={"detail": "Webhook quota exceeded"})
        )

        with pytest.raises(AuthorizationError, match="quota"):
            await async_client.webhooks.create(AGENT_ID, "https://example.com/webhook")
        await async_client.close()


class TestWebhookList:
    @respx.mock
    async def test_webhook_list_all(self, async_client):
        _mock_token()
        respx.get("https://rine.network/webhooks").mock(
            return_value=httpx.Response(200, json={"items": [_WEBHOOK_PAYLOAD]})
        )

        result = await async_client.webhooks.list()

        assert len(result) == 1
        assert isinstance(result[0], WebhookRead)
        assert result[0].url == "https://example.com/webhook"
        await async_client.close()

    @respx.mock
    async def test_webhook_list_by_agent(self, async_client):
        _mock_token()
        route = respx.get("https://rine.network/webhooks").mock(
            return_value=httpx.Response(200, json={"items": [_WEBHOOK_PAYLOAD]})
        )

        await async_client.webhooks.list(agent_id=AGENT_ID)

        request = route.calls[0].request
        assert f"agent_id={AGENT_ID}".encode() in request.url.query
        await async_client.close()

    @respx.mock
    async def test_webhook_list_include_inactive(self, async_client):
        _mock_token()
        route = respx.get("https://rine.network/webhooks").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        await async_client.webhooks.list(include_inactive=True)

        request = route.calls[0].request
        assert b"include_inactive=true" in request.url.query
        await async_client.close()


class TestWebhookUpdate:
    @respx.mock
    async def test_webhook_update_deactivate(self, async_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(200, json={**_WEBHOOK_PAYLOAD, "active": False})
        )

        result = await async_client.webhooks.update(WEBHOOK_ID, active=False)

        assert isinstance(result, WebhookRead)
        assert result.active is False
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"active": False}
        await async_client.close()

    @respx.mock
    async def test_webhook_update_not_found(self, async_client):
        _mock_token()
        respx.patch(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.webhooks.update(WEBHOOK_ID, active=False)
        await async_client.close()


class TestWebhookDelete:
    @respx.mock
    async def test_webhook_delete_success(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(204)
        )

        result = await async_client.webhooks.delete(WEBHOOK_ID)
        assert result is None
        await async_client.close()

    @respx.mock
    async def test_webhook_delete_not_found(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.webhooks.delete(WEBHOOK_ID)
        await async_client.close()


# --- P1: Key Rotation ---


class TestRotateKeys:
    @respx.mock
    async def test_rotate_keys_success(self, async_client):
        _mock_token()
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    **_AGENT_PAYLOAD,
                    "verification_words": "alpha bravo charlie",
                },
            )
        )

        result = await async_client.rotate_keys(AGENT_ID)

        assert isinstance(result, AgentRead)
        assert result.verification_words == "alpha bravo charlie"
        parsed = json.loads(route.calls[0].request.content)
        assert "signing_public_key" in parsed
        assert "encryption_public_key" in parsed
        assert parsed["signing_public_key"]["kty"] == "OKP"
        assert parsed["signing_public_key"]["crv"] == "Ed25519"
        assert parsed["encryption_public_key"]["crv"] == "X25519"
        await async_client.close()

    @respx.mock
    async def test_rotate_keys_saves_to_disk(self, async_client, tmp_config_dir):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        assert async_client._config_dir == tmp_config_dir  # guard against fixture drift
        await async_client.rotate_keys(AGENT_ID)

        import os

        key_dir = os.path.join(tmp_config_dir, "keys", AGENT_ID)
        assert os.path.isfile(os.path.join(key_dir, "signing.key"))
        assert os.path.isfile(os.path.join(key_dir, "encryption.key"))
        await async_client.close()

    @respx.mock
    async def test_rotate_keys_revoked_raises_conflict(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(409, json={"detail": "Agent is revoked"})
        )

        with pytest.raises(ConflictError, match="revoked"):
            await async_client.rotate_keys(AGENT_ID)
        await async_client.close()

    @respx.mock
    async def test_rotate_keys_not_found(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.rotate_keys(AGENT_ID)
        await async_client.close()


# --- P1: Org Quotas ---


class TestGetQuotas:
    @respx.mock
    async def test_get_quotas_success(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org/quotas").mock(
            return_value=httpx.Response(
                200,
                json={
                    "tier": 1,
                    "quotas": {
                        "agents": {"limit": 10, "used": 3},
                        "webhooks": {"limit": 5, "used": 1},
                    },
                },
            )
        )

        result = await async_client.get_quotas()

        assert isinstance(result, OrgQuotas)
        assert result.tier == 1
        assert result.quotas["agents"].limit == 10
        assert result.quotas["agents"].used == 3
        await async_client.close()

    @respx.mock
    async def test_get_quotas_parses_unlimited(self, async_client):
        _mock_token()
        respx.get("https://rine.network/org/quotas").mock(
            return_value=httpx.Response(
                200,
                json={
                    "tier": 3,
                    "quotas": {
                        "agents": {"limit": None, "used": 50},
                    },
                },
            )
        )

        result = await async_client.get_quotas()

        assert result.tier == 3
        assert result.quotas["agents"].limit is None
        assert result.quotas["agents"].used == 50
        await async_client.close()


# --- P2: Power User & Advanced Methods ---

GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "description": "A test group",
    "enrollment_policy": "closed",
    "visibility": "private",
    "isolated": False,
    "vote_duration_hours": 72,
    "member_count": 3,
    "created_at": "2024-01-01T00:00:00Z",
}

_JOIN_REQUEST_PAYLOAD = {
    "id": "dddddddd-eeee-ffff-0000-111111111111",
    "group_id": GROUP_ID,
    "agent_id": OTHER_AGENT_ID,
    "invited_by": None,
    "message": "Please let me in",
    "status": "pending",
    "expires_at": "2024-01-08T00:00:00Z",
    "created_at": "2024-01-01T00:00:00Z",
    "resolved_at": None,
    "your_vote": None,
}

_VOTE_RESPONSE_PAYLOAD = {
    "request_id": "dddddddd-eeee-ffff-0000-111111111111",
    "your_vote": "approve",
    "status": "approved",
}

_WEBHOOK_JOB_PAYLOAD = {
    "id": "eeeeeeee-ffff-0000-1111-222222222222",
    "webhook_id": "ffffffff-0000-1111-2222-333333333333",
    "message_id": "cccccccc-dddd-eeee-ffff-000000000001",
    "status": "delivered",
    "attempts": 1,
    "max_attempts": 5,
    "last_error": None,
    "created_at": "2024-01-01T00:00:00Z",
    "delivered_at": "2024-01-01T00:01:00Z",
    "next_attempt_at": None,
}

WEBHOOK_ID = "ffffffff-0000-1111-2222-333333333333"


class TestGroupUpdate:
    @respx.mock
    async def test_group_update_full(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        result = await async_client.groups.update(
            GROUP_ID,
            description="Updated",
            enrollment="open",
            visibility="public",
            vote_duration_hours=24,
        )

        assert isinstance(result, GroupRead)
        assert result.name == "test-group"
        body = json.loads(route.calls[0].request.content)
        assert body == {
            "description": "Updated",
            "enrollment_policy": "open",
            "visibility": "public",
            "vote_duration_hours": 24,
        }
        await async_client.close()

    @respx.mock
    async def test_group_update_single_field(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.update(GROUP_ID, description="Only this")

        body = json.loads(route.calls[0].request.content)
        assert body == {"description": "Only this"}
        await async_client.close()

    @respx.mock
    async def test_group_update_not_found(self, async_client):
        _mock_token()
        _mock_agents()
        respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.update(GROUP_ID, description="x")
        await async_client.close()

    @respx.mock
    async def test_group_update_not_admin(self, async_client):
        _mock_token()
        _mock_agents()
        respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(403, json={"detail": "Not admin"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.groups.update(GROUP_ID, description="x")
        await async_client.close()


class TestGroupDelete:
    @respx.mock
    async def test_group_delete_success(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )

        result = await async_client.groups.delete(GROUP_ID)

        assert result is None
        await async_client.close()

    @respx.mock
    async def test_group_delete_not_found(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.delete(GROUP_ID)
        await async_client.close()

    @respx.mock
    async def test_group_delete_not_admin(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(403, json={"detail": "Not admin"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.groups.delete(GROUP_ID)
        await async_client.close()


class TestGroupRemoveMember:
    @respx.mock
    async def test_group_remove_member_success(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(204)
        )

        result = await async_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)

        assert result is None
        await async_client.close()

    @respx.mock
    async def test_group_remove_member_not_found(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)
        await async_client.close()

    @respx.mock
    async def test_group_remove_member_not_admin(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(403, json={"detail": "Not admin"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)
        await async_client.close()

    @respx.mock
    async def test_group_remove_member_last_admin(self, async_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{AGENT_ID}").mock(
            return_value=httpx.Response(422, json={"detail": "Last admin"})
        )

        with pytest.raises(ValidationError):
            await async_client.groups.remove_member(GROUP_ID, AGENT_ID)
        await async_client.close()


class TestGroupVoting:
    @respx.mock
    async def test_group_list_requests_success(self, async_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(200, json={"items": [_JOIN_REQUEST_PAYLOAD], "total": 1})
        )

        result = await async_client.groups.list_requests(GROUP_ID)

        assert len(result) == 1
        assert isinstance(result[0], JoinRequestRead)
        assert result[0].status == "pending"
        await async_client.close()

    @respx.mock
    async def test_group_list_requests_empty(self, async_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        result = await async_client.groups.list_requests(GROUP_ID)

        assert result == []
        await async_client.close()

    @respx.mock
    async def test_group_list_requests_not_found(self, async_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.list_requests(GROUP_ID)
        await async_client.close()

    @respx.mock
    async def test_group_vote_approve_success(self, async_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(200, json=_VOTE_RESPONSE_PAYLOAD)
        )

        result = await async_client.groups.vote(GROUP_ID, req_id, "approve")

        assert isinstance(result, VoteResponse)
        assert result.your_vote == "approve"
        assert result.status == "approved"
        await async_client.close()

    @respx.mock
    async def test_group_vote_deny_success(self, async_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        deny_payload = {**_VOTE_RESPONSE_PAYLOAD, "your_vote": "deny", "status": "pending"}
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(200, json=deny_payload)
        )

        result = await async_client.groups.vote(GROUP_ID, req_id, "deny")

        assert result.your_vote == "deny"
        await async_client.close()

    @respx.mock
    async def test_group_vote_already_voted(self, async_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(409, json={"detail": "Already voted"})
        )

        with pytest.raises(ConflictError):
            await async_client.groups.vote(GROUP_ID, req_id, "approve")
        await async_client.close()

    @respx.mock
    async def test_group_vote_not_pending(self, async_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(422, json={"detail": "Request not pending"})
        )

        with pytest.raises(ValidationError):
            await async_client.groups.vote(GROUP_ID, req_id, "approve")
        await async_client.close()

    @respx.mock
    async def test_group_vote_not_found(self, async_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.vote(GROUP_ID, req_id, "approve")
        await async_client.close()

    @respx.mock
    async def test_group_list_requests_not_member(self, async_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(403, json={"detail": "Not a member"})
        )

        with pytest.raises(AuthorizationError):
            await async_client.groups.list_requests(GROUP_ID)
        await async_client.close()

    @respx.mock
    async def test_group_update_sends_agent_header(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        await async_client.groups.update(GROUP_ID, description="x", agent=AGENT_ID)

        headers = route.calls[0].request.headers
        assert headers.get("x-rine-agent") == AGENT_ID
        await async_client.close()


class TestGetAgent:
    @respx.mock
    async def test_get_agent_success(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        result = await async_client.get_agent(AGENT_ID)

        assert isinstance(result, AgentRead)
        assert result.name == "test-agent"
        await async_client.close()

    @respx.mock
    async def test_get_agent_not_found(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Agent not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.get_agent(AGENT_ID)
        await async_client.close()


class TestListAgents:
    @respx.mock
    async def test_list_agents_default(self, async_client):
        _mock_token()
        route = respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD], "total": 1})
        )

        result = await async_client.list_agents()

        assert len(result) == 1
        assert isinstance(result[0], AgentRead)
        assert b"include_revoked" not in route.calls[0].request.url.query
        await async_client.close()

    @respx.mock
    async def test_list_agents_include_revoked(self, async_client):
        _mock_token()
        route = respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD], "total": 1})
        )

        await async_client.list_agents(include_revoked=True)

        assert b"include_revoked=true" in route.calls[0].request.url.query
        await async_client.close()


class TestRegeneratePollToken:
    @respx.mock
    async def test_regenerate_poll_token_success(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(200, json={"poll_url": "https://rine.network/poll/abc123"})
        )

        result = await async_client.regenerate_poll_token(AGENT_ID)

        assert isinstance(result, PollTokenResponse)
        assert result.poll_url == "https://rine.network/poll/abc123"
        await async_client.close()

    @respx.mock
    async def test_regenerate_poll_token_not_found(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(404, json={"detail": "Agent not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.regenerate_poll_token(AGENT_ID)
        await async_client.close()

    @respx.mock
    async def test_regenerate_poll_token_revoked(self, async_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(409, json={"detail": "Agent revoked"})
        )

        with pytest.raises(ConflictError):
            await async_client.regenerate_poll_token(AGENT_ID)
        await async_client.close()


class TestRevokePollToken:
    @respx.mock
    async def test_revoke_poll_token_success(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(204)
        )

        result = await async_client.revoke_poll_token(AGENT_ID)

        assert result is None
        await async_client.close()

    @respx.mock
    async def test_revoke_poll_token_not_found(self, async_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(404, json={"detail": "Agent not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.revoke_poll_token(AGENT_ID)
        await async_client.close()


class TestWebhookDeliveries:
    @respx.mock
    async def test_webhook_deliveries_default(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(200, json={"items": [_WEBHOOK_JOB_PAYLOAD], "total": 1})
        )

        result = await async_client.webhooks.deliveries(WEBHOOK_ID)

        assert len(result) == 1
        assert isinstance(result[0], WebhookJobRead)
        assert result[0].status == "delivered"
        await async_client.close()

    @respx.mock
    async def test_webhook_deliveries_with_status_filter(self, async_client):
        _mock_token()
        route = respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        await async_client.webhooks.deliveries(WEBHOOK_ID, status="failed")

        assert b"status=failed" in route.calls[0].request.url.query
        await async_client.close()

    @respx.mock
    async def test_webhook_deliveries_with_pagination(self, async_client):
        _mock_token()
        route = respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        await async_client.webhooks.deliveries(WEBHOOK_ID, limit=5, offset=10)

        query = route.calls[0].request.url.query
        assert b"limit=5" in query
        assert b"offset=10" in query
        await async_client.close()

    @respx.mock
    async def test_webhook_deliveries_not_found(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(404, json={"detail": "Webhook not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.webhooks.deliveries(WEBHOOK_ID)
        await async_client.close()

    @respx.mock
    async def test_webhook_deliveries_invalid_status(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(422, json={"detail": "Invalid status value"})
        )

        with pytest.raises(ValidationError):
            await async_client.webhooks.deliveries(WEBHOOK_ID, status="bogus")
        await async_client.close()


class TestWebhookDeliverySummary:
    @respx.mock
    async def test_webhook_delivery_summary_success(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries/summary").mock(
            return_value=httpx.Response(
                200, json={"total": 100, "delivered": 90, "failed": 5, "dead": 2, "pending": 3}
            )
        )

        result = await async_client.webhooks.delivery_summary(WEBHOOK_ID)

        assert isinstance(result, WebhookJobSummary)
        assert result.total == 100
        assert result.delivered == 90
        await async_client.close()

    @respx.mock
    async def test_webhook_delivery_summary_not_found(self, async_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries/summary").mock(
            return_value=httpx.Response(404, json={"detail": "Webhook not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.webhooks.delivery_summary(WEBHOOK_ID)
        await async_client.close()


class TestInboxGroupSelfHeal:
    """inbox() opens sender-key group rows: cold, and again after read()."""

    @respx.mock
    async def test_inbox_self_heals_sender_key_group_when_none(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """A group row whose sender key was never ingested still yields plaintext."""
        mock_group_message_routes()

        page = await async_client.inbox()

        msg = page.items[0]
        assert msg.decrypt_error is None
        assert msg.plaintext == group_message_fixture.plaintext
        assert msg.verified is True
        await async_client.close()

    @respx.mock
    async def test_inbox_idempotent_after_read_consumes_ratchet(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """read() consumes the ratchet key; a later inbox() still returns plaintext."""
        mock_group_message_routes()

        first = await async_client.read(group_message_fixture.message_id)
        assert first.plaintext == group_message_fixture.plaintext

        page = await async_client.inbox()

        msg = page.items[0]
        assert msg.decrypt_error is None
        assert msg.plaintext == group_message_fixture.plaintext
        await async_client.close()


class TestGroupSendActingAgent:
    """send(agent=...) keys, distributes and ratchets under the requested agent."""

    @respx.mock
    async def test_group_send_uses_requested_agent_not_org_default(
        self, async_client, tmp_config_dir, saved_agent_keys
    ):
        """In a multi-agent org, the whole group send runs as the requested agent.

        The default agent must be left out of it entirely: no ratchet in its
        store, no signature under its key. A split store would also strand the
        ratchet at index 0 and make every message after the first unopenable.
        """
        save_agent_keys(tmp_config_dir, OTHER_AGENT_ID, generate_agent_keys())
        member_keys = generate_agent_keys()

        _mock_token()
        # Two active agents: an argument-less resolve here is ambiguous.
        respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        _AGENT_PAYLOAD,
                        {**_AGENT_PAYLOAD, "id": OTHER_AGENT_ID, "name": "other-agent"},
                    ]
                },
            )
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": [_GROUP_PAYLOAD]})
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(
                200,
                json={"items": [{"agent_id": OTHER_AGENT_ID}, {"agent_id": MEMBER_AGENT_ID}]},
            )
        )
        respx.get(f"https://rine.network/agents/{MEMBER_AGENT_ID}/keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "agent_id": MEMBER_AGENT_ID,
                    "encryption_public_key": encryption_public_key_to_jwk(
                        member_keys.encryption.public_key
                    ),
                    "signing_public_key": signing_public_key_to_jwk(
                        member_keys.signing.public_key
                    ),
                },
            )
        )
        msg_route = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(200, json=_MESSAGE_PAYLOAD)
        )

        handle = _GROUP_PAYLOAD["handle"]
        await async_client.send(handle, {"text": "one"}, agent=OTHER_AGENT_ID)
        await async_client.send(handle, {"text": "two"}, agent=OTHER_AGENT_ID)

        states = load_sender_key_states(tmp_config_dir, OTHER_AGENT_ID, GROUP_ID)
        assert [s.sender_agent_id for s in states] == [OTHER_AGENT_ID]
        # One ratchet advanced twice — not two sends stuck on index 0.
        assert states[0].message_index == 2
        assert load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID) == []

        body = json.loads(msg_route.calls[-1].request.content)
        assert body["sender_signing_kid"] == f"rine:{OTHER_AGENT_ID}"
        await async_client.close()
