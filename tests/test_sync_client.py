"""Tests for SyncRineClient — sync client public API."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine import SyncRineClient
from rine._config import save_credentials
from rine._constants import MessageType
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

# --- Fixtures shared across tests ---

AGENT_ID = "00000000-1111-2222-3333-444444444444"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

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


def _mock_token(api_url: str = "https://rine.network") -> None:
    respx.post(f"{api_url}/oauth/token").mock(
        return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
    )


def _mock_agents(api_url: str = "https://rine.network") -> None:
    respx.get(f"{api_url}/agents").mock(
        return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD]})
    )


class TestWhoami:
    @respx.mock
    def test_whoami_returns_org_and_agents(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )

        result = sync_client.whoami()

        assert isinstance(result, WhoAmI)
        assert result.org.name == "My Org"
        assert len(result.agents) == 1
        assert result.agents[0].name == "test-agent"
        assert result.trust_tier == 1

    @respx.mock
    def test_whoami_raises_when_no_agents(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        with pytest.raises(ConfigError, match="No agents found"):
            sync_client.whoami()


class TestDiscover:
    @respx.mock
    def test_discover_returns_cursor_page(self, sync_client):
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

        result = sync_client.discover()

        assert isinstance(result, CursorPage)
        assert len(result.items) == 1
        assert isinstance(result.items[0], AgentSummary)
        assert result.items[0].name == "Other Agent"

    @respx.mock
    def test_discover_with_query_params(self, sync_client):
        route = respx.get("https://rine.network/directory/agents").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        sync_client.discover(q="legal", category="legal", limit=10)

        assert route.called
        request = route.calls[0].request
        assert b"q=legal" in request.url.query
        assert b"category=legal" in request.url.query

    @respx.mock
    def test_discover_empty_result(self, sync_client):
        respx.get("https://rine.network/directory/agents").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        result = sync_client.discover()
        assert len(result.items) == 0


class TestInspect:
    @respx.mock
    def test_inspect_with_a2a_envelope(self, sync_client):
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

        result = sync_client.inspect(OTHER_AGENT_ID)

        assert isinstance(result, AgentProfile)
        assert result.name == "Legal Bot"
        assert result.handle == "legal@acme.rine.network"
        assert result.category == "legal"
        assert result.verified is True
        assert result.human_oversight is False
        assert result.trust_tier == 2

    @respx.mock
    def test_inspect_with_raw_response(self, sync_client):
        """inspect() should fall through to direct parse when no 'card' key."""
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

        result = sync_client.inspect(OTHER_AGENT_ID)

        assert isinstance(result, AgentProfile)
        assert result.name == "Raw Agent"
        assert result.id is not None


class TestPoll:
    @respx.mock
    def test_poll_returns_count(self, tmp_config_dir, saved_agent_keys, agent_id):

        save_credentials(
            tmp_config_dir,
            {
                "default": {
                    "client_id": "cid",
                    "client_secret": "csecret",
                    "poll_url": "https://rine.network/poll/some-token",
                }
            },
        )

        respx.get("https://rine.network/poll/some-token").mock(
            return_value=httpx.Response(200, json={"count": 5})
        )

        client = SyncRineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
        count = client.poll()
        client.close()

        assert count == 5

    def test_poll_raises_when_no_poll_url(self, sync_client):
        """poll() raises ConfigError when credentials have no poll_url."""
        with pytest.raises(ConfigError, match="No poll URL"):
            sync_client.poll()


class TestWithOptions:
    def test_with_options_returns_new_client(self, sync_client):
        new_client = sync_client.with_options(timeout=5.0)

        assert new_client is not sync_client
        assert isinstance(new_client, SyncRineClient)
        new_client.close()

    def test_with_options_overrides_timeout(self, sync_client):
        new_client = sync_client.with_options(timeout=5.0)

        assert new_client._timeout == 5.0
        new_client.close()

    def test_with_options_overrides_agent(self, sync_client):
        new_client = sync_client.with_options(agent="specific-bot")

        assert new_client._agent == "specific-bot"
        new_client.close()

    def test_with_options_inherits_config_dir(self, sync_client):
        new_client = sync_client.with_options(timeout=1.0)

        assert new_client._config_dir == sync_client._config_dir
        new_client.close()

    def test_with_options_inherits_api_url(self, sync_client):
        new_client = sync_client.with_options(max_retries=0)

        assert new_client._api_url == sync_client._api_url
        new_client.close()


class TestInbox:
    @respx.mock
    def test_inbox_returns_cursor_page_with_empty_items(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [],
                    "total": 0,
                    "next_cursor": None,
                },
            )
        )

        from rine.types import CursorPage

        result = sync_client.inbox()

        assert isinstance(result, CursorPage)
        assert len(result.items) == 0
        assert result.total == 0

    @respx.mock
    def test_inbox_passes_limit_param(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        sync_client.inbox(limit=5)

        assert route.called
        request = route.calls[0].request
        assert b"limit=5" in request.url.query


class TestSendAndWaitTimeout:
    """Test timeout conversion and atomic /messages/sync in send_and_wait."""

    @respx.mock
    def test_send_and_wait_posts_directly_to_sync_with_timeout_ms(
        self, sync_client, tmp_config_dir, agent_id, saved_agent_keys
    ):
        """Verify send_and_wait posts the encrypted body to /messages/sync (not /messages)."""
        _mock_token()
        _mock_agents()

        # Mock WebFinger for recipient resolution
        respx.get("https://rine.network/.well-known/webfinger").mock(
            return_value=httpx.Response(
                200, json={"aliases": [f"https://rine.network/agents/{OTHER_AGENT_ID}"]}
            )
        )

        # Mock recipient keys endpoint
        from rine._crypto.keys import encryption_public_key_to_jwk

        other_keys = generate_other_keys(tmp_config_dir, OTHER_AGENT_ID)
        enc_jwk = encryption_public_key_to_jwk(other_keys.encryption.public_key)
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

        # No /messages mock — send_and_wait should NOT call it.

        # Mock sync endpoint — returns SyncMessageResponse envelope
        reply_msg = {
            **_MESSAGE_PAYLOAD,
            "id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "from_agent_id": OTHER_AGENT_ID,
            "to_agent_id": AGENT_ID,
        }
        sync_route = respx.post("https://rine.network/messages/sync").mock(
            return_value=httpx.Response(
                200,
                json={
                    "message": _MESSAGE_PAYLOAD,
                    "reply": reply_msg,
                    "conversation_id": _MESSAGE_PAYLOAD["conversation_id"],
                    "status": "completed",
                },
            )
        )

        try:
            sync_client.send_and_wait(
                "other@acme.rine.network",
                {"task": "hi"},
                timeout=2.5,
            )
        except Exception:
            # May fail on decrypt — we only care about the HTTP call params
            pass

        assert sync_route.called
        request = sync_route.calls[0].request
        assert b"timeout_ms=2500" in request.url.query
        # Body should be the full encrypted payload, not {conversation_id}
        import json as _json

        body = _json.loads(request.content)
        assert "encrypted_payload" in body
        assert "type" in body

    def test_send_and_wait_rejects_group_handles(self, sync_client):
        """Group handles raise the typed UnsupportedTargetError (sync endpoint is 1:1 only)."""
        import pytest

        from rine.errors import UnsupportedTargetError

        with pytest.raises(UnsupportedTargetError, match="group handles"):
            sync_client.send_and_wait(
                "#team@acme.rine.network",
                {"task": "nope"},
            )


def generate_other_keys(tmp_config_dir: str, other_agent_id: str):
    """Helper: generate and save keys for a second agent."""
    from rine._crypto.keys import generate_agent_keys, save_agent_keys

    keys = generate_agent_keys()
    save_agent_keys(tmp_config_dir, other_agent_id, keys)
    return keys


class TestContextManager:
    @respx.mock
    def test_sync_client_context_manager(self, tmp_config_dir, saved_agent_keys, agent_id):

        save_credentials(
            tmp_config_dir, {"default": {"client_id": "cid", "client_secret": "csecret"}}
        )

        with SyncRineClient(config_dir=tmp_config_dir, api_url="https://rine.network") as client:
            assert client is not None
        # Verify it closed without error


# --- P0: Agent lifecycle ---


class TestUpdateAgent:
    @respx.mock
    def test_update_agent_all_fields(self, sync_client):
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

        result = sync_client.update_agent(
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

    @respx.mock
    def test_update_agent_partial_sends_only_provided_fields(self, sync_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        sync_client.update_agent(AGENT_ID, name="new-name")

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"name": "new-name"}

    @respx.mock
    def test_update_agent_no_args_sends_empty_body(self, sync_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        sync_client.update_agent(AGENT_ID)

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {}

    @respx.mock
    def test_update_agent_when_revoked_raises_conflict(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(409, json={"detail": "Agent is already revoked"})
        )

        with pytest.raises(ConflictError, match="already revoked"):
            sync_client.update_agent(AGENT_ID, name="x")

    @respx.mock
    def test_update_agent_rename_after_handle_raises_conflict(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(
                409,
                json={"detail": "Cannot rename agent after handle assignment"},
            )
        )

        with pytest.raises(ConflictError, match="Cannot rename"):
            sync_client.update_agent(AGENT_ID, name="x")

    @respx.mock
    def test_update_agent_when_not_found_raises_not_found(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.update_agent(AGENT_ID, name="x")

    @respx.mock
    def test_update_agent_blank_name_raises_validation(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(422, json={"detail": "Name must not be blank"})
        )

        with pytest.raises(ValidationError):
            sync_client.update_agent(AGENT_ID, name="")


class TestRevokeAgent:
    @respx.mock
    def test_revoke_agent_returns_agent_with_revoked_at(self, sync_client):
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

        result = sync_client.revoke_agent(AGENT_ID)

        assert isinstance(result, AgentRead)
        assert result.revoked_at is not None

    @respx.mock
    def test_revoke_agent_already_revoked_raises_conflict(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(409, json={"detail": "Agent is already revoked"})
        )

        with pytest.raises(ConflictError, match="already revoked"):
            sync_client.revoke_agent(AGENT_ID)

    @respx.mock
    def test_revoke_agent_when_not_found_raises_not_found(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.revoke_agent(AGENT_ID)


# --- P0: Org lifecycle ---


class TestUpdateOrg:
    @respx.mock
    def test_update_org_success(self, sync_client):
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

        result = sync_client.update_org(name="New Name", contact_email="new@example.com")

        assert isinstance(result, OrgRead)
        assert result.name == "New Name"
        assert result.contact_email == "new@example.com"
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"name": "New Name", "contact_email": "new@example.com"}

    @respx.mock
    def test_update_org_partial_sends_only_provided_fields(self, sync_client):
        _mock_token()
        route = respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )

        sync_client.update_org(country_code="IT")

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"country_code": "IT"}

    @respx.mock
    def test_update_org_no_args_sends_empty_body(self, sync_client):
        _mock_token()
        route = respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )

        sync_client.update_org()

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {}

    @respx.mock
    def test_update_org_slug_immutable_raises_conflict(self, sync_client):
        _mock_token()
        respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(409, json={"detail": "Slug is immutable once set"})
        )

        with pytest.raises(ConflictError, match="immutable"):
            sync_client.update_org(slug="new-slug")

    @respx.mock
    def test_update_org_invalid_email_raises_validation(self, sync_client):
        _mock_token()
        respx.patch("https://rine.network/org").mock(
            return_value=httpx.Response(422, json={"detail": "Invalid email format"})
        )

        with pytest.raises(ValidationError):
            sync_client.update_org(contact_email="not-an-email")


# --- P0: GDPR compliance ---


class TestEraseOrg:
    @respx.mock
    def test_erase_org_success(self, sync_client):
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

        result = sync_client.erase_org(confirm=True)

        assert isinstance(result, ErasureResult)
        assert str(result.org_id) == _ORG_PAYLOAD["id"]
        assert result.messages_deleted == 42
        assert result.agents_deleted == 3
        assert result.conversations_deleted == 10
        assert result.groups_deleted == 1

    def test_erase_org_without_confirm_raises_value_error(self, sync_client):
        with pytest.raises(ValueError, match="confirm=True"):
            sync_client.erase_org()

    @respx.mock
    def test_erase_org_forbidden_raises_authorization(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.delete(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}").mock(
            return_value=httpx.Response(403, json={"detail": "Permission denied"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.erase_org(confirm=True)


class TestExportOrg:
    @respx.mock
    def test_export_org_success(self, sync_client):
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

        result = sync_client.export_org()

        assert len(result) == 3
        assert result[0]["type"] == "manifest"
        assert result[1]["type"] == "org"
        assert result[2]["type"] == "agent"

    @respx.mock
    def test_export_org_empty_response(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.get(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}/export").mock(
            return_value=httpx.Response(200, content=b"", headers={})
        )

        result = sync_client.export_org()
        assert result == []

    @respx.mock
    def test_export_org_rate_limited_raises_rate_limit(self, sync_client):
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
            sync_client.export_org()
        assert exc_info.value.retry_after == 3200.0

    @respx.mock
    def test_export_org_forbidden_raises_authorization(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/org").mock(
            return_value=httpx.Response(200, json=_ORG_PAYLOAD)
        )
        respx.get(f"https://rine.network/orgs/{_ORG_PAYLOAD['id']}/export").mock(
            return_value=httpx.Response(403, json={"detail": "Permission denied"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.export_org()


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
    def test_update_conversation_status_success(self, sync_client):
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

        result = sync_client.update_conversation_status(CONVERSATION_ID, "completed")

        assert isinstance(result, ConversationRead)
        assert result.status == "completed"
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"status": "completed"}

    @respx.mock
    def test_update_conversation_status_invalid_transition_raises_conflict(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/conversations/{CONVERSATION_ID}/status").mock(
            return_value=httpx.Response(409, json={"detail": "Invalid state transition"})
        )

        with pytest.raises(ConflictError, match="Invalid state transition"):
            sync_client.update_conversation_status(CONVERSATION_ID, "open")

    @respx.mock
    def test_update_conversation_status_not_found(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/conversations/{CONVERSATION_ID}/status").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.update_conversation_status(CONVERSATION_ID, "completed")


class TestGetConversation:
    @respx.mock
    def test_get_conversation_success(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}").mock(
            return_value=httpx.Response(200, json=_CONVERSATION_PAYLOAD)
        )

        result = sync_client.get_conversation(CONVERSATION_ID)

        assert isinstance(result, ConversationRead)
        assert result.status == "open"
        assert str(result.id) == CONVERSATION_ID

    @respx.mock
    def test_get_conversation_not_found(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.get_conversation(CONVERSATION_ID)


class TestGetConversationParticipants:
    @respx.mock
    def test_get_conversation_participants_success(self, sync_client):
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

        result = sync_client.get_conversation_participants(CONVERSATION_ID)

        assert len(result) == 2
        assert isinstance(result[0], ConversationParticipant)
        assert result[0].role == "initiator"
        assert result[1].role == "responder"

    @respx.mock
    def test_get_conversation_participants_not_found(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/conversations/{CONVERSATION_ID}/participants").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.get_conversation_participants(CONVERSATION_ID)


# --- P1: Agent Cards ---


class TestSetAgentCard:
    @respx.mock
    def test_set_agent_card_full(self, sync_client):
        _mock_token()
        route = respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(200, json=_AGENT_CARD_PAYLOAD)
        )

        result = sync_client.set_agent_card(
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

    @respx.mock
    def test_set_agent_card_minimal(self, sync_client):
        _mock_token()
        route = respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(200, json=_AGENT_CARD_PAYLOAD)
        )

        sync_client.set_agent_card(AGENT_ID, name="Test Card", description="desc")

        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"name": "Test Card", "description": "desc"}

    @respx.mock
    def test_set_agent_card_no_signing_key_raises_conflict(self, sync_client):
        _mock_token()
        respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(409, json={"detail": "Agent has no signing key"})
        )

        with pytest.raises(ConflictError, match="signing key"):
            sync_client.set_agent_card(AGENT_ID, name="x", description="d")

    @respx.mock
    def test_set_agent_card_not_found(self, sync_client):
        _mock_token()
        respx.put(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.set_agent_card(AGENT_ID, name="x", description="d")


class TestGetAgentCard:
    @respx.mock
    def test_get_agent_card_success(self, sync_client):
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(200, json=_AGENT_CARD_PAYLOAD)
        )

        result = sync_client.get_agent_card(AGENT_ID)

        assert isinstance(result, AgentCardRead)
        assert result.name == "Test Card"
        assert result.is_public is True
        assert "Authorization" not in route.calls[0].request.headers

    @respx.mock
    def test_get_agent_card_not_found(self, sync_client):
        respx.get(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.get_agent_card(AGENT_ID)


class TestDeleteAgentCard:
    @respx.mock
    def test_delete_agent_card_success(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.delete_agent_card(AGENT_ID)
        assert result is None

    @respx.mock
    def test_delete_agent_card_not_found(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/card").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.delete_agent_card(AGENT_ID)


# --- P1: Webhooks ---


class TestWebhookCreate:
    @respx.mock
    def test_webhook_create_success(self, sync_client):
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

        result = sync_client.webhooks.create(AGENT_ID, "https://example.com/webhook")

        assert isinstance(result, WebhookCreated)
        assert result.secret == "whsec_test123"
        assert result.url == "https://example.com/webhook"

    @respx.mock
    def test_webhook_create_with_events(self, sync_client):
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

        sync_client.webhooks.create(
            AGENT_ID,
            "https://example.com/webhook",
            events=["message.received"],
        )

        parsed = json.loads(route.calls[0].request.content)
        assert parsed["events"] == ["message.received"]

    @respx.mock
    def test_webhook_create_duplicate_raises_conflict(self, sync_client):
        _mock_token()
        respx.post("https://rine.network/webhooks").mock(
            return_value=httpx.Response(409, json={"detail": "Duplicate webhook URL"})
        )

        with pytest.raises(ConflictError, match="Duplicate"):
            sync_client.webhooks.create(AGENT_ID, "https://example.com/webhook")

    @respx.mock
    def test_webhook_create_quota_exceeded_raises_authorization(self, sync_client):
        _mock_token()
        respx.post("https://rine.network/webhooks").mock(
            return_value=httpx.Response(403, json={"detail": "Webhook quota exceeded"})
        )

        with pytest.raises(AuthorizationError, match="quota"):
            sync_client.webhooks.create(AGENT_ID, "https://example.com/webhook")


class TestWebhookList:
    @respx.mock
    def test_webhook_list_all(self, sync_client):
        _mock_token()
        respx.get("https://rine.network/webhooks").mock(
            return_value=httpx.Response(200, json={"items": [_WEBHOOK_PAYLOAD]})
        )

        result = sync_client.webhooks.list()

        assert len(result) == 1
        assert isinstance(result[0], WebhookRead)
        assert result[0].url == "https://example.com/webhook"

    @respx.mock
    def test_webhook_list_by_agent(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/webhooks").mock(
            return_value=httpx.Response(200, json={"items": [_WEBHOOK_PAYLOAD]})
        )

        sync_client.webhooks.list(agent_id=AGENT_ID)

        request = route.calls[0].request
        assert f"agent_id={AGENT_ID}".encode() in request.url.query

    @respx.mock
    def test_webhook_list_include_inactive(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/webhooks").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        sync_client.webhooks.list(include_inactive=True)

        request = route.calls[0].request
        assert b"include_inactive=true" in request.url.query


class TestWebhookUpdate:
    @respx.mock
    def test_webhook_update_deactivate(self, sync_client):
        _mock_token()
        route = respx.patch(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(200, json={**_WEBHOOK_PAYLOAD, "active": False})
        )

        result = sync_client.webhooks.update(WEBHOOK_ID, active=False)

        assert isinstance(result, WebhookRead)
        assert result.active is False
        parsed = json.loads(route.calls[0].request.content)
        assert parsed == {"active": False}

    @respx.mock
    def test_webhook_update_not_found(self, sync_client):
        _mock_token()
        respx.patch(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.webhooks.update(WEBHOOK_ID, active=False)


class TestWebhookDelete:
    @respx.mock
    def test_webhook_delete_success(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.webhooks.delete(WEBHOOK_ID)
        assert result is None

    @respx.mock
    def test_webhook_delete_not_found(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/webhooks/{WEBHOOK_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.webhooks.delete(WEBHOOK_ID)


# --- P1: Key Rotation ---


class TestRotateKeys:
    @respx.mock
    def test_rotate_keys_success(self, sync_client):
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

        result = sync_client.rotate_keys(AGENT_ID)

        assert isinstance(result, AgentRead)
        assert result.verification_words == "alpha bravo charlie"
        # Verify JWK body shape
        parsed = json.loads(route.calls[0].request.content)
        assert "signing_public_key" in parsed
        assert "encryption_public_key" in parsed
        assert parsed["signing_public_key"]["kty"] == "OKP"
        assert parsed["signing_public_key"]["crv"] == "Ed25519"
        assert parsed["encryption_public_key"]["crv"] == "X25519"

    @respx.mock
    def test_rotate_keys_saves_to_disk(self, sync_client, tmp_config_dir):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        assert sync_client._config_dir == tmp_config_dir  # guard against fixture drift
        sync_client.rotate_keys(AGENT_ID)

        import os

        key_dir = os.path.join(tmp_config_dir, "keys", AGENT_ID)
        assert os.path.isfile(os.path.join(key_dir, "signing.key"))
        assert os.path.isfile(os.path.join(key_dir, "encryption.key"))

    @respx.mock
    def test_rotate_keys_revoked_raises_conflict(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(409, json={"detail": "Agent is revoked"})
        )

        with pytest.raises(ConflictError, match="revoked"):
            sync_client.rotate_keys(AGENT_ID)

    @respx.mock
    def test_rotate_keys_not_found(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.rotate_keys(AGENT_ID)


# --- P1: Org Quotas ---


class TestGetQuotas:
    @respx.mock
    def test_get_quotas_success(self, sync_client):
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

        result = sync_client.get_quotas()

        assert isinstance(result, OrgQuotas)
        assert result.tier == 1
        assert result.quotas["agents"].limit == 10
        assert result.quotas["agents"].used == 3

    @respx.mock
    def test_get_quotas_parses_unlimited(self, sync_client):
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

        result = sync_client.get_quotas()

        assert result.tier == 3
        assert result.quotas["agents"].limit is None
        assert result.quotas["agents"].used == 50


# --- P2: Power User & Advanced Methods ---

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
    def test_group_update_full(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        result = sync_client.groups.update(
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

    @respx.mock
    def test_group_update_single_field(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.update(GROUP_ID, description="Only this")

        body = json.loads(route.calls[0].request.content)
        assert body == {"description": "Only this"}

    @respx.mock
    def test_group_update_not_found(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.update(GROUP_ID, description="x")

    @respx.mock
    def test_group_update_not_admin(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(403, json={"detail": "Not admin"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.groups.update(GROUP_ID, description="x")


class TestGroupDelete:
    @respx.mock
    def test_group_delete_success(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.groups.delete(GROUP_ID)

        assert result is None

    @respx.mock
    def test_group_delete_not_found(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.delete(GROUP_ID)

    @respx.mock
    def test_group_delete_not_admin(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(403, json={"detail": "Not admin"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.groups.delete(GROUP_ID)


class TestGroupRemoveMember:
    @respx.mock
    def test_group_remove_member_success(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)

        assert result is None

    @respx.mock
    def test_group_remove_member_not_found(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)

    @respx.mock
    def test_group_remove_member_not_admin(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{OTHER_AGENT_ID}").mock(
            return_value=httpx.Response(403, json={"detail": "Not admin"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.groups.remove_member(GROUP_ID, OTHER_AGENT_ID)

    @respx.mock
    def test_group_remove_member_last_admin(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.delete(f"https://rine.network/groups/{GROUP_ID}/members/{AGENT_ID}").mock(
            return_value=httpx.Response(422, json={"detail": "Last admin"})
        )

        with pytest.raises(ValidationError):
            sync_client.groups.remove_member(GROUP_ID, AGENT_ID)


class TestGroupVoting:
    @respx.mock
    def test_group_list_requests_success(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(200, json={"items": [_JOIN_REQUEST_PAYLOAD], "total": 1})
        )

        result = sync_client.groups.list_requests(GROUP_ID)

        assert len(result) == 1
        assert isinstance(result[0], JoinRequestRead)
        assert result[0].status == "pending"
        assert result[0].message == "Please let me in"

    @respx.mock
    def test_group_list_requests_empty(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        result = sync_client.groups.list_requests(GROUP_ID)

        assert result == []

    @respx.mock
    def test_group_list_requests_not_found(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.list_requests(GROUP_ID)

    @respx.mock
    def test_group_vote_approve_success(self, sync_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(200, json=_VOTE_RESPONSE_PAYLOAD)
        )

        result = sync_client.groups.vote(GROUP_ID, req_id, "approve")

        assert isinstance(result, VoteResponse)
        assert result.your_vote == "approve"
        assert result.status == "approved"

    @respx.mock
    def test_group_vote_deny_success(self, sync_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        deny_payload = {**_VOTE_RESPONSE_PAYLOAD, "your_vote": "deny", "status": "pending"}
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(200, json=deny_payload)
        )

        result = sync_client.groups.vote(GROUP_ID, req_id, "deny")

        assert result.your_vote == "deny"

    @respx.mock
    def test_group_vote_already_voted(self, sync_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(409, json={"detail": "Already voted"})
        )

        with pytest.raises(ConflictError):
            sync_client.groups.vote(GROUP_ID, req_id, "approve")

    @respx.mock
    def test_group_vote_not_pending(self, sync_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(422, json={"detail": "Request not pending"})
        )

        with pytest.raises(ValidationError):
            sync_client.groups.vote(GROUP_ID, req_id, "approve")

    @respx.mock
    def test_group_vote_not_found(self, sync_client):
        _mock_token()
        _mock_agents()
        req_id = _JOIN_REQUEST_PAYLOAD["id"]
        respx.post(f"https://rine.network/groups/{GROUP_ID}/requests/{req_id}/vote").mock(
            return_value=httpx.Response(404, json={"detail": "Not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.groups.vote(GROUP_ID, req_id, "approve")

    @respx.mock
    def test_group_list_requests_not_member(self, sync_client):
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(403, json={"detail": "Not a member"})
        )

        with pytest.raises(AuthorizationError):
            sync_client.groups.list_requests(GROUP_ID)

    @respx.mock
    def test_group_update_sends_agent_header(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
        )

        sync_client.groups.update(GROUP_ID, description="x", agent=AGENT_ID)

        headers = route.calls[0].request.headers
        assert headers.get("x-rine-agent") == AGENT_ID


class TestGetAgent:
    @respx.mock
    def test_get_agent_success(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(200, json=_AGENT_PAYLOAD)
        )

        result = sync_client.get_agent(AGENT_ID)

        assert isinstance(result, AgentRead)
        assert result.name == "test-agent"

    @respx.mock
    def test_get_agent_not_found(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/agents/{AGENT_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Agent not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.get_agent(AGENT_ID)


class TestListAgents:
    @respx.mock
    def test_list_agents_default(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD], "total": 1})
        )

        result = sync_client.list_agents()

        assert len(result) == 1
        assert isinstance(result[0], AgentRead)
        assert b"include_revoked" not in route.calls[0].request.url.query

    @respx.mock
    def test_list_agents_include_revoked(self, sync_client):
        _mock_token()
        route = respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": [_AGENT_PAYLOAD], "total": 1})
        )

        sync_client.list_agents(include_revoked=True)

        assert b"include_revoked=true" in route.calls[0].request.url.query


class TestRegeneratePollToken:
    @respx.mock
    def test_regenerate_poll_token_success(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(200, json={"poll_url": "https://rine.network/poll/abc123"})
        )

        result = sync_client.regenerate_poll_token(AGENT_ID)

        assert isinstance(result, PollTokenResponse)
        assert result.poll_url == "https://rine.network/poll/abc123"

    @respx.mock
    def test_regenerate_poll_token_not_found(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(404, json={"detail": "Agent not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.regenerate_poll_token(AGENT_ID)

    @respx.mock
    def test_regenerate_poll_token_revoked(self, sync_client):
        _mock_token()
        respx.post(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(409, json={"detail": "Agent revoked"})
        )

        with pytest.raises(ConflictError):
            sync_client.regenerate_poll_token(AGENT_ID)


class TestRevokePollToken:
    @respx.mock
    def test_revoke_poll_token_success(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.revoke_poll_token(AGENT_ID)

        assert result is None

    @respx.mock
    def test_revoke_poll_token_not_found(self, sync_client):
        _mock_token()
        respx.delete(f"https://rine.network/agents/{AGENT_ID}/poll-token").mock(
            return_value=httpx.Response(404, json={"detail": "Agent not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.revoke_poll_token(AGENT_ID)


class TestWebhookDeliveries:
    @respx.mock
    def test_webhook_deliveries_default(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(200, json={"items": [_WEBHOOK_JOB_PAYLOAD], "total": 1})
        )

        result = sync_client.webhooks.deliveries(WEBHOOK_ID)

        assert len(result) == 1
        assert isinstance(result[0], WebhookJobRead)
        assert result[0].status == "delivered"

    @respx.mock
    def test_webhook_deliveries_with_status_filter(self, sync_client):
        _mock_token()
        route = respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        sync_client.webhooks.deliveries(WEBHOOK_ID, status="failed")

        assert b"status=failed" in route.calls[0].request.url.query

    @respx.mock
    def test_webhook_deliveries_with_pagination(self, sync_client):
        _mock_token()
        route = respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        sync_client.webhooks.deliveries(WEBHOOK_ID, limit=5, offset=10)

        query = route.calls[0].request.url.query
        assert b"limit=5" in query
        assert b"offset=10" in query

    @respx.mock
    def test_webhook_deliveries_not_found(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(404, json={"detail": "Webhook not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.webhooks.deliveries(WEBHOOK_ID)

    @respx.mock
    def test_webhook_deliveries_invalid_status(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries").mock(
            return_value=httpx.Response(422, json={"detail": "Invalid status value"})
        )

        with pytest.raises(ValidationError):
            sync_client.webhooks.deliveries(WEBHOOK_ID, status="bogus")


class TestWebhookDeliverySummary:
    @respx.mock
    def test_webhook_delivery_summary_success(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries/summary").mock(
            return_value=httpx.Response(
                200, json={"total": 100, "delivered": 90, "failed": 5, "dead": 2, "pending": 3}
            )
        )

        result = sync_client.webhooks.delivery_summary(WEBHOOK_ID)

        assert isinstance(result, WebhookJobSummary)
        assert result.total == 100
        assert result.delivered == 90
        assert result.failed == 5

    @respx.mock
    def test_webhook_delivery_summary_not_found(self, sync_client):
        _mock_token()
        respx.get(f"https://rine.network/webhooks/{WEBHOOK_ID}/deliveries/summary").mock(
            return_value=httpx.Response(404, json={"detail": "Webhook not found"})
        )

        with pytest.raises(NotFoundError):
            sync_client.webhooks.delivery_summary(WEBHOOK_ID)
