"""Tests for sender key orchestration — get_or_create and distribute."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, call, patch

import httpx
import pytest
import respx

from rine._config import save_credentials
from rine._constants import MessageType
from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    generate_agent_keys,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._http import SyncHttpClient
from rine._sender_key_ops import distribute_sender_key_sync, get_or_create_sender_key_sync
from rine.errors import NotFoundError


AGENT_ID = "00000000-1111-2222-3333-444444444444"
MEMBER_ID_1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MEMBER_ID_2 = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP_HANDLE = "#my-group@myorg.rine.network"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}


def _make_http_client(tmp_config_dir: str) -> SyncHttpClient:
    save_credentials(tmp_config_dir, {
        "default": {"client_id": "cid", "client_secret": "csecret"}
    })
    return SyncHttpClient(config_dir=tmp_config_dir, api_url="https://rine.network")


def _make_enc_jwk(agent_id: str, config_dir: str) -> dict[str, str]:
    """Return an encryption JWK for a fresh keypair saved to disk."""
    keys = generate_agent_keys()
    save_agent_keys(config_dir, agent_id, keys)
    return encryption_public_key_to_jwk(keys.encryption.public_key)


class TestGetOrCreateSenderKeySync:
    @respx.mock
    def test_creates_new_key_when_no_state_exists(self, tmp_config_dir, saved_agent_keys):
        """When no sender key state exists, a new key is generated and distributed."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )

        # Group resolve
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={
                "items": [{"id": GROUP_ID, "handle": GROUP_HANDLE}]
            })
        )

        # Members
        member1_jwk = _make_enc_jwk(MEMBER_ID_1, tmp_config_dir)
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={
                "items": [
                    {"agent_id": MEMBER_ID_1, "role": "member"},
                ]
            })
        )

        # Recipient keys fetch for distribution
        respx.get(f"https://rine.network/agents/{MEMBER_ID_1}/keys").mock(
            return_value=httpx.Response(200, json={
                "agent_id": MEMBER_ID_1,
                "encryption_public_key": member1_jwk,
                "signing_public_key": signing_public_key_to_jwk(
                    generate_agent_keys().signing.public_key
                ),
            })
        )

        # Message post for distribution
        respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(200, json={
                "id": "dddddddd-eeee-ffff-0000-111111111111",
                "conversation_id": "dddddddd-eeee-ffff-0000-111111111112",
                "from_agent_id": AGENT_ID,
                "to_agent_id": MEMBER_ID_1,
                "type": MessageType.SENDER_KEY_DISTRIBUTION,
                "encrypted_payload": "abc",
                "encryption_version": "hpke-v1",
                "sender_signing_kid": f"rine:{AGENT_ID}",
                "created_at": "2024-01-01T00:00:00Z",
            })
        )

        http = _make_http_client(tmp_config_dir)
        state, returned_group_id = get_or_create_sender_key_sync(
            http, tmp_config_dir, AGENT_ID, GROUP_HANDLE
        )
        http.close()

        assert returned_group_id == GROUP_ID
        assert isinstance(state, SenderKeyState)
        assert state.sender_agent_id == AGENT_ID
        assert len(state.chain_key) == 32

    @respx.mock
    def test_raises_not_found_when_group_missing(self, tmp_config_dir, saved_agent_keys):
        """get_or_create_sender_key_sync raises NotFoundError when group doesn't exist."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        http = _make_http_client(tmp_config_dir)
        with pytest.raises(NotFoundError, match="Group not found"):
            get_or_create_sender_key_sync(
                http, tmp_config_dir, AGENT_ID, "#nonexistent-group@org.rine.network"
            )
        http.close()

    @respx.mock
    def test_returns_existing_key_when_valid(self, tmp_config_dir, saved_agent_keys):
        """When a valid, non-rotated sender key exists, it is returned without generating a new one."""
        from rine._crypto.sender_keys_helpers import save_sender_key_state
        import time

        # Pre-populate state
        existing_state = generate_sender_key(GROUP_ID, AGENT_ID)
        existing_state.distributed_to = [MEMBER_ID_1]
        existing_state.created_at = int(time.time() * 1000)
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [existing_state])

        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(200, json={
                "items": [{"id": GROUP_ID, "handle": GROUP_HANDLE}]
            })
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={
                "items": [{"agent_id": MEMBER_ID_1, "role": "member"}]
            })
        )

        http = _make_http_client(tmp_config_dir)
        state, returned_group_id = get_or_create_sender_key_sync(
            http, tmp_config_dir, AGENT_ID, GROUP_HANDLE
        )
        http.close()

        assert returned_group_id == GROUP_ID
        assert state.sender_key_id == existing_state.sender_key_id


class TestDistributeSenderKeySync:
    @respx.mock
    def test_distributes_to_multiple_recipients(self, tmp_config_dir, saved_agent_keys):
        """distribute_sender_key_sync sends a message to each recipient."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )

        member2_jwk = _make_enc_jwk(MEMBER_ID_2, tmp_config_dir)

        for member_id, jwk in [(MEMBER_ID_1, _make_enc_jwk(MEMBER_ID_1, tmp_config_dir)),
                                (MEMBER_ID_2, member2_jwk)]:
            respx.get(f"https://rine.network/agents/{member_id}/keys").mock(
                return_value=httpx.Response(200, json={
                    "agent_id": member_id,
                    "encryption_public_key": jwk,
                    "signing_public_key": signing_public_key_to_jwk(
                        generate_agent_keys().signing.public_key
                    ),
                })
            )

        msg_route = respx.post("https://rine.network/messages").mock(
            return_value=httpx.Response(200, json={
                "id": "dddddddd-eeee-ffff-0000-111111111111",
                "conversation_id": "dddddddd-eeee-ffff-0000-111111111112",
                "from_agent_id": AGENT_ID,
                "to_agent_id": MEMBER_ID_1,
                "type": MessageType.SENDER_KEY_DISTRIBUTION,
                "encrypted_payload": "abc",
                "encryption_version": "hpke-v1",
                "sender_signing_kid": f"rine:{AGENT_ID}",
                "created_at": "2024-01-01T00:00:00Z",
            })
        )

        state = generate_sender_key(GROUP_ID, AGENT_ID)
        http = _make_http_client(tmp_config_dir)
        succeeded, failed = distribute_sender_key_sync(
            http,
            tmp_config_dir,
            AGENT_ID,
            state,
            GROUP_ID,
            [MEMBER_ID_1, MEMBER_ID_2],
        )
        http.close()

        assert len(succeeded) == 2
        assert MEMBER_ID_1 in succeeded
        assert MEMBER_ID_2 in succeeded
        assert failed == []
        assert msg_route.call_count == 2

    @respx.mock
    def test_records_failed_recipients(self, tmp_config_dir, saved_agent_keys):
        """distribute_sender_key_sync records failures without raising."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )

        # First member: key fetch returns 404
        respx.get(f"https://rine.network/agents/{MEMBER_ID_1}/keys").mock(
            return_value=httpx.Response(404, json={"detail": "not found"})
        )

        state = generate_sender_key(GROUP_ID, AGENT_ID)
        http = _make_http_client(tmp_config_dir)
        succeeded, failed = distribute_sender_key_sync(
            http,
            tmp_config_dir,
            AGENT_ID,
            state,
            GROUP_ID,
            [MEMBER_ID_1],
        )
        http.close()

        assert MEMBER_ID_1 in failed
        assert succeeded == []
