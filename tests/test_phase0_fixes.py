"""Phase-0 SDK fixes for the crewai-rine integration (TDD — RED first).

Covers the four small fixes from ``phases/crewai-integration/DECISIONS.md``:

- **P0-1** ``inbox(status=...)`` forwards the status filter to the inbox GET, and
  a new ``mark_delivered(agent_id, message_ids)`` method POSTs to the server's
  ``/agents/{id}/messages/mark-delivered`` endpoint. Sync + async.
- **P0-2** ``_decrypt_message`` (reached via ``read()``) sets a clear
  ``decrypt_error`` naming the unhandled ``encryption_version`` instead of
  silently returning the message with ``decrypt_error=None``. Sync + async.
- **P0-3** ``rine.__version__`` matches ``pyproject.toml`` (0.2.0), read from the
  file so it can't drift again.
- **P0-4** The sender-key send latch raises ``MlsUnsupportedError`` when the
  resolved ``/groups`` payload signals ``mls_pending`` (in addition to the
  existing ``mls_group_id`` case).

All HTTP is mocked with respx; no DB. Server contract verified against
``src/rine/api/messages.py`` (mark-delivered handler + ``_status_filter``) and
``src/rine/api/group_schemas.py`` / ``src/rine/api/schemas.py``:
- mark-delivered request body field is ``message_ids`` (list of UUIDs);
  response is ``{"marked": int}``.
- the ``/groups`` payload carries a top-level boolean ``mls_pending``.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._config import save_credentials
from rine._constants import EncryptionVersion, MessageType
from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    load_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.message import encrypt_message
from rine._http import SyncHttpClient
from rine._sender_key_ops import get_or_create_sender_key_sync
from rine.errors import MlsUnsupportedError

AGENT_ID = "00000000-1111-2222-3333-444444444444"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP_HANDLE = "#my-group@myorg.rine.network"
MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000001"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}

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


def _mock_own_signing_keys() -> None:
    """Mock the agent's own signing-key fetch used during read() verification."""
    respx.get(f"https://rine.network/agents/{AGENT_ID}/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "agent_id": AGENT_ID,
                "encryption_public_key": encryption_public_key_to_jwk(
                    load_agent_keys(_CONFIG_DIR_HOLDER["dir"], AGENT_ID).encryption.public_key
                ),
                "signing_public_key": signing_public_key_to_jwk(
                    load_agent_keys(_CONFIG_DIR_HOLDER["dir"], AGENT_ID).signing.public_key
                ),
            },
        )
    )


# Tiny holder so the signing-key mock can reach the active config dir without
# threading it through every call site.
_CONFIG_DIR_HOLDER: dict[str, str] = {"dir": ""}


def _build_message_payload(encryption_version: str, encrypted_payload: str) -> dict:
    return {
        "id": MESSAGE_ID,
        "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
        "from_agent_id": AGENT_ID,
        "to_agent_id": AGENT_ID,
        "type": MessageType.TASK_REQUEST,
        "encrypted_payload": encrypted_payload,
        "encryption_version": encryption_version,
        "sender_signing_kid": f"rine:{AGENT_ID}",
        "created_at": "2024-01-01T00:00:00Z",
    }


def _self_encrypt(config_dir: str, payload: dict) -> str:
    """HPKE-encrypt ``payload`` from AGENT_ID to AGENT_ID (self-readable)."""
    own_pk = load_agent_keys(config_dir, AGENT_ID).encryption.public_key
    result = encrypt_message(config_dir, AGENT_ID, own_pk, payload)
    return result.encrypted_payload


# =====================================================================
# P0-1: inbox(status=) filter + mark_delivered()
# =====================================================================


class TestInboxStatusFilterSync:
    @respx.mock
    def test_inbox_with_status_new_forwards_status_param(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        sync_client.inbox(status="new")

        assert route.called
        assert b"status=new" in route.calls[0].request.url.query

    @respx.mock
    def test_inbox_without_status_omits_status_param(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        sync_client.inbox()

        assert route.called
        assert b"status=" not in route.calls[0].request.url.query


class TestInboxStatusFilterAsync:
    @respx.mock
    async def test_inbox_with_status_new_forwards_status_param(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        await async_client.inbox(status="new")

        assert route.called
        assert b"status=new" in route.calls[0].request.url.query
        await async_client.close()

    @respx.mock
    async def test_inbox_without_status_omits_status_param(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.get(f"https://rine.network/agents/{AGENT_ID}/messages").mock(
            return_value=httpx.Response(200, json={"items": [], "total": 0})
        )

        await async_client.inbox()

        assert route.called
        assert b"status=" not in route.calls[0].request.url.query
        await async_client.close()


def _mock_webfinger(handle: str, agent_id: str) -> None:
    """Mock WebFinger so an explicit handle resolves to ``agent_id``."""
    respx.get("https://rine.network/.well-known/webfinger").mock(
        return_value=httpx.Response(
            200,
            json={
                "subject": f"acct:{handle}",
                "aliases": [f"https://rine.network/agents/{agent_id}"],
            },
        )
    )


class TestMarkDeliveredSync:
    @respx.mock
    def test_mark_delivered_resolves_default_agent_and_posts_message_ids(self, sync_client):
        # New public signature: mark_delivered(message_ids, *, agent=None).
        # With agent=None the single org agent is auto-resolved via /agents.
        _mock_token()
        _mock_agents()
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/messages/mark-delivered").mock(
            return_value=httpx.Response(200, json={"marked": 2})
        )

        result = sync_client.mark_delivered([MESSAGE_ID, OTHER_AGENT_ID])

        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body == {"message_ids": [MESSAGE_ID, OTHER_AGENT_ID]}
        assert result == 2

    @respx.mock
    def test_mark_delivered_empty_list_marks_none(self, sync_client):
        _mock_token()
        _mock_agents()
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/messages/mark-delivered").mock(
            return_value=httpx.Response(200, json={"marked": 0})
        )

        result = sync_client.mark_delivered([])

        assert route.called
        assert result == 0

    @respx.mock
    def test_mark_delivered_resolves_explicit_agent_handle(self, sync_client):
        # agent= accepts a handle and resolves it internally (no pre-resolved id).
        _mock_token()
        _mock_webfinger("test-agent@myorg.rine.network", AGENT_ID)
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/messages/mark-delivered").mock(
            return_value=httpx.Response(200, json={"marked": 1})
        )

        result = sync_client.mark_delivered([MESSAGE_ID], agent="test-agent@myorg")

        assert route.called
        # The path carried the resolved UUID, not the handle.
        assert AGENT_ID in str(route.calls[0].request.url)
        assert result == 1


class TestMarkDeliveredAsync:
    @respx.mock
    async def test_mark_delivered_resolves_default_agent_and_posts_message_ids(self, async_client):
        _mock_token()
        _mock_agents()
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/messages/mark-delivered").mock(
            return_value=httpx.Response(200, json={"marked": 2})
        )

        result = await async_client.mark_delivered([MESSAGE_ID, OTHER_AGENT_ID])

        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body == {"message_ids": [MESSAGE_ID, OTHER_AGENT_ID]}
        assert result == 2
        await async_client.close()

    @respx.mock
    async def test_mark_delivered_resolves_explicit_agent_handle(self, async_client):
        _mock_token()
        _mock_webfinger("test-agent@myorg.rine.network", AGENT_ID)
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/messages/mark-delivered").mock(
            return_value=httpx.Response(200, json={"marked": 1})
        )

        result = await async_client.mark_delivered([MESSAGE_ID], agent="test-agent@myorg")

        assert route.called
        assert AGENT_ID in str(route.calls[0].request.url)
        assert result == 1
        await async_client.close()


# =====================================================================
# P0-2: decrypt_error on unknown encryption_version (no silent passthrough)
# =====================================================================


class TestUnknownEncryptionVersionSync:
    @respx.mock
    def test_read_unknown_encryption_version_sets_decrypt_error(self, sync_client, tmp_config_dir):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload("hpke-hybrid-v1", "ZHVtbXk=")
            )
        )

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert "hpke-hybrid-v1" in msg.decrypt_error
        assert msg.plaintext is None

    @respx.mock
    def test_read_mls_message_still_sets_mls_marker(self, sync_client, tmp_config_dir):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload(EncryptionVersion.MLS_V1, "ZHVtbXk=")
            )
        )

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert "MLS" in msg.decrypt_error

    @respx.mock
    def test_read_normal_hpke_message_still_decrypts(self, sync_client, tmp_config_dir):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        _mock_own_signing_keys()
        ciphertext = _self_encrypt(tmp_config_dir, {"text": "hello world"})
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload(EncryptionVersion.HPKE_V1, ciphertext)
            )
        )

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is None
        assert msg.plaintext is not None
        assert "hello world" in msg.plaintext


class TestUnknownEncryptionVersionAsync:
    @respx.mock
    async def test_read_unknown_encryption_version_sets_decrypt_error(
        self, async_client, tmp_config_dir
    ):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload("hpke-hybrid-v1", "ZHVtbXk=")
            )
        )

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert "hpke-hybrid-v1" in msg.decrypt_error
        assert msg.plaintext is None
        await async_client.close()

    @respx.mock
    async def test_read_mls_message_still_sets_mls_marker(self, async_client, tmp_config_dir):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload(EncryptionVersion.MLS_V1, "ZHVtbXk=")
            )
        )

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert "MLS" in msg.decrypt_error
        await async_client.close()

    @respx.mock
    async def test_read_normal_hpke_message_still_decrypts(self, async_client, tmp_config_dir):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        _mock_own_signing_keys()
        ciphertext = _self_encrypt(tmp_config_dir, {"text": "hello world"})
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload(EncryptionVersion.HPKE_V1, ciphertext)
            )
        )

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is None
        assert msg.plaintext is not None
        assert "hello world" in msg.plaintext
        await async_client.close()


# =====================================================================
# P0-3: _version.py matches pyproject.toml
# =====================================================================


def _read_pyproject_version() -> str:
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    return str(data["project"]["version"])


class TestVersionConsistency:
    def test_version_matches_pyproject(self):
        from rine._version import __version__ as version_module

        assert version_module == _read_pyproject_version()

    def test_package_dunder_version_matches_pyproject(self):
        import rine

        assert rine.__version__ == _read_pyproject_version()


# =====================================================================
# P0-4: sender-key latch widened to mls_pending
# =====================================================================


def _make_http_client(tmp_config_dir: str) -> SyncHttpClient:
    save_credentials(tmp_config_dir, {"default": {"client_id": "cid", "client_secret": "csecret"}})
    return SyncHttpClient(config_dir=tmp_config_dir, api_url="https://rine.network")


class TestSenderKeyLatchMlsPending:
    @respx.mock
    def test_raises_mls_unsupported_when_group_mls_pending(self, tmp_config_dir, saved_agent_keys):
        """A group payload with mls_pending=True must trip the local latch."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": GROUP_ID,
                            "handle": GROUP_HANDLE,
                            "mls_group_id": None,
                            "mls_pending": True,
                        }
                    ]
                },
            )
        )
        # Members mocked empty so that, while the latch is NOT yet widened, the
        # call completes WITHOUT raising — making the assertion fail cleanly with
        # "DID NOT RAISE MlsUnsupportedError" rather than an unmocked-request error.
        respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        http = _make_http_client(tmp_config_dir)
        try:
            with pytest.raises(MlsUnsupportedError):
                get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, GROUP_HANDLE)
        finally:
            http.close()

    @respx.mock
    def test_raises_mls_unsupported_when_group_has_mls_group_id(
        self, tmp_config_dir, saved_agent_keys
    ):
        """Existing latch case: mls_group_id set still raises (regression guard)."""
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
        )
        respx.get("https://rine.network/groups").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": GROUP_ID,
                            "handle": GROUP_HANDLE,
                            "mls_group_id": "some-mls-id",
                            "mls_pending": False,
                        }
                    ]
                },
            )
        )

        http = _make_http_client(tmp_config_dir)
        try:
            with pytest.raises(MlsUnsupportedError):
                get_or_create_sender_key_sync(http, tmp_config_dir, AGENT_ID, GROUP_HANDLE)
        finally:
            http.close()
