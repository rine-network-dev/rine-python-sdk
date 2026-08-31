"""Phase-0 SDK fixes for the crewai-rine integration (TDD — RED first).

Covers four small fixes for the crewai-rine integration:

- ``inbox(status=...)`` forwards the status filter to the inbox GET, and
  a new ``mark_delivered(agent_id, message_ids)`` method POSTs to the server's
  ``/agents/{id}/messages/mark-delivered`` endpoint. Sync + async.
- ``_decrypt_message`` (reached via ``read()``) sets a clear
  ``decrypt_error`` naming the unhandled ``encryption_version`` instead of
  silently returning the message with ``decrypt_error=None``. Sync + async.
- ``rine.__version__`` matches ``pyproject.toml`` (0.2.0), read from the
  file so it can't drift again.
- A group send routes by the resolved ``/groups`` payload: ``mls_pending``
  (like ``mls_group_id``) means MLS, and must never reach the sender-key path.

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
from rine._group_send import encrypt_for_group_sync
from rine._http import SyncHttpClient
from rine.errors import CryptoError
from tests.conftest import recipient_view

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


def _build_message_payload(
    encryption_version: str, encrypted_payload: str, group_id: str | None = None
) -> dict:
    return {
        "id": MESSAGE_ID,
        "group_id": group_id,
        "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
        "from_agent_id": AGENT_ID,
        "to_agent_id": AGENT_ID,
        "type": MessageType.TASK_REQUEST,
        "encrypted_payload": encrypted_payload,
        "encryption_version": encryption_version,
        "sender_signing_kid": f"rine:{AGENT_ID}",
        "created_at": "2024-01-01T00:00:00Z",
    }


def _mock_unreachable_mls_group() -> None:
    """An MLS group this agent can neither be welcomed into nor self-join."""
    respx.get(f"https://rine.network/agents/{AGENT_ID}/mls/welcomes").mock(
        return_value=httpx.Response(200, json={"welcomes": []})
    )
    respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": GROUP_ID,
                "name": "g",
                "handle": GROUP_HANDLE,
                "created_at": "2024-01-01T00:00:00Z",
                "mls_enabled": True,
                "mls_group_id": "99999999-0000-1111-2222-333333333333",
                "mls_pending": False,
            },
        )
    )
    respx.get(f"https://rine.network/groups/{GROUP_ID}/mls/group-info").mock(
        return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
    )


def _self_encrypt(config_dir: str, payload: dict) -> str:
    """Encrypt ``payload`` from AGENT_ID to AGENT_ID (self-readable)."""
    own = recipient_view(load_agent_keys(config_dir, AGENT_ID))
    result = encrypt_message(config_dir, AGENT_ID, own, payload)
    return result.encrypted_payload


# =====================================================================
# inbox(status=) filter + mark_delivered()
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
        # It is resolved against the org's OWN agents — an acting agent is one
        # the caller owns, so the actor slot asks ``GET /agents`` and never
        # WebFinger, which answers for anybody's org and is the recipient
        # resolver's question.
        _mock_token()
        _mock_agents()
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
        # The sync twin states why this is ``GET /agents`` and not WebFinger.
        _mock_token()
        _mock_agents()
        route = respx.post(f"https://rine.network/agents/{AGENT_ID}/messages/mark-delivered").mock(
            return_value=httpx.Response(200, json={"marked": 1})
        )

        result = await async_client.mark_delivered([MESSAGE_ID], agent="test-agent@myorg")

        assert route.called
        assert AGENT_ID in str(route.calls[0].request.url)
        assert result == 1
        await async_client.close()


# =====================================================================
# decrypt_error on unknown encryption_version (no silent passthrough)
# =====================================================================

#: A version this SDK has never heard of. It used to be `hpke-hybrid-v1`, which
#: the SDK now decrypts — the row this pins is one from a FUTURE scheme, which
#: must still fail loud rather than arrive as empty plaintext.
_UNKNOWN_VERSION = "hpke-from-the-future-v9"


class TestUnknownEncryptionVersionSync:
    @respx.mock
    def test_read_unknown_encryption_version_sets_decrypt_error(self, sync_client, tmp_config_dir):
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200, json=_build_message_payload(_UNKNOWN_VERSION, "ZHVtbXk=")
            )
        )

        msg = sync_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert _UNKNOWN_VERSION in msg.decrypt_error
        assert msg.plaintext is None

    @respx.mock
    def test_read_mls_message_this_agent_cannot_join_fails_by_name(
        self, sync_client, tmp_config_dir
    ):
        """An MLS row is decrypted for real now, so an unreachable group must say so.

        No Welcome is waiting and the group has published no GroupInfo, so the
        read path's one-shot recovery cannot establish state. That surfaces as a
        ``decrypt_error`` naming the group — never as a silently undecrypted
        message, and never as an exception (``read()`` degrades like ``inbox()``).
        """
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        _mock_unreachable_mls_group()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200,
                json=_build_message_payload(EncryptionVersion.MLS_V1, "BAAB", group_id=GROUP_ID),
            )
        )

        msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert GROUP_ID in msg.decrypt_error

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
                200, json=_build_message_payload(_UNKNOWN_VERSION, "ZHVtbXk=")
            )
        )

        msg = await async_client.read(MESSAGE_ID)

        assert msg.decrypt_error is not None
        assert _UNKNOWN_VERSION in msg.decrypt_error
        assert msg.plaintext is None
        await async_client.close()

    @respx.mock
    async def test_read_mls_message_this_agent_cannot_join_fails_by_name(
        self, async_client, tmp_config_dir
    ):
        """Async counterpart: the same refusal, through the same implementation."""
        _CONFIG_DIR_HOLDER["dir"] = tmp_config_dir
        _mock_token()
        _mock_agents()
        _mock_unreachable_mls_group()
        respx.get(f"https://rine.network/messages/{MESSAGE_ID}").mock(
            return_value=httpx.Response(
                200,
                json=_build_message_payload(EncryptionVersion.MLS_V1, "BAAB", group_id=GROUP_ID),
            )
        )

        msg = await async_client.read(MESSAGE_ID)
        await async_client.close()

        assert msg.plaintext is None
        assert GROUP_ID in msg.decrypt_error

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
# _version.py matches pyproject.toml
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
# sender-key latch widened to mls_pending
# =====================================================================


def _make_http_client(tmp_config_dir: str) -> SyncHttpClient:
    save_credentials(tmp_config_dir, {"default": {"client_id": "cid", "client_secret": "csecret"}})
    return SyncHttpClient(config_dir=tmp_config_dir, api_url="https://rine.network")


class TestGroupSendRoutesMlsAwayFromSenderKeys:
    """The send dispatcher, not the sender-key path, decides which crypto a group gets.

    The server refuses a ``sender-key-v1`` send to an MLS (or MLS-initializing)
    group, so routing it there would produce an undeliverable message. These
    pin the routing decision itself, which is cheaper and more direct than
    driving a whole encrypt to observe it.
    """

    @respx.mock
    def test_mls_group_send_never_reaches_the_sender_key_path(
        self, tmp_config_dir, saved_agent_keys
    ):
        """Routing is proven by what is NOT called: no member fan-out, no distribution."""
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
                            "name": "g",
                            "handle": GROUP_HANDLE,
                            "created_at": "2024-01-01T00:00:00Z",
                            "mls_enabled": True,
                            "mls_group_id": None,
                            "mls_pending": True,
                        }
                    ]
                },
            )
        )
        members = respx.get(f"https://rine.network/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        # The MLS path with no local state: pre-sync fails quietly, then recovery
        # runs and cannot establish state either.
        respx.get(f"https://rine.network/groups/{GROUP_ID}/mls/handshakes").mock(
            return_value=httpx.Response(200, json={"handshakes": []})
        )
        respx.get(f"https://rine.network/agents/{AGENT_ID}/mls/welcomes").mock(
            return_value=httpx.Response(200, json={"welcomes": []})
        )
        respx.get(f"https://rine.network/groups/{GROUP_ID}/mls/group-info").mock(
            return_value=httpx.Response(200, json={"group_info": None, "epoch": None})
        )

        http = _make_http_client(tmp_config_dir)
        try:
            with pytest.raises(CryptoError, match=GROUP_ID):
                encrypt_for_group_sync(http, tmp_config_dir, AGENT_ID, GROUP_HANDLE, {"a": 1})
        finally:
            http.close()

        assert not members.called, "an MLS group must never be fanned out to sender keys"
