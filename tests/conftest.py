"""Shared fixtures for rine SDK tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import pytest

from rine._crypto.dm_envelope import RecipientKeys, recipient_keys_from_response
from rine._crypto.keys import generate_agent_keys, public_keys_body, save_agent_keys


def recipient_view(keys) -> RecipientKeys:
    """An agent's keys as a sender fetches them, through the published form.

    Round-tripping through ``public_keys_body`` keeps the tests honest about
    what actually reaches the wire — including whether a post-quantum key is
    advertised, which is what decides the envelope version.
    """
    return recipient_keys_from_response(public_keys_body(keys))


def signing_fingerprint(keys) -> str:
    """Fingerprint a keypair's signing key from its raw bytes.

    Derived straight from the 32 key bytes rather than through the SDK helper,
    so a test asserting a reported fingerprint checks the value and not just
    that the implementation agrees with itself.
    """
    return hashlib.sha256(keys.signing.public_key).hexdigest()


@pytest.fixture(autouse=True)
def _no_ambient_acting_agent(monkeypatch):
    """Keep the developer's own ``RINE_AGENT`` out of every test in this package.

    The client constructor reads it (rung 3 of the ladder), so a machine that
    exports one would silently give every client an actor the test never asked
    for. A test that wants the env rung sets it itself, after this has run.
    """
    monkeypatch.delenv("RINE_AGENT", raising=False)


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Provide a temporary config directory."""
    return str(tmp_path)


@pytest.fixture
def agent_keys():
    """Generate fresh agent keys."""
    return generate_agent_keys()


@pytest.fixture
def agent_id():
    """Provide a fixed agent UUID."""
    return "00000000-1111-2222-3333-444444444444"


@pytest.fixture
def other_agent_id():
    """Provide a second fixed agent UUID."""
    return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def saved_agent_keys(tmp_config_dir, agent_id, agent_keys):
    """Save agent keys to disk and return them."""
    save_agent_keys(tmp_config_dir, agent_id, agent_keys)
    return agent_keys


@pytest.fixture
def sync_client(tmp_config_dir, saved_agent_keys, agent_id):
    """Pre-configured SyncRineClient with saved credentials and keys."""
    from rine._config import save_credentials

    save_credentials(
        tmp_config_dir, {"default": {"client_id": "test-cid", "client_secret": "test-csecret"}}
    )
    from rine import SyncRineClient

    client = SyncRineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
    yield client
    client.close()


@pytest.fixture
def async_client(tmp_config_dir, saved_agent_keys, agent_id):
    """Pre-configured RineClient with saved credentials and keys."""
    from rine._config import save_credentials

    save_credentials(
        tmp_config_dir, {"default": {"client_id": "test-cid", "client_secret": "test-csecret"}}
    )
    from rine import RineClient

    client = RineClient(config_dir=tmp_config_dir, api_url="https://rine.network")
    return client


# --- Cold sender-key group message (shared by the sync and async receive tests) ---

_API_URL = "https://rine.network"
_GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_GROUP_MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000101"
_DISTRIBUTION_ID = "cccccccc-dddd-eeee-ffff-000000000102"


@dataclass(frozen=True)
class GroupMessageFixture:
    """A sender-key group message the recipient cannot open yet.

    Reproduces the live cold-group case: a foreign agent sealed a group message
    with a sender key the recipient has never ingested, and the matching
    distribution DM is still sitting unread on the server.
    """

    group_id: str
    sender_id: str
    message_id: str
    plaintext: str
    message_row: dict
    distribution_row: dict
    sender_key_jwks: dict


@pytest.fixture
def group_message_fixture(tmp_config_dir, agent_id, other_agent_id, saved_agent_keys):
    """Build a cold sender-key group message plus its distribution DM."""
    from rine._constants import MessageType
    from rine._crypto.keys import (
        encryption_public_key_to_jwk,
        load_agent_keys,
        signing_public_key_to_jwk,
    )
    from rine._crypto.message import encrypt_group_message, encrypt_message
    from rine._crypto.sender_keys import generate_sender_key
    from rine._utils import to_base64url

    sender_keys = generate_agent_keys()
    save_agent_keys(tmp_config_dir, other_agent_id, sender_keys)

    state = generate_sender_key(_GROUP_ID, other_agent_id)
    distribution_payload = {
        "group_id": _GROUP_ID,
        "sender_key_id": state.sender_key_id,
        "chain_key": to_base64url(state.chain_key),
        "message_index": state.message_index,
        "sender_agent_id": other_agent_id,
    }

    payload = {"text": "hello group"}
    sealed, _ = encrypt_group_message(tmp_config_dir, other_agent_id, _GROUP_ID, state, payload)

    recipient = recipient_view(load_agent_keys(tmp_config_dir, agent_id))
    distribution = encrypt_message(tmp_config_dir, other_agent_id, recipient, distribution_payload)

    def _row(message_id: str, msg_type: str, result, **extra) -> dict:
        return {
            "id": message_id,
            "conversation_id": "cccccccc-dddd-eeee-ffff-000000000103",
            "from_agent_id": other_agent_id,
            "to_agent_id": agent_id,
            "type": msg_type,
            "encrypted_payload": result.encrypted_payload,
            "encryption_version": result.encryption_version,
            "sender_signing_kid": result.sender_signing_kid,
            "created_at": "2024-01-01T00:00:00Z",
            **extra,
        }

    return GroupMessageFixture(
        group_id=_GROUP_ID,
        sender_id=other_agent_id,
        message_id=_GROUP_MESSAGE_ID,
        plaintext=json.dumps(payload, separators=(",", ":")),
        message_row=_row(
            _GROUP_MESSAGE_ID,
            MessageType.TASK_REQUEST,
            sealed,
            group_id=_GROUP_ID,
            to_agent_id=None,
        ),
        distribution_row=_row(_DISTRIBUTION_ID, MessageType.SENDER_KEY_DISTRIBUTION, distribution),
        sender_key_jwks={
            "agent_id": other_agent_id,
            "encryption_public_key": encryption_public_key_to_jwk(
                sender_keys.encryption.public_key
            ),
            "signing_public_key": signing_public_key_to_jwk(sender_keys.signing.public_key),
        },
    )


@pytest.fixture
def mock_group_message_routes(group_message_fixture, agent_id):
    """Return a callable registering every route the cold-group flow needs.

    Call it from inside the test's ``respx.mock`` context — respx routes cannot
    be registered during fixture setup, which runs before the mock is active.
    """
    import httpx
    import respx

    from rine._constants import MessageType

    fx = group_message_fixture

    def _register() -> None:
        respx.post(f"{_API_URL}/oauth/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "test-token", "expires_in": 900}
            )
        )
        respx.get(f"{_API_URL}/agents").mock(
            return_value=httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": agent_id,
                            "name": "test-agent",
                            "handle": "test-agent@myorg.rine.network",
                            "human_oversight": True,
                            "incoming_policy": "accept_all",
                            "outgoing_policy": "send_all",
                            "created_at": "2024-01-01T00:00:00Z",
                        }
                    ]
                },
            )
        )
        respx.get(f"{_API_URL}/agents/{fx.sender_id}/keys").mock(
            return_value=httpx.Response(200, json=fx.sender_key_jwks)
        )
        # Registered before the unfiltered inbox route: respx matches in
        # registration order, and both share the same path.
        respx.get(
            f"{_API_URL}/agents/{agent_id}/messages",
            params={"type": MessageType.SENDER_KEY_DISTRIBUTION},
        ).mock(
            return_value=httpx.Response(200, json={"items": [{"id": fx.distribution_row["id"]}]})
        )
        respx.get(f"{_API_URL}/messages/{fx.distribution_row['id']}").mock(
            return_value=httpx.Response(200, json=fx.distribution_row)
        )
        respx.get(f"{_API_URL}/messages/{fx.message_id}").mock(
            return_value=httpx.Response(200, json=fx.message_row)
        )
        respx.get(f"{_API_URL}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": [fx.message_row], "total": 1})
        )

    return _register
