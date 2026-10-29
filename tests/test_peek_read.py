"""``read(peek=True)`` — the read that does not consume the message.

A plain ``read()`` marks the message delivered for the acting agent before the
client has attempted a decrypt, and there is no un-mark route: the row leaves
``inbox(status="new")``, ``poll()`` and SSE catch-up whether or not the caller
could open it. ``peek=True`` sends ``X-Rine-Peek`` and the server suppresses
that write and nothing else.

Every test here exists in a sync/async pair, deliberately: the two clients are
independent hand-kept copies, so a kwarg added to one is not added to the other,
and a header spelled two ways is this package's most-paid-for defect class. The
pairs sit next to each other rather than in two files for the reason
``test_mls_messages`` gives for the same shape — a missing twin is visible.
"""

from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from rine import RineClient, SyncRineClient
from rine._actor import AGENT_HEADER
from rine._constants import PEEK_HEADER, EncryptionVersion
from rine._crypto.keys import load_agent_keys, make_kid, save_agent_keys
from rine._crypto.message import encrypt_message
from rine.testing import WORLD
from tests.conftest import recipient_view

API = "https://rine.network"
MESSAGE_ID = "cccccccc-dddd-eeee-ffff-000000000201"
CONVERSATION_ID = "cccccccc-dddd-eeee-ffff-000000000202"
TYPE = "rine.v1.task_request"


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "test-token", "expires_in": 900})
    )


def _mock_agents(agent_id: str) -> None:
    respx.get(f"{API}/agents").mock(
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


def _row(sender_id: str, agent_id: str, *, payload: str, version: str, kid: str | None) -> dict:
    return {
        "id": MESSAGE_ID,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": sender_id,
        "to_agent_id": agent_id,
        "type": TYPE,
        "encrypted_payload": payload,
        "encryption_version": version,
        "sender_signing_kid": kid,
        "created_at": "2024-01-01T00:00:00Z",
    }


def _mock_readable_dm(tmp_config_dir: str, agent_id: str, sender_id: str, payload: dict) -> None:
    """One openable 1:1 row on ``GET /messages/{id}``, sealed to this agent.

    Sealed with :func:`encrypt_message` rather than hand-built, so the kwarg is
    exercised against a row that really decrypts — a wire-only test would pass
    on a client that sent the header and then dropped the plaintext.
    """
    save_agent_keys(tmp_config_dir, sender_id, WORLD.keys(sender_id))
    recipient = recipient_view(load_agent_keys(tmp_config_dir, agent_id), agent_id)
    sealed = encrypt_message(tmp_config_dir, sender_id, recipient, payload)

    respx.get(f"{API}/agents/{sender_id}/keys").mock(
        return_value=httpx.Response(200, json=WORLD.keys_response(sender_id))
    )
    respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(
            200,
            json=_row(
                sender_id,
                agent_id,
                payload=sealed.encrypted_payload,
                version=sealed.encryption_version,
                kid=sealed.sender_signing_kid,
            ),
        )
    )


def _mock_unopenable_dm(sender_id: str, agent_id: str) -> respx.Route:
    """A 1:1 row whose envelope is not an envelope: it degrades, never raises."""
    return respx.get(f"{API}/messages/{MESSAGE_ID}").mock(
        return_value=httpx.Response(
            200,
            json=_row(
                sender_id,
                agent_id,
                payload="bm90LWFuLWVudmVsb3Bl",
                version=EncryptionVersion.HPKE_HYBRID_V2,
                kid=make_kid(sender_id, 0),
            ),
        )
    )


class TestTheDefaultDoesNotMove:
    """The opt-out is opt-in: a plain ``read()`` is the read it has always been."""

    @respx.mock
    def test_read_sends_no_peek_header_by_default(self, sync_client, agent_id, other_agent_id):
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        sync_client.read(MESSAGE_ID)

        assert PEEK_HEADER not in route.calls[0].request.headers

    @respx.mock
    async def test_read_sends_no_peek_header_by_default_async(
        self, async_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        await async_client.read(MESSAGE_ID)

        assert PEEK_HEADER not in route.calls[0].request.headers

    @respx.mock
    def test_a_read_whose_decrypt_fails_does_not_retroactively_peek(
        self, sync_client, agent_id, other_agent_id
    ):
        """The client half of "a failed read still consumes the row".

        The mark is already stamped when the body arrives, so the SDK cannot
        undo it and must not appear to try: one request, no peek header, and the
        failure reported on the row. This is the loss the opt-out exists for, and
        it is pinned here deliberately rather than left as an absent test.
        """
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        msg = sync_client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert route.call_count == 1
        assert PEEK_HEADER not in route.calls[0].request.headers

    @respx.mock
    async def test_a_read_whose_decrypt_fails_does_not_retroactively_peek_async(
        self, async_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        msg = await async_client.read(MESSAGE_ID)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert route.call_count == 1
        assert PEEK_HEADER not in route.calls[0].request.headers


class TestPeekReachesTheWire:
    @respx.mock
    def test_read_with_peek_sends_the_peek_header_and_still_names_the_actor(
        self, sync_client, agent_id, other_agent_id
    ):
        """Both halves, and the second is the load-bearing one.

        Suppressing the mark by *dropping* ``X-Rine-Agent`` was the rejected
        design: it would change which delivery row is resolved and which
        diagnostic runs, and for a one-agent org the server auto-selects and
        marks anyway. A client that dropped the actor header would satisfy the
        first assertion here and fail the second.
        """
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        sync_client.read(MESSAGE_ID, agent=agent_id, peek=True)

        headers = route.calls[0].request.headers
        assert headers[PEEK_HEADER] == "1"
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    async def test_read_with_peek_sends_the_peek_header_and_still_names_the_actor_async(
        self, async_client, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        route = _mock_unopenable_dm(other_agent_id, agent_id)

        await async_client.read(MESSAGE_ID, agent=agent_id, peek=True)

        headers = route.calls[0].request.headers
        assert headers[PEEK_HEADER] == "1"
        assert headers[AGENT_HEADER] == agent_id

    @respx.mock
    def test_a_peek_read_still_decrypts_and_returns_the_row(
        self, sync_client, tmp_config_dir, agent_id, other_agent_id
    ):
        """Peek changes what the server writes, not what the client gets back."""
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "still here"})

        msg = sync_client.read(MESSAGE_ID, peek=True)

        assert msg.decrypt_error is None
        assert msg.plaintext == '{"text":"still here"}'

    @respx.mock
    async def test_a_peek_read_still_decrypts_and_returns_the_row_async(
        self, async_client, tmp_config_dir, agent_id, other_agent_id
    ):
        _mock_token()
        _mock_agents(agent_id)
        _mock_readable_dm(tmp_config_dir, agent_id, other_agent_id, {"text": "still here"})

        msg = await async_client.read(MESSAGE_ID, peek=True)

        assert msg.decrypt_error is None
        assert msg.plaintext == '{"text":"still here"}'


class TestTheKwargContract:
    """The shape ``hermes-rine``'s retry sweep is specified against.

    🔴 A tripwire, not behavioural coverage: it introspects a signature, so it
    proves the call ``hermes-rine`` was written against still compiles and
    nothing about what ``peek=True`` does on the wire. That is the business of
    the classes above, which drive a mocked server and assert the header. Never
    count this one toward a mutation proof of the peek behaviour — it survives
    any mutation that leaves the signature alone.
    """

    @pytest.mark.parametrize("read", [SyncRineClient.read, RineClient.read])
    def test_peek_is_keyword_only_and_defaults_to_false(self, read):
        peek = inspect.signature(read).parameters["peek"]

        assert peek.kind is inspect.Parameter.KEYWORD_ONLY
        assert peek.default is False
