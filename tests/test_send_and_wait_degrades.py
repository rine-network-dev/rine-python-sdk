"""``send_and_wait()`` carries the same degrade contract as every other read.

Every receive surface on both clients reports an unopenable row rather than
raising it — ``inbox()``, ``read()`` and ``thread()`` all funnel a failed
decrypt through ``_apply_decrypt_failure``, so the caller gets the row back with
``decrypt_error`` set and ``plaintext = None``. ``send_and_wait()`` decrypted the
long-poll reply unguarded, so one unreadable answer took down the whole call:
the send had already happened, the reply was on the wire, and the caller was
handed an exception with no message object to inspect.

A 1:1 reply is the least likely row to be unopenable, which is exactly why this
went unnoticed — and why it is the same shape as everything else in this phase.
Both twins are here so a fix to one client is visibly not a fix to the other.
"""

from __future__ import annotations

import httpx
import respx

from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    generate_agent_keys,
    save_agent_keys,
    signing_public_key_to_jwk,
)

API = "https://rine.network"
OTHER_AGENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SENT_ID = "cccccccc-dddd-eeee-ffff-000000000301"
REPLY_ID = "cccccccc-dddd-eeee-ffff-000000000302"
CONVERSATION_ID = "cccccccc-dddd-eeee-ffff-000000000303"
TYPE = "rine.v1.task_request"


def _mock_send_and_wait_with_an_unopenable_reply(tmp_config_dir: str, agent_id: str) -> None:
    """The whole round trip, answered by a reply whose envelope is not an envelope.

    Sealing a *wrong* reply rather than corrupting a real one keeps the failure
    where the product would meet it: the server hands back whatever the peer
    posted, and this client's keys do not open it.
    """
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "test-token", "expires_in": 900})
    )
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
    respx.get(f"{API}/.well-known/webfinger").mock(
        return_value=httpx.Response(200, json={"aliases": [f"{API}/agents/{OTHER_AGENT_ID}"]})
    )

    peer_keys = generate_agent_keys()
    save_agent_keys(tmp_config_dir, OTHER_AGENT_ID, peer_keys)
    respx.get(f"{API}/agents/{OTHER_AGENT_ID}/keys").mock(
        return_value=httpx.Response(
            200,
            json={
                "agent_id": OTHER_AGENT_ID,
                "encryption_public_key": encryption_public_key_to_jwk(
                    peer_keys.encryption.public_key
                ),
                "signing_public_key": signing_public_key_to_jwk(peer_keys.signing.public_key),
            },
        )
    )

    def _row(message_id: str, sender: str, recipient: str) -> dict:
        return {
            "id": message_id,
            "conversation_id": CONVERSATION_ID,
            "from_agent_id": sender,
            "to_agent_id": recipient,
            "type": TYPE,
            "encrypted_payload": "bm90LWFuLWVudmVsb3Bl",
            "encryption_version": "hpke-v1",
            "sender_signing_kid": f"rine:{sender}",
            "created_at": "2024-01-01T00:00:00Z",
        }

    respx.post(f"{API}/messages/sync").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": _row(SENT_ID, agent_id, OTHER_AGENT_ID),
                "reply": _row(REPLY_ID, OTHER_AGENT_ID, agent_id),
                "conversation_id": CONVERSATION_ID,
                "status": "completed",
            },
        )
    )


class TestAnUnopenableReplyIsReportedNotRaised:
    @respx.mock
    def test_send_and_wait_reports_a_failed_reply_decrypt_on_the_row(
        self, sync_client, tmp_config_dir, agent_id
    ):
        _mock_send_and_wait_with_an_unopenable_reply(tmp_config_dir, agent_id)

        result = sync_client.send_and_wait("other@acme.rine.network", {"task": "hi"})

        assert result.sent.id is not None
        assert result.reply is not None, "the reply row survives a failed decrypt"
        assert result.reply.plaintext is None
        assert result.reply.decrypt_error is not None

    @respx.mock
    async def test_send_and_wait_reports_a_failed_reply_decrypt_on_the_row_async(
        self, async_client, tmp_config_dir, agent_id
    ):
        _mock_send_and_wait_with_an_unopenable_reply(tmp_config_dir, agent_id)

        result = await async_client.send_and_wait("other@acme.rine.network", {"task": "hi"})

        assert result.sent.id is not None
        assert result.reply is not None, "the reply row survives a failed decrypt"
        assert result.reply.plaintext is None
        assert result.reply.decrypt_error is not None
