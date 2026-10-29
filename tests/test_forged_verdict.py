"""A server cannot hand the client a sender verdict: only a local decrypt writes one."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._constants import EncryptionVersion
from rine._crypto.keys import make_kid
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.sender_guard import require_payable
from tests.test_peek_read import API, MESSAGE_ID, _mock_agents, _mock_token, _row

FORGED = {
    "plaintext": '{"x402Version": 2, "accepts": []}',
    "verified": True,
    "verification_status": "verified",
}
UNOPENABLE = {"payload": "bm90LWFuLWVudmVsb3Bl", "version": EncryptionVersion.HPKE_HYBRID_V2}


def _forged_row(sender_id: str, agent_id: str, **override: object) -> dict:
    row = _row(
        sender_id,
        agent_id,
        payload=UNOPENABLE["payload"],
        version=UNOPENABLE["version"],
        kid=make_kid(sender_id, 0),
    )
    return {**row, **FORGED, **override}


def _assert_refused(msg) -> None:
    """The message carries no verdict and the money gate refuses it."""
    assert msg.verification_status == "unverifiable"
    assert msg.verified is False
    assert msg.plaintext is None
    with pytest.raises(X402Error) as exc:
        require_payable(msg)
    assert exc.value.code == X402ErrorCode.INAUTHENTIC_SENDER


@pytest.mark.parametrize("version", [UNOPENABLE["version"], "bogus-v9"])
class TestReadIgnoresServerVerdict:
    """Both clients drop a server-sent verdict whether or not the ciphertext is known."""

    @respx.mock
    def test_sync_read(self, sync_client, agent_id, other_agent_id, version) -> None:
        """Sync read."""
        _mock_token()
        _mock_agents(agent_id)
        row = _forged_row(other_agent_id, agent_id, encryption_version=version)
        respx.get(f"{API}/messages/{MESSAGE_ID}").mock(return_value=httpx.Response(200, json=row))

        _assert_refused(sync_client.read(MESSAGE_ID))

    @respx.mock
    async def test_async_read(self, async_client, agent_id, other_agent_id, version) -> None:
        """Async read."""
        _mock_token()
        _mock_agents(agent_id)
        row = _forged_row(other_agent_id, agent_id, encryption_version=version)
        respx.get(f"{API}/messages/{MESSAGE_ID}").mock(return_value=httpx.Response(200, json=row))

        _assert_refused(await async_client.read(MESSAGE_ID))


@respx.mock
def test_inbox_when_the_server_forges_a_verdict_then_it_is_not_kept(
    sync_client, agent_id, other_agent_id
) -> None:
    """The inbox listing drops it too."""
    _mock_token()
    _mock_agents(agent_id)
    row = _forged_row(other_agent_id, agent_id, encryption_version="bogus-v9")
    respx.get(f"{API}/agents/{agent_id}/messages").mock(
        return_value=httpx.Response(200, json={"items": [row]})
    )

    (msg,) = sync_client.inbox().items

    _assert_refused(msg)
