"""Tests for SPIFFE identity verification — sync + async, mocked with respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._owner import resolve_owner_dir
from rine.errors import SpiffeVerificationError, ValidationError
from rine.testing import write_owner
from rine.types import VerifyIdentityResult
from tests.identity import echo_created_agent

AGENT_ID = "00000000-1111-2222-3333-444444444444"
API_URL = "https://rine.network"
_AUDIENCE = "spiffe://challenge.rine.network/tok-abc123"
_SVID = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ4In0.sig"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}
_CHALLENGE_RESPONSE = {"audience": _AUDIENCE, "expires_in": 300}
_ANY_AGENT_VERIFY = rf"{API_URL}/agents/[0-9a-f-]{{36}}/verify-svid$"
_ANY_AGENT_CHALLENGE = rf"{API_URL}/agents/[0-9a-f-]{{36}}/verify-svid/challenge$"
_VERIFY_RESPONSE = {
    "agent_id": AGENT_ID,
    "spiffe_id": "spiffe://example.org/workload/api",
    "trust_domain": "example.org",
    "trust_tier": 2,
    "verified_at": "2024-01-01T00:00:00Z",
}


def _mock_token() -> None:
    respx.post(f"{API_URL}/oauth/token").mock(
        return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
    )


def _mock_challenge() -> respx.Route:
    return respx.post(f"{API_URL}/agents/{AGENT_ID}/verify-svid/challenge").mock(
        return_value=httpx.Response(200, json=_CHALLENGE_RESPONSE)
    )


@pytest.fixture(autouse=True)
def _no_spiffe_env(monkeypatch):
    """Ensure the ambient SPIFFE socket env never leaks into unit tests."""
    monkeypatch.delenv("SPIFFE_ENDPOINT_SOCKET", raising=False)


class TestVerifyIdentitySync:
    @respx.mock
    def test_happy_path_returns_typed_result(self, sync_client):
        _mock_token()
        challenge = _mock_challenge()
        verify = respx.post(f"{API_URL}/agents/{AGENT_ID}/verify-svid").mock(
            return_value=httpx.Response(200, json=_VERIFY_RESPONSE)
        )

        result = sync_client.verify_identity(AGENT_ID, svid=_SVID)

        assert isinstance(result, VerifyIdentityResult)
        assert result.trust_tier == 2
        assert result.trust_domain == "example.org"
        # Challenge is requested before verify, and the SVID is forwarded verbatim.
        assert challenge.called
        assert verify.called
        assert json_body(verify) == {"svid": _SVID}

    @respx.mock
    def test_wrong_audience_422_surfaced_as_validation_error(self, sync_client):
        _mock_token()
        _mock_challenge()
        respx.post(f"{API_URL}/agents/{AGENT_ID}/verify-svid").mock(
            return_value=httpx.Response(
                422, json={"detail": "SVID audience does not match challenge"}
            )
        )

        with pytest.raises(ValidationError) as exc:
            sync_client.verify_identity(AGENT_ID, svid=_SVID)
        assert exc.value.status == 422

    @respx.mock
    def test_challenge_replay_422_surfaced(self, sync_client):
        """A single-use challenge already consumed → 422 propagates as typed error."""
        _mock_token()
        _mock_challenge()
        respx.post(f"{API_URL}/agents/{AGENT_ID}/verify-svid").mock(
            return_value=httpx.Response(422, json={"detail": "challenge already used"})
        )

        with pytest.raises(ValidationError, match="challenge already used"):
            sync_client.verify_identity(AGENT_ID, svid=_SVID)

    @respx.mock
    def test_no_svid_no_endpoint_raises_spiffe_error(self, sync_client):
        _mock_token()
        challenge = _mock_challenge()
        # Deliberately do NOT register the verify route: the SVID is resolved
        # before it would be posted, so reaching it would be an unmatched request.

        with pytest.raises(SpiffeVerificationError) as exc:
            sync_client.verify_identity(AGENT_ID)

        assert exc.value.reason == "no-svid"
        assert not challenge.called  # fail fast: no challenge minted when no SVID is obtainable

    @respx.mock
    def test_socket_present_no_svid_raises_autofetch_unavailable(self, sync_client, monkeypatch):
        monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock")
        _mock_token()
        _mock_challenge()

        with pytest.raises(SpiffeVerificationError) as exc:
            sync_client.verify_identity(AGENT_ID)

        assert exc.value.reason == "autofetch-unavailable"


class TestVerifyIdentityAsync:
    @respx.mock
    async def test_happy_path_returns_typed_result(self, async_client):
        _mock_token()
        _mock_challenge()
        verify = respx.post(f"{API_URL}/agents/{AGENT_ID}/verify-svid").mock(
            return_value=httpx.Response(200, json=_VERIFY_RESPONSE)
        )

        result = await async_client.verify_identity(AGENT_ID, svid=_SVID)

        assert isinstance(result, VerifyIdentityResult)
        assert result.trust_tier == 2
        assert json_body(verify) == {"svid": _SVID}
        await async_client.close()

    @respx.mock
    async def test_no_svid_no_endpoint_raises_spiffe_error(self, async_client):
        _mock_token()
        _mock_challenge()

        with pytest.raises(SpiffeVerificationError) as exc:
            await async_client.verify_identity(AGENT_ID)
        assert exc.value.reason == "no-svid"
        await async_client.close()


class TestCreateAgentAutoVerifyHook:
    @pytest.fixture(autouse=True)
    def _owner(self):
        write_owner(resolve_owner_dir())

    @respx.mock
    def test_create_agent_with_svid_runs_verify_and_attaches_identity(self, sync_client):
        _mock_token()
        _mock_create_agent()
        _mock_any_challenge()
        respx.post(url__regex=_ANY_AGENT_VERIFY).mock(
            return_value=httpx.Response(200, json=_VERIFY_RESPONSE)
        )

        agent = sync_client.create_agent("test-agent", svid=_SVID)

        assert agent.identity is not None
        assert agent.identity.trust_tier == 2
        assert agent.identity_error is None

    @respx.mock
    def test_verify_failure_does_not_undo_creation(self, sync_client):
        """A verify failure is captured in identity_error; the agent still returns."""
        _mock_token()
        _mock_create_agent()
        _mock_any_challenge()
        respx.post(url__regex=_ANY_AGENT_VERIFY).mock(
            return_value=httpx.Response(422, json={"detail": "bad svid"})
        )

        agent = sync_client.create_agent("test-agent", svid=_SVID)

        assert agent.id is not None  # creation succeeded
        assert agent.identity is None
        assert agent.identity_error is not None
        assert "bad svid" in agent.identity_error

    @respx.mock
    def test_no_verify_flag_skips_verification(self, sync_client):
        _mock_token()
        _mock_create_agent()
        # No challenge route is registered: were verification to run, the
        # challenge POST would be unmatched and fail the test.

        agent = sync_client.create_agent("test-agent")

        assert agent.identity is None
        assert agent.identity_error is None


# --- Helpers ---


def json_body(route: respx.Route) -> object:
    """Decode the JSON body of the last request captured by a respx route."""
    import json

    return json.loads(route.calls.last.request.content)


def _mock_create_agent() -> None:
    respx.post(f"{API_URL}/agents").mock(side_effect=echo_created_agent)


def _mock_any_challenge() -> respx.Route:
    """The challenge route of whichever agent id the client minted."""
    return respx.post(url__regex=_ANY_AGENT_CHALLENGE).mock(
        return_value=httpx.Response(200, json=_CHALLENGE_RESPONSE)
    )
