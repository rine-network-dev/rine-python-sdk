"""Holds: the typed refusal a held principal's mint raises, and the one reader of a hold.

The mint bodies are recorded from the server's own ``refuse_held_mint`` (for each hold and
principal kind) in ``fixtures/held-mint-refusals.json``, so these tests carry the server's real
refusal and not a shape the SDK assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from rine._http import SyncHttpClient, _fetch_oauth_token, _fetch_oauth_token_async
from rine.errors import AuthenticationError, AuthorizationError
from rine.holds import HoldCode, PrincipalHeldError, hold_of
from rine.testing import write_agent_identity
from tests.test_http import API_URL, TOKEN_URL, _signer

RECORDED = json.loads(
    (Path(__file__).parent / "fixtures" / "held-mint-refusals.json").read_text()
)["refusals"]
CODES_FIXTURE = (
    Path(__file__).resolve().parents[2] / "rine-core/test/fixtures/governance-codes.json"
)


def _mint_response(name: str) -> httpx.Response:
    recorded = RECORDED[name]
    return httpx.Response(recorded["status"], json=recorded["body"])


def test_hold_code_when_compared_to_the_shared_fixture_then_the_list_matches() -> None:
    if not CODES_FIXTURE.is_file():
        pytest.skip("rine-core is not checked out - SDK tested outside the monorepo")
    assert json.loads(CODES_FIXTURE.read_text())["holds"] == [hold.value for hold in HoldCode]


@pytest.mark.parametrize("name", RECORDED)
def test_hold_of_when_given_the_recorded_mint_refusal_then_it_names_the_hold(name: str) -> None:
    recorded = RECORDED[name]
    assert hold_of(recorded["status"], json.dumps(recorded["body"])) == HoldCode(
        recorded["body"]["reason"]
    )


@pytest.mark.parametrize("hold", HoldCode)
def test_hold_of_when_a_bearer_route_refuses_with_a_403_then_it_names_the_hold(
    hold: HoldCode,
) -> None:
    assert hold_of(403, json.dumps({"error": hold.value, "detail": "x"})) is hold


@pytest.mark.parametrize(
    ("status", "raw"),
    [
        (401, json.dumps({"error": "agent_suspended"})),
        (403, json.dumps({"error": "delegate_scope"})),
        (403, json.dumps({"error": "constructor"})),
        (403, json.dumps({"error": ["agent_suspended"]})),
        (403, json.dumps({"detail": "agent_suspended"})),
        (400, json.dumps({"error": "invalid_client", "reason": "agent_suspended"})),
        (400, json.dumps({"error": "unauthorized_client", "reason": "clock_skew"})),
        (400, json.dumps({"error": "unauthorized_client"})),
        (403, "not json"),
        (403, json.dumps(["agent_suspended"])),
        (403, None),
    ],
)
def test_hold_of_when_the_response_names_no_hold_then_it_is_none(status: int, raw: object) -> None:
    assert hold_of(status, raw) is None


@pytest.mark.parametrize("name", RECORDED)
@respx.mock
def test_fetch_oauth_token_when_a_hold_refuses_then_it_raises_the_typed_hold(
    name: str, agent_id: str
) -> None:
    respx.post(TOKEN_URL).mock(return_value=_mint_response(name))
    with httpx.Client() as http, pytest.raises(PrincipalHeldError) as caught:
        _fetch_oauth_token(http, API_URL, _signer(agent_id))
    body = RECORDED[name]["body"]
    assert caught.value.hold is HoldCode(body["reason"])
    assert caught.value.detail == body["error_description"]
    assert isinstance(caught.value, AuthenticationError)
    assert hold_of(400, caught.value.raw) is caught.value.hold


@pytest.mark.parametrize("name", RECORDED)
@respx.mock
async def test_fetch_oauth_token_async_when_a_hold_refuses_then_it_raises_the_typed_hold(
    name: str, agent_id: str
) -> None:
    respx.post(TOKEN_URL).mock(return_value=_mint_response(name))
    async with httpx.AsyncClient() as http:
        with pytest.raises(PrincipalHeldError) as caught:
            await _fetch_oauth_token_async(http, API_URL, _signer(agent_id))
    body = RECORDED[name]["body"]
    assert (caught.value.hold, caught.value.detail) == (
        HoldCode(body["reason"]),
        body["error_description"],
    )


@respx.mock
def test_fetch_oauth_token_when_the_assertion_is_refused_then_it_is_not_a_hold(
    agent_id: str,
) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_client", "reason": "agent_suspended"}
        )
    )
    with httpx.Client() as http, pytest.raises(AuthenticationError) as caught:
        _fetch_oauth_token(http, API_URL, _signer(agent_id))
    assert not isinstance(caught.value, PrincipalHeldError)


@respx.mock
def test_client_request_when_the_mint_is_held_then_the_caller_gets_the_hold(
    tmp_config_dir: str, agent_id: str
) -> None:
    write_agent_identity(tmp_config_dir, agent_id)
    respx.post(TOKEN_URL).mock(return_value=_mint_response("agent:agent_suspended"))
    client = SyncHttpClient(config_dir=tmp_config_dir)
    with pytest.raises(PrincipalHeldError) as caught:
        client.get("/agents")
    client.close()
    assert caught.value.hold is HoldCode.AGENT_SUSPENDED


@respx.mock
def test_client_request_when_a_bearer_route_holds_then_the_hold_is_read_from_the_body(
    tmp_config_dir: str, agent_id: str
) -> None:
    write_agent_identity(tmp_config_dir, agent_id)
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
    )
    respx.get(f"{API_URL}/agents").mock(
        return_value=httpx.Response(
            403, json={"error": "branch_suspended", "detail": "This agent's branch is suspended."}
        )
    )
    client = SyncHttpClient(config_dir=tmp_config_dir)
    with pytest.raises(AuthorizationError) as caught:
        client.get("/agents")
    client.close()
    assert hold_of(caught.value.status, caught.value.raw) is HoldCode.BRANCH_SUSPENDED
