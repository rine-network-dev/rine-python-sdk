"""A refusal naming a revoked agent or branch is its own typed error, not a bad credential."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._http import _check_response, _fetch_oauth_token, _fetch_oauth_token_async
from rine.errors import AuthenticationError, PrincipalRevokedError, RevokedScope
from tests.test_http import API_URL, TOKEN_URL, _signer

MINT_REVOKED = {"error": "invalid_client", "detail": "The principal is revoked"}
SCOPES = [
    ("agent_revoked", RevokedScope.AGENT),
    ("branch_revoked", RevokedScope.BRANCH),
]


@pytest.mark.parametrize(("reason", "scope"), SCOPES)
def test_check_response_when_a_bearer_route_names_a_revoked_principal_then_the_scope_is_typed(
    reason: str, scope: RevokedScope
) -> None:
    """A bearer route names the revoked scope in its error key."""
    response = httpx.Response(401, json={"error": reason, "detail": "Principal is revoked"})

    with pytest.raises(PrincipalRevokedError) as caught:
        _check_response(response)

    assert caught.value.scope is scope
    assert caught.value.status == 401
    assert isinstance(caught.value, AuthenticationError)


def test_check_response_when_a_401_names_no_revocation_then_it_is_plain() -> None:
    """An ordinary 401 stays the generic authentication error."""
    response = httpx.Response(401, json={"error": "invalid_token", "detail": "expired"})

    with pytest.raises(AuthenticationError) as caught:
        _check_response(response)

    assert not isinstance(caught.value, PrincipalRevokedError)


def test_check_response_when_a_revoked_code_rides_a_non_401_then_it_is_not_a_revocation() -> None:
    """Only a 401 is a revocation refusal; a 422 with the same code is not."""
    response = httpx.Response(422, json={"error": "agent_revoked", "detail": "refused"})

    with pytest.raises(Exception) as caught:  # noqa: PT011 - asserting the class below
        _check_response(response)

    assert not isinstance(caught.value, PrincipalRevokedError)


@respx.mock
@pytest.mark.parametrize(("reason", "scope"), SCOPES)
def test_fetch_oauth_token_when_the_mint_names_a_revoked_principal_then_the_scope_is_typed(
    agent_id: str, reason: str, scope: RevokedScope
) -> None:
    """The token mint names the scope in its reason key once the assertion verified."""
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(401, json={**MINT_REVOKED, "reason": reason})
    )

    with httpx.Client() as http, pytest.raises(PrincipalRevokedError) as caught:
        _fetch_oauth_token(http, API_URL, _signer(agent_id))

    assert caught.value.scope is scope
    assert "Token fetch failed" in caught.value.detail


@respx.mock
def test_fetch_oauth_token_when_the_mint_refuses_without_a_reason_then_it_is_a_plain_error(
    agent_id: str,
) -> None:
    """A mint refusal without a reason reveals nothing and stays the generic error."""
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(401, json={"error": "invalid_client", "detail": "bad"})
    )

    with httpx.Client() as http, pytest.raises(AuthenticationError) as caught:
        _fetch_oauth_token(http, API_URL, _signer(agent_id))

    assert not isinstance(caught.value, PrincipalRevokedError)


@respx.mock
@pytest.mark.parametrize(("reason", "scope"), SCOPES)
async def test_fetch_oauth_token_async_when_the_mint_names_a_revoked_principal_then_it_is_typed(
    agent_id: str, reason: str, scope: RevokedScope
) -> None:
    """The async mint maps the revoked scope the same way."""
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(401, json={**MINT_REVOKED, "reason": reason})
    )

    async with httpx.AsyncClient() as http:
        with pytest.raises(PrincipalRevokedError) as caught:
            await _fetch_oauth_token_async(http, API_URL, _signer(agent_id))

    assert caught.value.scope is scope


@respx.mock
@pytest.mark.parametrize("status", [400, 403, 500])
def test_fetch_oauth_token_when_a_non_401_carries_a_revoked_reason_then_it_is_not_a_revocation(
    agent_id: str, status: int
) -> None:
    """The mint answers a revocation with a 401 only; another status is not one."""
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(status, json={**MINT_REVOKED, "reason": "agent_revoked"})
    )

    with httpx.Client() as http, pytest.raises(AuthenticationError) as caught:
        _fetch_oauth_token(http, API_URL, _signer(agent_id))

    assert not isinstance(caught.value, PrincipalRevokedError)
