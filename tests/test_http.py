"""Tests for HTTP client with token management."""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._assertion import CLIENT_ASSERTION_TYPE
from rine._crypto.jws import JwsTyp, verify_jws
from rine._custody import Signer
from rine._http import (
    AsyncHttpClient,
    SyncHttpClient,
    _check_response,
    _fetch_oauth_token,
    _fetch_oauth_token_async,
    _parse_error_detail,
)
from rine._principal import agent_principal
from rine.errors import AuthenticationError, NotFoundError, RateLimitError
from rine.testing import WORLD, write_agent_identity

API_URL = "https://rine.network"
TOKEN_URL = f"{API_URL}/oauth/token"


def _signer(agent_id: str) -> Signer:
    """The agent's principal and the seed that signs its assertions."""
    return Signer(agent_principal(agent_id), WORLD.keys(agent_id).signing.private_key)


def _posted_form(request: httpx.Request) -> dict[str, str]:
    """The urlencoded token form a request carried."""
    return dict(httpx.QueryParams(request.content.decode()))


def _assertion_claims(form: dict[str, str], agent_id: str) -> dict[str, str | int]:
    """Verify the form's assertion against the agent's signing public key."""
    return verify_jws(
        form["client_assertion"], WORLD.keys(agent_id).signing.public_key, JwsTyp.ASSERTION
    )


class TestParseErrorDetail:
    def test_json_string_detail(self):
        resp = httpx.Response(400, json={"detail": "bad request"})
        assert _parse_error_detail(resp) == "bad request"

    def test_json_array_detail(self):
        resp = httpx.Response(422, json={"detail": [{"msg": "field required", "type": "missing"}]})
        assert "field required" in _parse_error_detail(resp)

    def test_non_json_body(self):
        resp = httpx.Response(500, text="Internal Server Error")
        assert "Internal Server Error" in _parse_error_detail(resp)


class TestCheckResponse:
    def test_204_returns_none(self):
        resp = httpx.Response(204)
        assert _check_response(resp) is None

    def test_200_returns_json(self):
        resp = httpx.Response(200, json={"ok": True})
        assert _check_response(resp) == {"ok": True}

    def test_404_raises_not_found(self):
        resp = httpx.Response(404, json={"detail": "not found"})
        with pytest.raises(NotFoundError):
            _check_response(resp)

    def test_429_raises_rate_limit(self):
        resp = httpx.Response(429, json={"detail": "slow down"}, headers={"Retry-After": "5"})
        with pytest.raises(RateLimitError) as exc_info:
            _check_response(resp)
        assert exc_info.value.retry_after == 5.0


class TestFetchOauthToken:
    @respx.mock
    def test_fetch_oauth_token_when_success_then_posts_a_verifiable_assertion(self, agent_id):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )

        with httpx.Client() as http:
            token, expires_in = _fetch_oauth_token(http, API_URL, _signer(agent_id))

        assert (token, expires_in) == ("tok", 900)
        form = _posted_form(route.calls.last.request)
        assert form["grant_type"] == "client_credentials"
        assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE
        claims = _assertion_claims(form, agent_id)
        principal = str(agent_principal(agent_id))
        assert claims["iss"] == principal
        assert claims["sub"] == principal
        assert claims["aud"] == f"{API_URL}/oauth/token"

    @respx.mock
    def test_fetch_oauth_token_when_retried_after_429_then_each_attempt_carries_a_fresh_jti(
        self, agent_id
    ):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[
                httpx.Response(429, json={"detail": "slow down"}),
                httpx.Response(200, json={"access_token": "tok", "expires_in": 900}),
            ]
        )

        with httpx.Client() as http:
            token, _ = _fetch_oauth_token(http, API_URL, _signer(agent_id), rng=lambda: 0.0)

        assert token == "tok"
        assert len(route.calls) == 2
        jtis = [
            _assertion_claims(_posted_form(call.request), agent_id)["jti"] for call in route.calls
        ]
        assert jtis[0] != jtis[1]


class TestFetchOauthTokenAsync:
    @respx.mock
    async def test_fetch_oauth_token_async_when_success_then_posts_a_verifiable_assertion(
        self, agent_id
    ):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )

        async with httpx.AsyncClient() as http:
            token, expires_in = await _fetch_oauth_token_async(http, API_URL, _signer(agent_id))

        assert (token, expires_in) == ("tok", 900)
        form = _posted_form(route.calls.last.request)
        assert form["grant_type"] == "client_credentials"
        assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE
        claims = _assertion_claims(form, agent_id)
        principal = str(agent_principal(agent_id))
        assert claims["iss"] == principal
        assert claims["sub"] == principal
        assert claims["aud"] == f"{API_URL}/oauth/token"

    @respx.mock
    async def test_fetch_oauth_token_when_retried_after_429_then_each_attempt_carries_a_fresh_jti(
        self, agent_id
    ):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[
                httpx.Response(429, json={"detail": "slow down"}),
                httpx.Response(200, json={"access_token": "tok", "expires_in": 900}),
            ]
        )

        async with httpx.AsyncClient() as http:
            token, _ = await _fetch_oauth_token_async(
                http, API_URL, _signer(agent_id), rng=lambda: 0.0
            )

        assert token == "tok"
        assert len(route.calls) == 2
        jtis = [
            _assertion_claims(_posted_form(call.request), agent_id)["jti"] for call in route.calls
        ]
        assert jtis[0] != jtis[1]


class TestSyncHttpClient:
    @respx.mock
    def test_authenticated_request(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)

        # Mock token endpoint
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": "test-token", "expires_in": 900}
            )
        )

        # Mock API endpoint
        respx.get(f"{API_URL}/agents").mock(return_value=httpx.Response(200, json={"items": []}))

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.get("/agents")
        assert result == {"items": []}
        client.close()

    @respx.mock
    def test_401_triggers_token_refresh(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)

        # First token fetch
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "new-token", "expires_in": 900})
        )

        # First request returns 401, second (after token refresh) succeeds
        call_count = 0

        def api_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(200, json={"ok": True})

        respx.get(f"{API_URL}/test").mock(side_effect=api_handler)

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.get("/test")
        assert result == {"ok": True}
        client.close()

    @respx.mock
    def test_unauthenticated_request(self, tmp_config_dir):
        respx.get(f"{API_URL}/public").mock(
            return_value=httpx.Response(200, json={"data": "public"})
        )

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.request("GET", "/public", authenticated=False)
        assert result == {"data": "public"}
        client.close()

    @respx.mock
    def test_no_identity_raises_authentication_error(self, tmp_config_dir):
        client = SyncHttpClient(config_dir=tmp_config_dir)
        with pytest.raises(AuthenticationError, match="No identity found"):
            client.get("/agents")
        client.close()

    @respx.mock
    def test_5xx_retries_then_succeeds(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )

        call_count = 0

        def flaky_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500, json={"detail": "server error"})
            return httpx.Response(200, json={"ok": True})

        respx.get(f"{API_URL}/flaky").mock(side_effect=flaky_handler)

        client = SyncHttpClient(config_dir=tmp_config_dir, max_retries=2)
        result = client.get("/flaky")
        client.close()

        assert result == {"ok": True}
        assert call_count == 2


class TestSyncGetNdjson:
    @respx.mock
    def test_get_ndjson_parses_lines(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        ndjson_body = (
            '{"type": "manifest", "version": 1}\n'
            '{"type": "org", "name": "Acme"}\n'
            '{"type": "agent", "name": "bot-1"}\n'
        )
        respx.get(f"{API_URL}/export").mock(
            return_value=httpx.Response(
                200,
                content=ndjson_body.encode(),
                headers={"content-type": "application/x-ndjson"},
            )
        )

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.get_ndjson("/export")
        client.close()

        assert len(result) == 3
        assert result[0] == {"type": "manifest", "version": 1}
        assert result[1] == {"type": "org", "name": "Acme"}
        assert result[2] == {"type": "agent", "name": "bot-1"}

    @respx.mock
    def test_get_ndjson_skips_empty_lines(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        ndjson_body = '{"type": "a"}\n\n   \n{"type": "b"}\n\n'
        respx.get(f"{API_URL}/export").mock(
            return_value=httpx.Response(
                200,
                content=ndjson_body.encode(),
                headers={"content-type": "application/x-ndjson"},
            )
        )

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.get_ndjson("/export")
        client.close()

        assert len(result) == 2
        assert result[0] == {"type": "a"}
        assert result[1] == {"type": "b"}


class TestAsyncHttpClient:
    @respx.mock
    async def test_authenticated_request(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        respx.get(f"{API_URL}/agents").mock(return_value=httpx.Response(200, json={"items": []}))

        client = AsyncHttpClient(config_dir=tmp_config_dir)
        result = await client.get("/agents")
        await client.close()

        assert result == {"items": []}

    @respx.mock
    async def test_401_triggers_token_refresh(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "fresh-tok", "expires_in": 900})
        )

        call_count = 0

        def api_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(200, json={"ok": True})

        respx.get(f"{API_URL}/test").mock(side_effect=api_handler)

        client = AsyncHttpClient(config_dir=tmp_config_dir)
        result = await client.get("/test")
        await client.close()

        assert result == {"ok": True}
        assert call_count == 2

    @respx.mock
    async def test_unauthenticated_request(self, tmp_config_dir):
        respx.get(f"{API_URL}/public").mock(
            return_value=httpx.Response(200, json={"data": "public"})
        )

        client = AsyncHttpClient(config_dir=tmp_config_dir)
        result = await client.request("GET", "/public", authenticated=False)
        await client.close()

        assert result == {"data": "public"}

    @respx.mock
    async def test_5xx_retries_then_succeeds(self, tmp_config_dir, agent_id):
        write_agent_identity(tmp_config_dir, agent_id)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )

        call_count = 0

        def flaky_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500, json={"detail": "server error"})
            return httpx.Response(200, json={"ok": True})

        respx.get(f"{API_URL}/flaky").mock(side_effect=flaky_handler)

        client = AsyncHttpClient(config_dir=tmp_config_dir, max_retries=2)
        result = await client.get("/flaky")
        await client.close()

        assert result == {"ok": True}
        assert call_count == 2
