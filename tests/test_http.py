"""Tests for HTTP client with token management."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._config import save_credentials
from rine._http import AsyncHttpClient, SyncHttpClient, _check_response, _parse_error_detail
from rine.errors import (
    APITimeoutError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    RineApiError,
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


class TestSyncHttpClient:
    @respx.mock
    def test_authenticated_request(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })

        # Mock token endpoint
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "test-token", "expires_in": 900
            })
        )

        # Mock API endpoint
        respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.get("/agents")
        assert result == {"items": []}
        client.close()

    @respx.mock
    def test_401_triggers_token_refresh(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })

        # First token fetch
        token_route = respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "new-token", "expires_in": 900
            })
        )

        # First request returns 401, second (after token refresh) succeeds
        call_count = 0
        def api_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(200, json={"ok": True})

        respx.get("https://rine.network/test").mock(side_effect=api_handler)

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.get("/test")
        assert result == {"ok": True}
        client.close()

    @respx.mock
    def test_unauthenticated_request(self, tmp_config_dir):
        respx.get("https://rine.network/public").mock(
            return_value=httpx.Response(200, json={"data": "public"})
        )

        client = SyncHttpClient(config_dir=tmp_config_dir)
        result = client.request("GET", "/public", authenticated=False)
        assert result == {"data": "public"}
        client.close()

    @respx.mock
    def test_5xx_retries_then_succeeds(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )

        call_count = 0

        def flaky_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500, json={"detail": "server error"})
            return httpx.Response(200, json={"ok": True})

        respx.get("https://rine.network/flaky").mock(side_effect=flaky_handler)

        client = SyncHttpClient(config_dir=tmp_config_dir, max_retries=2)
        result = client.get("/flaky")
        client.close()

        assert result == {"ok": True}
        assert call_count == 2


class TestSyncGetNdjson:
    @respx.mock
    def test_get_ndjson_parses_lines(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        ndjson_body = (
            '{"type": "manifest", "version": 1}\n'
            '{"type": "org", "name": "Acme"}\n'
            '{"type": "agent", "name": "bot-1"}\n'
        )
        respx.get("https://rine.network/export").mock(
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
    def test_get_ndjson_skips_empty_lines(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        ndjson_body = (
            '{"type": "a"}\n'
            '\n'
            '   \n'
            '{"type": "b"}\n'
            '\n'
        )
        respx.get("https://rine.network/export").mock(
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
    async def test_authenticated_request(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        client = AsyncHttpClient(config_dir=tmp_config_dir)
        result = await client.get("/agents")
        await client.close()

        assert result == {"items": []}

    @respx.mock
    async def test_401_triggers_token_refresh(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "fresh-tok", "expires_in": 900})
        )

        call_count = 0

        def api_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(200, json={"ok": True})

        respx.get("https://rine.network/test").mock(side_effect=api_handler)

        client = AsyncHttpClient(config_dir=tmp_config_dir)
        result = await client.get("/test")
        await client.close()

        assert result == {"ok": True}
        assert call_count == 2

    @respx.mock
    async def test_unauthenticated_request(self, tmp_config_dir):
        respx.get("https://rine.network/public").mock(
            return_value=httpx.Response(200, json={"data": "public"})
        )

        client = AsyncHttpClient(config_dir=tmp_config_dir)
        result = await client.request("GET", "/public", authenticated=False)
        await client.close()

        assert result == {"data": "public"}

    @respx.mock
    async def test_5xx_retries_then_succeeds(self, tmp_config_dir):
        save_credentials(tmp_config_dir, {
            "default": {"client_id": "cid", "client_secret": "csecret"}
        })
        respx.post("https://rine.network/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )

        call_count = 0

        def flaky_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(500, json={"detail": "server error"})
            return httpx.Response(200, json={"ok": True})

        respx.get("https://rine.network/flaky").mock(side_effect=flaky_handler)

        client = AsyncHttpClient(config_dir=tmp_config_dir, max_retries=2)
        result = await client.get("/flaky")
        await client.close()

        assert result == {"ok": True}
        assert call_count == 2
