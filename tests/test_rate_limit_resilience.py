"""Rate-limit resilience: token 429 backoff, jittered refresh margin, key cache.

Pure unit / respx — no real network, injected RNG and
clock instead of freezing time.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine._config import cache_token, save_credentials
from rine._crypto._agent_keys import fetch_recipient_keys_async, fetch_recipient_keys_sync
from rine._crypto._key_cache import KeyCache
from rine._crypto._sender_verify import (
    signing_key_fingerprint,
    verify_envelope_sender_async,
    verify_envelope_sender_sync,
)
from rine._crypto.keys import (
    encryption_public_key_to_jwk,
    generate_agent_keys,
    make_kid,
    signing_public_key_to_jwk,
)
from rine._crypto.sign import sign_payload
from rine._http import AsyncHttpClient, SyncHttpClient
from rine.errors import AuthenticationError
from tests.conftest import signing_fingerprint

API = "https://rine.network"
TOKEN_URL = f"{API}/oauth/token"
_CREDS = {"default": {"client_id": "cid", "client_secret": "csecret"}}
_TOKEN_OK = {"access_token": "tok", "expires_in": 3600}
SENDER_ID = "11111111-2222-3333-4444-555555555555"
KEYS_URL = f"{API}/agents/{SENDER_ID}/keys"


def _token_ok(_request):
    return httpx.Response(200, json=_TOKEN_OK)


def _keys_body(keys):
    return {
        "signing_public_key": signing_public_key_to_jwk(keys.signing.public_key),
        "encryption_public_key": encryption_public_key_to_jwk(keys.encryption.public_key),
    }


class TestTokenRetry:
    @respx.mock
    def test_token_fetch_when_429_then_200_retries_and_succeeds(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        n = {"c": 0}

        def token_handler(_request):
            n["c"] += 1
            if n["c"] == 1:
                return httpx.Response(429, json={"detail": "slow"}, headers={"Retry-After": "0"})
            return httpx.Response(200, json=_TOKEN_OK)

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        assert client.get("/agents") == {"items": []}
        assert n["c"] == 2
        client.close()

    @respx.mock
    def test_token_fetch_when_persistent_429_fails_after_max_attempts(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        n = {"c": 0}

        def token_handler(_request):
            n["c"] += 1
            return httpx.Response(429, json={"detail": "no"}, headers={"Retry-After": "0"})

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        with pytest.raises(AuthenticationError):
            client.get("/agents")
        assert n["c"] == 3
        client.close()

    @respx.mock
    def test_token_fetch_honors_retry_after_over_jitter(self, tmp_config_dir, monkeypatch):
        save_credentials(tmp_config_dir, _CREDS)
        slept: list[float] = []
        monkeypatch.setattr("rine._http.time.sleep", lambda d: slept.append(d))
        n = {"c": 0}

        def token_handler(_request):
            n["c"] += 1
            if n["c"] == 1:
                return httpx.Response(429, json={"detail": "slow"}, headers={"Retry-After": "7"})
            return httpx.Response(200, json=_TOKEN_OK)

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))
        # rng=0 → full-jitter backoff would be 0s; the 7s Retry-After must win.
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 0.0)
        client.get("/agents")
        assert slept == [7.0]
        client.close()

    @respx.mock
    def test_token_fetch_caps_cumulative_backoff_at_30s(self, tmp_config_dir, monkeypatch):
        save_credentials(tmp_config_dir, _CREDS)
        slept: list[float] = []
        monkeypatch.setattr("rine._http.time.sleep", lambda d: slept.append(d))
        n = {"c": 0}

        def token_handler(_request):
            n["c"] += 1
            return httpx.Response(429, json={"detail": "no"}, headers={"Retry-After": "100"})

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        with pytest.raises(AuthenticationError):
            client.get("/agents")
        # First wait clamped to the 30s remaining budget; then the budget is spent.
        assert slept == [30.0]
        assert sum(slept) <= 30.0
        client.close()

    @respx.mock
    def test_token_fetch_non_429_fails_fast(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        n = {"c": 0}

        def token_handler(_request):
            n["c"] += 1
            return httpx.Response(401, json={"detail": "bad creds"})

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        with pytest.raises(AuthenticationError):
            client.get("/agents")
        assert n["c"] == 1
        client.close()

    @respx.mock
    async def test_token_fetch_async_when_429_then_200_retries(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        n = {"c": 0}

        def token_handler(_request):
            n["c"] += 1
            if n["c"] == 1:
                return httpx.Response(429, json={"detail": "slow"}, headers={"Retry-After": "0"})
            return httpx.Response(200, json=_TOKEN_OK)

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))
        client = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        assert await client.get("/agents") == {"items": []}
        assert n["c"] == 2
        await client.close()


class TestRefreshMarginJitter:
    def test_jittered_margin_is_base_plus_bounded_jitter(self, tmp_config_dir):
        low = SyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 0.0)
        high = SyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 1.0)
        assert low._refresh_margin == 60.0
        assert high._refresh_margin == 180.0
        low.close()
        high.close()

    @respx.mock
    def test_per_instance_margin_desyncs_refresh(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        # Disk token valid for 120s: inside a 180s margin, outside a 60s margin.
        cache_token(tmp_config_dir, "default", "disk-tok", 120)
        posts = {"c": 0}

        def token_handler(_request):
            posts["c"] += 1
            return httpx.Response(200, json=_TOKEN_OK)

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))

        low = SyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 0.0)
        low.get("/agents")
        assert posts["c"] == 0  # cached disk token still fresh for the 60s-margin client

        high = SyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 1.0)
        high.get("/agents")
        assert posts["c"] == 1  # 180s-margin client treats it as stale and refreshes
        low.close()
        high.close()

    @respx.mock
    async def test_per_instance_margin_desyncs_refresh_async(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        cache_token(tmp_config_dir, "default", "disk-tok", 120)
        posts = {"c": 0}

        def token_handler(_request):
            posts["c"] += 1
            return httpx.Response(200, json=_TOKEN_OK)

        respx.post(TOKEN_URL).mock(side_effect=token_handler)
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": []}))

        low = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 0.0)
        await low.get("/agents")
        assert posts["c"] == 0

        high = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API, rng=lambda: 1.0)
        await high.get("/agents")
        assert posts["c"] == 1
        await low.close()
        await high.close()


class TestKeyCacheUnit:
    def test_get_returns_none_after_ttl(self):
        now = {"t": 0.0}
        cache = KeyCache(10.0, 8, time_fn=lambda: now["t"])
        cache.set("a", {"k": 1})
        assert cache.get("a") == {"k": 1}
        now["t"] = 10.0
        assert cache.get("a") is None

    def test_lru_eviction_over_capacity(self):
        cache = KeyCache(100.0, 2, time_fn=lambda: 0.0)
        cache.set("a", {"v": "a"})
        cache.set("b", {"v": "b"})
        cache.get("a")  # "a" is now most-recently-used
        cache.set("c", {"v": "c"})  # evicts the LRU entry "b"
        assert cache.get("b") is None
        assert cache.get("a") == {"v": "a"}
        assert cache.get("c") == {"v": "c"}

    def test_invalidate_drops_entry(self):
        cache = KeyCache(100.0, 8, time_fn=lambda: 0.0)
        cache.set("a", {"v": 1})
        cache.invalidate("a")
        assert cache.get("a") is None


class TestVerifyPathCache:
    """The verify path may serve a cached key; a failure there has a way out."""

    @respx.mock
    def test_verify_second_message_from_same_sender_within_ttl_hits_cache(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        keys = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(keys.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(keys))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        first = verify_envelope_sender_sync(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        second = verify_envelope_sender_sync(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert first.verified is True
        assert second.verified is True
        assert calls["c"] == 1
        client.close()

    @respx.mock
    def test_verify_key_refetched_after_ttl_expiry(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        keys = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(keys.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(keys))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        now = {"t": 1000.0}
        client._keys_cache = KeyCache(600.0, 256, time_fn=lambda: now["t"])
        verify_envelope_sender_sync(make_kid(SENDER_ID), payload, signature, client, SENDER_ID)
        verify_envelope_sender_sync(make_kid(SENDER_ID), payload, signature, client, SENDER_ID)
        assert calls["c"] == 1
        now["t"] = 1601.0  # past the 600s TTL
        verify_envelope_sender_sync(make_kid(SENDER_ID), payload, signature, client, SENDER_ID)
        assert calls["c"] == 2
        client.close()

    @respx.mock
    async def test_verify_second_message_within_ttl_hits_cache_async(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        keys = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(keys.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(keys))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        await verify_envelope_sender_async(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        await verify_envelope_sender_async(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert calls["c"] == 1
        await client.close()


class TestSendPathFetchesFresh:
    """A seal has no failure signal, so it never reads a cached recipient key.

    These are the guards that fail if anyone routes the send path back through
    the key cache: the peer's rotation would then stay invisible for a TTL and
    every message sealed in that window would be unreadable for its recipient.
    """

    @respx.mock
    def test_send_key_fetch_after_peer_rotation_uses_current_key(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        rotated_away = generate_agent_keys()
        current = generate_agent_keys()
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(current))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(rotated_away))

        first = fetch_recipient_keys_sync(client, SENDER_ID)
        second = fetch_recipient_keys_sync(client, SENDER_ID)

        assert first.encryption == current.encryption.public_key
        assert second.encryption == current.encryption.public_key
        assert calls["c"] == 2  # every send goes to the network
        # The seal path neither read nor wrote the cache.
        assert client._keys_cache.get(SENDER_ID) == _keys_body(rotated_away)
        client.close()

    @respx.mock
    async def test_send_key_fetch_after_peer_rotation_uses_current_key_async(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        rotated_away = generate_agent_keys()
        current = generate_agent_keys()
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(current))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(rotated_away))

        first = await fetch_recipient_keys_async(client, SENDER_ID)
        second = await fetch_recipient_keys_async(client, SENDER_ID)

        assert first.encryption == current.encryption.public_key
        assert second.encryption == current.encryption.public_key
        assert calls["c"] == 2
        assert client._keys_cache.get(SENDER_ID) == _keys_body(rotated_away)
        await client.close()


class TestSigningKeyFingerprint:
    def test_fingerprint_of_known_key_matches_cross_language_vector(self):
        # Hex SHA-256 over the raw 32-byte Ed25519 key. The expected digest is
        # the one the TypeScript stack produces for the same JWK, so a peer's
        # key reads as the same fingerprint whichever client reports it.
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}
        assert signing_key_fingerprint({"signing_public_key": jwk}) == (
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
        )


class TestVerifyFailRefetch:
    @respx.mock
    def test_verify_fail_triggers_one_bypass_refetch_then_verifies(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        new = generate_agent_keys()
        old = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(new.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(new))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(old))  # stale, rotated-away key
        result = verify_envelope_sender_sync(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert result.verified is True
        assert result.verification_status == "verified"
        assert calls["c"] == 1  # only the cache-bypassing refetch touched the network
        assert result.key_changed is not None
        assert result.key_changed.agent_id == SENDER_ID
        assert result.key_changed.previous_fingerprint == signing_fingerprint(old)
        assert result.key_changed.current_fingerprint == signing_fingerprint(new)
        client.close()

    @respx.mock
    def test_verify_fail_when_rotated_key_also_fails_reports_the_change(self, tmp_config_dir):
        # The rotation is reported even though it does not rescue the signature:
        # the signal is about the key, not about the verdict.
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        old = generate_agent_keys()
        current = generate_agent_keys()
        forger = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(forger.signing.private_key, payload)

        respx.get(KEYS_URL).mock(return_value=httpx.Response(200, json=_keys_body(current)))
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(old))
        result = verify_envelope_sender_sync(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert result.verified is False
        assert result.verification_status == "invalid"
        assert result.key_changed is not None
        assert result.key_changed.previous_fingerprint == signing_fingerprint(old)
        assert result.key_changed.current_fingerprint == signing_fingerprint(current)
        client.close()

    @respx.mock
    def test_verify_fail_when_refetch_returns_same_key_reports_no_change(self, tmp_config_dir):
        # A bounded retry, not an oracle: the same key back means one refetch and
        # a plain failure, with nothing to report and no second verification.
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        real = generate_agent_keys()
        forger = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(forger.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(real))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(real))
        result = verify_envelope_sender_sync(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert result.verified is False
        assert result.verification_status == "invalid"
        assert result.key_changed is None
        assert calls["c"] == 1  # exactly one refetch, then it stops
        client.close()

    @respx.mock
    def test_verify_fail_forged_signature_cold_cache_fetches_once(self, tmp_config_dir):
        # A forged signature against a NON-cached (cold) sender must fetch keys
        # exactly once: a fresh miss is not re-fetched, only a stale cache hit is.
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        real = generate_agent_keys()
        forger = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(forger.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(real))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = SyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        result = verify_envelope_sender_sync(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert result.verified is False
        assert result.verification_status == "invalid"
        assert result.key_changed is None
        assert calls["c"] == 1  # cold miss: no second (cache-bypassing) fetch
        client.close()

    @respx.mock
    async def test_verify_fail_bypass_refetch_then_verifies_async(self, tmp_config_dir):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        new = generate_agent_keys()
        old = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(new.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(new))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(old))
        result = await verify_envelope_sender_async(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert result.verified is True
        assert result.verification_status == "verified"
        assert calls["c"] == 1
        assert result.key_changed is not None
        assert result.key_changed.previous_fingerprint == signing_fingerprint(old)
        assert result.key_changed.current_fingerprint == signing_fingerprint(new)
        await client.close()

    @respx.mock
    async def test_verify_fail_when_refetch_returns_same_key_reports_no_change_async(
        self, tmp_config_dir
    ):
        save_credentials(tmp_config_dir, _CREDS)
        respx.post(TOKEN_URL).mock(side_effect=_token_ok)
        real = generate_agent_keys()
        forger = generate_agent_keys()
        payload = b'{"text":"hi"}'
        signature = sign_payload(forger.signing.private_key, payload)
        calls = {"c": 0}

        def keys_handler(_request):
            calls["c"] += 1
            return httpx.Response(200, json=_keys_body(real))

        respx.get(KEYS_URL).mock(side_effect=keys_handler)
        client = AsyncHttpClient(config_dir=tmp_config_dir, api_url=API)
        client._keys_cache.set(SENDER_ID, _keys_body(real))
        result = await verify_envelope_sender_async(
            make_kid(SENDER_ID), payload, signature, client, SENDER_ID
        )
        assert result.verified is False
        assert result.key_changed is None
        assert calls["c"] == 1
        await client.close()
