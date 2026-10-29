"""HTTP layer (sync + async) with OAuth2 token refresh and multi-agent support."""

from __future__ import annotations

import json as _json
import random
import time
from collections.abc import AsyncIterator, Callable, Iterable, Iterator
from typing import TYPE_CHECKING, Any

import httpx

from rine._actor import AGENT_HEADER
from rine._assertion import TOKEN_PATH, token_form
from rine._client_auth import ClientAuth
from rine._config import resolve_api_url
from rine._constants import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    KEY_CACHE_MAX_ENTRIES,
    KEY_CACHE_TTL,
    RETRYABLE_STATUS_CODES,
    TOKEN_REFRESH_JITTER,
    TOKEN_REFRESH_MARGIN,
    TOKEN_RETRY_ATTEMPTS,
    TOKEN_RETRY_TOTAL_CAP,
)
from rine._crypto._key_cache import KeyCache
from rine._logging import logger
from rine._owner import effective_owner_dir
from rine._version import __version__
from rine.errors import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    RateLimitError,
    raise_for_status,
    revoked_error,
)

if TYPE_CHECKING:
    from rine._crypto._key_pins import KeyPins
    from rine._custody import Signer
    from rine._principal import Principal

_USER_AGENT = f"rine-python/{__version__}"
_TOKEN_BACKOFF_BASE = 0.5
_TOKEN_BACKOFF_CAP = 8.0
_TOKEN_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _backoff_delay(attempt: int, base: float = 0.5, max_delay: float = 8.0) -> float:
    """Exponential backoff with jitter."""
    # Annotated because mypy types ``int ** int`` as Any (the result is float for a
    # negative exponent), which would otherwise propagate out through the return.
    delay: float = min(base * (2**attempt), max_delay)
    return delay * (0.5 + random.random() * 0.5)  # noqa: S311


def _parse_error_detail(response: httpx.Response) -> str:
    """Extract error detail from response body."""
    try:
        body = response.json()
        detail = body.get("detail", "")
        if isinstance(detail, list):
            return "; ".join(
                d.get("msg", str(d)) if isinstance(d, dict) else str(d) for d in detail
            )
        return str(detail) if detail else response.reason_phrase or "Unknown error"
    except Exception:
        text = response.text[:500] if response.text else response.reason_phrase or "Unknown error"
        return text


def _parse_retry_after(response: httpx.Response) -> float | None:
    """Parse the ``Retry-After`` header into seconds, or ``None`` if absent."""
    retry_after = response.headers.get("Retry-After")
    return float(retry_after) if retry_after else None


def _token_retry_delay(attempt: int, retry_after: float | None, rng: Callable[[], float]) -> float:
    """Delay before the next token retry: honor ``Retry-After``, else full jitter.

    Full jitter draws uniformly from ``[0, min(cap, base * 2**attempt))`` so
    co-located clients that all trip a 429 do not retry in lockstep.

    Args:
        attempt: Zero-based retry attempt index.
        retry_after: Server-advised wait in seconds, or ``None``.
        rng: Uniform ``[0, 1)`` source (injectable for deterministic tests).

    Returns:
        Seconds to wait before the next attempt.
    """
    if retry_after is not None:
        return retry_after
    ceiling = min(_TOKEN_BACKOFF_CAP, _TOKEN_BACKOFF_BASE * float(2**attempt))
    return ceiling * rng()


def _token_backoff(
    resp: httpx.Response, attempt: int, slept: float, rng: Callable[[], float]
) -> float | None:
    """Compute the sleep before retrying a token 429, or ``None`` to fail now.

    Returns ``None`` when the response is not a retryable 429, no attempts
    remain, or the cumulative-sleep budget (``TOKEN_RETRY_TOTAL_CAP``) is spent.

    Args:
        resp: The failed token response.
        attempt: Zero-based attempt index just completed.
        slept: Seconds already slept across prior retries.
        rng: Uniform ``[0, 1)`` source.

    Returns:
        Seconds to sleep, or ``None`` to fail fast.
    """
    if resp.status_code != 429 or attempt >= TOKEN_RETRY_ATTEMPTS - 1:
        return None
    remaining = TOKEN_RETRY_TOTAL_CAP - slept
    if remaining <= 0:
        return None
    return min(_token_retry_delay(attempt, _parse_retry_after(resp), rng), remaining)


def _jittered_margin(rng: Callable[[], float]) -> float:
    """Draw a per-client token-refresh margin: base + uniform(0, jitter) seconds.

    Drawn once per client so a single client stays stable around the expiry
    boundary while co-located clients desynchronize.

    Args:
        rng: Uniform ``[0, 1)`` source.

    Returns:
        Effective refresh margin in seconds.
    """
    return TOKEN_REFRESH_MARGIN + rng() * TOKEN_REFRESH_JITTER


def _token_result(resp: httpx.Response) -> tuple[str, int]:
    """Parse a successful token response into ``(access_token, expires_in)``."""
    body = resp.json()
    return body["access_token"], body.get("expires_in", 900)


def _token_error(resp: httpx.Response) -> AuthenticationError:
    """Build the hard-failure error for a non-success token response.

    A refusal that names a revoked principal comes back as the typed
    :class:`PrincipalRevokedError`, so a caller can tell it from a bad credential.
    """
    detail = f"Token fetch failed: {_parse_error_detail(resp)}"
    return revoked_error(resp.status_code, detail, resp.text) or AuthenticationError(detail=detail, raw=resp.text)


def _check_response(response: httpx.Response) -> Any:
    """Check response and raise appropriate error or return parsed body."""
    if response.status_code == 204:
        return None

    if response.is_success:
        if not response.content:
            return None
        return response.json()

    detail = _parse_error_detail(response)

    if response.status_code == 429:
        raise RateLimitError(
            detail=detail, retry_after=_parse_retry_after(response), raw=response.text
        )

    raise_for_status(response.status_code, detail, raw=response.text)


def _check_response_with_status(response: httpx.Response) -> tuple[int, Any]:
    """Like :func:`_check_response`, but also returns the HTTP status code.

    For callers that must discriminate on the status code (e.g. group ``join``:
    200 member vs 202 pending request), which the body alone cannot tell apart.
    Error / 204 / empty handling is identical to :func:`_check_response`.
    """
    return response.status_code, _check_response(response)


def _fetch_oauth_token(
    http: httpx.Client,
    api_url: str,
    signer: Signer,
    *,
    rng: Callable[[], float] = random.random,
) -> tuple[str, int]:
    """Fetch an OAuth2 token with a ``private_key_jwt`` client assertion.

    Every attempt carries a fresh assertion: its ``jti`` is single-use, so a
    retry that resent the first form would be refused as a replay.

    On a ``429`` the POST is retried up to ``TOKEN_RETRY_ATTEMPTS`` times,
    honoring ``Retry-After`` (else exponential backoff with full jitter) and
    capping cumulative sleep at ``TOKEN_RETRY_TOTAL_CAP`` seconds. Non-429
    failures fail fast.

    Args:
        http: HTTP client.
        api_url: API base URL.
        signer: The principal to authenticate as and the seed that signs for it.
        rng: Uniform ``[0, 1)`` jitter source (injectable for tests).

    Returns:
        Tuple of (access_token, expires_in).
    """
    slept = 0.0
    for attempt in range(TOKEN_RETRY_ATTEMPTS):
        form = token_form(signer, api_url)
        resp = http.post(f"{api_url}{TOKEN_PATH}", data=form, headers=_TOKEN_FORM_HEADERS)
        if resp.is_success:
            return _token_result(resp)
        delay = _token_backoff(resp, attempt, slept, rng)
        if delay is None:
            raise _token_error(resp)
        logger.warning("429 on token fetch, retrying in %.1fs", delay)
        time.sleep(delay)
        slept += delay
    raise AuthenticationError(detail="Token fetch failed: retries exhausted")


async def _fetch_oauth_token_async(
    http: httpx.AsyncClient,
    api_url: str,
    signer: Signer,
    *,
    rng: Callable[[], float] = random.random,
) -> tuple[str, int]:
    """Async version of :func:`_fetch_oauth_token` (same retry semantics)."""
    import asyncio

    slept = 0.0
    for attempt in range(TOKEN_RETRY_ATTEMPTS):
        form = token_form(signer, api_url)
        resp = await http.post(f"{api_url}{TOKEN_PATH}", data=form, headers=_TOKEN_FORM_HEADERS)
        if resp.is_success:
            return _token_result(resp)
        delay = _token_backoff(resp, attempt, slept, rng)
        if delay is None:
            raise _token_error(resp)
        logger.warning("429 on token fetch, retrying in %.1fs", delay)
        await asyncio.sleep(delay)
        slept += delay
    raise AuthenticationError(detail="Token fetch failed: retries exhausted")


class SyncHttpClient:
    """Synchronous HTTP client with token management.

    Args:
        config_dir: Runtime config directory (profiles, agent keys, token cache).
        api_url: API base URL.
        agent_id: Optional agent UUID for ``X-Rine-Agent`` header.
        timeout: Request timeout in seconds.
        max_retries: Max retry attempts for rate limiting.
        http_client: Optional custom ``httpx.Client``.
        rng: Uniform ``[0, 1)`` source for the per-instance refresh-margin jitter
            and token-retry backoff (injectable for deterministic tests).
        keys_cache: An existing signing-key cache to share instead of starting a
            fresh one — how a short-lived client borrows a long-lived client's
            view of its peers' keys, which is what lets it notice a rotation.
        time_fn: Wall-clock source for token expiry (injectable for deterministic
            tests). Must agree with the clock ``cache_token`` writes against.
        owner_dir: Owner directory holding ``root.key``. ``RINE_OWNER_DIR``, else
            ``~/.config/rine-owner``, when omitted.
        profile: Named profile to act as; the default profile when omitted.
        agent_only: Never read the owner dir, so ``root.key`` cannot make this
            client the org (excludes ``owner_dir``).
    """

    def __init__(
        self,
        config_dir: str,
        api_url: str | None = None,
        agent_id: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: httpx.Client | None = None,
        rng: Callable[[], float] = random.random,
        keys_cache: KeyCache | None = None,
        time_fn: Callable[[], float] = time.time,
        owner_dir: str | None = None,
        profile: str | None = None,
        agent_only: bool = False,
    ) -> None:
        self._config_dir = config_dir
        self._api_url = api_url or resolve_api_url()
        self._agent_id = agent_id
        self._timeout = timeout
        self._max_retries = max_retries
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)
        self._rng = rng
        self._time_fn = time_fn
        self._refresh_margin = _jittered_margin(rng)
        self._auth = ClientAuth(
            config_dir,
            effective_owner_dir(owner_dir, agent_only),
            profile,
            self._refresh_margin,
            time_fn,
        )
        self._keys_cache = keys_cache or KeyCache(KEY_CACHE_TTL, KEY_CACHE_MAX_ENTRIES)
        self._auth.seed_pins(self._keys_cache.pins)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._owns_client:
            self._http.close()

    def _get_token(self, force: bool = False) -> str:
        """Get a valid token, refreshing it before it expires.

        The held token is only handed back while it is still fresh by this
        client's jittered margin. Without that check a process that outlives one
        token lifetime — a poller, a gateway, any always-on agent — holds its
        first token forever and learns it expired from a 401, which is one
        rejected request per token lifetime for as long as the process runs.
        Everything about which token counts as fresh lives in
        :class:`rine._token_cache.TokenCache`, held by both clients; what
        is left here is the fetch, which is the only part that differs.
        """
        if not force:
            held = self._auth.tokens.fresh_token()
            if held is not None:
                return held

        token, expires_in = _fetch_oauth_token(
            self._http,
            self._api_url,
            self._auth.resolved().signer,
            rng=self._rng,
        )
        self._auth.tokens.stamp(token, expires_in)
        return token

    def _invalidate_token(self) -> None:
        """Invalidate the in-memory token cache, expiry included."""
        self._auth.invalidate()

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers: dict[str, str] = {"User-Agent": _USER_AGENT}
        if self._agent_id:
            headers[AGENT_HEADER] = self._agent_id
        if extra:
            headers.update(extra)
        return headers

    def _execute(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> httpx.Response:
        """Run a request with token management and retries, returning the settled response.

        Shared by :meth:`request` (body only) and :meth:`request_with_status`
        (``(status, body)``) so the retry loop lives in one place.

        Args:
            method: HTTP method.
            path: URL path (appended to api_url).
            params: Query parameters.
            json_body: JSON request body.
            extra_headers: Additional headers.
            authenticated: Whether to include auth token.

        Returns:
            The settled ``httpx.Response`` — the caller checks it.

        Raises:
            APITimeoutError: On request timeout.
            APIConnectionError: On network failure.
        """
        url = path if path.startswith("http") else f"{self._api_url}{path}"
        headers = self._headers(extra_headers)
        if authenticated:
            headers["Authorization"] = f"Bearer {self._get_token()}"

        # Filter None values from params
        if params:
            params = {k: v for k, v in params.items() if v is not None}

        start = time.monotonic()
        max_attempts = self._max_retries + 2  # extra slot for 401 retry
        auth_retried = False
        resp: httpx.Response | None = None

        for attempt in range(max_attempts):
            try:
                resp = self._http.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                )
                logger.debug(
                    "%s %s → %d (%.0fms)",
                    method,
                    path,
                    resp.status_code,
                    (time.monotonic() - start) * 1000,
                )
            except httpx.TimeoutException as exc:
                if attempt < self._max_retries:
                    delay = _backoff_delay(attempt)
                    logger.warning("Timeout on %s %s, retrying in %.1fs", method, path, delay)
                    time.sleep(delay)
                    continue
                raise APITimeoutError(f"Request timed out: {method} {path}") from exc
            except httpx.ConnectError as exc:
                if attempt < self._max_retries:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        "Connect error on %s %s, retrying in %.1fs", method, path, delay
                    )
                    time.sleep(delay)
                    continue
                raise APIConnectionError(f"Connection failed: {method} {path}") from exc

            # Auto-refresh on 401 (once). WARNING, and it belongs at WARNING:
            # ``_get_token`` refreshes before the token expires, so reaching here
            # means the server rejected a token this client believed was live —
            # a revocation, a clock skew, a credential change. That is rare and
            # unexpected. It was demoted to DEBUG while this path *was* the
            # refresh mechanism and fired every token lifetime; if it ever looks
            # like routine noise again, the expiry check has regressed and that
            # is the thing to fix.
            if resp.status_code == 401 and authenticated and not auth_retried:
                logger.warning("401 received, refreshing token")
                auth_retried = True
                self._invalidate_token()
                headers["Authorization"] = f"Bearer {self._get_token(force=True)}"
                continue

            # Retry on retryable status codes
            if resp.status_code in RETRYABLE_STATUS_CODES and attempt < self._max_retries:
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 1))
                    logger.warning("429 rate limited, retrying in %.1fs", retry_after)
                    time.sleep(retry_after)
                else:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        "%d on %s %s, retrying in %.1fs", resp.status_code, method, path, delay
                    )
                    time.sleep(delay)
                continue

            return resp

        assert resp is not None
        return resp

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> Any:
        """Execute an HTTP request and return the parsed body (``None`` for 204).

        Raises:
            RineApiError: On HTTP errors.
            APITimeoutError: On request timeout.
            APIConnectionError: On network failure.
        """
        return _check_response(
            self._execute(
                method,
                path,
                params=params,
                json_body=json_body,
                extra_headers=extra_headers,
                authenticated=authenticated,
            )
        )

    def request_with_status(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[int, Any]:
        """Like :meth:`request`, but returns ``(status_code, body)``.

        For callers that discriminate on the HTTP status code (e.g. group
        ``join``: 200 member vs 202 pending request). Error handling is identical.
        """
        return _check_response_with_status(
            self._execute(
                method,
                path,
                params=params,
                json_body=json_body,
                extra_headers=extra_headers,
                authenticated=authenticated,
            )
        )

    def stream_sse(
        self,
        path: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> Iterator[tuple[str, str, str | None]]:
        """Stream server-sent events from a path.

        Args:
            path: URL path (appended to api_url).
            extra_headers: Additional headers.

        Yields:
            Tuples of (event_type, event_data, event_id).
        """
        url = path if path.startswith("http") else f"{self._api_url}{path}"
        token = self._get_token()
        headers = self._headers(extra_headers)
        headers["Authorization"] = f"Bearer {token}"

        with self._http.stream("GET", url, headers=headers, timeout=None) as resp:
            event_type = ""
            event_data = ""
            event_id: str | None = None

            for line in resp.iter_lines():
                if line.startswith("event:"):
                    event_type = line[6:].strip()
                elif line.startswith("data:"):
                    event_data = line[5:].strip()
                elif line.startswith("id:"):
                    event_id = line[3:].strip()
                elif line == "":
                    if event_type or event_data:
                        yield event_type, event_data, event_id
                        event_type = ""
                        event_data = ""
                        event_id = None

    def get_ndjson(self, path: str) -> list[dict[str, Any]]:
        """Stream NDJSON and return parsed records.

        Uses ``httpx.Client.stream()`` directly instead of ``self.request()``
        because streaming responses cannot be replayed through the generic
        retry loop.  Manual 401 handling mirrors ``request()``.

        Args:
            path: URL path (appended to api_url).

        Returns:
            List of parsed JSON objects (one per line).
        """
        url = path if path.startswith("http") else f"{self._api_url}{path}"

        for auth_attempt in range(2):
            token = self._get_token(force=auth_attempt > 0)
            headers = self._headers()
            headers["Authorization"] = f"Bearer {token}"

            with self._http.stream("GET", url, headers=headers) as resp:
                if resp.status_code == 401 and auth_attempt == 0:
                    resp.read()
                    self._invalidate_token()
                    continue
                if not resp.is_success:
                    resp.read()
                    if resp.status_code == 429:
                        detail = _parse_error_detail(resp)
                        raise RateLimitError(
                            detail=detail,
                            retry_after=_parse_retry_after(resp),
                            raw=resp.text,
                        )
                    detail = _parse_error_detail(resp)
                    raise_for_status(resp.status_code, detail, raw=resp.text)
                records: list[dict[str, Any]] = []
                for line in resp.iter_lines():
                    stripped = line.strip()
                    if stripped:
                        records.append(_json.loads(stripped))
                return records

        return []  # unreachable — satisfies type checker

    @property
    def key_pins(self) -> KeyPins:
        """The pins every key read of this client is admitted to."""
        return self._keys_cache.pins

    @property
    def principal(self) -> Principal:
        """The principal this client signs its token requests as.

        Raises:
            AuthenticationError: This process holds no identity to act as.
        """
        return self._auth.resolved().signer.principal

    def pin_own_agents(self, agent_ids: Iterable[str]) -> None:
        """Pin agents this client knows are its own org's, before any key read of them."""
        self._auth.pin_agents(self._keys_cache.pins, agent_ids)

    def get(self, path: str, **kwargs: Any) -> Any:
        """HTTP GET."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        """HTTP POST."""
        return self.request("POST", path, **kwargs)

    def post_with_status(self, path: str, **kwargs: Any) -> tuple[int, Any]:
        """HTTP POST returning ``(status_code, body)``."""
        return self.request_with_status("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        """HTTP PUT."""
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        """HTTP PATCH."""
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        """HTTP DELETE."""
        return self.request("DELETE", path, **kwargs)

    @staticmethod
    def public_get(api_url: str, path: str, params: dict[str, Any] | None = None) -> Any:
        """Unauthenticated GET for public endpoints.

        Args:
            api_url: API base URL.
            path: URL path.
            params: Query parameters.

        Returns:
            Parsed JSON response.
        """
        with httpx.Client() as http:
            resp = http.get(
                f"{api_url}{path}",
                params=params,
                headers={"User-Agent": _USER_AGENT},
            )
            return _check_response(resp)


class AsyncHttpClient:
    """Async HTTP client with token management.

    Args:
        config_dir: Runtime config directory (profiles, agent keys, token cache).
        api_url: API base URL.
        agent_id: Optional agent UUID for ``X-Rine-Agent`` header.
        timeout: Request timeout in seconds.
        max_retries: Max retry attempts for rate limiting.
        http_client: Optional custom ``httpx.AsyncClient``.
        rng: Uniform ``[0, 1)`` source for the per-instance refresh-margin jitter
            and token-retry backoff (injectable for deterministic tests).
        time_fn: Wall-clock source for token expiry (injectable for deterministic
            tests). Must agree with the clock ``cache_token`` writes against.
        owner_dir: Owner directory holding ``root.key``. ``RINE_OWNER_DIR``, else
            ``~/.config/rine-owner``, when omitted.
        profile: Named profile to act as; the default profile when omitted.
        agent_only: Never read the owner dir, so ``root.key`` cannot make this
            client the org (excludes ``owner_dir``).
    """

    def __init__(
        self,
        config_dir: str,
        api_url: str | None = None,
        agent_id: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: httpx.AsyncClient | None = None,
        rng: Callable[[], float] = random.random,
        time_fn: Callable[[], float] = time.time,
        owner_dir: str | None = None,
        profile: str | None = None,
        agent_only: bool = False,
    ) -> None:
        self._config_dir = config_dir
        self._api_url = api_url or resolve_api_url()
        self._agent_id = agent_id
        self._timeout = timeout
        self._max_retries = max_retries
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout)
        self._rng = rng
        self._time_fn = time_fn
        self._refresh_margin = _jittered_margin(rng)
        self._auth = ClientAuth(
            config_dir,
            effective_owner_dir(owner_dir, agent_only),
            profile,
            self._refresh_margin,
            time_fn,
        )
        self._keys_cache = KeyCache(KEY_CACHE_TTL, KEY_CACHE_MAX_ENTRIES)
        self._auth.seed_pins(self._keys_cache.pins)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._owns_client:
            await self._http.aclose()

    async def _get_token(self, force: bool = False) -> str:
        """Get a valid token, refreshing it before it expires.

        The held token is only handed back while it is still fresh by this
        client's jittered margin. Without that check a process that outlives one
        token lifetime — a poller, a gateway, any always-on agent — holds its
        first token forever and learns it expired from a 401, which is one
        rejected request per token lifetime for as long as the process runs.
        Everything about which token counts as fresh lives in
        :class:`rine._token_cache.TokenCache`, held by both clients; what
        is left here is the fetch, which is the only part that differs.
        """
        if not force:
            held = self._auth.tokens.fresh_token()
            if held is not None:
                return held

        token, expires_in = await _fetch_oauth_token_async(
            self._http,
            self._api_url,
            self._auth.resolved().signer,
            rng=self._rng,
        )
        self._auth.tokens.stamp(token, expires_in)
        return token

    def _invalidate_token(self) -> None:
        """Invalidate the in-memory token cache, expiry included."""
        self._auth.invalidate()

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers: dict[str, str] = {"User-Agent": _USER_AGENT}
        if self._agent_id:
            headers[AGENT_HEADER] = self._agent_id
        if extra:
            headers.update(extra)
        return headers

    async def _execute(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> httpx.Response:
        """Run an async request with token management and retries, returning the response.

        Shared by :meth:`request` (body only) and :meth:`request_with_status`
        (``(status, body)``) so the retry loop lives in one place.

        Args:
            method: HTTP method.
            path: URL path (appended to api_url).
            params: Query parameters.
            json_body: JSON request body.
            extra_headers: Additional headers.
            authenticated: Whether to include auth token.

        Returns:
            The settled ``httpx.Response`` — the caller checks it.

        Raises:
            APITimeoutError: On request timeout.
            APIConnectionError: On network failure.
        """
        import asyncio

        url = path if path.startswith("http") else f"{self._api_url}{path}"
        headers = self._headers(extra_headers)
        if authenticated:
            headers["Authorization"] = f"Bearer {await self._get_token()}"

        if params:
            params = {k: v for k, v in params.items() if v is not None}

        start = time.monotonic()
        max_attempts = self._max_retries + 2  # extra slot for 401 retry
        auth_retried = False
        resp: httpx.Response | None = None

        for attempt in range(max_attempts):
            try:
                resp = await self._http.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                )
                logger.debug(
                    "%s %s → %d (%.0fms)",
                    method,
                    path,
                    resp.status_code,
                    (time.monotonic() - start) * 1000,
                )
            except httpx.TimeoutException as exc:
                if attempt < self._max_retries:
                    delay = _backoff_delay(attempt)
                    logger.warning("Timeout on %s %s, retrying in %.1fs", method, path, delay)
                    await asyncio.sleep(delay)
                    continue
                raise APITimeoutError(f"Request timed out: {method} {path}") from exc
            except httpx.ConnectError as exc:
                if attempt < self._max_retries:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        "Connect error on %s %s, retrying in %.1fs", method, path, delay
                    )
                    await asyncio.sleep(delay)
                    continue
                raise APIConnectionError(f"Connection failed: {method} {path}") from exc

            # Auto-refresh on 401 (once). WARNING, and it belongs at WARNING:
            # ``_get_token`` refreshes before the token expires, so reaching here
            # means the server rejected a token this client believed was live —
            # a revocation, a clock skew, a credential change. That is rare and
            # unexpected. It was demoted to DEBUG while this path *was* the
            # refresh mechanism and fired every token lifetime; if it ever looks
            # like routine noise again, the expiry check has regressed and that
            # is the thing to fix.
            if resp.status_code == 401 and authenticated and not auth_retried:
                logger.warning("401 received, refreshing token")
                auth_retried = True
                self._invalidate_token()
                headers["Authorization"] = f"Bearer {await self._get_token(force=True)}"
                continue

            # Retry on retryable status codes
            if resp.status_code in RETRYABLE_STATUS_CODES and attempt < self._max_retries:
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 1))
                    logger.warning("429 rate limited, retrying in %.1fs", retry_after)
                    await asyncio.sleep(retry_after)
                else:
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        "%d on %s %s, retrying in %.1fs", resp.status_code, method, path, delay
                    )
                    await asyncio.sleep(delay)
                continue

            return resp

        assert resp is not None
        return resp

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> Any:
        """Execute an async HTTP request and return the parsed body (``None`` for 204).

        Raises:
            RineApiError: On HTTP errors.
            APITimeoutError: On request timeout.
            APIConnectionError: On network failure.
        """
        return _check_response(
            await self._execute(
                method,
                path,
                params=params,
                json_body=json_body,
                extra_headers=extra_headers,
                authenticated=authenticated,
            )
        )

    async def request_with_status(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> tuple[int, Any]:
        """Like :meth:`request`, but returns ``(status_code, body)``.

        For callers that discriminate on the HTTP status code (e.g. group
        ``join``: 200 member vs 202 pending request). Error handling is identical.
        """
        return _check_response_with_status(
            await self._execute(
                method,
                path,
                params=params,
                json_body=json_body,
                extra_headers=extra_headers,
                authenticated=authenticated,
            )
        )

    async def stream_sse(
        self,
        path: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[tuple[str, str, str | None]]:
        """Stream server-sent events from a path (async).

        Args:
            path: URL path (appended to api_url).
            extra_headers: Additional headers.

        Yields:
            Tuples of (event_type, event_data, event_id).
        """
        url = path if path.startswith("http") else f"{self._api_url}{path}"
        token = await self._get_token()
        headers = self._headers(extra_headers)
        headers["Authorization"] = f"Bearer {token}"

        async with self._http.stream("GET", url, headers=headers, timeout=None) as resp:
            event_type = ""
            event_data = ""
            event_id: str | None = None

            async for line in resp.aiter_lines():
                if line.startswith("event:"):
                    event_type = line[6:].strip()
                elif line.startswith("data:"):
                    event_data = line[5:].strip()
                elif line.startswith("id:"):
                    event_id = line[3:].strip()
                elif line == "":
                    if event_type or event_data:
                        yield event_type, event_data, event_id
                        event_type = ""
                        event_data = ""
                        event_id = None

    async def get_ndjson(self, path: str) -> list[dict[str, Any]]:
        """Stream NDJSON and return parsed records (async).

        Uses ``httpx.AsyncClient.stream()`` directly instead of
        ``self.request()`` because streaming responses cannot be replayed
        through the generic retry loop.  Manual 401 handling mirrors
        ``request()``.

        Args:
            path: URL path (appended to api_url).

        Returns:
            List of parsed JSON objects (one per line).
        """
        url = path if path.startswith("http") else f"{self._api_url}{path}"

        for auth_attempt in range(2):
            token = await self._get_token(force=auth_attempt > 0)
            headers = self._headers()
            headers["Authorization"] = f"Bearer {token}"

            async with self._http.stream("GET", url, headers=headers) as resp:
                if resp.status_code == 401 and auth_attempt == 0:
                    await resp.aread()
                    self._invalidate_token()
                    continue
                if not resp.is_success:
                    await resp.aread()
                    if resp.status_code == 429:
                        detail = _parse_error_detail(resp)
                        raise RateLimitError(
                            detail=detail,
                            retry_after=_parse_retry_after(resp),
                            raw=resp.text,
                        )
                    detail = _parse_error_detail(resp)
                    raise_for_status(resp.status_code, detail, raw=resp.text)
                records: list[dict[str, Any]] = []
                async for line in resp.aiter_lines():
                    stripped = line.strip()
                    if stripped:
                        records.append(_json.loads(stripped))
                return records

        return []  # unreachable — satisfies type checker

    @property
    def key_pins(self) -> KeyPins:
        """The pins every key read of this client is admitted to."""
        return self._keys_cache.pins

    def pin_own_agents(self, agent_ids: Iterable[str]) -> None:
        """Pin agents this client knows are its own org's, before any key read of them."""
        self._auth.pin_agents(self._keys_cache.pins, agent_ids)

    async def get(self, path: str, **kwargs: Any) -> Any:
        """HTTP GET."""
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:
        """HTTP POST."""
        return await self.request("POST", path, **kwargs)

    async def post_with_status(self, path: str, **kwargs: Any) -> tuple[int, Any]:
        """HTTP POST returning ``(status_code, body)``."""
        return await self.request_with_status("POST", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> Any:
        """HTTP PUT."""
        return await self.request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> Any:
        """HTTP PATCH."""
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> Any:
        """HTTP DELETE."""
        return await self.request("DELETE", path, **kwargs)
