"""Running the SDK's one MLS implementation from an async client.

MLS is compiled, synchronous work interleaved with HTTP calls. Rather than carry
a second async copy of every protocol flow — two chances to diverge on epoch
handling, one-shot fetches and state persistence — the async client runs the same
functions the sync client does, on a worker thread with its own HTTP client.

That client is short-lived, but the async client's key cache is not, and the
worker borrows it. Verifying an inbound envelope reports a peer's key rotation
only by noticing that the key it had cached no longer verifies, so a per-call
cache would be empty every time and no MLS group message could ever report one.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")


async def with_sync_http(client: Any, work: Callable[[Any], T]) -> T:
    """Run ``work`` against a short-lived sync HTTP client, off the event loop.

    Args:
        client: The async client, read for its config dir, API URL, timeout and
            key cache — which the worker shares rather than starting cold.
        work: Callable taking the sync HTTP client.

    Returns:
        Whatever ``work`` returns.
    """
    from rine._http import SyncHttpClient

    def _run() -> T:
        http = SyncHttpClient(
            config_dir=client._config_dir,
            api_url=client._api_url,
            timeout=client._timeout,
            keys_cache=client._http._keys_cache,
            owner_dir=client._owner_dir,
            profile=client._profile,
            agent_only=client._agent_only,
        )
        try:
            return work(http)
        finally:
            http.close()

    return await asyncio.to_thread(_run)
