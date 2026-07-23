"""Running the SDK's one MLS implementation from an async client.

MLS is compiled, synchronous work interleaved with HTTP calls. Rather than carry
a second async copy of every protocol flow — two chances to diverge on epoch
handling, one-shot fetches and state persistence — the async client runs the same
functions the sync client does, on a worker thread with its own HTTP client.
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
        client: The async client, read for its config dir, API URL and timeout.
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
        )
        try:
            return work(http)
        finally:
            http.close()

    return await asyncio.to_thread(_run)
