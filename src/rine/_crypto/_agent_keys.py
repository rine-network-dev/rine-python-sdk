"""The two reads of an agent's published keys — and why they differ.

``GET /agents/{id}/keys`` is read on two paths, and the one thing that matters
about them is that they are *not* the same read:

* the inbound-verify read goes through the client's TTL key cache — a stale key
  announces itself there, because the signature fails and
  :mod:`rine._crypto._sender_verify` refetches once;
* the outbound-seal read never touches that cache, and its parameter type does
  not even carry one.

Keeping the two apart is what makes a peer's key rotation visible to a send
immediately rather than a TTL later.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from rine._crypto.dm_envelope import recipient_keys_from_response

if TYPE_CHECKING:
    from rine._crypto.dm_envelope import RecipientKeys
    from rine._http import AsyncHttpClient, SyncHttpClient


class PublishedKeysReader(Protocol):
    """A client narrowed to the one capability the seal path may use (sync)."""

    def get(self, path: str, **kwargs: Any) -> Any:
        """Perform an HTTP GET and return the decoded body."""
        ...


class AsyncPublishedKeysReader(Protocol):
    """A client narrowed to the one capability the seal path may use (async)."""

    async def get(self, path: str, **kwargs: Any) -> Any:
        """Perform an HTTP GET and return the decoded body."""
        ...


def get_published_keys_sync(client: PublishedKeysReader, agent_id: str) -> dict[str, Any]:
    """Read an agent's published keys straight from the API (sync).

    Args:
        client: Anything that can GET; a full HTTP client satisfies it.
        agent_id: Agent UUID.

    Returns:
        The raw ``/agents/{id}/keys`` response.
    """
    data: dict[str, Any] = client.get(f"/agents/{agent_id}/keys")
    return data


async def get_published_keys_async(
    client: AsyncPublishedKeysReader, agent_id: str
) -> dict[str, Any]:
    """Read an agent's published keys straight from the API (async).

    See :func:`get_published_keys_sync`.
    """
    data: dict[str, Any] = await client.get(f"/agents/{agent_id}/keys")
    return data


def get_agent_keys_sync(
    client: SyncHttpClient, agent_id: str, *, bypass: bool = False
) -> tuple[dict[str, Any], bool]:
    """Fetch an agent's public keys through the client's TTL cache (sync).

    The INBOUND-VERIFY read, and the only one that may serve a cached key: a
    stale key announces itself, because the signature fails and
    :func:`rine._crypto._sender_verify.verify_envelope_sender_sync` refetches.

    Args:
        client: HTTP client owning the per-instance key cache.
        agent_id: Agent UUID.
        bypass: Skip the cache read (forces a network fetch) but still refresh
            the cache with the result — used by the verify-failure refetch.

    Returns:
        A ``(keys, from_cache)`` pair: the raw ``/agents/{id}/keys`` response
        (signing + encryption keys) and whether it was served from the cache.
        Callers use ``from_cache`` to gate the verify-failure refetch so a fresh
        miss is not re-fetched.
    """
    if not bypass:
        cached = client._keys_cache.get(agent_id)
        if cached is not None:
            return cached, True
    data = get_published_keys_sync(client, agent_id)
    client._keys_cache.set(agent_id, data)
    return data, False


async def get_agent_keys_async(
    client: AsyncHttpClient, agent_id: str, *, bypass: bool = False
) -> tuple[dict[str, Any], bool]:
    """Fetch an agent's public keys through the client's TTL cache (async).

    Returns a ``(keys, from_cache)`` pair; see :func:`get_agent_keys_sync`.
    """
    if not bypass:
        cached = client._keys_cache.get(agent_id)
        if cached is not None:
            return cached, True
    data = await get_published_keys_async(client, agent_id)
    client._keys_cache.set(agent_id, data)
    return data, False


def fetch_recipient_keys_sync(client: PublishedKeysReader, agent_id: str) -> RecipientKeys:
    """Fetch a recipient's published encryption keys (sync).

    The OUTBOUND-SEAL read, and deliberately cache-free: the parameter type
    grants only ``get``, so this path cannot reach the client's key cache even by
    accident. Sealing is one-shot and silent — nothing ever tells this client
    that the key it sealed to was superseded, so a cached entry would let a
    peer's rotation pass unnoticed for a whole TTL, and every message sealed in
    that window would be permanently unreadable for its recipient. The verify
    path can afford a cache precisely because it has a failure signal to act on;
    this one does not. Keep the two asymmetric.

    Args:
        client: Anything that can GET; a full HTTP client satisfies it.
        agent_id: Agent UUID.

    Returns:
        The recipient's X25519 key and, when published, its ML-KEM-768 key —
        which is what decides whether the message is sealed post-quantum.
    """
    return recipient_keys_from_response(get_published_keys_sync(client, agent_id))


async def fetch_recipient_keys_async(
    client: AsyncPublishedKeysReader, agent_id: str
) -> RecipientKeys:
    """Fetch a recipient's published encryption keys (async).

    Mirrors :func:`fetch_recipient_keys_sync`, cache-free for the same reason.

    Args:
        client: Anything that can GET; a full HTTP client satisfies it.
        agent_id: Agent UUID.

    Returns:
        The recipient's X25519 key and, when published, its ML-KEM-768 key.
    """
    return recipient_keys_from_response(await get_published_keys_async(client, agent_id))
