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

Both reads end in the same place: the response is chain-verified and admitted
to the client's pins before anything downstream sees a key
(:mod:`rine._crypto.certs`, :mod:`rine._crypto._key_pins`). A key that fails
either is never cached, never sealed to and never used to verify a signature.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._crypto.certs import ChainError, VerifiedAgentKeys, verify_agent_chain

if TYPE_CHECKING:
    from rine._crypto._key_pins import KeyPins
    from rine._crypto._published_keys_readers import AsyncPublishedKeysReader, PublishedKeysReader
    from rine._http import AsyncHttpClient, SyncHttpClient


def _params(gen: int | None) -> dict[str, Any]:
    return {} if gen is None else {"params": {"gen": gen}}


def _admit(
    pins: KeyPins, data: dict[str, Any], agent_id: str, gen: int | None
) -> VerifiedAgentKeys:
    """Verify a raw response and pin it; ``gen`` marks a deliberate old-generation read."""
    keys = verify_agent_chain(data, agent_id)
    if gen is not None and keys.key_gen != gen:
        raise ChainError("the response is not the generation that was asked for")
    pins.admit(keys, historical=gen is not None)
    return keys


def _cache_key(agent_id: str, gen: int | None) -> str:
    """A superseded generation caches under ``<agent id>#<gen>``, apart from the current one."""
    return agent_id if gen is None else f"{agent_id}#{gen}"


def _admissible(pins: KeyPins, cached: VerifiedAgentKeys, *, historical: bool = False) -> bool:
    """Whether a cached answer still clears the pins as they stand now.

    A pin may have moved since the entry was cached (a newer generation seen on
    another path), and a cache hit must not outlive it. A refusal is not an
    error here: it means the entry is stale, so the caller reads fresh.
    """
    try:
        pins.admit(cached, historical=historical)
    except ChainError:
        return False
    return True


def fetch_verified_keys_sync(
    client: PublishedKeysReader, agent_id: str, *, gen: int | None = None
) -> VerifiedAgentKeys:
    """Read an agent's keys straight from the API, chain-verified (sync).

    Args:
        client: Anything that can GET and carries the pins.
        agent_id: Agent UUID.
        gen: A superseded generation to read, for verifying an old message.

    Raises:
        ChainError: The chain or a pin refuses the answer.
    """
    data: dict[str, Any] = client.get(f"/agents/{agent_id}/keys", **_params(gen))
    return _admit(client.key_pins, data, agent_id, gen)


async def fetch_verified_keys_async(
    client: AsyncPublishedKeysReader, agent_id: str, *, gen: int | None = None
) -> VerifiedAgentKeys:
    """Read an agent's keys straight from the API, chain-verified (async).

    See :func:`fetch_verified_keys_sync`.
    """
    data: dict[str, Any] = await client.get(f"/agents/{agent_id}/keys", **_params(gen))
    return _admit(client.key_pins, data, agent_id, gen)


def get_agent_keys_sync(
    client: SyncHttpClient,
    agent_id: str,
    *,
    bypass: bool = False,
    gen: int | None = None,
) -> tuple[VerifiedAgentKeys, bool]:
    """Fetch an agent's verified keys through the client's TTL cache (sync).

    The INBOUND-VERIFY read, and the only one that may serve a cached key: a
    stale key announces itself, because the signature fails and
    :func:`rine._crypto._sender_verify.verify_envelope_sender_sync` refetches.

    Args:
        client: HTTP client owning the per-instance key cache.
        agent_id: Agent UUID.
        bypass: Skip the cache read (forces a network fetch) but still refresh
            the cache with the result — used by the verify-failure refetch.
        gen: A superseded generation to read. It caches apart from the
            current-generation entry (see :func:`_cache_key`).

    Returns:
        A ``(keys, from_cache)`` pair. Callers use ``from_cache`` to gate the
        verify-failure refetch so a fresh miss is not re-fetched.
    """
    cache_key = _cache_key(agent_id, gen)
    if not bypass:
        cached = client._keys_cache.get(cache_key)
        if cached is not None and _admissible(client.key_pins, cached, historical=gen is not None):
            return cached, True
    keys = fetch_verified_keys_sync(client, agent_id, gen=gen)
    client._keys_cache.set(cache_key, keys)
    return keys, False


async def get_agent_keys_async(
    client: AsyncHttpClient,
    agent_id: str,
    *,
    bypass: bool = False,
    gen: int | None = None,
) -> tuple[VerifiedAgentKeys, bool]:
    """Fetch an agent's verified keys through the client's TTL cache (async).

    Returns a ``(keys, from_cache)`` pair; see :func:`get_agent_keys_sync`.
    """
    cache_key = _cache_key(agent_id, gen)
    if not bypass:
        cached = client._keys_cache.get(cache_key)
        if cached is not None and _admissible(client.key_pins, cached, historical=gen is not None):
            return cached, True
    keys = await fetch_verified_keys_async(client, agent_id, gen=gen)
    client._keys_cache.set(cache_key, keys)
    return keys, False


def fetch_recipient_keys_sync(client: PublishedKeysReader, agent_id: str) -> VerifiedAgentKeys:
    """Fetch a recipient's verified keys for sealing (sync).

    The OUTBOUND-SEAL read, and deliberately cache-free: the parameter type
    grants only ``get`` and the pins, so this path cannot reach the client's key
    cache even by accident. Sealing is one-shot and silent — nothing ever tells
    this client that the key it sealed to was superseded, so a cached entry would
    let a peer's rotation pass unnoticed for a whole TTL, and every message
    sealed in that window would be permanently unreadable for its recipient. The
    verify path can afford a cache precisely because it has a failure signal to
    act on; this one does not. Keep the two asymmetric.

    Args:
        client: Anything that can GET and carries the pins.
        agent_id: Agent UUID.

    Returns:
        The recipient's chain-verified keys.
    """
    return fetch_verified_keys_sync(client, agent_id)


async def fetch_recipient_keys_async(
    client: AsyncPublishedKeysReader, agent_id: str
) -> VerifiedAgentKeys:
    """Fetch a recipient's verified keys for sealing (async).

    Mirrors :func:`fetch_recipient_keys_sync`, cache-free for the same reason.
    """
    return await fetch_verified_keys_async(client, agent_id)
