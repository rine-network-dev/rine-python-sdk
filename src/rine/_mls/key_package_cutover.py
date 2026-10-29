"""The KeyPackage cutover: discard the agent's whole pool, server and local, and republish.

Split from :mod:`rine._mls.key_packages`, which owns the everyday publish and top-up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._actor import AGENT_HEADER
from rine._mls.actor import MlsActor
from rine._mls.api import claim_key_packages, upload_key_packages
from rine._mls.binding import open_mls_client
from rine._mls.failures import mls_boundary
from rine._mls.key_current import disk_key_is_current
from rine._mls.key_not_current import MlsKeyNotCurrentError
from rine.errors import ConflictError

# Largest ``count`` the server's claim endpoint accepts in one request.
DRAIN_PAGE = 100
# Pages the drain will claim before giving up. The server caps an agent's
# inventory at 200 packages, so two pages empty a full pool; the extra pages
# absorb a peer uploading concurrently without letting the drain loop forever
# against a server that keeps answering.
DRAIN_MAX_PAGES = 4


@dataclass(frozen=True)
class MlsCutoverResult:
    """Outcome of the KeyPackage cutover (mirrors TS ``MlsCutoverResult``)."""

    drained: int
    """Stale KeyPackages claimed out of the server pool and discarded."""

    stored: int
    """Freshly minted KeyPackages this core published and the server stored."""


@mls_boundary
def drain_and_republish_mls_key_packages(
    client: Any, config_dir: str, agent_id: str
) -> MlsCutoverResult:
    """Discard the agent's whole KeyPackage pool — server and local — and republish.

    This is the cutover primitive: KeyPackages published by the previous
    MLS core cannot be read by this one, so a peer trying to add this agent would
    fail on every stale entry. The pool is replaced as a whole, once — never
    walked one failed add at a time.

    A device holding an earlier key generation than the agent's current one must not run
    any of this: the server refuses its packages, and the claim has already emptied the
    pool by then. So the key is checked first, before anything is minted or claimed.

    Ordering is the whole design, and matches the TS reference
    (``rine-core/src/mls-cutover.ts``) so the two stacks cut over the same way:

    1. Mint the fresh pool locally. The core persists each private half before
       returning the blob, so a crash here costs a file, never a published
       package whose private half is gone (which would make every incoming
       Welcome permanently unprocessable).
    2. Claim the stale pool out of the server. The server has no delete endpoint,
       but its claim endpoint is destructive and the owning org may claim its own
       agent's packages, so claiming-and-discarding empties the stale pool for
       real. This must precede the upload: the server hands out the *oldest*
       unconsumed package first, so publishing before draining would leave peers
       claiming stale (unreadable) packages until the last one was consumed.
    3. Upload the fresh pool.

    The window that remains: between the last claim and the upload landing this
    agent has no claimable KeyPackage, so a peer adding it in that instant gets a
    clean, retriable "No key packages available" refusal rather than a broken
    join. If the upload itself fails the window stays open.

    🔴 On the TypeScript stack the next MLS operation closes that window on its
    own: ``ensureMlsKeyPackages`` asks ``needsMlsKeyPackageCutover`` first, so
    every heartbeat retries a cutover that did not finish. This stack has no such
    detector — the legacy store and its marker are a TypeScript-side layout — so
    the cutover runs only where an operator asks for it, through
    :meth:`rine.RineClient.republish_mls_key_packages`. An earlier version of
    this docstring claimed the TypeScript behaviour for both.

    Returns:
        The count drained from the server and the count freshly stored.

    Raises:
        MlsKeyNotCurrentError: When this device's key is not the agent's current one.
    """
    if not disk_key_is_current(MlsActor(client=client, config_dir=config_dir, agent_id=agent_id)):
        raise MlsKeyNotCurrentError
    mls = open_mls_client(config_dir, agent_id)
    packages = mls.drain_and_republish_key_packages()
    drained = _claim_out_pool(client, agent_id)
    stored = upload_key_packages(client, agent_id, packages)
    return MlsCutoverResult(drained=drained, stored=stored)


def _claim_out_pool(client: Any, agent_id: str) -> int:
    """Claim the agent's own unconsumed KeyPackages out until the server has none.

    The owning org may claim its own agent's packages, and each claim marks one
    consumed, so this empties the stale server pool for real rather than leaving
    it merely outnumbered. Bounded by :data:`DRAIN_MAX_PAGES` so a peer uploading
    concurrently can never turn it into an unbounded loop.
    """
    headers = {AGENT_HEADER: agent_id}
    drained = 0
    for _ in range(DRAIN_MAX_PAGES):
        try:
            claimed = claim_key_packages(client, agent_id, DRAIN_PAGE, headers)
        except ConflictError:
            # 409 "No key packages available" is the drain's success condition —
            # the pool is empty, never an error to propagate.
            return drained
        drained += len(claimed)
        if len(claimed) < DRAIN_PAGE:
            return drained
    return drained
