"""KeyPackage pool lifecycle: publish, low-water top-up, and the cutover drain.

Every add by a peer consumes one KeyPackage globally, so an agent that never
replenishes eventually becomes un-addable: the adder either fails with "No key
packages available" or silently leaves the agent out of the group it is founding.

The policy — how many to hold, when to top up, how many fit in one request — lives
in the Rust core and is read from it here, so the Python and TypeScript stacks
cannot drift apart on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._logging import logger
from rine._mls.api import claim_key_packages, upload_key_packages
from rine._mls.binding import KEY_PACKAGE_TARGET, open_mls_client
from rine.errors import ConflictError, RineApiError

# Largest ``count`` the server's claim endpoint accepts in one request.
DRAIN_PAGE = 100
# Pages the drain will claim before giving up. The server caps an agent's
# inventory at 200 packages, so two pages empty a full pool; the extra pages
# absorb a peer uploading concurrently without letting the drain loop forever
# against a server that keeps answering.
DRAIN_MAX_PAGES = 4


@dataclass(frozen=True)
class MlsKeyPackageStatus:
    """Outcome of a replenishment attempt."""

    available: int
    """Unconsumed KeyPackages held before the call."""

    published: int
    """Minted and uploaded by this call; 0 means the pool was already healthy."""

    cap_reached: bool
    """Server inventory is at its cap — a no-op success, not a failure."""


@dataclass(frozen=True)
class MlsCutoverResult:
    """Outcome of the KeyPackage cutover (mirrors TS ``MlsCutoverResult``)."""

    drained: int
    """Stale KeyPackages claimed out of the server pool and discarded."""

    stored: int
    """Freshly minted KeyPackages this core published and the server stored."""


def publish_mls_key_packages(
    client: Any, config_dir: str, agent_id: str, count: int = KEY_PACKAGE_TARGET
) -> int:
    """Mint a batch of KeyPackages and publish the public halves.

    The private halves are persisted by the core before this returns, so a
    KeyPackage the server hands out always has a private half we can process the
    resulting Welcome with. A stored private half the server never received only
    costs a file.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: Agent UUID.
        count: How many to mint. Defaults to the core's target pool size; the
            core refuses a batch above what fits in one request body.

    Returns:
        How many the server stored.
    """
    mls = open_mls_client(config_dir, agent_id)
    return upload_key_packages(client, agent_id, mls.generate_key_packages(count))


def ensure_mls_key_packages(client: Any, config_dir: str, agent_id: str) -> MlsKeyPackageStatus:
    """Top the agent's KeyPackage pool back up when it runs low.

    Inventory is read from the locally stored private halves, because the
    server's claim endpoint consumes what it returns and there is no read-only
    count endpoint. The local mirror can over-count (delaying a top-up), never
    under-count.

    Returns:
        What was held, what was published, and whether the server was at its cap.
    """
    mls = open_mls_client(config_dir, agent_id)
    available = mls.key_package_count()
    packages = mls.replenish_key_packages()
    if not packages:
        return MlsKeyPackageStatus(available=available, published=0, cap_reached=False)
    try:
        stored = upload_key_packages(client, agent_id, packages)
    except RineApiError as err:
        # The server refuses an upload that would exceed its inventory cap. Being
        # at the cap means the agent already holds far more than enough, so this
        # is a no-op success rather than an error.
        if _is_inventory_full(err):
            return MlsKeyPackageStatus(available=available, published=0, cap_reached=True)
        raise
    return MlsKeyPackageStatus(available=available, published=stored, cap_reached=False)


def replenish_mls_key_packages(client: Any, config_dir: str, agent_id: str) -> None:
    """Replenish as a side effect of an MLS operation.

    Replenishment is maintenance, never the caller's purpose: a failed top-up must
    not fail the group operation it rode along with, and every later MLS operation
    retries it, so the pool self-heals with no user-facing surface.
    """
    try:
        ensure_mls_key_packages(client, config_dir, agent_id)
    except Exception:
        logger.debug("MLS KeyPackage replenishment deferred", exc_info=True)


def drain_and_republish_mls_key_packages(
    client: Any, config_dir: str, agent_id: str
) -> MlsCutoverResult:
    """Discard the agent's whole KeyPackage pool — server and local — and republish.

    This is the cutover primitive: KeyPackages published by the previous
    MLS core cannot be read by this one, so a peer trying to add this agent would
    fail on every stale entry. The pool is replaced as a whole, once — never
    walked one failed add at a time.

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
    join. If the upload itself fails the window stays open, and the next MLS
    operation this agent performs closes it by retrying the cutover.

    Returns:
        The count drained from the server and the count freshly stored.
    """
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
    headers = {"X-Rine-Agent": agent_id}
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


def _is_inventory_full(err: RineApiError) -> bool:
    return "inventory full" in str(err.detail).lower()
