"""KeyPackage pool lifecycle: publish and low-water top-up.

The cutover drain lives in :mod:`rine._mls.key_package_cutover`.

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
from rine._mls.api import upload_key_packages
from rine._mls.binding import KEY_PACKAGE_TARGET, open_mls_client
from rine._mls.wire import api_error_code
from rine.errors import RineApiError


@dataclass(frozen=True)
class MlsKeyPackageStatus:
    """Outcome of a replenishment attempt."""

    available: int
    """Unconsumed KeyPackages held before the call."""

    published: int
    """Minted and uploaded by this call; 0 means the pool was already healthy."""

    cap_reached: bool
    """Server inventory is at its cap — a no-op success, not a failure."""


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
        if is_inventory_full(err):
            return MlsKeyPackageStatus(available=available, published=0, cap_reached=True)
        raise
    return MlsKeyPackageStatus(available=available, published=stored, cap_reached=False)


def replenish_mls_key_packages(client: Any, config_dir: str, agent_id: str) -> None:
    """Replenish as a side effect of an MLS operation.

    Replenishment is maintenance, never the caller's purpose: a failed top-up must
    not fail the group operation it rode along with, and every later MLS operation
    retries it, so the pool self-heals with no user-facing surface.

    The heartbeat does not go through here — it awaits
    :func:`ensure_mls_key_packages` itself, because it has to know whether the
    beat actually did the maintenance its floor then claims was done. This is
    the wrapper for the callers that genuinely do not care: onboarding, which
    mints the FIRST pool with no group and nothing to be short for.
    """
    try:
        ensure_mls_key_packages(client, config_dir, agent_id)
    except Exception:
        logger.debug("MLS KeyPackage replenishment deferred", exc_info=True)


#: The server's ``error`` key when an upload would take the agent past its cap.
INVENTORY_FULL = "key_package_inventory_full"


def is_inventory_full(err: object) -> bool:
    """The server refusing an upload that would push this agent past its cap.

    A no-op success wherever it is caught: an agent at the cap already holds far
    more key packages than any peer can claim. The machine code decides; the
    detail sentence is matched only for a server that answers without one.
    """
    if not isinstance(err, RineApiError):
        return False
    return api_error_code(err) == INVENTORY_FULL or "inventory full" in str(err.detail).lower()
