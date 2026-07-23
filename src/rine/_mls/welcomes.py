"""Installing the Welcomes an agent has been sent — one of the two ways in.

A member added by an existing member gets a Welcome: the founder's commit sealed
this agent's group secrets to the KeyPackage it published. Processing it is what
turns a rine group membership into an MLS membership.

Ordering is the whole design here. The Welcome is fetched destructively (see
:mod:`rine._mls.welcome_spool`), so it is persisted before it is used, and the
spooled copy is dropped only once the join has a final outcome — installed, or
provably unusable.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from rine._logging import logger
from rine._mls.api import MlsWelcomeDelivery, fetch_welcomes
from rine._mls.binding import (
    CipherSuiteMismatchError,
    MlsClient,
    MlsProtocolError,
    open_mls_client,
)
from rine._mls.group_access import load_mls_group
from rine._mls.key_packages import replenish_mls_key_packages
from rine._mls.welcome_spool import WelcomeSpool


@dataclass(frozen=True)
class MlsWelcomeOutcome:
    """What installing this agent's pending Welcomes achieved."""

    group_ids: tuple[str, ...]
    """Groups this agent now holds MLS state for."""

    discarded: int
    """Welcomes this MLS core cannot use; each was reported and dropped."""


def process_mls_welcomes(client: Any, config_dir: str, agent_id: str) -> MlsWelcomeOutcome:
    """Install every Welcome waiting for this agent.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: Agent UUID whose Welcomes are being installed.

    Returns:
        The groups now joined, and how many Welcomes were unusable.
    """
    spool = WelcomeSpool(config_dir, agent_id)
    for delivery in fetch_welcomes(client, agent_id):
        spool.store(delivery)

    pending = spool.pending()
    if not pending:
        return MlsWelcomeOutcome(group_ids=(), discarded=0)

    mls = open_mls_client(config_dir, agent_id)
    joined: list[str] = []
    discarded = 0
    for path, delivery in pending:
        group_id = _install(mls, delivery)
        if group_id is None:
            discarded += 1
        else:
            joined.append(group_id)
        spool.discard(path)

    # Every processed Welcome consumed one of this agent's published KeyPackages.
    # This is the only path on which an agent's own pool shrinks, so it is where
    # topping it back up matters most: without it the agent silently becomes
    # un-addable once its onboarding batch runs out.
    replenish_mls_key_packages(client, config_dir, agent_id)
    return MlsWelcomeOutcome(group_ids=tuple(joined), discarded=discarded)


def _install(mls: MlsClient, delivery: MlsWelcomeDelivery) -> str | None:
    """Join the group one Welcome invites this agent to.

    Returns:
        The group id now held locally, or ``None`` when the Welcome is unusable
        and there is nothing to retry.
    """
    try:
        group = mls.join_from_welcome(delivery.welcome)
    except (MlsProtocolError, CipherSuiteMismatchError) as exc:
        # Replaying a Welcome that already joined is one of these: `save()`
        # consumed the private KeyPackage half, so the second attempt cannot
        # find it. Local state settles which it was.
        if load_mls_group(mls, delivery.group_id) is not None:
            return delivery.group_id
        logger.warning(
            "Discarding an unusable MLS welcome for group %s: %s. It was minted by a "
            "different MLS core or for a different ciphersuite — ask an existing member "
            "to invite this agent again once everyone is on the current rine release.",
            delivery.group_id,
            exc,
        )
        return None

    joined_id = str(uuid.UUID(bytes=group.group_id()))
    if joined_id != delivery.group_id.lower():
        # The state key and the group a user sees would disagree from here on,
        # which is unrecoverable in a way that failing loudly is not.
        logger.warning(
            "Discarding an MLS welcome delivered for group %s that carries group id %s",
            delivery.group_id,
            joined_id,
        )
        return None

    group.save()
    return delivery.group_id
