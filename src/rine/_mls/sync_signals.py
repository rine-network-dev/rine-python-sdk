"""What a sync tells the server and re-bootstraps when its own state is the problem.

Split from :mod:`rine._mls.sync`: the three helpers are the sync's side effects on
the group (an ACK, a NACK, an external re-join), and the sync reads as the
catch-up loop without them in the middle.
"""

from __future__ import annotations

from typing import Any

from rine._logging import logger
from rine._mls.api import fetch_group_info
from rine._mls.external_join import ExternalJoin, ExternalJoinResult, external_join_mls_group
from rine._mls.sync_api import MlsHandshake, mls_ack, mls_nack


def reconcile_if_orphaned(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    local_epoch: int,
    headers: dict[str, str],
    carry_unreported: bool,
) -> ExternalJoinResult | None:
    """Re-bootstrap when our own local state, not the commit, is the problem.

    The orphan signal is the server's *confirmed* epoch being below our local
    one: that can only happen if our own tentative commit was rolled back, since
    the server cannot serve a confirmed token as high as an epoch we alone hold.

    Returns:
        The re-bootstrapped epoch with its escrow report, or ``None`` when the
        state is not orphaned and the caller should NACK the commit instead.
    """
    try:
        confirmed = fetch_group_info(client, group_id, headers).epoch
    except Exception:
        # pending_confirmation, or a transport hiccup: we cannot prove the state
        # is orphaned, so the commit gets the benefit of the doubt and a NACK.
        logger.debug("MLS orphan check failed for group %s", group_id, exc_info=True)
        return None
    if confirmed is None or confirmed >= local_epoch:
        return None
    return external_join_mls_group(
        ExternalJoin(
            client=client,
            config_dir=config_dir,
            agent_id=agent_id,
            group_id=group_id,
            extra_headers=headers,
            carry_unreported=carry_unreported,
        )
    )


def emit_ack(client: Any, group_id: str, object_id: str, headers: dict[str, str]) -> None:
    """Fire-and-forget ACK; a failed ACK must never fail the sync."""
    try:
        mls_ack(client, group_id, object_id, headers)
    except Exception:
        # Best-effort: the commit still confirms once any peer ACKs.
        logger.debug("MLS ack failed for group %s", group_id, exc_info=True)


def emit_nack(
    client: Any,
    group_id: str,
    handshake: MlsHandshake,
    err: BaseException,
    headers: dict[str, str],
) -> None:
    """Fire-and-forget NACK; a failed NACK must never fail the sync."""
    try:
        mls_nack(client, group_id, handshake, str(err), headers)
    except Exception:
        # Best-effort: a timeout-based rollback still self-heals the group.
        logger.debug("MLS nack failed for group %s", group_id, exc_info=True)


__all__ = ["emit_ack", "emit_nack", "reconcile_if_orphaned"]
