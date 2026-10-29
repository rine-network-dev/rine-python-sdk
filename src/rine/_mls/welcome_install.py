"""Joining the group one Welcome invites this agent to."""

from __future__ import annotations

from rine._logging import logger
from rine._mls.allowed import WELCOME_VERIFICATION_LIMIT
from rine._mls.api import MlsWelcomeDelivery
from rine._mls.binding import (
    CipherSuiteMismatchError,
    MlsClient,
    MlsCoreError,
    MlsProtocolError,
    PeerNotAdmittedError,
)
from rine._mls.commit_admission import admit_refused_peers, refused_agent
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
from rine._mls.escrow_settle import settle_escrow
from rine._mls.group_access import load_mls_group, note_mls_state_changed
from rine._mls.heartbeat import MlsActor
from rine._mls.peer_refusal import peer_not_admitted_refusal
from rine._mls.welcome_guard import welcome_refusal


class WelcomeKept(Exception):
    """A member's verification failed for now: the Welcome stays spooled for the next pass."""


def install_welcome(
    actor: MlsActor, mls: MlsClient, delivery: MlsWelcomeDelivery
) -> tuple[str, EscrowReport] | None:
    """Join the group one Welcome invites this agent to.

    Returns:
        The group id now held locally with its escrow report, or ``None`` when the
        Welcome is unusable and there is nothing to retry.

    Raises:
        MlsWelcomeRefusedError: The Welcome joined a group this client refuses to
            adopt under that id — see :mod:`rine._mls.welcome_guard` — or its tree holds
            a member this agent cannot verify (``peer_not_admitted``).
        WelcomeKept: A member the Welcome names could not be verified for now. Nothing
            was written, so the private half is intact for the next pass.
    """
    try:
        group = admit_refused_peers(
            actor,
            mls,
            lambda: mls.join_from_welcome(delivery.welcome),
            WELCOME_VERIFICATION_LIMIT,
        )
    except (MlsProtocolError, CipherSuiteMismatchError) as exc:
        if isinstance(exc, PeerNotAdmittedError):
            # Read first: any later call on `mls` clears what the core recorded.
            refused = refused_agent(mls)
            if refused == actor.agent_id.lower():
                # The agent's own leaf under a key it rotated away from. The server
                # still vouches for it and no reclaim removes it, so the Welcome is
                # dropped and the seat retake answers for the leaf.
                return None
            logger.warning(
                "Discarding the MLS welcome for group %s: its ratchet tree holds a "
                "member this agent could not verify (agent %s).",
                delivery.group_id,
                refused,
            )
            # A refusal no later attempt on these bytes can clear.
            raise peer_not_admitted_refusal(delivery.group_id) from exc
        # Replaying a Welcome that already joined is one of these: `save()`
        # consumed the private KeyPackage half, so the second attempt cannot
        # find it. Local state settles which it was.
        if load_mls_group(mls, delivery.group_id) is not None:
            return delivery.group_id, EscrowReport()
        logger.warning(
            "Discarding an unusable MLS welcome for group %s: %s. It was minted by a "
            "different MLS core or for a different ciphersuite — ask an existing member "
            "to invite this agent again once everyone is on the current rine release.",
            delivery.group_id,
            exc,
        )
        return None
    except MlsCoreError:
        raise
    except Exception as exc:
        logger.warning(
            "Could not verify a member named by the MLS welcome for group %s; "
            "it is kept for the next pass.",
            delivery.group_id,
            exc_info=True,
        )
        raise WelcomeKept from exc

    # A processed Welcome is an establishment: invalidate here, at the mutation,
    # so a "this agent holds no MLS state" answer taken before it cannot survive
    # the join that made it false.
    note_mls_state_changed(actor.config_dir, actor.agent_id, delivery.group_id)

    refusal = welcome_refusal(actor.client, mls, group, delivery, actor.agent_id)
    if refusal is not None:
        raise refusal

    settled = settle_escrow(actor, delivery.group_id)
    drained = drain_escrow(actor, delivery.group_id, group, carry_unreported=True)
    return delivery.group_id, settled.merge(drained.report())
