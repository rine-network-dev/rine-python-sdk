"""Taking back this agent's own seat when no local state matches it.

A seated member that holds no loadable MLS state, with no Welcome waiting for it, still
has a leaf in the tree under its own credential. Once the tree verifies, it replaces that
leaf by external commit, exactly as recovery does for a restored device. That is the one
place a resync starts from absent state, and the trigger is the state itself: nothing is
remembered about how the agent came to lose it.

The retake runs on group sync and on the join verb, never on a read or a send. The reclaim
admits nobody.
"""

from __future__ import annotations

from typing import Any

from rine._mls.binding import NoSeatToReplaceError, PeerNotAdmittedError
from rine._mls.group_access import holds_mls_state, open_mls_group
from rine._mls.peer_refusal import peer_not_admitted_refusal
from rine._mls.resync import MlsRecoveryResult, recover_mls_group
from rine._mls.rotated_leaf import MlsRotatedLeafError
from rine._mls.welcome_spool import WelcomeSpool
from rine._mls.welcomes import process_mls_welcomes
from rine._recover_reseat import ReseatStatus, retake_seat
from rine.errors import MlsResyncUnavailableError


def welcome_kept(config_dir: str, agent_id: str, group_id: str) -> bool:
    """Whether a Welcome for the group is still on the spool, kept for a later attempt."""
    return any(
        d.group_id.lower() == group_id.lower()
        for _, d in WelcomeSpool(config_dir, agent_id).pending()
    )


def reseat_stranded_seat(
    client: Any, config_dir: str, agent_id: str, group_id: str
) -> MlsRecoveryResult | None:
    """Retake this agent's own leaf, for a caller that found no loadable state.

    A Welcome for the group is installed first. A Welcome kept on the spool stops the
    retake, because replacing the leaf would orphan the KeyPackage that Welcome is sealed
    to.

    Returns:
        The recovery result of the retake, or ``None`` when the Welcome pass installed
        state and the caller should carry on with it.

    Raises:
        MlsWelcomeRefusedError: A Welcome for this group was refused, or the tree holds a
            member this agent cannot verify (``peer_not_admitted``).
        MlsResyncUnavailableError: A Welcome is kept for the group, the tree holds no leaf
            this agent can replace, or the group has published no GroupInfo.
    """
    process_mls_welcomes(client, config_dir, agent_id, for_group=group_id)
    if holds_mls_state(config_dir, agent_id, group_id):
        return None
    if welcome_kept(config_dir, agent_id, group_id):
        raise MlsResyncUnavailableError(group_id)
    try:
        reseat = retake_seat(client, config_dir, agent_id, group_id)
    except PeerNotAdmittedError as err:
        raise peer_not_admitted_refusal(group_id) from err
    except (NoSeatToReplaceError, MlsRotatedLeafError) as err:
        raise MlsResyncUnavailableError(group_id) from err
    if reseat.status is not ReseatStatus.RESEATED:
        raise MlsResyncUnavailableError(group_id)
    epoch = open_mls_group(config_dir, agent_id, group_id).epoch()
    return MlsRecoveryResult(
        regime="mls",
        rung="resync",
        from_epoch=epoch,
        epoch=epoch,
        behind=None,
        processed=0,
        evicted=False,
        escrow=reseat.escrow,
    )


def recover_mls_group_or_reseat(
    client: Any, config_dir: str, agent_id: str, group_id: str
) -> MlsRecoveryResult:
    """:func:`~rine._mls.resync.recover_mls_group`, after retaking an agent's own seat.

    State that loads goes straight to the ladder. State that does not is retaken first;
    a Welcome that installed it is caught up by the ladder like any held state.
    """
    if not holds_mls_state(config_dir, agent_id, group_id):
        reseated = reseat_stranded_seat(client, config_dir, agent_id, group_id)
        if reseated is not None:
            return reseated
    return recover_mls_group(client, config_dir, agent_id, group_id)
