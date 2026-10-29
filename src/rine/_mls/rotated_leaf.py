"""A resync that fails because the agent's leaf still carries a key it has rotated away from.

A resync replaces the agent's own leaf and keeps the key that leaf carries: the
core refuses an external commit that would change it. When the agent has rotated
since it was seated, the leaf holds a superseded key, so the resync is refused
and the refusal names the agent's own id. Said that way it reads as a defect in
the agent's keys; the truth is a membership fact with a remedy, so it gets its
own typed error.

Rotation moves the agent's own leaf (:mod:`rine._mls.self_update`), so this is
reached only on a device that holds no group state able to do that, such as a
fresh device after a recovery. Only a member removing the agent and inviting it
again replaces such a leaf.

The TypeScript twin is ``MlsRotatedLeafError`` in ``rine-core/src/mls-rotated-leaf.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from rine._mls.binding import PeerNotAdmittedError, ResyncChangesKeyError
from rine._mls.commit_admission import RefusalSource, admit_refused_peers, refused_agent
from rine.errors import MlsError

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._mls.actor import MlsActor

_T = TypeVar("_T")

#: The stable code a rotated agent's resync refusal carries, shared byte-for-byte with
#: ``rine-core``'s ``MLS_ERR_ROTATED_LEAF``. A value to branch on, never a message to parse.
#: Deliberately outside the ``RINE_MLS_`` namespace: that prefix is the MLS core's own
#: vocabulary, which the TypeScript retry paths classify as a recoverable MLS read.
MLS_ERR_ROTATED_LEAF = "mls_rotated_leaf"


class MlsRotatedLeafError(MlsError):
    """This agent's leaf in the group carries a rotated-away key, so it cannot resync.

    This device holds no group state that can move the leaf. Only a member
    removing the agent and inviting it again replaces it with one under the
    current key.

    Args:
        agent_id: The agent whose seat holds the superseded key.
        group_id: The group it is seated in.
    """

    def __init__(self, agent_id: str, group_id: str) -> None:
        """Build the refusal for one agent in one group."""
        self.agent_id = agent_id
        self.group_id = group_id
        super().__init__(
            MLS_ERR_ROTATED_LEAF,
            f"Agent {agent_id}'s leaf in group {group_id} still carries a key it has since "
            "rotated away from, and this device holds no group state that can move it; "
            "a member must remove the agent and invite it again before it can resync.",
        )


def admit_refused_peers_for_resync(
    actor: MlsActor, source: RefusalSource, attempt: Callable[[], _T], group_id: str
) -> _T:
    """:func:`~rine._mls.commit_admission.admit_refused_peers` for a resync of ``group_id``.

    Raises:
        MlsRotatedLeafError: The final refusal names the acting agent itself, either as
            a leaf the allowed set does not hold or as a replacement that changes its key.
        PeerNotAdmittedError: The final refusal names any other agent.
    """
    try:
        return admit_refused_peers(actor, source, attempt)
    except PeerNotAdmittedError as err:
        if refused_agent(source) == actor.agent_id.lower():
            raise MlsRotatedLeafError(actor.agent_id, group_id) from err
        raise
    except ResyncChangesKeyError as err:
        # The core names the agent in its message, as the canonical lower-case id.
        if actor.agent_id.lower() in str(err):
            raise MlsRotatedLeafError(actor.agent_id, group_id) from err
        raise


__all__ = ["MLS_ERR_ROTATED_LEAF", "MlsRotatedLeafError", "admit_refused_peers_for_resync"]
