"""Holding an add while the tree carries a leaf no key read serves.

A revoked agent drops out of ``GET /agents/keys`` and its leaf stays in the ratchet tree
until a member reclaims it. A Welcome minted over that tree seats the newcomer beside a
leaf it can never verify: the core refuses the Welcome for it, the refusal is final, and
the newcomer holds a seat it cannot read from. So the adder holds every pending newcomer
until a member has reclaimed the leaf, and never removes the leaf itself — reclaiming
is a separate, deliberate act.

The TypeScript twin is ``admitGroupPeersChecked`` and ``admitUnlessHeld`` in
``rine-core/src/mls-revoked-seat.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.commit_admission import agent_id_of_identity

if TYPE_CHECKING:
    from rine._mls.admission_state import Admission
    from rine._mls.binding import MlsGroup


def _other_identities(group: MlsGroup) -> list[bytes]:
    """The credential identity of every leaf in the tree but this agent's own."""
    own = group.current_member_index()
    return [bytes(leaf.identity) for leaf in group.member_identities() if leaf.index != own]


def tree_agent_ids(group: MlsGroup) -> list[str]:
    """The agent id of every leaf in the tree but this agent's own, where it spells one."""
    spelled = (agent_id_of_identity(identity) for identity in _other_identities(group))
    return [agent_id for agent_id in spelled if agent_id is not None]


def hold_for_revoked_seats(
    admission: Admission, group: MlsGroup, candidates: list[str], served: dict[str, bytes]
) -> list[str]:
    """The candidates still to admit: none while a leaf in the tree is not served.

    Args:
        admission: The admission, which records each held newcomer as skipped.
        group: The group the candidates would join.
        candidates: Agents that hold no leaf yet.
        served: The identities the key read returned, keyed by agent id.
    """
    known = set(served.values())
    if all(identity in known for identity in _other_identities(group)):
        return candidates
    for member in candidates:
        admission.skip(member, "revoked_seat_unreclaimed")
    return []
