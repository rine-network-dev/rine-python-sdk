"""The refusal a join earns when the tree holds a member this agent cannot verify."""

from __future__ import annotations

from rine.errors import MlsWelcomeRefusedError


def peer_not_admitted_refusal(group_id: str) -> MlsWelcomeRefusedError:
    """The typed refusal for the core's final ``PeerNotAdmittedError`` on a join or a retake.

    The caller raises it ``from`` the core's error, so the cause stays on the chain. Final
    for the tree it names: a later attempt succeeds once any member reclaims the seat it
    cannot verify. The sentence is the TypeScript twin's, byte for byte
    (``peerNotAdmittedRefusal`` in ``rine-core/src/mls-peer-refusal.ts``).
    """
    return MlsWelcomeRefusedError(
        group_id,
        "peer_not_admitted",
        f"Cannot join the MLS group {group_id} yet: its ratchet tree holds a member "
        "this agent cannot verify, because the server no longer vouches for that "
        "agent. The group's seat for it must be reclaimed first: any other member "
        "that holds a leaf in the group can run "
        "`rine group resume-admission --reclaim` (an admin is not required); then "
        "the join can be repeated.",
    )
