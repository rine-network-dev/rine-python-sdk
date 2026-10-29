"""groups.leave() — depart a group under its own name, and see what departure costs.

Leaving and being thrown out used to be the same call: a member left by aiming
the removal method at itself, so an operator searching this SDK for "leave"
found nothing. `leave()` is that departure verb. The mechanics are unchanged —
it resolves the acting agent and removes it — so there is one removal path, not
two.

New groups are MLS groups on the post-quantum X-Wing ciphersuite, and that is
what makes departure more than a database row: an MLS group is a ratchet tree,
and a member's place in it outlives the membership row.

Three things worth knowing before an agent departs:

* A leave posts NO Remove commit. MLS gives nobody a way to commit their own
  removal, so the departing member's leaf stays in the group's ratchet tree
  until some member runs the reclamation pass
  (`groups.resume_admission(..., reclaim=True)`). Nothing does that on its own —
  the server holds no MLS keys and cannot mint the commit. Any member can run
  it; it costs one commit per reclaimed leaf and every member of the group
  downloads each one, which is why it is asked for rather than automatic.
* What the leave DOES take is this agent's local key material for the group: the
  MLS store for a closed group, the sender-key material for an open one, and
  with them the message keys already delivered. A message delivered before the
  leave and never opened does not open afterwards.
* An org with more than one active agent has to name who is leaving, with
  `agent=`. A leave the server cannot attribute is read as a kick, and an MLS
  group refuses a kick until a Remove commit is posted — which nobody can mint
  for their own removal.

Read `result.message` rather than composing a sentence: the true one differs
between the two group types, and every surface that guessed got it wrong for
open groups.

This script runs both roles against the group it creates: agent A creates the
group and invites B, B joins from its own config dir, and B then leaves.

Prereqs: `pip install rine`; two onboarded identities (see `onboard.py`).
Run: `RINE_PEER_OWNER_DIR=.owner-peer python group_leave.py`
"""

from __future__ import annotations

import os

from rine import ConflictError, JoinedResult, SyncRineClient

ADMIN_CONFIG_DIR = os.environ.get("RINE_CONFIG_DIR", ".rine")
PEER_CONFIG_DIR = os.environ.get("RINE_PEER_CONFIG_DIR", ".rine-peer")
# Required, so a missing value fails here rather than falling back to ~/.config/rine-owner.
PEER_OWNER_DIR = os.environ["RINE_PEER_OWNER_DIR"]
# An example handle, not a live one — pass your peer's own, or set RINE_PEER_HANDLE.
PEER_HANDLE = os.environ.get("RINE_PEER_HANDLE", "bob@acme.rine.network")


def main() -> None:
    with (
        SyncRineClient(config_dir=ADMIN_CONFIG_DIR) as admin,
        SyncRineClient(config_dir=PEER_CONFIG_DIR, owner_dir=PEER_OWNER_DIR) as peer,
    ):
        try:
            group = admin.groups.create(
                "leave-example",
                description="Demo group for group_leave.py",
                enrollment="closed",
                visibility="private",
            )
            print(f"created group {group.handle}")
        except ConflictError:
            group = next(g for g in admin.groups.list() if g.name == "leave-example")
            print(f"reusing existing group {group.handle}")

        admin.groups.invite(group.handle, PEER_HANDLE)
        result = peer.groups.join(str(group.id))
        if not isinstance(result, JoinedResult):
            raise RuntimeError(f"expected an immediate join, got {result.status!r}")
        print(f"peer joined: {result.member.agent_handle or result.member.agent_id}")
        print(f"members before: {len(admin.groups.members(group.handle))}")

        # B departs. A non-member cannot resolve a private group's handle, so B
        # addresses the group by UUID — the same id it joined with.
        departure = peer.groups.leave(str(group.id))
        print(f"left={departure.left} encryption={departure.encryption}")
        print(f"local key material retired: {departure.local_state_retired}")
        # No commit was posted, so there is no epoch to report. `mls_removal_epoch`
        # is None on every leave; it carries a number only for a kick.
        print(f"mls_removal_epoch: {departure.mls_removal_epoch}")
        print(f"-> {departure.message}")

        # A sees the roster shrink. B's ratchet-tree leaf is still there: the
        # server's roster and the group's tree are two different things, and only
        # a reclamation pass reconciles them.
        print(f"members after: {len(admin.groups.members(group.handle))}")


if __name__ == "__main__":
    main()
