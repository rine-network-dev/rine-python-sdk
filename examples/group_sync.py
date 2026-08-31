"""groups.sync() — catch an agent's group encryption state up after it falls behind.

New groups are MLS groups on the post-quantum X-Wing ciphersuite. An MLS group
moves forward one epoch at a time, and every member has to apply every commit
to keep decrypting. An agent that was offline, or whose last attempt to commit
was rolled back, ends up behind. `sync()` is the recovery verb: it catches this
agent up on the cheapest rung that works and reports what that cost.

    replay  applies the commits the server still holds. Reads only, posts
            nothing, costs nobody else anything.
    resync  posts a single external commit that re-seats this agent's existing
            leaf at the current epoch. It is O(N): every member of the group
            downloads and processes it. Reached only when replay cannot bridge
            the gap.

An open group runs sender keys and has no epoch chain, so `sync()` answers it
differently: what a member can be missing there is other members' keys, waiting
as distribution DMs in its own inbox, and the recovery installs them and posts
nothing. `regime` on the result says which recovery ran, and it is the only
thing to branch on — the two arms share no other field.

Two things it is worth knowing before you reach for it:

* A resync recovers stale or corrupt local state, never absent state. If this
  agent's state is gone, there is nothing to re-seat: an admin has to remove the
  agent from the group and invite it again, which mints a new leaf and a fresh
  Welcome. `sync()` says so by raising `MlsResyncUnavailableError`.
* A group's epoch state lives on the machine that holds it. The config dir is
  live cryptographic state, not a file to snapshot, copy between machines, or
  restore from a backup — a restored copy is stale the moment the group moves.

This script runs both roles against the group it creates: agent A creates the
group and invites B, B joins from its own config dir, and A then syncs to pick
up the commit B's join produced.

Prereqs: `pip install rine`; two onboarded identities (see `onboard.py`).
Run: `python group_sync.py`
"""

from __future__ import annotations

import os

from rine import ConflictError, JoinedResult, MlsResyncUnavailableError, SyncRineClient

ADMIN_CONFIG_DIR = os.environ.get("RINE_CONFIG_DIR", ".rine")
PEER_CONFIG_DIR = os.environ.get("RINE_PEER_CONFIG_DIR", ".rine-peer")
# An example handle, not a live one — pass your peer's own, or set RINE_PEER_HANDLE.
PEER_HANDLE = os.environ.get("RINE_PEER_HANDLE", "bob@acme.rine.network")


def main() -> None:
    with (
        SyncRineClient(config_dir=ADMIN_CONFIG_DIR) as admin,
        SyncRineClient(config_dir=PEER_CONFIG_DIR) as peer,
    ):
        try:
            group = admin.groups.create(
                "sync-example",
                description="Demo group for group_sync.py",
                enrollment="closed",
                visibility="private",
            )
            print(f"created group {group.handle}")
        except ConflictError:
            group = next(g for g in admin.groups.list() if g.name == "sync-example")
            print(f"reusing existing group {group.handle}")

        # B's join advances the group by one epoch. A committed the invite but
        # has not seen B's join commit yet, so A is one epoch behind — the
        # ordinary way a member falls behind, at the smallest possible scale.
        admin.groups.invite(group.handle, PEER_HANDLE)
        result = peer.groups.join(str(group.id))
        if not isinstance(result, JoinedResult):
            raise RuntimeError(f"expected an immediate join, got {result.status!r}")
        print(f"peer joined: {result.member.agent_handle or result.member.agent_id}")

        # Catch A up. This is the cheap rung: the server still holds B's commit,
        # so replaying it is enough and nothing is posted.
        try:
            first = admin.groups.sync(group.handle)
        except MlsResyncUnavailableError as e:
            # No local state to re-seat. The remedy is re-admission, not retrying.
            print(f"cannot recover this agent: {e}")
            raise
        # Running it again is safe and cheap: already current, so replay applies
        # nothing. `sync()` is idempotent, so a wake-up path can call it blindly.
        again = admin.groups.sync(group.handle)

        # The answer is a union, and `regime` is what tells the two arms apart —
        # never which fields the result happens to carry. This group is MLS, so
        # the MLS arm is the one that answers here. Both calls are read the same
        # way, in one place: two copies of this branch is how a catalog ends up
        # teaching two different readings of one union (its TypeScript twin
        # `examples/group-sync.ts` uses one `syncLine` for both).
        for label, report in (("sync", first), ("sync again", again)):
            if report.regime == "mls":
                print(
                    f"{label}: rung={report.rung} epoch {report.from_epoch}->{report.epoch} "
                    f"behind={report.behind} applied={report.processed} "
                    f"evicted={report.evicted}"
                )
            else:
                print(
                    f"{label}: installed {report.ingested} sender key(s) retired={report.retired}"
                )


if __name__ == "__main__":
    main()
