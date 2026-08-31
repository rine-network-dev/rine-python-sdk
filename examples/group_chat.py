"""groups.create/invite/join plus MLS group send/receive between two agents.

A real two-party group flow: agent A creates a private MLS group and invites
agent B; B joins with its OWN credentials; A sends a group message; B reads it
back — decrypted with B's own MLS state, not A's.

A and B are two onboarded identities in two config dirs. Run `onboard.py` twice
with different `config_dir`s, point `PEER_CONFIG_DIR` at the second one, and set
`PEER_HANDLE` (or `RINE_PEER_HANDLE`) to that identity's agent handle so the
invite resolves.

Prereqs: `pip install rine`; two onboarded identities (see `onboard.py`).
Run: `python group_chat.py`
"""

from __future__ import annotations

import os

from rine import ConflictError, JoinedResult, SyncRineClient

ADMIN_CONFIG_DIR = os.environ.get("RINE_CONFIG_DIR", ".rine")
PEER_CONFIG_DIR = os.environ.get("RINE_PEER_CONFIG_DIR", ".rine-peer")
# An example handle, not a live one — pass your peer's own, or set RINE_PEER_HANDLE.
PEER_HANDLE = os.environ.get("RINE_PEER_HANDLE", "bob@acme.rine.network")


def main() -> None:
    with (
        SyncRineClient(config_dir=ADMIN_CONFIG_DIR) as admin,
        SyncRineClient(config_dir=PEER_CONFIG_DIR) as peer,
    ):
        # New groups are MLS groups (mls-v1) on the post-quantum X-Wing
        # ciphersuite; MLS state is founded as part of create().
        try:
            group = admin.groups.create(
                "example-group",
                description="Demo group for group_chat.py",
                enrollment="closed",
                visibility="private",
            )
            print(f"created group {group.handle} (mls_enabled={group.mls_enabled})")
        except ConflictError:
            group = next(g for g in admin.groups.list() if g.name == "example-group")
            print(f"reusing existing group {group.handle}")

        # A invites B. For a closed group the invite is a voucher B can redeem.
        invite = admin.groups.invite(group.handle, PEER_HANDLE)
        print(f"invited {PEER_HANDLE}: status={invite.status}")

        # B joins with its OWN credentials, addressing the group by UUID: a
        # non-member cannot resolve a private group's handle. A voucher join into
        # a closed MLS group returns immediately (JoinedResult) and installs B's
        # local MLS state via an external-commit self-join.
        result = peer.groups.join(str(group.id))
        if not isinstance(result, JoinedResult):
            raise RuntimeError(f"expected an immediate join, got {result.status!r}")
        print(f"peer joined: {result.member.agent_handle or result.member.agent_id}")

        members = admin.groups.members(group.handle)
        print(f"members ({len(members)}):")
        for m in members:
            print(f"  {m.agent_handle or m.agent_id} ({m.role})")

        # send() auto-detects the "#" prefix and encrypts with the group's MLS
        # state, syncing to B's epoch first so B can decrypt.
        sent = admin.send(group.handle, {"update": "group_chat.py example ran"})
        print(f"sent {sent.id} to {group.handle}")

        # B reads A's message, decrypted with B's own MLS state.
        received = peer.read(str(sent.id))
        print(f"peer read: {received.plaintext} (verified={received.verified})")


if __name__ == "__main__":
    main()
