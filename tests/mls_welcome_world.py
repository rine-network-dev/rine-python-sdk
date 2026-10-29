"""The scene a Welcome-catch-up test drives: a Welcome naming a member the roster did not.

``FOUNDER`` founds a group with ``PEER``, adds ``UNLISTED`` and then the joiner. The joiner's
Welcome therefore carries a ratchet tree of four leaves, while the roster the joiner reads
lists three: ``UNLISTED`` was seated after the read, or added and removed since. The group,
the Welcome and the core's refusals are the real ``rine-mls`` core's; only the server is a
stand-in, and ``UNLISTED`` is the one agent whose key read the tests make fail in each way.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from rine._config import mls_store_dir
from rine._mls.binding import allowed_for, credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes, mls_state_path
from rine._mls.wire import mls_to_base64
from rine.errors import RineApiError
from rine.testing import WORLD
from tests.mls_admission_world import (
    ADDED,
    FOUNDER,
    GROUP_ID,
    MEMBER,
    Server,
    device,
)

JOINER = MEMBER
UNLISTED = ADDED
PEER = "33333333-4444-5555-6666-777777777777"
OTHER_GROUP = "cccccccc-dddd-eeee-ffff-000000000000"


class WelcomeServer(Server):
    """The stand-in server, serving Welcomes and rosters and failing key reads per agent."""

    def __init__(self) -> None:
        """Start with the three-member roster, no Welcomes queued and every key readable."""
        super().__init__()
        self.rosters: dict[str, list[str]] = {GROUP_ID: [FOUNDER, PEER, JOINER]}
        self.roster_error: Exception | None = None
        self.queue: list[dict[str, str]] = []
        self.paths: list[str] = []
        self.tampered: set[str] = set()
        self.failing: set[str] = set()

    def deliver(self, group_id: str, welcome: bytes) -> None:
        """Queue a Welcome the next fetch serves."""
        self.queue.append(
            {
                "id": f"welcome-{len(self.queue)}",
                "group_id": group_id,
                "blob": mls_to_base64(welcome),
            }
        )

    def named(self, agent_id: str) -> int:
        """How many key reads asked for this agent."""
        return sum(agent_id in ids for ids in self.key_reads)

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer the Welcome fetch, the roster reads and the key reads; the rest as before."""
        self.paths.append(path)
        if path.endswith("/mls/welcomes"):
            served, self.queue = self.queue, []
            return {"welcomes": served}
        if path.endswith("/members"):
            if self.roster_error is not None:
                raise self.roster_error
            return {
                "items": [{"agent_id": a} for a in self.rosters[path.split("/")[2]]],
            }
        if path.endswith("/requests"):
            return {"items": []}
        if path != "/agents/keys":
            return super().get(path, **kwargs)
        ids = [i for i in str(kwargs["params"]["ids"]).split(",") if i]
        if self.failing & set(ids):
            self.key_reads.append(ids)
            raise RineApiError(503, "unavailable", "")
        answer = super().get(path, **kwargs)
        for agent in self.tampered & answer["keys"].keys():
            answer["keys"][agent] = {
                **answer["keys"][agent],
                "agent_certificate": WORLD.keys_response(FOUNDER)["agent_certificate"],
            }
        return answer


@dataclass
class Scene:
    """The founder's group, the joiner's device and the Welcome the joiner is waiting on."""

    server: WelcomeServer
    config_dir: str
    founder_group: Any
    welcome: bytes
    founder_dir: str

    def post(self, commit: Any) -> None:
        """Publish one of the founder's commits to the server's backlog."""
        self.server.handshakes.append(
            {
                "id": f"h{len(self.server.handshakes)}",
                "epoch": commit.epoch,
                "blob": mls_to_base64(commit.commit),
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

    def remove_unlisted(self) -> None:
        """The founder removes ``UNLISTED`` and publishes the commit."""
        leaf = self.founder_group.member_index(credential_identity(UNLISTED))
        self.post(self.founder_group.remove_member(leaf))
        self.founder_group.save()

    def another_group(self) -> bytes:
        """A second group, founded by ``FOUNDER`` with the joiner alone: its Welcome."""
        founder = open_mls_client(self.founder_dir, FOUNDER)
        group = founder.create_group_with_members(
            mls_group_id_bytes(OTHER_GROUP), [self.joiner().generate_key_package()]
        )
        group.save()
        self.server.rosters[OTHER_GROUP] = [FOUNDER, JOINER]
        return group.last_commit().welcomes[0]

    def joiner(self) -> Any:
        """The joiner's MLS client."""
        return open_mls_client(self.config_dir, JOINER)

    def state(self, group_id: str = GROUP_ID) -> bytes | None:
        """The joiner's persisted state for a group, or ``None`` when it holds none."""
        path = mls_state_path(mls_store_dir(self.config_dir, JOINER), group_id)
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as handle:
            return handle.read()

    def joiner_allows(self, agent_id: str) -> bool:
        """Whether the joiner's allowed set holds the agent's served key."""
        return allowed_for(self.config_dir, JOINER).contains(
            credential_identity(agent_id), WORLD.keys(agent_id).mls.public_key
        )


def build_scene(
    base: Any,
    *,
    with_unlisted: bool = True,
    unlisted_gen: int = 0,
    reinvite: bool = False,
) -> Scene:
    """Found the group, seat the joiner and queue nothing: the Welcome is on the scene.

    With ``reinvite`` the joiner was seated in the group before, was removed, and holds
    that old state when the new Welcome arrives. ``unlisted_gen`` is the generation of
    ``UNLISTED``'s leaf key; the server serves generation zero.
    """
    joiner_dir = device(base, "joiner", JOINER)
    founder_dir = device(
        base, "founder", FOUNDER, (PEER, 0), (UNLISTED, unlisted_gen), (JOINER, 0)
    )
    peer_dir = device(base, "peer", PEER, (FOUNDER, 0))
    unlisted_dir = device(base, "unlisted", UNLISTED, (FOUNDER, 0), (UNLISTED, unlisted_gen))
    founder = open_mls_client(founder_dir, FOUNDER)
    joiner = open_mls_client(joiner_dir, JOINER)
    group_id = mls_group_id_bytes(GROUP_ID)
    peer_package = open_mls_client(peer_dir, PEER).generate_key_package()
    if reinvite:
        group = founder.create_group_with_members(group_id, [joiner.generate_key_package()])
        allowed_for(joiner_dir, JOINER).insert(
            credential_identity(FOUNDER), WORLD.keys(FOUNDER).mls.public_key, 0
        )
        joiner.join_from_welcome(group.last_commit().welcomes[0]).save()
        group.add_member(peer_package)
        group.remove_member(group.member_index(credential_identity(JOINER)))
    else:
        group = founder.create_group_with_members(group_id, [peer_package])
    if with_unlisted:
        group.add_member(open_mls_client(unlisted_dir, UNLISTED).generate_key_package())
    welcome = group.add_member(joiner.generate_key_package()).welcomes[0]
    group.save()
    return Scene(WelcomeServer(), joiner_dir, group, welcome, founder_dir)


class RefusalSpy:
    """A client that counts how often the pass asks it which agent it refused."""

    def __init__(self, client: Any) -> None:
        """Wrap a real client."""
        self._client = client
        self.reads = 0

    def refused_peer(self) -> bytes | None:
        """The refused identity, counted."""
        self.reads += 1
        return self._client.refused_peer()

    def __getattr__(self, name: str) -> Any:
        """Everything else is the real client."""
        return getattr(self._client, name)
