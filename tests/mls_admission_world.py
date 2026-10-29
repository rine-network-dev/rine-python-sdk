"""The stand-in server and the three-member world the commit-admission tests drive.

The group, its commits and the refusals are the real ``rine-mls`` core's; only the server
is a stand-in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._crypto.keys import save_agent_keys
from rine._mls.binding import allowed_for, credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.heartbeat import MlsActor
from rine._mls.sync import sync_mls_group
from rine._mls.wire import mls_to_base64
from rine.errors import RineApiError
from rine.testing import WORLD
from tests.test_crypto.world import KeyServer

GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
FOUNDER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ADDED = "12121212-3434-5656-7878-909090909090"
SECOND_ADDED = "21212121-4343-6565-8787-090909090909"
MEMBER = "00000000-1111-2222-3333-444444444444"

#: The server's answer to a replay it cannot serve, as the wire body carries it.
REPLAY_REFUSED = '{"error": "mls_resync_required"}'

GROUP_ROW = {
    "id": GROUP_ID,
    "name": "ops",
    "handle": "#ops@acme",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_group_id": "latched",
    "member_agent_ids": [MEMBER],
}

#: The most key reads a test lets a runaway retry make before it fails loudly.
READ_CEILING = 4


class Server:
    """The group endpoints a catch-up touches, serving the shared test world's keys."""

    def __init__(self) -> None:
        """Start with no handshakes and every key readable."""
        self._keys = KeyServer(WORLD)
        self.key_pins = self._keys.key_pins
        self.handshakes: list[dict[str, Any]] = []
        self.key_reads: list[list[str]] = []
        self.nacks: list[str] = []
        self.acks: list[str] = []
        self.absent: set[str] = set()
        self.served_gen: dict[str, int] = {}
        self.outage: Exception | None = None
        self.tamper: Any = None
        self.group_info: tuple[bytes, int] | None = None
        self.replay_refused = False
        self.commits: list[dict[str, Any]] = []

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer the handshake listing, the GroupInfo, the group list and the batch key read."""
        if path.endswith("/mls/handshakes"):
            if self.replay_refused:
                raise RineApiError(409, "replay cannot bridge that gap", REPLAY_REFUSED)
            return {"handshakes": self.handshakes}
        if path.endswith("/mls/group-info"):
            assert self.group_info is not None
            return {"group_info": mls_to_base64(self.group_info[0]), "epoch": self.group_info[1]}
        if path == "/groups":
            return {"items": [GROUP_ROW]}
        assert path == "/agents/keys", path
        ids = [i for i in str(kwargs["params"]["ids"]).split(",") if i]
        self.key_reads.append(ids)
        assert len(self.key_reads) <= READ_CEILING, "the retry is not bounded"
        if self.outage is not None:
            raise self.outage
        bodies = {
            i: WORLD.keys_response(i, self.served_gen.get(i, 0))
            for i in ids
            if i not in self.absent
        }
        return {"keys": {i: self.tamper(b) if self.tamper else b for i, b in bodies.items()}}

    def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Record an ACK, a NACK or a posted commit."""
        if path.endswith("/mls/commit"):
            self.commits.append(kwargs["json_body"])
            return {"epoch": kwargs["json_body"]["epoch"], "delivered_to": 1}
        if path.endswith("/mls/ack"):
            self.acks.append(kwargs["json_body"]["object_id"])
            return {"confirmed": True}
        assert path.endswith("/mls/nack"), path
        self.nacks.append(kwargs["json_body"]["object_id"])
        return {"quarantined": True}


@dataclass
class Edges:
    """Three members: the founder commits, ``MEMBER`` is the one under test."""

    server: Server
    config_dir: str
    founder_group: Any
    added_package: bytes

    @property
    def actor(self) -> MlsActor:
        """The member under test, acting through the stand-in server."""
        return MlsActor(client=self.server, config_dir=self.config_dir, agent_id=MEMBER)

    def post(self, commit: Any) -> None:
        """Publish one of the founder's commits to the server's backlog."""
        n = len(self.server.handshakes)
        self.server.handshakes.append(
            {
                "id": f"h{n}",
                "epoch": commit.epoch,
                "blob": mls_to_base64(commit.commit),
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

    def add_then_remove_added(self) -> None:
        """The founder Adds ``ADDED`` and then Removes it, while the member is away."""
        self.post(self.founder_group.add_member(self.added_package))
        leaf = self.founder_group.member_index(credential_identity(ADDED))
        self.post(self.founder_group.remove_member(leaf))
        self.founder_group.save()

    def sync(self) -> Any:
        """Catch the member up."""
        return sync_mls_group(self.server, self.config_dir, MEMBER, GROUP_ID)

    def member_epoch(self) -> int:
        """The member's persisted epoch."""
        return open_mls_group(self.config_dir, MEMBER, GROUP_ID).epoch()

    def member_allows(self, agent_id: str) -> bool:
        """Whether the member's allowed set holds the agent's verified key."""
        return allowed_for(self.config_dir, MEMBER).contains(
            credential_identity(agent_id), WORLD.keys(agent_id).mls.public_key
        )


def device(base: Any, name: str, agent: str, *others: tuple[str, int]) -> str:
    """A config dir holding ``agent``'s keys and the given peers' (id, generation)."""
    path = str(base / name)
    save_agent_keys(path, agent, WORLD.keys(agent))
    for other, gen in others:
        save_agent_keys(path, other, WORLD.keys(other, gen))
    return path


def build_world(tmp_path: Any, *, added_gen: int = 0, member_knows_added: bool = False) -> Edges:
    """The founder seats the member; the added peer's key package is ready."""
    known = [(ADDED, 0)] if member_knows_added else []
    member_dir = device(tmp_path, "member", MEMBER, (FOUNDER, 0), *known)
    founder_dir = device(
        tmp_path, "founder", FOUNDER, (MEMBER, 0), (ADDED, added_gen), (SECOND_ADDED, 0)
    )
    added_dir = device(tmp_path, "added", ADDED, (FOUNDER, 0))
    group = open_mls_client(founder_dir, FOUNDER).create_group_with_members(
        mls_group_id_bytes(GROUP_ID), [open_mls_client(member_dir, MEMBER).generate_key_package()]
    )
    welcome = group.last_commit().welcomes[0]
    group.save()
    open_mls_client(member_dir, MEMBER).join_from_welcome(welcome).save()
    if added_gen:
        save_agent_keys(added_dir, ADDED, WORLD.keys(ADDED, added_gen))
    package = open_mls_client(added_dir, ADDED).generate_key_package()
    return Edges(Server(), member_dir, group, package)
