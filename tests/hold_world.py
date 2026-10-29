"""The rotation world's server, taught the open-enrollment hold.

An open-enrollment group answers a commit ``confirmed: false`` and keeps it
tentative: the latch advances, the confirmed epoch does not, and the commit is
rolled back unless a member acknowledges it. ``HoldServer`` plays that, and can
also fail the next commit post, so each outcome of a self-update is reachable
with the real ``rine-mls`` core running behind it.

The handshakes read is modelled the way the server decides it: a commit is never
fanned back to its sender; a read naming ``pending_epoch`` (which must be
``since_epoch + 1``, else 422) also answers where the caller's own commit at that
epoch stands and measures replay reachability from that epoch only when it is
``confirmed``; a read that serves nothing while the group has confirmed an epoch
past its starting point is refused ``409 mls_resync_required``.
"""

from __future__ import annotations

import re
from typing import Any

from rine._actor import AGENT_HEADER
from rine._mls.actor import MlsActor
from rine.errors import ConflictError, RineApiError
from rine.testing import WORLD
from tests.rotation_world import G1, A, Server, fresh_process, rotate, world


class HoldServer(Server):
    """A rotation-world server that tracks a confirmed epoch and a latch."""

    def __init__(self) -> None:
        """Start with every group closed and no failure queued."""
        super().__init__()
        self.open_groups: set[str] = set()
        self.confirmed: dict[str, int] = {}
        self.latch: dict[str, int] = {}
        self.fail_posts: list[Exception] = []
        self.commit_posts = 0
        self.uploads: list[str] = []
        self.fail_upload: Exception | None = None
        self.pending_reads: list[int | None] = []
        self.standing_override: str | None = None
        self.omit_standing = False
        self.echo_own = False

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer as the base world does, minus the reader's own commits, plus the epochs."""
        claim = re.fullmatch(r"/agents/([^/]+)/mls/key-packages", path)
        if claim and not self.kps.get(claim[1]):
            raise ConflictError("No key packages available", '{"error": "no_key_packages"}')
        data = super().get(path, **kwargs)
        reader = (kwargs.get("extra_headers") or {}).get(AGENT_HEADER)
        if m := re.fullmatch(r"/groups/([^/]+)/mls/handshakes", path):
            return self._handshakes(m[1], reader, kwargs.get("params") or {}, data)
        if m := re.fullmatch(r"/groups/([^/]+)/mls/group-info", path):
            data["confirmed_epoch"] = self.confirmed.get(m[1], data["epoch"])
            data["latch_epoch"] = self.latch.get(m[1], data["epoch"])
        return data

    def _standing(self, gid: str, reader: str | None, pending: int) -> str:
        """Where ``reader``'s own commit at ``pending`` stands, as the server reads it."""
        if self.standing_override is not None:
            return self.standing_override
        at = [h for h in self.handshakes.get(gid, []) if h["epoch"] == pending]
        if any(h.get("author") == reader and h.get("quarantined") for h in at):
            return "rolled_back"
        if any(h.get("author") == reader for h in at):
            if self.latch.get(gid, pending) < pending:
                return "rolled_back"
            return "confirmed" if self.confirmed.get(gid, 0) >= pending else "tentative"
        return "superseded" if any(not h.get("quarantined") for h in at) else "absent"

    def _handshakes(
        self, gid: str, reader: str | None, params: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        """The feed for ``reader``: no own commits, a standing, and the reachability rule."""
        since = int(params.get("since_epoch", 0) or 0)
        raw = params.get("pending_epoch")
        pending = None if raw is None else int(raw)
        self.pending_reads.append(pending)
        if pending is not None and pending != since + 1:
            raise RineApiError(422, "pending_epoch must be since_epoch + 1")
        served = [
            h
            for h in data["handshakes"]
            if (self.echo_own or h.get("author") != reader) and not h.get("quarantined")
        ]
        standing = None if pending is None else self._standing(gid, reader, pending)
        reachable_from = pending if standing == "confirmed" and pending else since
        if not served and reachable_from < self.confirmed.get(gid, 0):
            raise RineApiError(409, "resync required", '{"error": "mls_resync_required"}')
        if standing is None or self.omit_standing:
            return {"handshakes": served}
        return {"handshakes": served, "pending_commit": standing}

    def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Accept a commit tentatively in an open group, or fail the queued posts first."""
        if m := re.fullmatch(r"/groups/([^/]+)/mls/commit", path):
            self.commit_posts += 1
            if self.fail_posts:
                raise self.fail_posts.pop(0)
            answer = super().post(path, **kwargs)
            author = (kwargs.get("extra_headers") or {}).get(AGENT_HEADER)
            self.handshakes[m[1]][-1]["author"] = author
            epoch = int(answer["epoch"])
            if m[1] in self.open_groups:
                self.latch[m[1]] = epoch
                return {**answer, "confirmed": False}
            self.confirmed[m[1]] = self.latch[m[1]] = epoch
            return answer
        if m := re.fullmatch(r"/agents/([^/]+)/mls/key-packages", path):
            if self.fail_upload is not None:
                raise self.fail_upload
            self.uploads.append(m[1])
        return super().post(path, **kwargs)

    def open_group(self, gid: str) -> None:
        """Make ``gid`` an open-enrollment group at its current epoch."""
        self.open_groups.add(gid)
        self.confirmed[gid] = self.latch[gid] = self.group_info[gid][1]

    def confirm(self, gid: str) -> None:
        """A member acknowledged the tentative commit: it is now the confirmed epoch."""
        self.confirmed[gid] = self.latch[gid]

    def roll_back(self, gid: str) -> None:
        """The deadline passed: the tentative commit is quarantined and the latch falls back."""
        self.handshakes[gid][-1]["quarantined"] = True
        self.latch[gid] = self.confirmed[gid]


def rotated(tmp_path: Any, *, open_group: bool = False) -> tuple[HoldServer, str, str, MlsActor]:
    """A group of ``R`` and ``A`` whose ``A`` has rotated to generation 1 on device ``d1``.

    Returns:
        The server, ``A``'s config dir, ``R``'s config dir and ``A`` as an actor.
    """
    server = HoldServer()
    _, d1, dr, _dc = world(tmp_path, G1, [A], server)
    if open_group:
        server.open_group(G1)
    rotate(server, d1, A)
    fresh_process()
    return server, d1, dr, MlsActor(client=server, config_dir=d1, agent_id=A)


def held(tmp_path: Any) -> tuple[HoldServer, str, MlsActor, int]:
    """An open group whose rotated agent's self-update is pending: server, d1, actor, epoch."""
    from rine._mls.self_update import self_update_group

    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    seat = self_update_group(actor, G1)
    assert seat.epoch is not None
    return server, d1, actor, seat.epoch


def leaf_key(config_dir: str, viewer: str, gid: str, agent: str) -> bytes:
    """The signature key ``agent``'s leaf carries in ``viewer``'s tree of ``gid``."""
    from rine._mls.group_access import open_mls_group

    group = open_mls_group(config_dir, viewer, gid)
    (mine,) = [m for m in group.member_identities() if m.identity.decode() == agent]
    return bytes(mine.signature_key)


def new_key() -> bytes:
    """The signature key ``A`` signs with after the rotation."""
    return WORLD.keys(A, 1).mls.public_key


def old_key() -> bytes:
    """The signature key ``A``'s leaf carried before the rotation."""
    return WORLD.keys(A, 0).mls.public_key


__all__ = ["HoldServer", "held", "leaf_key", "new_key", "old_key", "rotated"]
