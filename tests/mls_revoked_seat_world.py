"""A group whose tree still holds the leaf of a member that has since been revoked.

``FOUNDER`` founds a group with ``PEER``, adds ``UNLISTED`` and then ``JOINER``. ``UNLISTED`` is
then revoked: the key read no longer serves it and the roster omits it, while its leaf stays in
the tree until a member reclaims it. ``JOINER`` holds the Welcome minted over that tree, so it
cannot be opened. The group, the Welcome and the core's refusals are the real ``rine-mls``
core's; only the server is a stand-in.
"""

from __future__ import annotations

import json
import os
from typing import Any

from rine import SyncRineClient
from rine._config import mls_store_dir
from rine._crypto.keys import save_agent_keys
from rine._mls import process_mls_welcomes
from rine._mls.binding import credential_identity, open_mls_client
from rine._mls.group_access import mls_state_path, open_mls_group
from rine._mls.wire import mls_from_base64
from rine.errors import ConflictError
from rine.testing import WORLD, write_agent_identity
from rine.types import GroupRead
from tests.mls_admission_world import FOUNDER, GROUP_ID, GROUP_ROW, SECOND_ADDED, device
from tests.mls_welcome_world import JOINER, UNLISTED, Scene, WelcomeServer, build_scene

MEMBER_ROW = {"group_id": GROUP_ID, "role": "member", "joined_at": "2024-01-01T00:00:00Z"}


class RevokedSeatServer(WelcomeServer):
    """The Welcome server, with live invitations and the routes a public group verb uses."""

    def __init__(self) -> None:
        """Start with no live invitations and a join that answers 200."""
        super().__init__()
        self.outstanding: list[dict[str, str]] = []
        self.join_error: Exception | None = None
        self.joins = 0
        self.group_row: dict[str, Any] = GROUP_ROW

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer the group row, the roster rows and the invitation read; the rest as before."""
        if path == f"/groups/{GROUP_ID}":
            return self.group_row
        if path.endswith("/requests"):
            return {"items": self.outstanding}
        if path.endswith("/members"):
            if self.roster_error is not None:
                raise self.roster_error
            return {"items": [{**MEMBER_ROW, "agent_id": a} for a in self.rosters[GROUP_ID]]}
        return super().get(path, **kwargs)

    def post_with_status(self, path: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        """Answer the join, counting it, or raise what the test staged."""
        assert path == f"/groups/{GROUP_ID}/join", path
        self.joins += 1
        if self.join_error is not None:
            raise self.join_error
        return 200, {**MEMBER_ROW, "agent_id": JOINER}


def revoked_scene(base: Any) -> Scene:
    """The group above, with ``UNLISTED`` revoked and ``SECOND_ADDED`` not yet in the tree.

    The founder's device holds ``SECOND_ADDED``'s keys so an Add for it is admitted by the
    core. The roster stays the three members; a test that seats ``SECOND_ADDED`` adds it.
    """
    scene = build_scene(base)
    scene.server = RevokedSeatServer()
    scene.server.absent.add(UNLISTED)
    save_agent_keys(scene.founder_dir, SECOND_ADDED, WORLD.keys(SECOND_ADDED))
    return scene


def seated_scene(base: Any, server_cls: type[RevokedSeatServer] = RevokedSeatServer) -> Scene:
    """The joiner is seated through its Welcome; its group state is then lost.

    Nothing is spooled and no marker is left behind: the leaf stands in the tree and no file
    on the joiner's device says so. The group's GroupInfo is the one the founder published.
    ``server_cls`` stands in for the server, for a test that injects a fault after the seat.
    """
    scene = build_scene(base)
    scene.server = server_cls()
    scene.server.deliver(GROUP_ID, scene.welcome)
    process_mls_welcomes(scene.server, scene.config_dir, JOINER, for_group=GROUP_ID)
    os.remove(mls_state_path(mls_store_dir(scene.config_dir, JOINER), GROUP_ID))
    publish_group_info(scene)
    return scene


def group_row() -> Any:
    """The group row a join reads, as the server serves it."""
    return GroupRead.model_validate(GROUP_ROW)


def newcomer(base: Any) -> str:
    """A config dir for ``SECOND_ADDED``, which holds no state for the group."""
    return device(base, "newcomer", SECOND_ADDED, (FOUNDER, 0))


def key_package(base: Any) -> bytes:
    """A KeyPackage ``SECOND_ADDED`` published."""
    return open_mls_client(newcomer(base), SECOND_ADDED).generate_key_package()


def reclaim(scene: Scene) -> None:
    """A member removes the revoked leaf and the group's GroupInfo moves to that epoch."""
    group = scene.founder_group
    bundle = group.remove_member(group.member_index(credential_identity(UNLISTED)))
    group.save()
    scene.server.group_info = (bundle.group_info, bundle.epoch)


def publish_group_info(scene: Scene) -> None:
    """Serve the GroupInfo of the founder's latest commit, revoked leaf still in the tree."""
    bundle = scene.founder_group.last_commit()
    assert bundle is not None
    scene.server.group_info = (bundle.group_info, bundle.epoch)


def apply_posted_commit(scene: Scene) -> None:
    """The founder applies the one commit the server received, as every member would."""
    (posted,) = scene.server.commits
    scene.founder_group.apply_commit(mls_from_base64(posted["commit"]))
    scene.founder_group.save()


def joiner_state(scene: Scene) -> Any:
    """The joiner's group handle, or the refusal raised when it holds none."""
    return open_mls_group(scene.config_dir, JOINER, GROUP_ID)


def already_a_member(code: str | None = "already_a_member") -> ConflictError:
    """The 409 the server answers an agent that is seated already."""
    body = {"detail": "Agent is already a member of this group"}
    return ConflictError(body["detail"], json.dumps({"error": code, **body} if code else body))


def verb_client(config_dir: str, agent_id: str, server: Any) -> SyncRineClient:
    """A client acting as ``agent_id`` from ``config_dir`` whose HTTP boundary is ``server``."""
    write_agent_identity(config_dir, agent_id)
    client = SyncRineClient(config_dir=config_dir, api_url="https://rine.network")
    client._http.close()
    client._http = server
    return client
