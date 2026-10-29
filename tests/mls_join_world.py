"""Helpers shared by the ``groups.join()`` already-a-member suites."""

from __future__ import annotations

from typing import Any

from rine._mls.binding import open_mls_client
from rine._mls.group_access import load_mls_group
from tests.mls_admission_world import GROUP_ID
from tests.mls_revoked_seat_world import RevokedSeatServer, already_a_member
from tests.mls_welcome_world import JOINER, Scene


def holds_state(scene: Scene) -> bool:
    return load_mls_group(open_mls_client(scene.config_dir, JOINER), GROUP_ID) is not None


def seated(scene: Scene) -> Scene:
    scene.server.join_error = already_a_member()
    return scene


class AsyncBoundary:
    """The stand-in server behind the async client's awaited HTTP calls."""

    def __init__(self, server: RevokedSeatServer) -> None:
        self._server = server

    async def get(self, path: str, **kwargs: Any) -> Any:
        return self._server.get(path, **kwargs)

    async def post_with_status(self, path: str, **kwargs: Any) -> Any:
        return self._server.post_with_status(path, **kwargs)

    async def close(self) -> None:
        return None
