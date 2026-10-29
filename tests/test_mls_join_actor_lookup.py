"""``groups.join()`` for a seated agent whose actor lookup fails: the 409 stands.

The sync and async verbs resolve the acting agent's id before establishing local state. When that
lookup fails the join verb raises the server's 409 untouched, posts no commit and leaves the agent
without state; a failure of the lookup must never be turned into a half-established seat.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._client import RineClient
from rine.errors import ConflictError, RineApiError
from rine.testing import write_agent_identity
from tests.mls_admission_world import GROUP_ID
from tests.mls_join_world import AsyncBoundary, holds_state, seated
from tests.mls_revoked_seat_world import seated_scene, verb_client
from tests.mls_welcome_world import JOINER

pytestmark = pytest.mark.usefixtures("real_roster_read", "mls_escrow_stub")


class TestTheSyncVerb:
    def test_join_when_the_actor_lookup_fails_then_the_409_is_raised(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scene = seated(seated_scene(tmp_path))
        client = verb_client(scene.config_dir, JOINER, scene.server)

        def _lookup_down(_agent: str | None = None) -> str:
            raise RineApiError(503, "agents down", "")

        monkeypatch.setattr(client, "_resolve_agent_id", _lookup_down)

        with pytest.raises(ConflictError):
            client.groups.join(GROUP_ID, agent=JOINER)

        assert scene.server.commits == []
        assert not holds_state(scene)


class TestTheAsyncVerb:
    async def test_join_when_the_actor_lookup_fails_then_the_409_is_raised(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scene = seated(seated_scene(tmp_path))
        write_agent_identity(scene.config_dir, JOINER)
        client = RineClient(config_dir=scene.config_dir, api_url="https://rine.network")
        client._http = AsyncBoundary(scene.server)  # type: ignore[assignment]

        async def _lookup_down(_agent: str | None = None) -> str:
            raise RineApiError(503, "agents down", "")

        monkeypatch.setattr(client, "_resolve_agent_id", _lookup_down)

        with pytest.raises(ConflictError):
            await client.groups.join(GROUP_ID, agent=JOINER)

        assert scene.server.commits == []
        assert not holds_state(scene)
