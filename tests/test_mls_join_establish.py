"""``groups.join()`` for an agent the server already seats.

The server answers such an agent 409 ``already_a_member``. When the agent holds no local state
for the group, that answer is the cue to establish it: install the Welcome waiting for it, take
its own leaf back, or join by external commit when no leaf exists. A seat made usable that way
is reported joined. Everything else about the 409 stays as it was. The group, the Welcomes and
the core's refusals are the real ``rine-mls`` core's and only the server is a stand-in.

The TypeScript twin is ``rine-core/test/mls-join-establish.test.ts``.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest

from rine._client import RineClient
from rine._mls import process_mls_welcomes
from rine._mls.welcome_spool import WelcomeSpool
from rine.errors import ConflictError, MlsWelcomeRefusedError, RineApiError
from rine.testing import write_agent_identity
from rine.types import JoinedResult
from tests.mls_admission_world import GROUP_ID, GROUP_ROW, SECOND_ADDED
from tests.mls_join_world import AsyncBoundary, holds_state, seated
from tests.mls_revoked_seat_world import (
    RevokedSeatServer,
    already_a_member,
    newcomer,
    publish_group_info,
    reclaim,
    revoked_scene,
    seated_scene,
    verb_client,
)
from tests.mls_welcome_world import JOINER, Scene, build_scene

pytestmark = pytest.mark.usefixtures("real_roster_read", "mls_escrow_stub")


@pytest.fixture(autouse=True)
def _no_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the key-package top-up out of the requests these tests measure."""
    for module in ("welcomes", "sync", "add_members"):
        monkeypatch.setattr(f"rine._mls.{module}.mls_heartbeat", lambda *_a: None)


class _RosterDownOnce(RevokedSeatServer):
    """The server whose first roster read fails, which keeps the Welcome pass's Welcome."""

    def __init__(self) -> None:
        super().__init__()
        self._down = True

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        if path.endswith("/members") and self._down:
            self._down = False
            raise RineApiError(503, "roster down", "")
        return super().get(path, **kwargs)


class _RosterDownAfterReseat(RevokedSeatServer):
    """The server whose roster read fails once the agent has retaken its seat."""

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        if path.endswith("/members") and self.commits:
            raise RineApiError(503, "roster down", "")
        return super().get(path, **kwargs)


def _join(scene: Scene, config_dir: str | None = None, agent: str = JOINER) -> Any:
    client = verb_client(config_dir or scene.config_dir, agent, scene.server)
    return client.groups.join(GROUP_ID, agent=agent)


class TestASeatedAgentWithNoStateIsEstablished:
    def test_join_when_already_a_member_with_no_state_then_reseats_and_reports_joined(
        self, tmp_path: Any
    ) -> None:
        scene = seated(seated_scene(tmp_path))

        result = _join(scene)

        assert isinstance(result, JoinedResult)
        assert str(result.member.agent_id) == JOINER
        assert len(scene.server.commits) == 1
        assert holds_state(scene)

    def test_join_when_already_a_member_and_a_welcome_waits_then_it_installs_and_reports_joined(
        self, tmp_path: Any
    ) -> None:
        scene = build_scene(tmp_path)
        scene.server = RevokedSeatServer()
        seated(scene)
        scene.server.deliver(GROUP_ID, scene.welcome)

        result = _join(scene)

        assert isinstance(result, JoinedResult)
        assert holds_state(scene)
        assert scene.server.commits == []

    def test_join_when_already_a_member_holding_no_leaf_then_it_joins_by_external_commit(
        self, tmp_path: Any
    ) -> None:
        scene = seated(revoked_scene(tmp_path))
        scene.server.rosters[GROUP_ID].append(SECOND_ADDED)
        reclaim(scene)

        result = _join(scene, newcomer(tmp_path), SECOND_ADDED)

        assert isinstance(result, JoinedResult)
        assert str(result.member.agent_id) == SECOND_ADDED
        assert len(scene.server.commits) == 1


class TestTheConflictIsKeptWhenNothingWasEstablished:
    def test_join_when_already_a_member_and_the_retake_fails_then_the_409_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = seated(seated_scene(tmp_path))
        scene.server.outage = RineApiError(503, "unavailable", "")

        with pytest.raises(ConflictError):
            _join(scene)

        assert scene.server.commits == []

    def test_join_when_already_a_member_and_a_welcome_is_kept_then_no_leaf_is_replaced_under_it(
        self, tmp_path: Any
    ) -> None:
        scene = build_scene(tmp_path)
        scene.server = _RosterDownOnce()
        seated(scene)
        scene.server.deliver(GROUP_ID, scene.welcome)
        publish_group_info(scene)

        with pytest.raises(ConflictError):
            _join(scene)

        assert scene.server.commits == []
        assert len(WelcomeSpool(scene.config_dir, JOINER).pending()) == 1
        assert not holds_state(scene)

    def test_join_when_already_a_member_and_the_state_loads_then_the_409_is_raised_untouched(
        self, tmp_path: Any
    ) -> None:
        scene = build_scene(tmp_path, reinvite=True)
        scene.server = RevokedSeatServer()
        seated(scene)

        with pytest.raises(ConflictError):
            _join(scene)

        assert not any(path.endswith("/mls/welcomes") for path in scene.server.paths)

    def test_join_when_the_409_carries_no_code_then_it_is_raised_and_nothing_is_established(
        self, tmp_path: Any
    ) -> None:
        scene = seated_scene(tmp_path)
        scene.server.join_error = already_a_member(None)

        with pytest.raises(ConflictError):
            _join(scene)

        assert scene.server.commits == []
        assert not holds_state(scene)

    def test_join_when_the_group_is_not_mls_then_the_409_is_raised(self, tmp_path: Any) -> None:
        scene = seated(seated_scene(tmp_path))
        scene.server.group_row = {**GROUP_ROW, "mls_group_id": None}

        with pytest.raises(ConflictError):
            _join(scene)

        assert scene.server.commits == []

    def test_join_when_the_roster_does_not_list_the_agent_then_the_409_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = seated(seated_scene(tmp_path))
        scene.server.rosters[GROUP_ID].remove(JOINER)

        with pytest.raises(ConflictError):
            _join(scene)

    def test_join_when_the_roster_read_fails_after_establishment_then_the_409_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = seated(seated_scene(tmp_path, _RosterDownAfterReseat))

        with pytest.raises(ConflictError):
            _join(scene)

        assert holds_state(scene)


class TestARefusalForTheGroupIsRaised:
    def test_join_when_already_a_member_and_the_tree_holds_an_unverifiable_leaf_then_it_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = seated(revoked_scene(tmp_path))
        scene.server.deliver(GROUP_ID, scene.welcome)
        with contextlib.suppress(MlsWelcomeRefusedError):
            process_mls_welcomes(scene.server, scene.config_dir, JOINER, for_group=GROUP_ID)
        publish_group_info(scene)

        with pytest.raises(MlsWelcomeRefusedError) as refusal:
            _join(scene)

        assert refusal.value.reason == "peer_not_admitted"
        assert scene.server.commits == []

    def test_join_when_the_server_seats_the_agent_and_its_welcome_is_refused_then_it_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = revoked_scene(tmp_path)
        scene.server.deliver(GROUP_ID, scene.welcome)

        with pytest.raises(MlsWelcomeRefusedError) as refusal:
            _join(scene)

        assert refusal.value.reason == "peer_not_admitted"


class TestTheAsyncVerbEstablishesToo:
    async def test_join_when_already_a_member_with_no_state_then_reseats_and_reports_joined(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scene = seated(seated_scene(tmp_path))
        write_agent_identity(scene.config_dir, JOINER)

        async def _hop(_client: object, work: Any) -> Any:
            return await asyncio.to_thread(work, scene.server)

        monkeypatch.setattr("rine._mls.bridge.with_sync_http", _hop)
        client = RineClient(config_dir=scene.config_dir, api_url="https://rine.network")
        client._http = AsyncBoundary(scene.server)  # type: ignore[assignment]

        result = await client.groups.join(GROUP_ID, agent=JOINER)

        assert isinstance(result, JoinedResult)
        assert str(result.member.agent_id) == JOINER
        assert len(scene.server.commits) == 1
        assert holds_state(scene)

    async def test_join_when_the_roster_read_fails_after_establishment_then_the_409_is_raised(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scene = seated(seated_scene(tmp_path, _RosterDownAfterReseat))
        write_agent_identity(scene.config_dir, JOINER)

        async def _hop(_client: object, work: Any) -> Any:
            return await asyncio.to_thread(work, scene.server)

        monkeypatch.setattr("rine._mls.bridge.with_sync_http", _hop)
        client = RineClient(config_dir=scene.config_dir, api_url="https://rine.network")
        client._http = AsyncBoundary(scene.server)  # type: ignore[assignment]

        with pytest.raises(ConflictError):
            await client.groups.join(GROUP_ID, agent=JOINER)

        assert holds_state(scene)
