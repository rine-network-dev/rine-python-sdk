"""A join over a revoked member's unreclaimed leaf, against the real ``rine-mls`` core.

The tree still holds a revoked member's leaf until somebody reclaims it, and no key read serves
that member any more. So a Welcome minted over the tree can never be opened, and the group must
not seat a newcomer on it. Three things follow, each tested here: the adder holds the newcomer
back, a Welcome that meets the revoked leaf is raised as a refusal and never counted, and a
reclaim admits nobody. The seat a refused Welcome leaves behind is taken back by the agent
itself: ``test_mls_seat_retake.py``.

The TypeScript twin is ``rine-core/test/mls-revoked-seat-join.test.ts``.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.add_members import add_mls_group_members
from rine._mls.admission import MlsAdmissionOutcome
from rine._mls.join import install_mls_state
from rine._mls.orphans import reclaim_orphan_leaves
from rine.errors import MlsWelcomeRefusedError
from tests.mls_admission_world import FOUNDER, GROUP_ID, SECOND_ADDED
from tests.mls_revoked_seat_world import (
    group_row,
    key_package,
    newcomer,
    publish_group_info,
    revoked_scene,
)
from tests.mls_welcome_world import JOINER, UNLISTED, Scene

pytestmark = pytest.mark.usefixtures("real_roster_read")


@pytest.fixture(autouse=True)
def _no_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the key-package top-up out of the requests these tests measure."""
    for module in ("welcomes", "sync", "add_members"):
        monkeypatch.setattr(f"rine._mls.{module}.mls_heartbeat", lambda *_a: None)


class TestTheAdderHoldsTheNewcomer:
    @pytest.fixture
    def adds(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> dict[str, list[Any]]:
        """What the adder claimed and posted, with the claim served from a real KeyPackage."""
        package = key_package(tmp_path)
        seen: dict[str, list[Any]] = {"claims": [], "posts": []}

        def _claim(_c: Any, batch: list[str], _h: dict[str, str]) -> dict[str, bytes]:
            seen["claims"].append(batch)
            return {agent.lower(): package for agent in batch}

        def _post(_actor: Any, _group: str, commit: Any, _h: dict[str, str]) -> int:
            seen["posts"].append(commit)
            return commit.epoch

        monkeypatch.setattr("rine._mls.admission_loop.claim_founding_key_packages", _claim)
        monkeypatch.setattr("rine._mls.admission_state.post_mls_commit", _post)
        return seen

    def _add(self, scene: Scene) -> Any:
        scene.server.rosters[GROUP_ID].append(SECOND_ADDED)
        return add_mls_group_members(
            scene.server, scene.founder_dir, FOUNDER, GROUP_ID, [SECOND_ADDED]
        )

    def test_add_when_the_tree_holds_a_revoked_unreclaimed_leaf_then_no_welcome_is_minted(
        self, tmp_path: Any, adds: dict[str, list[Any]], mls_escrow_stub: Any
    ) -> None:
        scene = revoked_scene(tmp_path)

        result = self._add(scene)

        assert result.outcomes == (
            MlsAdmissionOutcome(SECOND_ADDED, "skipped", "revoked_seat_unreclaimed"),
        )
        assert (result.added, result.commits) == (0, 0)
        assert adds == {"claims": [], "posts": []}

    def test_add_when_every_leaf_in_the_tree_is_served_then_the_newcomer_is_added(
        self, tmp_path: Any, adds: dict[str, list[Any]], mls_escrow_stub: Any
    ) -> None:
        scene = revoked_scene(tmp_path)
        scene.server.absent.clear()

        result = self._add(scene)

        assert [(o.agent_id, o.status) for o in result.outcomes] == [(SECOND_ADDED, "added")]
        assert len(adds["posts"]) == 1
        assert [w.agent_id for w in adds["posts"][0].welcomes] == [SECOND_ADDED]


class TestAWelcomeThatMeetsTheRevokedLeafIsRaised:
    def test_join_state_when_the_welcome_meets_a_revoked_member_then_the_refusal_is_raised(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scene = revoked_scene(tmp_path)
        scene.server.deliver(GROUP_ID, scene.welcome)
        external: list[Any] = []
        monkeypatch.setattr("rine._mls.join.external_join_mls_group", external.append)

        with pytest.raises(MlsWelcomeRefusedError) as refusal:
            install_mls_state(scene.server, scene.config_dir, JOINER, group_row())

        assert refusal.value.reason == "peer_not_admitted"
        assert external == []

    def test_join_state_when_the_welcome_meets_a_revoked_member_then_the_log_names_the_agent(
        self, tmp_path: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        scene = revoked_scene(tmp_path)
        scene.server.deliver(GROUP_ID, scene.welcome)

        with pytest.raises(MlsWelcomeRefusedError):
            install_mls_state(scene.server, scene.config_dir, JOINER, group_row())

        assert any(UNLISTED in record.getMessage() for record in caplog.records)

    def test_join_state_when_the_external_join_meets_a_revoked_member_then_the_refusal_is_raised(
        self, tmp_path: Any, mls_escrow_stub: Any
    ) -> None:
        scene = revoked_scene(tmp_path)
        publish_group_info(scene)

        with pytest.raises(MlsWelcomeRefusedError) as refusal:
            install_mls_state(scene.server, newcomer(tmp_path), SECOND_ADDED, group_row())

        assert refusal.value.reason == "peer_not_admitted"
        assert scene.server.commits == []


class TestAReclaimAdmitsNobody:
    def test_reclaim_when_a_newcomer_waits_then_the_commit_removes_the_leaf_and_welcomes_nobody(
        self, tmp_path: Any, mls_escrow_stub: Any
    ) -> None:
        scene = revoked_scene(tmp_path)
        scene.server.outstanding = [
            {"agent_id": SECOND_ADDED, "status": "invited", "invited_by": FOUNDER}
        ]

        result = reclaim_orphan_leaves(scene.server, scene.founder_dir, FOUNDER, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (1, 1, 1)
        (posted,) = scene.server.commits
        assert posted["welcomes"] == []
        assert posted["removes"] == [UNLISTED]
