"""``groups.sync()`` for a seated agent that holds no local group state.

The leaf stands in the tree and nothing on the device matches it, whether the state was lost,
moved aside, or never written because a Welcome was refused. The agent takes its own seat back
on its next group sync, after installing any Welcome waiting for it, and never from a read or a
send. Every test goes through the public verb; the group, the Welcomes and the core's refusals
are the real ``rine-mls`` core's and only the server is a stand-in.

The TypeScript twin is ``rine-core/test/mls-stranded-seat.test.ts``.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from rine._group_recovery import KeyPackageTopUp
from rine._mls import process_mls_welcomes
from rine._mls.binding import open_mls_client
from rine._mls.group_access import load_mls_group
from rine._mls.join import install_mls_state
from rine._mls.peer_refusal import peer_not_admitted_refusal
from rine.errors import MlsResyncUnavailableError, MlsWelcomeRefusedError, RineApiError
from tests.mls_admission_world import GROUP_ID, SECOND_ADDED
from tests.mls_revoked_seat_world import (
    RevokedSeatServer,
    apply_posted_commit,
    group_row,
    joiner_state,
    newcomer,
    publish_group_info,
    reclaim,
    revoked_scene,
    seated_scene,
    verb_client,
)
from tests.mls_welcome_world import JOINER, Scene, build_scene

if TYPE_CHECKING:
    from rine._mls.resync import MlsRecoveryResult

pytestmark = pytest.mark.usefixtures("real_roster_read", "mls_escrow_stub")


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the key-package top-up and the leaf rotation out of the requests measured here."""
    for module in ("welcomes", "sync", "add_members"):
        monkeypatch.setattr(f"rine._mls.{module}.mls_heartbeat", lambda *_a: None)
    monkeypatch.setattr(
        "rine._resources.group_sync.top_up_key_packages",
        lambda _actor: KeyPackageTopUp(outcome="healthy"),
    )
    monkeypatch.setattr("rine._resources.group_sync.self_update_group", lambda *_a: None)


def _refused_welcome(base: Any) -> Scene:
    """The joiner's Welcome meets the revoked leaf: refused and dropped, no state written."""
    scene = revoked_scene(base)
    scene.server.deliver(GROUP_ID, scene.welcome)
    with contextlib.suppress(MlsWelcomeRefusedError):
        process_mls_welcomes(scene.server, scene.config_dir, JOINER, for_group=GROUP_ID)
    return scene


def _sync(scene: Scene, config_dir: str | None = None, agent: str = JOINER) -> MlsRecoveryResult:
    client = verb_client(config_dir or scene.config_dir, agent, scene.server)
    return client.groups.sync(GROUP_ID, agent=agent)  # type: ignore[return-value]


def _holds_state(scene: Scene) -> bool:
    return load_mls_group(open_mls_client(scene.config_dir, JOINER), GROUP_ID) is not None


def _reads_after_the_retake(scene: Scene) -> None:
    apply_posted_commit(scene)
    sealed = scene.founder_group.encrypt_application_message(b"after the retake")
    assert joiner_state(scene).decrypt_application_message(sealed).envelope == b"after the retake"


class TestTheSeatIsRetaken:
    def test_sync_when_seated_with_no_state_and_no_marker_then_reseats(
        self, tmp_path: Any
    ) -> None:
        scene = seated_scene(tmp_path)

        result = _sync(scene)

        assert (result.rung, result.evicted) == ("resync", False)
        assert len(scene.server.commits) == 1
        assert joiner_state(scene).epoch() == scene.founder_group.epoch() + 1
        _reads_after_the_retake(scene)

    def test_sync_when_a_refused_welcome_left_no_state_then_the_seat_is_retaken_after_the_reclaim(
        self, tmp_path: Any
    ) -> None:
        scene = _refused_welcome(tmp_path)
        reclaim(scene)

        result = _sync(scene)

        assert (result.rung, result.evicted) == ("resync", False)
        assert len(scene.server.commits) == 1
        _reads_after_the_retake(scene)

    def test_sync_when_the_seat_was_retaken_then_the_next_sync_posts_nothing_more(
        self, tmp_path: Any
    ) -> None:
        scene = seated_scene(tmp_path)
        _sync(scene)

        _sync(scene)

        assert len(scene.server.commits) == 1

    def test_sync_when_the_agent_holds_state_then_it_does_not_reseat(self, tmp_path: Any) -> None:
        scene = build_scene(tmp_path, reinvite=True)
        scene.server = RevokedSeatServer()
        publish_group_info(scene)

        _sync(scene)

        assert scene.server.commits == []


class TestAWelcomeComesFirst:
    def test_sync_when_a_welcome_waits_on_the_server_then_it_installs_before_any_reseat(
        self, tmp_path: Any
    ) -> None:
        scene = build_scene(tmp_path)
        scene.server = RevokedSeatServer()
        scene.server.deliver(GROUP_ID, scene.welcome)

        result = _sync(scene)

        assert _holds_state(scene)
        assert scene.server.commits == []
        assert result.rung != "resync"

    def test_sync_when_a_waiting_welcome_is_refused_then_that_refusal_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = revoked_scene(tmp_path)
        scene.server.deliver(GROUP_ID, scene.welcome)

        with pytest.raises(MlsWelcomeRefusedError) as refusal:
            _sync(scene)

        assert refusal.value.reason == "peer_not_admitted"
        assert scene.server.commits == []

    def test_sync_when_the_welcome_is_kept_on_the_spool_then_nothing_is_posted(
        self, tmp_path: Any
    ) -> None:
        scene = build_scene(tmp_path)
        scene.server = RevokedSeatServer()
        scene.server.deliver(GROUP_ID, scene.welcome)
        scene.server.roster_error = RineApiError(503, "unavailable", "")
        publish_group_info(scene)

        with pytest.raises(MlsResyncUnavailableError):
            _sync(scene)

        assert scene.server.commits == []
        assert not _holds_state(scene)


class TestTheRetakeRefusesWhatItCannotDo:
    def test_sync_when_the_tree_holds_an_unverifiable_leaf_then_the_shared_refusal_is_raised(
        self, tmp_path: Any
    ) -> None:
        scene = _refused_welcome(tmp_path)
        publish_group_info(scene)

        with pytest.raises(MlsWelcomeRefusedError) as refusal:
            _sync(scene)

        assert (refusal.value.group_id, refusal.value.reason) == (GROUP_ID, "peer_not_admitted")
        assert str(refusal.value) == str(peer_not_admitted_refusal(GROUP_ID))
        assert scene.server.commits == []
        assert not _holds_state(scene)

    def test_sync_when_the_agent_holds_no_leaf_then_it_is_unavailable_and_nothing_is_posted(
        self, tmp_path: Any
    ) -> None:
        scene = revoked_scene(tmp_path)
        reclaim(scene)

        with pytest.raises(MlsResyncUnavailableError):
            _sync(scene, newcomer(tmp_path), SECOND_ADDED)

        assert scene.server.commits == []

    def test_sync_when_the_retake_meets_an_outage_then_the_error_propagates(
        self, tmp_path: Any
    ) -> None:
        scene = seated_scene(tmp_path)
        scene.server.outage = RineApiError(503, "unavailable", "")

        with pytest.raises(RineApiError):
            _sync(scene)

        assert scene.server.commits == []


class TestReadAndSendNeverRetake:
    def test_read_when_state_is_absent_then_no_reseat_is_attempted(self, tmp_path: Any) -> None:
        scene = _refused_welcome(tmp_path)
        reclaim(scene)

        with contextlib.suppress(Exception):
            install_mls_state(scene.server, scene.config_dir, JOINER, group_row())

        assert scene.server.commits == []
