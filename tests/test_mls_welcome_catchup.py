"""A Welcome whose tree names a member the roster did not is verified, then opened again.

The pass admits the roster's members before it opens a Welcome, but the Welcome's tree is
whoever was seated when it was minted. A member seated after the roster read, or added and
removed since, is refused by the core for being new. The pass reads that agent, puts it
through the same chain verification as every other peer and opens the same Welcome again; a
member that does not verify ends the Welcome, which is discarded with its KeyPackage half.

These drive the real ``rine-mls`` core: the group, the Welcome and the refusals are
genuine, and only the server is a stand-in. The TypeScript twin is
``rine-core/test/mls-welcome-catchup.test.ts``.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from rine._mls import process_mls_welcomes
from rine._mls import welcomes as welcomes_module
from rine._mls.group_access import open_mls_group
from rine._mls.sync import sync_mls_group
from rine._mls.welcome_spool import WelcomeSpool
from rine.errors import RineApiError
from tests.mls_peers import refused_flags
from tests.mls_welcome_world import (
    GROUP_ID,
    JOINER,
    OTHER_GROUP,
    UNLISTED,
    RefusalSpy,
    Scene,
    build_scene,
)

pytestmark = pytest.mark.usefixtures("real_roster_read")


@pytest.fixture(autouse=True)
def _no_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the key-package top-up out of the request counts this file measures."""
    for module in ("welcomes", "sync"):
        monkeypatch.setattr(f"rine._mls.{module}.mls_heartbeat", lambda *_a: None)


def _pass(scene: Scene) -> Any:
    scene.server.deliver(GROUP_ID, scene.welcome)
    return process_mls_welcomes(scene.server, scene.config_dir, JOINER)


def _pending(scene: Scene) -> int:
    return len(WelcomeSpool(scene.config_dir, JOINER).pending())


def _half_held(scene: Scene) -> bool:
    """Whether the KeyPackage half the Welcome names is still in the joiner's store."""
    return scene.joiner().discard_welcome_key_package(scene.welcome)


def test_welcome_pass_when_the_tree_holds_a_member_the_roster_omits_then_it_installs(
    tmp_path: Any,
) -> None:
    """One key read for the unlisted member, and the joiner reads the next message."""
    scene = build_scene(tmp_path)
    payload = scene.founder_group.encrypt_application_message(b"welcome aboard")
    scene.founder_group.save()

    outcome = _pass(scene)

    assert outcome.group_ids == (GROUP_ID,)
    assert outcome.discarded == 0
    assert scene.server.named(UNLISTED) == 1
    assert scene.joiner_allows(UNLISTED)
    assert (
        open_mls_group(scene.config_dir, JOINER, GROUP_ID)
        .decrypt_application_message(payload)
        .envelope
        == b"welcome aboard"
    )


def test_welcome_pass_when_the_member_was_removed_since_then_it_installs_and_catches_up(
    tmp_path: Any,
) -> None:
    """Added, then the joiner added, then removed: the Welcome installs and the removal syncs."""
    scene = build_scene(tmp_path)
    scene.remove_unlisted()

    outcome = _pass(scene)
    synced = sync_mls_group(scene.server, scene.config_dir, JOINER, GROUP_ID)

    assert outcome.group_ids == (GROUP_ID,)
    assert synced.epoch == scene.founder_group.epoch()
    assert scene.server.nacks == []


@pytest.mark.parametrize("shape", ["broken_chain", "deleted", "another_key"])
def test_welcome_pass_when_the_member_does_not_verify_then_the_welcome_is_dropped_and_released(
    tmp_path: Any, shape: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A final refusal discards the Welcome and its half and reads the member exactly once."""
    scene = build_scene(tmp_path, unlisted_gen=1 if shape == "another_key" else 0)
    if shape == "deleted":
        scene.server.absent.add(UNLISTED)
    if shape == "broken_chain":
        scene.server.tampered.add(UNLISTED)

    with caplog.at_level(logging.WARNING, logger="rine"):
        outcome = _pass(scene)

    assert outcome.group_ids == ()
    assert outcome.discarded == 1
    assert _pending(scene) == 0
    assert not _half_held(scene)
    assert scene.state() is None
    assert scene.joiner_allows(UNLISTED) == (shape == "another_key")
    assert scene.server.named(UNLISTED) == 1
    assert not any(path.endswith("key-packages/count") for path in scene.server.paths)
    assert any("cannot verify" in record.getMessage() for record in caplog.records)


def test_welcome_pass_when_a_reinvited_agent_meets_an_unverifiable_member_then_it_is_not_joined(
    tmp_path: Any,
) -> None:
    """Old local state no longer hides the refusal: not joined, released, state untouched."""
    scene = build_scene(tmp_path, reinvite=True)
    scene.server.absent.add(UNLISTED)
    before = scene.state()
    assert before is not None

    outcome = _pass(scene)

    assert outcome.group_ids == ()
    assert outcome.discarded == 1
    assert not _half_held(scene)
    assert scene.state() == before


def test_welcome_pass_when_verifying_the_member_fails_then_the_welcome_waits_for_the_next_pass(
    tmp_path: Any,
) -> None:
    """A transport failure keeps the bytes and the half; the next pass installs them."""
    scene = build_scene(tmp_path)
    scene.server.failing.add(UNLISTED)
    scene.server.deliver(OTHER_GROUP, scene.another_group())

    outcome = _pass(scene)

    assert outcome.group_ids == (OTHER_GROUP,)
    assert outcome.discarded == 0
    assert _pending(scene) == 1
    assert refused_flags(scene.config_dir, JOINER) == [False]
    assert not any(path.endswith("key-packages/count") for path in scene.server.paths)

    scene.server.failing.clear()
    scene.server.key_reads.clear()
    retry = process_mls_welcomes(scene.server, scene.config_dir, JOINER)

    assert retry.group_ids == (GROUP_ID,)
    assert _pending(scene) == 0


def test_welcome_pass_when_the_roster_covers_the_tree_then_no_refusal_is_read(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordinary path makes the same requests as before: the helper does nothing."""
    scene = build_scene(tmp_path, with_unlisted=False)
    spies: list[RefusalSpy] = []
    real = welcomes_module.open_mls_client

    def spied(config_dir: str, agent_id: str) -> RefusalSpy:
        spies.append(RefusalSpy(real(config_dir, agent_id)))
        return spies[-1]

    monkeypatch.setattr(welcomes_module, "open_mls_client", spied)

    outcome = _pass(scene)

    assert outcome.group_ids == (GROUP_ID,)
    assert [spy.reads for spy in spies] == [0]
    assert scene.server.named(UNLISTED) == 0
    assert len(scene.server.key_reads) == 2


def test_welcome_pass_when_the_roster_is_forbidden_then_the_member_is_never_read(
    tmp_path: Any,
) -> None:
    """The roster's answer decides first: an unaccepted invitation is kept unopened."""
    scene = build_scene(tmp_path)
    scene.server.roster_error = RineApiError(403, "forbidden", "")

    outcome = _pass(scene)

    assert outcome.group_ids == ()
    assert scene.server.key_reads == []
    assert refused_flags(scene.config_dir, JOINER) == [True]
