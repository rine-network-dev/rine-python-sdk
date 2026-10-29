"""A Welcome whose tree the roster cannot account for: refused, or read leaf by leaf.

The pass admits the roster's members before it opens a Welcome, and the guard then asks
whether anyone else in the tree the Welcome seats the joiner in is an agent the roster
names. A tree whose only other leaf is off the roster corroborates nothing, so the
Welcome is refused and kept; a tree holding two members the roster omits is read once
per member, corroborated by the members it does name, and installed.

These drive the real ``rine-mls`` core: the group, the Welcome and the refusals are
genuine, and only the server is a stand-in.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls import process_mls_welcomes
from rine._mls.group_access import open_mls_group
from rine._mls.welcome_guard import MlsWelcomeRefusedError
from rine._mls.welcome_spool import WelcomeSpool
from tests.mls_admission_world import SECOND_ADDED
from tests.mls_peers import refused_flags
from tests.mls_welcome_roster_world import (
    build_offroster_founder_scene,
    build_two_unlisted_scene,
)
from tests.mls_welcome_world import GROUP_ID, JOINER, UNLISTED, Scene

pytestmark = pytest.mark.usefixtures("real_roster_read")


@pytest.fixture(autouse=True)
def _no_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the key-package top-up out of the request counts this file measures."""
    for module in ("welcomes", "sync"):
        monkeypatch.setattr(f"rine._mls.{module}.mls_heartbeat", lambda *_a: None)


def _pass(scene: Scene) -> Any:
    """Deliver the scene's Welcome and run one pass over the joiner's queue."""
    scene.server.deliver(GROUP_ID, scene.welcome)
    return process_mls_welcomes(scene.server, scene.config_dir, JOINER)


def _pending(scene: Scene) -> int:
    """How many Welcomes the joiner's spool still holds."""
    return len(WelcomeSpool(scene.config_dir, JOINER).pending())


def _half_held(scene: Scene) -> bool:
    """Whether the KeyPackage half the Welcome names is still in the joiner's store."""
    return scene.joiner().discard_welcome_key_package(scene.welcome)


def test_welcome_pass_when_the_only_peer_is_off_the_roster_then_the_guard_refuses_it(
    tmp_path: Any,
) -> None:
    """The off-roster founder verifies, so the open succeeds and the guard refuses it."""
    scene = build_offroster_founder_scene(tmp_path)

    with pytest.raises(MlsWelcomeRefusedError) as exc:
        _pass(scene)

    assert exc.value.reason == "roster_uncorroborated"
    assert scene.server.named(UNLISTED) == 1
    assert scene.state() is None
    assert _pending(scene) == 1
    assert refused_flags(scene.config_dir, JOINER) == [True]
    assert _half_held(scene)


def test_welcome_pass_when_two_members_are_unlisted_then_each_is_read_once_and_it_installs(
    tmp_path: Any,
) -> None:
    """Two off-roster leaves cost one read each, and the roster's own members corroborate."""
    scene = build_two_unlisted_scene(tmp_path)
    payload = scene.founder_group.encrypt_application_message(b"x")
    scene.founder_group.save()

    outcome = _pass(scene)

    assert outcome.group_ids == (GROUP_ID,)
    assert outcome.discarded == 0
    assert scene.server.named(UNLISTED) == 1
    assert scene.server.named(SECOND_ADDED) == 1
    assert len(scene.server.key_reads) == 4
    assert scene.joiner_allows(UNLISTED)
    assert (
        open_mls_group(scene.config_dir, JOINER, GROUP_ID)
        .decrypt_application_message(payload)
        .envelope
        == b"x"
    )
