"""Scenes where the roster a Welcome's joiner reads does not account for its tree.

Two shapes, both driven against the real ``rine-mls`` core and the stand-in server of
:mod:`tests.mls_welcome_world`:

* A founder the roster does not name seats the joiner alone, so the Welcome's only
  other leaf is an agent the roster read never mentions.
* A founder seats two members the roster omits and then the joiner, so the Welcome's
  tree holds two leaves no roster read accounts for.

The group, the Welcome and the core's refusals are genuine; only the server is a
stand-in.
"""

from __future__ import annotations

from typing import Any

from rine._mls.binding import open_mls_client
from rine._mls.group_access import mls_group_id_bytes
from tests.mls_admission_world import FOUNDER, GROUP_ID, SECOND_ADDED, device
from tests.mls_welcome_world import JOINER, PEER, UNLISTED, Scene, WelcomeServer


def build_offroster_founder_scene(base: Any) -> Scene:
    """A founder the roster does not name seats the joiner alone: the Welcome's only peer."""
    joiner_dir = device(base, "joiner", JOINER)
    outsider_dir = device(base, "outsider", UNLISTED, (JOINER, 0))
    group = open_mls_client(outsider_dir, UNLISTED).create_group_with_members(
        mls_group_id_bytes(GROUP_ID),
        [open_mls_client(joiner_dir, JOINER).generate_key_package()],
    )
    group.save()
    welcome = group.last_commit().welcomes[0]
    return Scene(WelcomeServer(), joiner_dir, group, welcome, outsider_dir)


def build_two_unlisted_scene(base: Any) -> Scene:
    """Found the group, seat two members the roster omits, then seat the joiner."""
    joiner_dir = device(base, "joiner", JOINER)
    founder_dir = device(
        base,
        "founder",
        FOUNDER,
        (PEER, 0),
        (UNLISTED, 0),
        (SECOND_ADDED, 0),
        (JOINER, 0),
    )
    peer_dir = device(base, "peer", PEER, (FOUNDER, 0))
    unlisted_dir = device(base, "unlisted", UNLISTED, (FOUNDER, 0))
    second_dir = device(base, "second", SECOND_ADDED, (FOUNDER, 0))
    founder = open_mls_client(founder_dir, FOUNDER)
    joiner = open_mls_client(joiner_dir, JOINER)
    group_id = mls_group_id_bytes(GROUP_ID)
    peer_package = open_mls_client(peer_dir, PEER).generate_key_package()
    group = founder.create_group_with_members(group_id, [peer_package])
    group.add_member(open_mls_client(unlisted_dir, UNLISTED).generate_key_package())
    group.add_member(open_mls_client(second_dir, SECOND_ADDED).generate_key_package())
    welcome = group.add_member(joiner.generate_key_package()).welcomes[0]
    group.save()
    return Scene(WelcomeServer(), joiner_dir, group, welcome, founder_dir)
