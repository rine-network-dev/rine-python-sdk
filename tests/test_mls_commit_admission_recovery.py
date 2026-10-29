"""Recovery climbs past a refusal and admits the peers a GroupInfo tree holds.

The real ``rine-mls`` core refuses the leaf; only the server is a stand-in.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.resync import recover_mls_group
from rine._recover_reseat import ReseatStatus, reseat_closed_groups
from tests.mls_admission_world import (
    ADDED,
    FOUNDER,
    GROUP_ID,
    MEMBER,
    build_world,
    device,
)

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")


def test_recover_when_the_replay_ends_in_a_refusal_then_it_resyncs_past_it(tmp_path: Any) -> None:
    """Recovery reads the typed refusal as the signal to climb to the resync rung."""
    edges = build_world(tmp_path)
    start = edges.member_epoch()
    edges.add_then_remove_added()
    edges.server.absent.add(ADDED)
    edges.server.group_info = (
        edges.founder_group.last_commit().group_info,
        edges.founder_group.epoch(),
    )

    result = recover_mls_group(edges.server, edges.config_dir, MEMBER, GROUP_ID)

    assert (result.rung, result.from_epoch) == ("resync", start)
    assert result.epoch == edges.founder_group.epoch() + 1
    assert len(edges.server.commits) == 1


def test_recover_when_the_tree_holds_a_verifying_peer_the_roster_lacks_then_it_verifies_once(
    tmp_path: Any,
) -> None:
    """The external commit meets every leaf, so a verifying non-roster leaf is admitted first."""
    edges = build_world(tmp_path)
    added = edges.founder_group.add_member(edges.added_package)
    edges.founder_group.save()
    edges.server.replay_refused = True
    edges.server.group_info = (added.group_info, added.epoch)

    result = recover_mls_group(edges.server, edges.config_dir, MEMBER, GROUP_ID)

    assert result.rung == "resync"
    assert edges.server.key_reads == [[ADDED]]
    assert len(edges.server.commits) == 1
    assert edges.member_allows(ADDED)


def test_reseat_when_the_tree_holds_a_verifying_peer_the_roster_lacks_then_it_verifies_once(
    tmp_path: Any,
) -> None:
    """A restored device holds no state; its reseat commit meets the same unknown leaf."""
    edges = build_world(tmp_path)
    added = edges.founder_group.add_member(edges.added_package)
    edges.founder_group.save()
    edges.server.group_info = (added.group_info, added.epoch)
    restored = device(tmp_path, "restored", MEMBER, (FOUNDER, 0))

    [outcome] = reseat_closed_groups(edges.server, restored, [MEMBER])

    assert outcome.status == ReseatStatus.RESEATED, outcome.reason
    assert edges.server.key_reads == [[ADDED]]
    assert len(edges.server.commits) == 1
