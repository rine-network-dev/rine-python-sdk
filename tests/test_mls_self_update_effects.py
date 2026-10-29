"""What an applied self-update does besides moving the leaf: drain the escrow, drop the memo.

Moving the leaf is observable on its own, but two follow-ups are not. The new epoch's escrow
has to be sealed and uploaded (or the send gate waits on it forever), and the process's
memo of "this group's state is held here" has to be forgotten (or a stale answer outlives
the change). Each is asserted at the seam the self-update reaches it through, on both the
closed regime (applied on the post) and the settled hold (applied by a later sync), and a
held commit, which applies nothing, must do neither.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls import pending_commit, self_update
from rine._mls.escrow_drain import drain_escrow
from rine._mls.group_access import note_mls_state_changed
from rine._mls.self_update import self_update_group
from rine._seat_update import SeatUpdateStatus
from tests.hold_world import rotated
from tests.rotation_world import G1

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


@pytest.fixture
def effects(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Every drain and memo invalidation the self-update paths make, as (what, group id)."""
    seen: list[tuple[str, str]] = []

    def drain(actor, group_id, *rest, **options):
        seen.append(("drain", group_id))
        return drain_escrow(actor, group_id, *rest, **options)

    def forget(config_dir, agent_id, group_id):
        seen.append(("forget", group_id))
        note_mls_state_changed(config_dir, agent_id, group_id)

    for module in (self_update, pending_commit):
        monkeypatch.setattr(module, "drain_escrow", drain)
        monkeypatch.setattr(module, "note_mls_state_changed", forget)
    return seen


def test_self_update_when_the_post_confirms_then_the_escrow_drains_and_the_memo_is_forgotten(
    tmp_path: Any, mls_escrow_stub: Any, effects: list[tuple[str, str]]
) -> None:
    _server, _d1, _dr, actor = rotated(tmp_path)

    assert self_update_group(actor, G1).status is SeatUpdateStatus.UPDATED

    assert sorted(effects) == [("drain", G1), ("forget", G1)]


def test_self_update_when_the_commit_is_held_then_nothing_drains_and_no_memo_is_forgotten(
    tmp_path: Any, mls_escrow_stub: Any, effects: list[tuple[str, str]]
) -> None:
    _server, _d1, _dr, actor = rotated(tmp_path, open_group=True)

    self_update_group(actor, G1)

    assert effects == []


def test_self_update_when_a_later_sync_settles_the_hold_then_it_drains_and_forgets(
    tmp_path: Any, mls_escrow_stub: Any, effects: list[tuple[str, str]]
) -> None:
    server, _d1, _dr, actor = rotated(tmp_path, open_group=True)
    self_update_group(actor, G1)
    server.confirm(G1)

    assert self_update_group(actor, G1).status is SeatUpdateStatus.CURRENT

    assert sorted(effects) == [("drain", G1), ("forget", G1)]
