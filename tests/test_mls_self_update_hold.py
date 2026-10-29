"""A rotated agent's self-update in an open-enrollment group: held, confirmed, rolled back.

The real ``rine-mls`` core runs; only the server is a stub. An open group answers a
commit tentatively, so the update stays pending on disk until a member acknowledges it.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.group_access import open_mls_group
from rine._mls.pending_commit import PendingCommitOutcome
from rine._mls.self_update import self_update_group
from rine._mls.sync import sync_mls_group
from rine._mls.wire import mls_to_base64
from rine._seat_update import SeatDeferReason, SeatUpdateStatus
from tests.hold_world import leaf_key, new_key, old_key, rotated
from tests.rotation_world import G1, A, R

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def test_self_update_when_the_group_is_open_then_it_holds_and_keeps_the_old_leaf(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A tentative commit leaves the live state alone and stays pending on disk."""
    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.DEFERRED
    assert seat.reason is SeatDeferReason.AWAITING_ACK
    assert seat.epoch == server.latch[G1]
    assert leaf_key(d1, A, G1, A) == old_key()
    assert open_mls_group(d1, A, G1).pending_commit_epoch() == seat.epoch


def test_self_update_when_a_commit_is_held_then_a_second_call_waits_for_it(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A held commit is not built again; the answer names the same epoch."""
    server, _d1, _dr, actor = rotated(tmp_path, open_group=True)
    first = self_update_group(actor, G1)
    posts = server.commit_posts
    second = self_update_group(actor, G1)
    assert second.reason is SeatDeferReason.AWAITING_ACK
    assert second.epoch == first.epoch
    assert server.commit_posts == posts


def test_sync_when_a_commit_is_held_then_a_commit_built_past_it_is_neither_applied_nor_nacked(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A commit past a tentative one cannot be told from one past a rolled-back epoch."""
    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    held = self_update_group(actor, G1).epoch
    assert held is not None
    server.handshakes[G1].append(
        {
            "id": "past-the-held-commit",
            "epoch": held + 1,
            "blob": mls_to_base64(b"a commit built on the tentative epoch"),
            "author": R,
            "created_at": "2024-01-01T00:00:00Z",
        }
    )
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome.value == "held"
    assert synced.processed == 0
    assert server.nacks == []


def test_self_update_when_the_hold_is_confirmed_then_the_next_call_reports_the_move(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A member's acknowledgement turns the held commit into the live state."""
    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    self_update_group(actor, G1)
    server.confirm(G1)
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.CURRENT
    assert leaf_key(d1, A, G1, A) == new_key()
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


def test_self_update_when_the_hold_is_rolled_back_then_the_pending_commit_is_dropped(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A rolled-back commit is cleared, and the next call builds a fresh one."""
    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    self_update_group(actor, G1)
    server.roll_back(G1)
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is PendingCommitOutcome.ROLLED_BACK
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None
    assert leaf_key(d1, A, G1, A) == old_key()
    again = self_update_group(actor, G1)
    assert again.reason is SeatDeferReason.AWAITING_ACK


@pytest.mark.parametrize(
    ("standing", "reason"),
    [
        ("rolled_back", SeatDeferReason.ROLLED_BACK),
        ("superseded", SeatDeferReason.EPOCH_RACE),
        ("absent", SeatDeferReason.UNREACHABLE),
    ],
)
def test_self_update_when_the_held_commit_is_dead_then_the_seat_names_where_it_died(
    tmp_path: Any, mls_escrow_stub: Any, standing: str, reason: SeatDeferReason
) -> None:
    """Each end of a held commit has its own reason, and the unposted one carries no prose."""
    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    self_update_group(actor, G1)
    server.standing_override = standing
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.DEFERRED
    assert seat.reason is reason
    assert seat.detail is None
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None
