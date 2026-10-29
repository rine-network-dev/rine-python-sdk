"""A rotated agent moves its own leaf: the closed regime, the hold, and every refusal.

The real ``rine-mls`` core runs; only the server is a stub. ``A`` is seated in a
group from device ``d1`` and rotates to generation 1, so the tree still holds its
generation-0 leaf while its disk holds generation 1.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from rine._mls.escrow_gap import DrainGap, EscrowLoss, LocatedGap
from rine._mls.escrow_handoff import note_unreported, reset_escrow_handoff, take_unreported
from rine._mls.group_access import open_mls_group
from rine._mls.pending_commit import PendingCommitOutcome
from rine._mls.self_update import self_update_group
from rine._mls.sync import sync_mls_group
from rine._seat_update import SeatDeferReason, SeatFailReason, SeatUpdateStatus
from rine.errors import ConflictError, RineApiError
from tests.hold_world import leaf_key, new_key, rotated
from tests.rotation_world import G1, A, R

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def _epoch_conflict() -> ConflictError:
    return ConflictError("the group moved on", '{"error": "epoch_conflict"}')


def test_self_update_when_the_group_is_closed_then_the_leaf_moves_and_a_peer_follows(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A closed group confirms on the post, so the commit applies at once."""
    server, d1, dr, actor = rotated(tmp_path)
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.UPDATED
    assert seat.group_id == G1
    assert seat.epoch == server.confirmed[G1]
    assert leaf_key(d1, A, G1, A) == new_key()
    sync_mls_group(server, dr, R, G1)
    assert leaf_key(dr, R, G1, A) == new_key()


def test_self_update_when_the_epoch_escrow_is_stored_then_the_seat_reports_none_pending(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The drain sealed and uploaded the new epoch, so the send gate has nothing to wait for."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    assert self_update_group(actor, G1).escrow_pending is False


def test_self_update_when_the_escrow_upload_fails_then_the_seat_reports_it_pending(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A sealed file still waiting for its upload is pending even though nothing is queued."""

    def refuse(*_args: Any) -> None:
        raise ConnectionError("network down")

    _server, _d1, _dr, actor = rotated(tmp_path)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("rine._mls.escrow_upload.upload_escrow", refuse)
        seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.UPDATED
    assert seat.escrow_pending is True


def test_self_update_when_it_applies_then_a_filed_loss_stays_for_a_result_that_reports_it(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A seat carries no gap list, so its drain must leave the news for a result that does."""
    reset_escrow_handoff()
    _server, d1, _dr, actor = rotated(tmp_path)
    lost = DrainGap(3, EscrowLoss.AGENT_REVOKED)
    note_unreported(d1, A, [LocatedGap(G1, lost)])
    assert self_update_group(actor, G1).status is SeatUpdateStatus.UPDATED
    assert take_unreported(d1, A, G1) == (lost,)


def test_self_update_when_the_leaf_is_already_current_then_it_is_current_and_posts_nothing(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A second update finds the leaf moved and builds no commit."""
    server, _d1, _dr, actor = rotated(tmp_path)
    self_update_group(actor, G1)
    posts = server.commit_posts
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.CURRENT
    assert server.commit_posts == posts


def test_self_update_when_the_epoch_race_is_lost_once_then_it_retries_and_moves(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """One lost compare-and-swap is caught up and rebuilt."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.fail_posts = [_epoch_conflict()]
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.UPDATED
    assert server.commit_posts == 2
    assert leaf_key(d1, A, G1, A) == new_key()


def test_self_update_when_the_epoch_race_is_lost_twice_then_it_is_deferred(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A second lost race is reported, with the pending commit cleared."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.fail_posts = [_epoch_conflict(), _epoch_conflict()]
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.DEFERRED
    assert seat.reason is SeatDeferReason.EPOCH_RACE
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


def test_self_update_when_the_server_answers_with_a_refusal_then_the_pending_commit_is_cleared(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """An answered 4xx proves the commit was not taken, so it is dropped."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.fail_posts = [RineApiError(422, "refused")]
    seat = self_update_group(actor, G1)
    assert seat.reason is SeatDeferReason.UNREACHABLE
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


def test_self_update_when_the_server_fails_to_answer_then_the_pending_commit_stays_saved(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A 5xx may hide an accepted commit, so it stays pending and the next sync settles it."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.fail_posts = [RineApiError(503, "unavailable")]
    seat = self_update_group(actor, G1)
    assert seat.reason is SeatDeferReason.UNREACHABLE
    held = open_mls_group(d1, A, G1).pending_commit_epoch()
    assert held is not None
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.epoch == held - 1
    assert synced.pending_commit.outcome is PendingCommitOutcome.NOT_POSTED
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


def test_self_update_when_the_agent_was_evicted_then_it_is_failed_evicted(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An eviction found while catching up ends the update."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    monkeypatch.setattr(
        "rine._mls.self_update.sync_mls_group",
        lambda *a, **k: SimpleNamespace(evicted=True, pending_commit=None),
    )
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.FAILED
    assert seat.reason is SeatFailReason.EVICTED
