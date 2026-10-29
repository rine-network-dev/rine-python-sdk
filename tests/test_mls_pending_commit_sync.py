"""What a sync does with a self-update this member built and has not applied.

The handshakes read names the pending epoch and the server answers where the caller's own
commit stands, so a confirmed own commit is applied instead of being refused a replay. The
real ``rine-mls`` core runs behind the stub open-enrollment server.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.escrow_gap import DrainGap, EscrowLoss, LocatedGap
from rine._mls.escrow_handoff import note_unreported, reset_escrow_handoff
from rine._mls.group_access import open_mls_group
from rine._mls.pending_commit import PendingCommitOutcome
from rine._mls.sync import sync_mls_group
from rine._mls.sync_api import fetch_handshake_feed
from rine.errors import RineApiError
from tests.hold_world import held, rotated
from tests.rotation_world import G1, A

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def test_sync_when_the_commit_is_confirmed_then_it_applies_without_a_replay_refusal(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The read names the pending epoch, so a confirmed own commit is reachable."""
    server, d1, actor, epoch = held(tmp_path)
    server.confirm(G1)
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is PendingCommitOutcome.APPLIED
    assert synced.epoch == epoch
    assert server.pending_reads[-1] == epoch


def test_sync_when_the_feed_still_carries_the_applied_commit_then_it_is_skipped_not_nacked(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The feed was read before the apply, so a handshake at the held epoch is already ours."""
    server, d1, _actor, epoch = held(tmp_path)
    server.confirm(G1)
    server.echo_own = True
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is PendingCommitOutcome.APPLIED
    assert (synced.processed, synced.epoch) == (0, epoch)
    assert server.nacks == []


def test_sync_when_a_holding_handle_reads_then_the_request_names_its_pending_epoch(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A tentative commit holds the sync, and only a holding handle sends pending_epoch."""
    server, d1, _actor, epoch = held(tmp_path)
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is PendingCommitOutcome.HELD
    assert server.pending_reads[-1] == epoch
    _server, _d1, _dr, other = rotated(tmp_path / "idle")
    sync_mls_group(_server, other.config_dir, A, G1)
    assert _server.pending_reads == [None]


def test_sync_when_the_server_sends_no_standing_then_the_commit_stays_pending(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A server that predates pending_commit must not get a held commit dropped."""
    server, d1, _actor, epoch = held(tmp_path)
    server.omit_standing = True
    with pytest.raises(RuntimeError, match="did not say where the pending commit stands"):
        sync_mls_group(server, d1, A, G1)
    assert open_mls_group(d1, A, G1).pending_commit_epoch() == epoch


def test_fetch_handshake_feed_when_pending_epoch_is_not_the_next_epoch_then_the_server_refuses(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The 422 the real server answers, so a client that mis-names it is caught here."""
    server, _d1, _actor, epoch = held(tmp_path)
    with pytest.raises(RineApiError) as caught:
        fetch_handshake_feed(server, G1, epoch + 3, {}, pending_epoch=epoch)
    assert caught.value.status == 422


def test_sync_when_the_group_rolled_the_commit_back_then_it_is_dropped_and_reported(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A quarantined own commit is rolled back, not lost to a peer."""
    server, d1, _actor, _epoch = held(tmp_path)
    server.roll_back(G1)
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is PendingCommitOutcome.ROLLED_BACK
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


@pytest.mark.parametrize(
    ("standing", "outcome"),
    [("absent", PendingCommitOutcome.NOT_POSTED), ("superseded", PendingCommitOutcome.LOST)],
)
def test_sync_when_the_server_never_took_or_replaced_the_commit_then_it_is_dropped(
    tmp_path: Any, mls_escrow_stub: Any, standing: str, outcome: PendingCommitOutcome
) -> None:
    """An absent or superseded own commit is dead; the sync clears it and goes on."""
    server, d1, _actor, _epoch = held(tmp_path)
    server.standing_override = standing
    synced = sync_mls_group(server, d1, A, G1)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is outcome
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


def test_sync_when_the_pending_commit_applies_then_a_loss_the_sweep_filed_is_reported(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The settle drain's news reaches the sync result instead of being taken and dropped."""
    reset_escrow_handoff()
    server, d1, actor, _epoch = held(tmp_path)
    server.confirm(G1)
    lost = DrainGap(3, EscrowLoss.AGENT_REVOKED)
    note_unreported(d1, A, [LocatedGap(G1, lost)])
    synced = sync_mls_group(server, d1, A, G1, carry_unreported=True)
    assert synced.pending_commit is not None
    assert synced.pending_commit.outcome is PendingCommitOutcome.APPLIED
    assert lost in synced.escrow.gaps
