"""What a sync decides about a self-update this member built and has not applied.

The real ``rine-mls`` core runs behind a stub server that plays the
open-enrollment hold: a tentative commit advances the latch and not the confirmed
epoch, and the handshakes read answers where the caller's own commit stands. Each test
starts from a commit left pending on disk by a real self-update.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.group_access import open_mls_group
from rine._mls.pending_commit import (
    PendingCommitOutcome,
    drop_pending_commit,
    settle_pending_commit,
)
from rine._mls.sync_api import OwnCommitStanding
from tests.hold_world import held, leaf_key, new_key, rotated
from tests.rotation_world import G1, A

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def _settle(actor: Any, standing: OwnCommitStanding | None) -> Any:
    group = open_mls_group(actor.config_dir, A, G1)
    return settle_pending_commit(actor, G1, group, standing), group


def test_settle_pending_commit_when_nothing_is_pending_then_it_returns_none_without_a_request(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A handle with no pending commit costs a sync nothing."""
    server, _d1, _dr, actor = rotated(tmp_path)
    calls = len(server.calls)
    settled, _group = _settle(actor, None)
    assert settled is None
    assert len(server.calls) == calls


def test_settle_pending_commit_when_the_standing_is_confirmed_then_it_applies_and_moves_the_leaf(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """Confirmation at the pending epoch is what justifies applying it, with no read of its own."""
    server, d1, actor, epoch = held(tmp_path)
    calls = len(server.calls)
    settled, _group = _settle(actor, OwnCommitStanding.CONFIRMED)
    assert settled is not None
    assert (settled.epoch, settled.outcome) == (epoch, PendingCommitOutcome.APPLIED)
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None
    assert leaf_key(d1, A, G1, A) == new_key()
    assert not [c for c in server.calls[calls:] if "group-info" in c]


def test_settle_pending_commit_when_the_standing_is_tentative_then_it_is_held_and_untouched(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A tentative commit keeps holding: nothing is cleared and nothing is saved."""
    _server, d1, actor, epoch = held(tmp_path)
    settled, _group = _settle(actor, OwnCommitStanding.TENTATIVE)
    assert settled is not None
    assert (settled.epoch, settled.outcome) == (epoch, PendingCommitOutcome.HELD)
    assert open_mls_group(d1, A, G1).pending_commit_epoch() == epoch


@pytest.mark.parametrize(
    ("standing", "outcome"),
    [
        (OwnCommitStanding.ROLLED_BACK, PendingCommitOutcome.ROLLED_BACK),
        (OwnCommitStanding.SUPERSEDED, PendingCommitOutcome.LOST),
        (OwnCommitStanding.ABSENT, PendingCommitOutcome.NOT_POSTED),
    ],
)
def test_settle_pending_commit_when_the_commit_is_dead_then_it_is_cleared_and_saved(
    tmp_path: Any, mls_escrow_stub: Any, standing: OwnCommitStanding, outcome: PendingCommitOutcome
) -> None:
    """Each way a commit dies names its own outcome, and the clear survives a reload."""
    _server, d1, actor, epoch = held(tmp_path)
    settled, group = _settle(actor, standing)
    assert settled is not None
    assert (settled.epoch, settled.outcome) == (group.epoch(), outcome)
    assert group.epoch() < epoch
    assert open_mls_group(d1, A, G1).pending_commit_epoch() is None


def test_settle_pending_commit_when_the_server_names_no_standing_then_it_fails_closed(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A holding handle that cannot tell tentative from an old server keeps its commit."""
    _server, d1, actor, epoch = held(tmp_path)
    with pytest.raises(RuntimeError, match="did not say where the pending commit stands"):
        _settle(actor, None)
    assert open_mls_group(d1, A, G1).pending_commit_epoch() == epoch


def test_drop_pending_commit_when_another_process_already_applied_it_then_the_store_is_not_rewound(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A stale handle's late clear must not put the stored epoch back."""
    _server, d1, actor, epoch = held(tmp_path)
    stale = open_mls_group(d1, A, G1)
    winner = open_mls_group(d1, A, G1)
    winner.apply_pending_commit()
    winner.save()
    drop_pending_commit(actor, G1, stale)
    reloaded = open_mls_group(d1, A, G1)
    assert reloaded.epoch() == epoch
    assert leaf_key(d1, A, G1, A) == new_key()
