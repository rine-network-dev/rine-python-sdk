"""The epochs a parked snapshot held are recorded at park time, so losing it still names them."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest

from rine._mls.escrow_backlog import give_up_snapshots
from rine._mls.escrow_gap import EscrowLoss
from rine._mls.escrow_head import EscrowHead, write_head
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_queued import (
    MAX_DROPPED_EPOCHS,
    MAX_LOST_EPOCHS,
    MAX_QUEUED_EXPORTS,
    lost_epochs,
)
from rine._mls.escrow_snapshots import list_snapshots, park_snapshot
from tests._twin import core_source, ts_number
from tests.test_mls_escrow_drain import AGENT, GROUP
from tests.test_mls_escrow_sweep import NO_FORK_FP, _deferred_group
from tests.test_mls_escrow_sweep import _cold_state as _cold_state  # the autouse fixture
from tests.test_mls_escrow_sweep import actor as actor  # the fixture

if TYPE_CHECKING:
    from rine._mls.escrow_snapshots import BacklogSnapshot
    from rine._mls.heartbeat import MlsActor

EPOCH = 7


def _unreadable_snapshot(actor: MlsActor, queued: int = 3) -> BacklogSnapshot:
    """A parked snapshot at ``EPOCH`` whose bytes no longer open."""
    _deferred_group(actor)
    assert park_snapshot(actor.config_dir, AGENT, GROUP, EPOCH, queued)
    snapshot = list_snapshots(actor.config_dir, AGENT)[0]
    with open(snapshot.path, "wb") as handle:
        handle.write(b"not a group state")
    return snapshot


def _sidecar(snapshot: BacklogSnapshot) -> str:
    return f"{os.path.splitext(snapshot.path)[0]}.queued"


def test_park_snapshot_when_it_holds_queued_exports_then_the_count_is_recorded_beside_it(
    actor: MlsActor,
) -> None:
    """The sidecar names the snapshot's epoch and how many exports it was holding."""
    snapshot = _unreadable_snapshot(actor)

    with open(_sidecar(snapshot), encoding="utf-8") as handle:
        assert json.load(handle) == {"epoch": EPOCH, "queued": 3, "dropped": 0}
    assert snapshot.path.endswith(f"{EPOCH}.snapshot")


def test_give_up_snapshots_when_a_snapshot_is_unreadable_then_its_whole_queued_range_is_lost(
    actor: MlsActor,
) -> None:
    """The recorded range names every epoch the snapshot held, not just its own."""
    _unreadable_snapshot(actor, queued=3)

    result = give_up_snapshots(actor, EscrowLoss.UNREADABLE)

    assert [g.epoch for g in result.gaps] == [5, 6, 7]
    for epoch in (5, 6, 7):
        assert read_gap(actor.config_dir, AGENT, GROUP, epoch, NO_FORK_FP) is EscrowLoss.UNREADABLE
    assert read_gap(actor.config_dir, AGENT, GROUP, 4, NO_FORK_FP) is None


def test_give_up_snapshots_when_the_snapshot_is_deleted_then_its_sidecar_goes_with_it(
    actor: MlsActor,
) -> None:
    """Nothing is left behind, so the group's backlog dir is removed."""
    snapshot = _unreadable_snapshot(actor)

    give_up_snapshots(actor, EscrowLoss.UNREADABLE)

    assert not os.path.exists(_sidecar(snapshot))
    assert not os.path.exists(os.path.dirname(snapshot.path))


@pytest.mark.parametrize(
    ("head_epoch", "lost"),
    [(4, [5, 6, 7]), (None, [7]), (9, list(range(EPOCH + 1)))],
)
def test_give_up_snapshots_when_there_is_no_sidecar_then_the_range_starts_after_the_head(
    actor: MlsActor, head_epoch: int | None, lost: list[int]
) -> None:
    """Without a record, the epochs after the escrow head through the snapshot's own are lost."""
    snapshot = _unreadable_snapshot(actor)
    os.unlink(_sidecar(snapshot))
    if head_epoch is not None:
        write_head(actor.config_dir, AGENT, GROUP, EscrowHead(head_epoch, b"\x01" * 16))

    result = give_up_snapshots(actor, EscrowLoss.UNREADABLE)

    assert [g.epoch for g in result.gaps] == lost


@pytest.mark.parametrize("content", [b"{", b"[]", b'{"epoch": 7}', b'{"epoch": -1, "queued": 2}'])
def test_give_up_snapshots_when_the_sidecar_is_malformed_then_it_is_ignored(
    actor: MlsActor, content: bytes
) -> None:
    """An advisory record that cannot be trusted falls back to the snapshot's own epoch."""
    snapshot = _unreadable_snapshot(actor)
    with open(_sidecar(snapshot), "wb") as handle:
        handle.write(content)

    result = give_up_snapshots(actor, EscrowLoss.UNREADABLE)

    assert [g.epoch for g in result.gaps] == [EPOCH]


def test_give_up_snapshots_when_the_queue_overflowed_then_the_dropped_epochs_are_lost_too(
    actor: MlsActor,
) -> None:
    """The epochs a full queue pushed out sit just below the queued ones, and are named."""
    _deferred_group(actor)
    assert park_snapshot(actor.config_dir, AGENT, GROUP, EPOCH, 2, 3)
    snapshot = list_snapshots(actor.config_dir, AGENT)[0]
    with open(snapshot.path, "wb") as handle:
        handle.write(b"not a group state")

    result = give_up_snapshots(actor, EscrowLoss.UNREADABLE)

    assert [g.epoch for g in result.gaps] == [3, 4, 5, 6, 7]


def test_lost_epochs_when_the_sidecar_predates_dropped_then_it_still_names_the_queued_range(
    actor: MlsActor,
) -> None:
    """A record written before the dropped count existed reads as dropping none."""
    snapshot = _unreadable_snapshot(actor, queued=2)
    with open(_sidecar(snapshot), "w", encoding="utf-8") as handle:
        json.dump({"epoch": EPOCH, "queued": 2}, handle)

    assert lost_epochs(actor.config_dir, AGENT, GROUP, snapshot.path, EPOCH) == range(6, 8)


@pytest.mark.parametrize(
    "record",
    [
        {"epoch": 10**9, "queued": 10**9, "dropped": 0},
        {"epoch": EPOCH, "queued": 33, "dropped": 0},
        {"epoch": EPOCH, "queued": 1, "dropped": 1025},
        {"epoch": EPOCH + 1, "queued": 3, "dropped": 0},
    ],
)
def test_lost_epochs_when_the_sidecar_is_not_believable_then_it_is_ignored(
    actor: MlsActor, record: dict[str, int]
) -> None:
    """A sidecar for another epoch, or claiming more than the queue can hold, names nothing."""
    snapshot = _unreadable_snapshot(actor)
    with open(_sidecar(snapshot), "w", encoding="utf-8") as handle:
        json.dump(record, handle)

    assert lost_epochs(actor.config_dir, AGENT, GROUP, snapshot.path, EPOCH) == range(
        EPOCH, EPOCH + 1
    )


def test_lost_epochs_when_the_head_is_far_behind_then_the_range_is_capped(actor: MlsActor) -> None:
    """No snapshot can have held more than a full queue plus what it pushed out."""
    write_head(actor.config_dir, AGENT, GROUP, EscrowHead(0, b"\x01" * 16))

    lost = lost_epochs(actor.config_dir, AGENT, GROUP, "/nowhere/5000.snapshot", 5000)

    assert len(lost) == MAX_LOST_EPOCHS
    assert lost[-1] == 5000


def test_the_queue_caps_when_read_from_the_twin_then_both_stacks_agree() -> None:
    """Both stacks restate the native queue's two caps, so a test is what binds them.

    ``rine-core/src/mls-escrow-queued.ts`` reads the same sidecar and bounds the
    same range: a cap that moves on one side alone makes the two stacks name
    different lost epochs for one snapshot.
    """
    source = core_source("mls-escrow-queued.ts")

    assert ts_number(source, "MAX_QUEUED_EXPORTS") == MAX_QUEUED_EXPORTS
    assert ts_number(source, "MAX_DROPPED_EPOCHS") == MAX_DROPPED_EPOCHS
