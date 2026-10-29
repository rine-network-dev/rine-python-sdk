"""A gap and a parked snapshot name the fork they are lost for, so a fork's loss stays its own."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from rine._mls.binding import EscrowGapReason, open_mls_client
from rine._mls.escrow_backlog import give_up_snapshots
from rine._mls.escrow_drain import escrow_fp_for
from rine._mls.escrow_gap import EscrowLoss
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_queued import recorded_forks, write_queued
from rine._mls.escrow_settle import settle_escrow
from rine._mls.escrow_snapshots import list_snapshots
from rine._mls.escrow_store import pending_dir
from rine._mls.escrow_take import take_and_seal
from rine._mls.group_access import load_mls_group
from rine.errors import CryptoError, EscrowGapError
from tests.test_mls_escrow_drain import AGENT, GROUP
from tests.test_mls_escrow_sweep import NO_FORK_FP, _deferred_group
from tests.test_mls_escrow_sweep import _cold_state as _cold_state  # the autouse fixture
from tests.test_mls_escrow_sweep import actor as actor  # the fixture

if TYPE_CHECKING:
    from pathlib import Path

    from rine._mls.escrow_snapshots import BacklogSnapshot
    from rine._mls.heartbeat import MlsActor

FORK_A = b"\x0a" * 16
FORK_B = b"\x0b" * 16


def _parked_fork(actor: MlsActor) -> tuple[BacklogSnapshot, dict[int, bytes]]:
    """Park a deferred group with no escrow key; the snapshot and the fork of each epoch."""
    _deferred_group(actor)
    group = load_mls_group(open_mls_client(actor.config_dir, AGENT), GROUP)
    assert group is not None
    forks = dict(group.queued_escrow_fingerprints())
    forks[group.epoch()] = group.epoch_fingerprint()
    settle_escrow(actor, GROUP)
    (snapshot,) = list_snapshots(actor.config_dir, AGENT)
    return snapshot, forks


def _sidecar(snapshot: BacklogSnapshot) -> str:
    return f"{os.path.splitext(snapshot.path)[0]}.queued"


def _corrupt(snapshot: BacklogSnapshot) -> None:
    with open(snapshot.path, "wb") as handle:
        handle.write(b"not a group state")


def _markers(actor: MlsActor, group_id: str) -> list[str]:
    directory = pending_dir(actor.config_dir, AGENT, group_id)
    return sorted(n for n in os.listdir(directory) if n.endswith(".gap"))


def test_settle_escrow_when_it_parks_a_state_then_the_sidecar_names_each_epochs_fork(
    actor: MlsActor,
) -> None:
    """The sidecar records the fork of each queued epoch and of the snapshot epoch."""
    snapshot, forks = _parked_fork(actor)

    with open(_sidecar(snapshot), encoding="utf-8") as handle:
        assert json.load(handle)["fps"] == {str(e): fp.hex() for e, fp in forks.items()}


def test_give_up_snapshots_when_a_parked_state_is_unreadable_then_each_epoch_names_its_fork(
    actor: MlsActor,
) -> None:
    """Every epoch the parked state held is lost for the fork it held, not for no fork."""
    snapshot, forks = _parked_fork(actor)
    _corrupt(snapshot)

    give_up_snapshots(actor, EscrowLoss.UNREADABLE)

    assert _markers(actor, GROUP) == sorted(f"{e}-{fp.hex()}.gap" for e, fp in forks.items())
    for epoch in forks:
        assert read_gap(actor.config_dir, AGENT, GROUP, epoch, NO_FORK_FP) is None


def test_escrow_fp_for_when_another_fork_was_lost_at_the_epoch_then_the_live_fork_still_sends(
    actor: MlsActor,
) -> None:
    """Fork A is set aside and unreadable; the agent moves to fork B at the same epoch."""
    snapshot, forks = _parked_fork(actor)
    epoch = max(forks)
    _corrupt(snapshot)
    give_up_snapshots(actor, EscrowLoss.UNREADABLE)
    live: Any = SimpleNamespace(epoch=lambda: epoch, epoch_fingerprint=lambda: FORK_B)

    with pytest.raises(CryptoError) as caught:
        escrow_fp_for(actor, GROUP, live)
    assert not isinstance(caught.value, EscrowGapError)


def test_escrow_fp_for_when_the_lost_fork_is_the_live_one_then_the_send_names_the_loss(
    actor: MlsActor,
) -> None:
    """The loss of the live fork itself still blocks a send and names its reason."""
    snapshot, forks = _parked_fork(actor)
    epoch = max(forks)
    _corrupt(snapshot)
    give_up_snapshots(actor, EscrowLoss.UNREADABLE)
    live: Any = SimpleNamespace(epoch=lambda: epoch, epoch_fingerprint=lambda: forks[epoch])

    with pytest.raises(EscrowGapError) as caught:
        escrow_fp_for(actor, GROUP, live)
    assert caught.value.reason is EscrowLoss.UNREADABLE


def test_take_and_seal_when_the_core_names_the_fork_of_a_gap_then_the_marker_is_filed_under_it(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A drain gap with a known fork is filed under it; one with none is filed for no fork."""
    gap = SimpleNamespace(epoch=4, reason=EscrowGapReason.TOO_MANY_LEAVES, fp=FORK_A)
    queue_overflow = SimpleNamespace(epoch=2, reason=EscrowGapReason.QUEUE_OVERFLOW, fp=None)
    group: Any = SimpleNamespace(
        take_escrow_exports=lambda: SimpleNamespace(exports=[], gaps=[gap, queue_overflow])
    )

    monkeypatch.setattr("rine._mls.escrow_take.seal_taken", lambda *_args: 0)

    taken = take_and_seal(actor, GROUP, None, None, group)  # type: ignore[arg-type]

    assert _markers(actor, GROUP) == ["2.gap", f"4-{FORK_A.hex()}.gap"]
    assert [g.fp for g in taken.gaps] == [FORK_A, None]


def test_recorded_forks_when_the_sidecar_has_unbelievable_entries_then_only_the_good_ones_stay(
    tmp_path: Path,
) -> None:
    """An entry with a bad epoch, bad fingerprint or an epoch past the snapshot is ignored."""
    snapshot = str(tmp_path / "9.snapshot")
    write_queued(snapshot, 9, 2, 0, {8: FORK_A, 9: FORK_B})
    with open(str(tmp_path / "9.queued"), "w", encoding="utf-8") as handle:
        json.dump(
            {
                "epoch": 9,
                "queued": 2,
                "dropped": 0,
                "fps": {
                    "8": FORK_A.hex(),
                    "10": FORK_B.hex(),
                    "x": FORK_B.hex(),
                    "7": "zz",
                    "6": 12,
                },
            },
            handle,
        )

    assert recorded_forks(snapshot, 9) == {8: FORK_A}


def test_recorded_forks_when_the_sidecar_predates_forks_then_none_are_named(
    tmp_path: Path,
) -> None:
    """A sidecar without forks reads as naming none, and is written without the key."""
    snapshot = str(tmp_path / "9.snapshot")
    write_queued(snapshot, 9, 2, 1)

    assert recorded_forks(snapshot, 9) == {}
    with open(str(tmp_path / "9.queued"), encoding="utf-8") as handle:
        assert "fps" not in json.load(handle)
