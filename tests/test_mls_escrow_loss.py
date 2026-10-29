"""An escrow given up for good is recorded as lost before its file goes; anything else stays."""

from __future__ import annotations

import contextlib
import json
import os
from types import SimpleNamespace
from typing import Any

import pytest

from rine._mls.escrow_answer import EscrowCode
from rine._mls.escrow_backlog import give_up_snapshots, process_backlog
from rine._mls.escrow_drain import escrow_fp_for
from rine._mls.escrow_gap import EscrowLoss, give_up_pending
from rine._mls.escrow_head import EscrowHead, read_head, write_head
from rine._mls.escrow_keys import drop_escrow_keys, resolve_escrow_key
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_retry import MAX_ATTEMPTS, note_failure
from rine._mls.escrow_settle import settle_escrow
from rine._mls.escrow_snapshots import list_snapshots
from rine._mls.escrow_store import PendingEscrow, list_pending, pending_path
from rine._mls.escrow_sweep import reset_escrow_sweep_gate, sweep_pending_escrow
from rine._mls.heartbeat import MlsActor, reset_mls_heartbeat_gate
from rine.errors import EscrowGapError, RineApiError
from tests.test_mls_escrow_backlog import _keys
from tests.test_mls_escrow_drain import AGENT, GROUP
from tests.test_mls_escrow_sweep import (
    DAY,
    NO_FORK_FP,
    STRAY,
    STRAY_FP,
    _deferred_group,
    _stray,
    marked_fork_gap,
)
from tests.test_mls_escrow_sweep import actor as actor  # the fixture


@pytest.fixture(autouse=True)
def _cold_state() -> None:
    drop_escrow_keys()
    reset_mls_heartbeat_gate()
    reset_escrow_sweep_gate()


def _refused(status: int, code: EscrowCode) -> RineApiError:
    return RineApiError(status, code.value, json.dumps({"error": code.value}))


def _stray_file() -> PendingEscrow:
    return PendingEscrow(STRAY, 3, STRAY_FP, b"sealed-stray")


def _gap(actor: MlsActor, group: str, epoch: int, fp: bytes = NO_FORK_FP) -> Any:
    return read_gap(actor.config_dir, AGENT, group, epoch, fp)


def test_sweep_pending_escrow_when_the_server_refuses_for_good_then_the_report_counts_the_gap(
    actor: MlsActor,
) -> None:
    """The sweep's own record names the epoch and the reason, not only the marker file."""
    actor.client.put_error = _refused(403, EscrowCode.NO_SEAT)

    outcome = sweep_pending_escrow(actor)

    assert outcome is not None
    gaps = outcome.report().gaps
    assert [(g.epoch, g.reason) for g in gaps] == [(3, EscrowLoss.REFUSED)]


def test_sweep_pending_escrow_when_the_failure_is_transient_then_the_file_stays_unmarked(
    actor: MlsActor,
) -> None:
    """A 503 or a dropped connection says nothing about the file: no marker, no deletion."""
    for error in (RineApiError(503, "unavailable"), ConnectionError("network down")):
        actor.client.put_error = error
        reset_escrow_sweep_gate()

        sweep_pending_escrow(actor)

        assert len(_stray(actor)) == 1
        assert _gap(actor, STRAY, 3) is None


def test_sweep_pending_escrow_when_the_marker_cannot_be_written_then_the_file_stays(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file is the only record of the epoch until the marker is durable."""
    actor.client.put_error = _refused(409, EscrowCode.FORK_LIMIT)
    monkeypatch.setattr(
        "rine._mls.escrow_gap.create_exclusive",
        lambda *a, **k: (_ for _ in ()).throw(OSError("disk")),
    )

    outcome = sweep_pending_escrow(actor)

    assert outcome is not None
    assert outcome.report().gaps == ()
    assert any(isinstance(f, OSError) for f in outcome.upload.failures)
    assert len(_stray(actor)) == 1


def test_sweep_pending_escrow_when_a_crash_split_marker_from_delete_then_the_next_sweep_finishes(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A marker with its file still on disk is completed without another upload attempt."""
    pending = _stray_file()
    path = pending_path(actor.config_dir, AGENT, pending)
    for _ in range(MAX_ATTEMPTS):
        note_failure(path, "409 escrow_missing", now=0.0)
    with monkeypatch.context() as crash:
        crash.setattr(
            "rine._mls.escrow_gap.delete_pending",
            lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        with pytest.raises(KeyboardInterrupt):
            give_up_pending(actor.config_dir, AGENT, pending, EscrowLoss.REFUSED)
    assert _gap(actor, STRAY, 3, STRAY_FP) is EscrowLoss.REFUSED
    assert len(_stray(actor)) == 1

    sweep_pending_escrow(actor)

    assert _stray(actor) == []
    assert _gap(actor, STRAY, 3, STRAY_FP) is EscrowLoss.REFUSED
    assert not any("/mls/escrow/" in p for p, _ in actor.client.calls)


def test_sweep_pending_escrow_when_the_branch_is_revoked_then_all_work_is_given_up(
    actor: MlsActor,
) -> None:
    """A revoked branch ends all hope: each epoch is recorded as lost, then its file goes."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    parked = list_snapshots(actor.config_dir, AGENT)
    assert len(parked) == 1
    actor.client.escrow_error = RineApiError(410, "branch revoked")

    outcome = sweep_pending_escrow(actor)

    assert outcome is not None
    assert list_snapshots(actor.config_dir, AGENT) == []
    assert _stray(actor) == []
    assert not os.path.exists(parked[0].path)
    assert _gap(actor, STRAY, 3, STRAY_FP) is EscrowLoss.BRANCH_REVOKED
    assert marked_fork_gap(actor, GROUP, parked[0].epoch) is EscrowLoss.BRANCH_REVOKED
    reasons = {g.reason for g in outcome.report().gaps}
    assert reasons == {EscrowLoss.BRANCH_REVOKED}
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


def test_sweep_pending_escrow_when_the_key_read_fails_otherwise_then_nothing_is_given_up(
    actor: MlsActor,
) -> None:
    """Only a revoked branch is final: an outage keeps every file and snapshot."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    actor.client.escrow_error = RineApiError(503, "unavailable")

    outcome = sweep_pending_escrow(actor)

    assert outcome is None
    assert len(list_snapshots(actor.config_dir, AGENT)) == 1
    assert len(_stray(actor)) == 1
    assert _gap(actor, STRAY, 3) is None


def test_escrow_fp_for_when_the_head_epoch_was_given_up_then_the_send_names_the_loss(
    actor: MlsActor,
) -> None:
    """A refused epoch must not keep vouching for an escrow that is not there."""
    pending = PendingEscrow(GROUP, 3, b"\x07" * 16, b"sealed")
    write_head(actor.config_dir, AGENT, GROUP, EscrowHead(3, pending.fp))
    group = SimpleNamespace(epoch=lambda: 3, epoch_fingerprint=lambda: pending.fp)

    give_up_pending(actor.config_dir, AGENT, pending, EscrowLoss.REFUSED)

    with pytest.raises(EscrowGapError) as caught:
        escrow_fp_for(actor, GROUP, group)  # type: ignore[arg-type]
    assert caught.value.reason is EscrowLoss.REFUSED


def test_give_up_pending_when_the_head_names_another_fork_then_the_head_stays(
    actor: MlsActor,
) -> None:
    """Only the head that vouches for the given-up file is forgotten."""
    pending = PendingEscrow(GROUP, 3, b"\x07" * 16, b"sealed")
    live = EscrowHead(3, b"\x08" * 16)
    write_head(actor.config_dir, AGENT, GROUP, live)

    give_up_pending(actor.config_dir, AGENT, pending, EscrowLoss.REFUSED)

    assert read_head(actor.config_dir, AGENT, GROUP) == live


def test_give_up_snapshots_when_the_marker_cannot_be_written_then_the_snapshot_stays(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The snapshot is the only record of its epochs until the marker is durable."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    monkeypatch.setattr(
        "rine._mls.escrow_backlog.write_gap", lambda *a: (_ for _ in ()).throw(ValueError("bad"))
    )

    result = give_up_snapshots(actor, EscrowLoss.BRANCH_REVOKED)

    assert result.gaps == ()
    assert len(result.failures) == 1
    assert len(list_snapshots(actor.config_dir, AGENT)) == 1


def test_process_backlog_when_a_snapshot_is_already_exhausted_then_it_is_given_up_unprocessed(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Used-up attempts end the snapshot before it is reopened again."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    snapshot = list_snapshots(actor.config_dir, AGENT)[0]
    for _ in range(MAX_ATTEMPTS):
        note_failure(snapshot.path, "unreadable", now=0.0)
    monkeypatch.setattr(
        "rine._mls.escrow_backlog._process", lambda *a: (_ for _ in ()).throw(AssertionError)
    )

    result = process_backlog(actor, resolve_escrow_key(actor), _keys(actor), now=1.0)

    assert list_snapshots(actor.config_dir, AGENT) == []
    assert result.failures == ()
    assert marked_fork_gap(actor, GROUP, snapshot.epoch) is EscrowLoss.UNREADABLE


def test_give_up_snapshots_when_it_drops_exports_then_their_plaintext_is_zeroed(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exports nobody will seal must not linger in memory."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    plaintext = bytearray(b"secret-export")
    take = SimpleNamespace(
        gaps=[], exports=[SimpleNamespace(epoch=5, fp=b"\x01" * 16, plaintext=plaintext)]
    )
    group = SimpleNamespace(take_escrow_exports=lambda: take)

    @contextlib.contextmanager
    def reopened(*_args: Any) -> Any:
        yield group

    monkeypatch.setattr("rine._mls.escrow_backlog.reopened", reopened)

    result = give_up_snapshots(actor, EscrowLoss.BRANCH_REVOKED)

    assert [g.epoch for g in result.gaps] == [5]
    assert plaintext == bytearray(len(b"secret-export"))


def test_process_backlog_when_sealing_a_readable_snapshot_keeps_failing_then_it_is_never_given_up(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a state that cannot be opened uses up attempts: a seal-path bug keeps the bytes."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    snapshot = list_snapshots(actor.config_dir, AGENT)[0]
    monkeypatch.setattr(
        "rine._mls.escrow_backlog.take_and_seal", lambda *a: (_ for _ in ()).throw(RuntimeError)
    )
    key = resolve_escrow_key(actor)

    for step in range(MAX_ATTEMPTS + 2):
        result = process_backlog(actor, key, _keys(actor), now=step * 2 * DAY)
        assert len(result.failures) == 1

    assert [s.path for s in list_snapshots(actor.config_dir, AGENT)] == [snapshot.path]
    assert _gap(actor, GROUP, snapshot.epoch) is None


def test_sweep_pending_escrow_when_a_crash_follows_a_terminal_refusal_then_the_next_sweep_finishes(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal keeps no attempts record, so recovery re-uploads and meets the same answer."""
    actor.client.put_error = _refused(409, EscrowCode.FORK_LIMIT)
    with monkeypatch.context() as crash:
        crash.setattr(
            "rine._mls.escrow_gap.delete_pending",
            lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        with pytest.raises(KeyboardInterrupt):
            sweep_pending_escrow(actor)
    assert _gap(actor, STRAY, 3, STRAY_FP) is EscrowLoss.REFUSED
    assert len(_stray(actor)) == 1
    reset_escrow_sweep_gate()

    sweep_pending_escrow(actor)

    assert _stray(actor) == []
    assert _gap(actor, STRAY, 3, STRAY_FP) is EscrowLoss.REFUSED
