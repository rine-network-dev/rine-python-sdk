"""The parked-snapshot store: lossless settle, unique names, failure isolation, scratch."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest

from rine._crypto.keys import load_agent_keys
from rine._mls.escrow_backlog import process_backlog
from rine._mls.escrow_gap import _REASONS, EscrowLoss
from rine._mls.escrow_head import read_head
from rine._mls.escrow_keys import EscrowKeyError, drop_escrow_keys, resolve_escrow_key
from rine._mls.escrow_leaves import reclaim_once_for_gap, reset_gap_reclamation
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_retry import MAX_ATTEMPTS, read_attempts
from rine._mls.escrow_scratch import STALE_AFTER_S, clear_scratch
from rine._mls.escrow_settle import settle_escrow
from rine._mls.escrow_snapshots import (
    SCRATCH_PREFIX,
    SNAPSHOT_NAME_RE,
    backlog_root,
    list_snapshots,
    park_snapshot,
)
from rine._mls.escrow_store import list_pending
from rine._mls.escrow_sweep import reset_escrow_sweep_gate, sweep_pending_escrow
from rine._mls.heartbeat import MlsActor, reset_mls_heartbeat_gate
from tests.test_mls_escrow_drain import AGENT, GROUP
from tests.test_mls_escrow_sweep import DAY, NO_FORK_FP, STRAY, _cache_key, _deferred_group
from tests.test_mls_escrow_sweep import actor as actor  # the fixture

PYI = Path(__file__).parents[2] / "rine-mls" / "crates" / "rine-mls-py" / "rine_mls.pyi"


@pytest.fixture(autouse=True)
def _cold_state() -> None:
    drop_escrow_keys()
    reset_mls_heartbeat_gate()
    reset_escrow_sweep_gate()
    reset_gap_reclamation()


def _keys(actor: MlsActor) -> Any:
    return load_agent_keys(actor.config_dir, AGENT)


def test_settle_escrow_when_sealing_fails_after_the_take_then_the_report_keeps_the_held_exports(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The take drains the queue, so the counts are read before it or they report zero."""
    _deferred_group(actor)
    _cache_key(actor)
    monkeypatch.setattr(
        "rine._mls.escrow_take.seal_taken", lambda *a: (_ for _ in ()).throw(OSError("disk"))
    )

    report = settle_escrow(actor, GROUP)

    assert report.queued >= 1
    assert report.backlogged == 1
    assert len(list_snapshots(actor.config_dir, AGENT)) == 1


def test_park_snapshot_when_parked_twice_at_one_epoch_then_both_copies_survive(
    actor: MlsActor,
) -> None:
    """A second park at the same epoch never replaces the first one's bytes."""
    _deferred_group(actor)

    assert park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)
    assert park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)

    snapshots = list_snapshots(actor.config_dir, AGENT)
    assert len(snapshots) == 2
    assert all(SNAPSHOT_NAME_RE.fullmatch(os.path.basename(s.path)) for s in snapshots)
    assert len({s.path for s in snapshots}) == 2


def test_park_snapshot_when_no_state_is_stored_then_nothing_is_parked(actor: MlsActor) -> None:
    """With no stored state there is nothing to park."""
    assert not park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)
    assert list_snapshots(actor.config_dir, AGENT) == []


def test_list_snapshots_when_a_group_dir_is_a_link_then_it_is_neither_listed_nor_swept(
    actor: MlsActor, tmp_path: Path
) -> None:
    """A link to a directory is not a group dir, as in the pending store and the TS twin."""
    _deferred_group(actor)
    assert park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)
    group_dir = Path(backlog_root(actor.config_dir, AGENT)) / GROUP
    moved = tmp_path / "moved"
    group_dir.rename(moved)
    group_dir.symlink_to(moved, target_is_directory=True)
    scratch = moved / f"{SCRATCH_PREFIX}abc"
    scratch.mkdir()
    old = scratch.stat().st_mtime - STALE_AFTER_S - 1
    os.utime(scratch, (old, old))

    clear_scratch(actor.config_dir, AGENT)

    assert list_snapshots(actor.config_dir, AGENT) == []
    assert scratch.is_dir()


def test_clear_scratch_when_a_scratch_store_is_fresh_then_it_stays_and_when_stale_it_goes(
    actor: MlsActor,
) -> None:
    """A younger scratch store may belong to a live process: only the stale one is removed."""
    scratch = os.path.join(backlog_root(actor.config_dir, AGENT), f"{SCRATCH_PREFIX}abc")
    os.makedirs(scratch)

    clear_scratch(actor.config_dir, AGENT)
    assert os.path.isdir(scratch)

    old = os.stat(scratch).st_mtime - STALE_AFTER_S - 1
    os.utime(scratch, (old, old))
    clear_scratch(actor.config_dir, AGENT)
    assert not os.path.exists(scratch)


def test_settle_escrow_when_it_seals_locally_then_the_live_head_is_not_written(
    actor: MlsActor,
) -> None:
    """The head names the live epoch's fork; an old state's exports must not move it."""
    _deferred_group(actor)
    _cache_key(actor)

    settle_escrow(actor, GROUP)

    assert read_head(actor.config_dir, AGENT, GROUP) is None


def test_process_backlog_when_it_seals_a_parked_snapshot_then_the_live_head_is_not_written(
    actor: MlsActor,
) -> None:
    """Reopening an old state never moves the head either."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    key = resolve_escrow_key(actor)

    result = process_backlog(actor, key, _keys(actor))

    assert result.sealed >= 1
    assert read_head(actor.config_dir, AGENT, GROUP) is None


def test_process_backlog_when_one_snapshot_is_unreadable_then_the_rest_still_seal(
    actor: MlsActor,
) -> None:
    """A bad snapshot is recorded and counted; the next one is still processed."""
    _deferred_group(actor)
    park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)
    bad = list_snapshots(actor.config_dir, AGENT)[0]
    with open(bad.path, "wb") as f:
        f.write(b"not a group state")
    park_snapshot(actor.config_dir, AGENT, GROUP, 1, 1)
    key = resolve_escrow_key(actor)

    result = process_backlog(actor, key, _keys(actor), now=10.0)

    assert result.sealed >= 1
    assert len(result.failures) == 1
    record = read_attempts(bad.path)
    assert record is not None
    assert record.attempts == 1
    assert [s.path for s in list_snapshots(actor.config_dir, AGENT)] == [bad.path]


def test_process_backlog_when_a_snapshot_keeps_failing_then_it_is_given_up_after_sixteen_tries(
    actor: MlsActor,
) -> None:
    """The cap deletes an unreadable snapshot once its epoch is recorded as lost."""
    _deferred_group(actor)
    park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)
    bad = list_snapshots(actor.config_dir, AGENT)[0]
    with open(bad.path, "wb") as f:
        f.write(b"not a group state")
    key = resolve_escrow_key(actor)

    now = 0.0
    for _ in range(MAX_ATTEMPTS):
        assert len(list_snapshots(actor.config_dir, AGENT)) == 1
        process_backlog(actor, key, _keys(actor), now=now)
        now += 2 * DAY

    assert list_snapshots(actor.config_dir, AGENT) == []
    assert not os.path.exists(bad.path)
    assert read_gap(actor.config_dir, AGENT, GROUP, bad.epoch, NO_FORK_FP) is EscrowLoss.UNREADABLE


def test_sweep_pending_escrow_when_a_snapshot_is_unreadable_then_pending_files_still_upload(
    actor: MlsActor,
) -> None:
    """The backlog pass never stops the upload of what is already pending."""
    _deferred_group(actor)
    park_snapshot(actor.config_dir, AGENT, GROUP, 0, 1)
    with open(list_snapshots(actor.config_dir, AGENT)[0].path, "wb") as f:
        f.write(b"not a group state")

    outcome = sweep_pending_escrow(actor, now=5.0)

    assert outcome is not None
    assert len(outcome.backlog.failures) == 1
    assert outcome.upload.uploaded == 1
    assert list_pending(actor.config_dir, AGENT) == []


def test_reclaim_once_for_gap_when_the_epoch_differs_then_the_gate_opens_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One attempt per gap epoch, so a later epoch's gap is not starved by an earlier try."""
    runs: list[int] = []
    monkeypatch.setattr("rine._mls.escrow_leaves.reclaim_orphan_leaves", lambda *a: runs.append(1))

    assert reclaim_once_for_gap(object(), "/c", AGENT, GROUP, 4)
    assert not reclaim_once_for_gap(object(), "/c", AGENT, GROUP, 4)
    assert reclaim_once_for_gap(object(), "/c", AGENT, GROUP, 5)
    assert reclaim_once_for_gap(object(), "/c", STRAY, GROUP, 4)
    assert len(runs) == 3


def test_resolve_escrow_key_when_the_keys_answer_is_malformed_then_it_is_an_escrow_key_error(
    actor: MlsActor,
) -> None:
    """A body without the branch or the certificate is a typed refusal, not a KeyError."""
    real_get = actor.client.get

    def get(path: str, **kwargs: Any) -> dict[str, Any]:
        if path.endswith("/keys"):
            return {}
        return real_get(path, **kwargs)

    actor.client.get = get
    with pytest.raises(EscrowKeyError):
        resolve_escrow_key(actor)


def test_escrow_gap_reasons_when_compared_with_the_binding_stub_then_every_member_is_known() -> (
    None
):
    """A variant added to the native enum is picked up here, or read_gap would drop it."""
    stub = PYI.read_text()
    body = stub.split("class EscrowGapReason:", 1)[1].split("\nclass ", 1)[0]
    declared = set(re.findall(r"^    ([A-Z_]+): EscrowGapReason$", body, re.MULTILINE))

    assert declared
    assert {name.upper() for name in _REASONS} == declared | {loss.name for loss in EscrowLoss}
