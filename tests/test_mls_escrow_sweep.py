"""Pending escrow outlives group state: the local settle and the gated group-less sweep."""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

import pytest

from rine import RineClient, SyncRineClient
from rine._mls.escrow_answer import EscrowCode
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_gap import EscrowLoss
from rine._mls.escrow_keys import cached_escrow_key, drop_escrow_keys, resolve_escrow_key
from rine._mls.escrow_markers import group_markers, read_gap
from rine._mls.escrow_report import EscrowDeferral, EscrowReport
from rine._mls.escrow_retry import MAX_ATTEMPTS, read_attempts
from rine._mls.escrow_settle import settle_escrow
from rine._mls.escrow_snapshots import list_snapshots
from rine._mls.escrow_store import (
    PendingEscrow,
    delete_pending,
    list_pending,
    pending_dir,
    pending_path,
    write_pending,
)
from rine._mls.escrow_sweep import (
    has_escrow_work,
    reset_escrow_sweep_gate,
    startup_escrow_sweep,
    sweep_pending_escrow,
)
from rine._mls.heartbeat import MlsActor, mls_heartbeat, reset_mls_heartbeat_gate
from rine.errors import RineApiError
from rine.testing import WORLD, write_agent_identity
from tests.test_mls_escrow_drain import AGENT, GROUP, FakeClient, _fresh_group

#: A fork fingerprint no marker is filed under, so a read sees only fork-less markers.
NO_FORK_FP = bytes(16)

STRAY = "99999999-8888-7777-6666-555555555555"
STRAY_FP = b"\x05" * 16
DAY = 24 * 60 * 60.0


@pytest.fixture(autouse=True)
def _cold_state() -> None:
    drop_escrow_keys()
    reset_mls_heartbeat_gate()
    reset_escrow_sweep_gate()


@pytest.fixture
def actor(tmp_path: Any) -> MlsActor:
    """An actor whose leaf keys are on disk, with one file pending for a group it does not hold."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    client = FakeClient()
    client.key_pins.pin_own_agent(AGENT, WORLD.org_id)
    write_pending(config_dir, AGENT, PendingEscrow(STRAY, 3, STRAY_FP, b"sealed-stray"))
    return MlsActor(client=client, config_dir=config_dir, agent_id=AGENT)


def _uploaded_groups(actor: MlsActor) -> list[str]:
    """The group of every escrow PUT the client has seen, in order."""
    return [path.split("/")[2] for path, _ in actor.client.calls if "/mls/escrow/" in path]


def _stray(actor: MlsActor) -> list[PendingEscrow]:
    return list_pending(actor.config_dir, AGENT, STRAY)


def _refusal(status: int, code: str | None = None) -> RineApiError:
    return RineApiError(status, code or "refused", json.dumps({"error": code} if code else {}))


def test_drain_escrow_when_another_group_has_a_pending_file_then_it_is_not_swept(
    actor: MlsActor,
) -> None:
    """The cross-group sweep never runs inside a drain: it has its own gate."""
    outcome = drain_escrow(actor, GROUP, _fresh_group(actor))

    assert outcome.failures == ()
    assert STRAY not in _uploaded_groups(actor)
    assert len(_stray(actor)) == 1


def test_sweep_pending_escrow_when_the_slot_is_taken_then_the_file_is_retired(
    actor: MlsActor,
) -> None:
    """The existing answer classes retire a swept file: stored deletes it."""
    actor.client.put_error = _refusal(409, EscrowCode.SLOT_TAKEN)

    sweep_pending_escrow(actor)

    assert _stray(actor) == []


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (409, EscrowCode.FORK_LIMIT),
        (403, EscrowCode.NO_SEAT),
        (404, EscrowCode.GROUP_NOT_FOUND),
        (422, EscrowCode.BRANCH_REVOKED),
        (422, EscrowCode.AGENT_REVOKED),
    ],
)
def test_sweep_pending_escrow_when_the_server_refuses_for_good_then_the_file_is_given_up(
    actor: MlsActor, status: int, code: EscrowCode
) -> None:
    """A terminal code deletes the file once its epoch is recorded as lost, not retried."""
    actor.client.put_error = _refusal(status, code)

    sweep_pending_escrow(actor)
    reset_escrow_sweep_gate()
    sweep_pending_escrow(actor)

    assert _stray(actor) == []
    assert _uploaded_groups(actor) == [STRAY]
    lost = {
        EscrowCode.BRANCH_REVOKED: EscrowLoss.BRANCH_REVOKED,
        EscrowCode.AGENT_REVOKED: EscrowLoss.AGENT_REVOKED,
    }.get(code, EscrowLoss.REFUSED)
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, STRAY_FP) is lost


def test_sweep_pending_escrow_when_the_branch_is_revoked_then_the_cached_key_is_dropped(
    actor: MlsActor,
) -> None:
    """A branch_revoked answer ends trust in the cached key, so the next resolve refetches."""
    actor.client.put_error = _refusal(422, EscrowCode.BRANCH_REVOKED)

    sweep_pending_escrow(actor)

    assert cached_escrow_key(actor) is None


@pytest.mark.parametrize("status", [403, 404])
def test_sweep_pending_escrow_when_the_refusal_has_no_code_then_it_is_retried_on_a_schedule(
    actor: MlsActor, status: int
) -> None:
    """A bare 403 or 404 might be a proxy: the file waits out a growing delay, then retries."""
    actor.client.put_error = _refusal(status)

    sweep_pending_escrow(actor, now=1000.0)
    reset_escrow_sweep_gate()
    sweep_pending_escrow(actor, now=1001.0)

    assert len(_stray(actor)) == 1
    assert _uploaded_groups(actor) == [STRAY]
    pending = _stray(actor)[0]
    record = read_attempts(pending_path(actor.config_dir, AGENT, pending))
    assert record is not None
    assert (record.attempts, record.last) == (1, str(status))

    reset_escrow_sweep_gate()
    sweep_pending_escrow(actor, now=1000.0 + DAY)

    assert _uploaded_groups(actor) == [STRAY, STRAY]
    second = read_attempts(pending_path(actor.config_dir, AGENT, pending))
    assert second is not None
    assert second.attempts == 2


def test_sweep_pending_escrow_when_a_file_keeps_failing_then_it_parks_after_sixteen_attempts(
    actor: MlsActor,
) -> None:
    """The cap is a count of retryable refusals, not a clock."""
    actor.client.put_error = _refusal(403)
    now = 0.0

    for _ in range(MAX_ATTEMPTS):
        assert len(_stray(actor)) == 1
        reset_escrow_sweep_gate()
        sweep_pending_escrow(actor, now=now)
        now += 2 * DAY

    assert _stray(actor) == []
    assert len(_uploaded_groups(actor)) == MAX_ATTEMPTS


@pytest.mark.parametrize("status", [429, 500, 503])
def test_sweep_pending_escrow_when_the_server_is_overloaded_then_the_pass_stops(
    actor: MlsActor, status: int
) -> None:
    """A 429 or a 5xx says nothing about the file: the pass stops and no attempt is counted."""
    write_pending(actor.config_dir, AGENT, PendingEscrow(STRAY, 4, b"\x06" * 16, b"sealed-next"))
    actor.client.put_error = _refusal(status)

    sweep_pending_escrow(actor)

    assert len(_uploaded_groups(actor)) == 1
    assert len(_stray(actor)) == 2
    assert read_attempts(pending_path(actor.config_dir, AGENT, _stray(actor)[0])) is None


def test_sweep_pending_escrow_when_the_network_fails_then_the_file_stays(
    actor: MlsActor,
) -> None:
    """A network failure leaves a file for the next sweep and counts no attempt."""
    actor.client.put_error = ConnectionError("down")

    sweep_pending_escrow(actor)

    assert len(_stray(actor)) == 1
    assert read_attempts(pending_path(actor.config_dir, AGENT, _stray(actor)[0])) is None


def test_sweep_pending_escrow_when_the_key_cannot_be_verified_then_nothing_is_lost(
    actor: MlsActor,
) -> None:
    """A best-effort sweep never raises and leaves every file where it is."""
    actor.client.escrow_error = RineApiError(503, "unavailable")

    sweep_pending_escrow(actor)

    assert len(_stray(actor)) == 1


def test_sweep_pending_escrow_when_nothing_is_pending_then_it_makes_no_call(
    actor: MlsActor,
) -> None:
    """Nothing pending: the sweep costs no request, so every heartbeat can run it."""
    sweep_pending_escrow(actor)
    reset_escrow_sweep_gate()
    actor.client.calls.clear()

    sweep_pending_escrow(actor)

    assert actor.client.calls == []


def test_sweep_pending_escrow_when_called_twice_within_the_interval_then_it_runs_once(
    actor: MlsActor,
) -> None:
    """The sweep is gated per heartbeat interval, not per call."""
    actor.client.put_error = ConnectionError("down")

    assert sweep_pending_escrow(actor) is not None
    assert sweep_pending_escrow(actor) is None

    assert len(_uploaded_groups(actor)) == 1


def test_startup_escrow_sweep_when_files_are_waiting_then_it_uploads_them(
    actor: MlsActor,
) -> None:
    """A previous process left a file; starting a client clears it without any MLS operation."""
    startup_escrow_sweep(actor.client, actor.config_dir)

    assert _stray(actor) == []
    assert _uploaded_groups(actor) == [STRAY]


def test_startup_escrow_sweep_when_a_backlog_snapshot_is_waiting_then_it_seals_and_uploads_it(
    actor: MlsActor,
) -> None:
    """A parked snapshot alone is escrow work: start-up reopens and clears it."""
    write_pending_free = list_pending(actor.config_dir, AGENT, STRAY)[0]
    delete_pending(actor.config_dir, AGENT, write_pending_free)
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    assert len(list_snapshots(actor.config_dir, AGENT)) == 1

    startup_escrow_sweep(actor.client, actor.config_dir)

    assert list_snapshots(actor.config_dir, AGENT) == []
    assert GROUP in _uploaded_groups(actor)
    assert list_pending(actor.config_dir, AGENT) == []


def test_startup_escrow_sweep_when_there_is_no_work_then_it_makes_no_call(
    actor: MlsActor,
) -> None:
    """A client with nothing queued starts without a request."""
    delete_pending(actor.config_dir, AGENT, _stray(actor)[0])

    startup_escrow_sweep(actor.client, actor.config_dir)

    assert actor.client.calls == []


def test_has_escrow_work_when_the_only_file_sits_behind_a_link_or_a_misnamed_dir_then_no_work(
    actor: MlsActor, tmp_path: Any
) -> None:
    """A group dir the sweep never reads must not make the heartbeat report work."""
    file_name = os.path.basename(pending_path(actor.config_dir, AGENT, _stray(actor)[0]))
    group_dir = pending_dir(actor.config_dir, AGENT, STRAY)
    shutil.rmtree(group_dir)
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / file_name).write_bytes(b"sealed")
    os.symlink(real, group_dir)
    misnamed = os.path.join(os.path.dirname(group_dir), "not-a-group")
    os.makedirs(misnamed)
    with open(os.path.join(misnamed, file_name), "wb") as handle:
        handle.write(b"sealed")

    assert has_escrow_work(actor.config_dir, AGENT) is False


def test_mls_heartbeat_when_it_beats_then_it_sweeps_the_pending_files(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first beat of a process is the startup sweep."""
    monkeypatch.setattr("rine._mls.heartbeat.ensure_mls_key_packages", lambda *a: None)

    mls_heartbeat(actor, "gated")

    assert _stray(actor) == []


def test_mls_heartbeat_when_the_sweep_fails_then_it_does_not_raise(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The beat runs behind work that already succeeded, so a sweep fault is swallowed."""
    monkeypatch.setattr("rine._mls.heartbeat.ensure_mls_key_packages", lambda *a: None)
    monkeypatch.setattr(
        "rine._mls.heartbeat.sweep_pending_escrow", lambda a: (_ for _ in ()).throw(OSError("x"))
    )

    mls_heartbeat(actor, "forced")


def marked_fork_gap(actor: MlsActor, group: str, epoch: int) -> EscrowLoss | None:
    """The reason recorded for the fork a marker at ``epoch`` is named for."""
    markers = group_markers(pending_dir(actor.config_dir, AGENT, group))
    fork = next(m.fork for m in markers if m.epoch == epoch)
    return read_gap(
        actor.config_dir, AGENT, group, epoch, NO_FORK_FP if fork is None else bytes.fromhex(fork)
    )


def _deferred_group(actor: MlsActor) -> None:
    """Leave stored state whose epoch exports were never taken: a deferred drain."""
    actor.client.escrow_error = RineApiError(503, "unavailable")
    assert drain_escrow(actor, GROUP, _fresh_group(actor)).deferred is not None
    actor.client.escrow_error = None
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


def _cache_key(actor: MlsActor) -> None:
    """Warm the verified escrow-key cache, then forget the calls that did it."""
    resolve_escrow_key(actor)
    actor.client.calls.clear()


def test_settle_escrow_when_the_key_is_cached_then_it_seals_locally(
    actor: MlsActor,
) -> None:
    """The old exports become pending files with no request, and nothing is parked."""
    _deferred_group(actor)
    _cache_key(actor)

    report = settle_escrow(actor, GROUP)

    assert actor.client.calls == []
    assert report.deferral is None
    assert len(list_pending(actor.config_dir, AGENT, GROUP)) >= 1
    assert list_snapshots(actor.config_dir, AGENT) == []


def test_settle_escrow_when_the_key_is_not_cached_then_it_parks_the_snapshot(
    actor: MlsActor,
) -> None:
    """Without the key the old state moves to the backlog; nothing waits on the network."""
    _deferred_group(actor)
    actor.client.calls.clear()

    report = settle_escrow(actor, GROUP)

    assert actor.client.calls == []
    assert report.deferral == EscrowDeferral.KEY_UNAVAILABLE
    assert report.backlogged == 1
    assert report.queued >= 1
    assert list_pending(actor.config_dir, AGENT, GROUP) == []
    assert [s.group_id for s in list_snapshots(actor.config_dir, AGENT)] == [GROUP]


def test_sweep_pending_escrow_when_a_snapshot_is_parked_then_it_seals_uploads_and_deletes_it(
    actor: MlsActor,
) -> None:
    """The sweep reopens the parked state, so a leave loses no read access."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    actor.client.calls.clear()

    sweep_pending_escrow(actor)

    assert GROUP in _uploaded_groups(actor)
    assert list_snapshots(actor.config_dir, AGENT) == []
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


def test_settle_escrow_when_no_state_is_stored_then_it_does_nothing(
    actor: MlsActor,
) -> None:
    """No stored state is nothing to settle, and not an error."""
    report = settle_escrow(actor, GROUP)

    assert report == EscrowReport()
    assert actor.client.calls == []
    assert len(_stray(actor)) == 1


def test_settle_escrow_when_sealing_fails_then_it_parks_instead(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sealing fault must not block the caller's replacement nor lose the exports."""
    _deferred_group(actor)
    _cache_key(actor)
    monkeypatch.setattr(
        "rine._mls.escrow_settle.take_and_seal", lambda *a: (_ for _ in ()).throw(OSError("disk"))
    )

    report = settle_escrow(actor, GROUP)

    assert report.backlogged == 1
    assert len(list_snapshots(actor.config_dir, AGENT)) == 1


def test_sync_client_when_it_starts_then_it_sweeps_the_files_a_previous_process_left(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Start-up clears pending files and backlog snapshots without any MLS operation."""
    swept: list[str] = []
    monkeypatch.setattr(
        "rine._sync_client.startup_escrow_sweep",
        lambda _http, config_dir, _only: swept.append(config_dir),
    )

    client = SyncRineClient(config_dir=actor.config_dir, api_url="https://rine.network")
    client.close()

    assert swept == [actor.config_dir]


@pytest.mark.parametrize("pending", [True, False])
async def test_async_client_when_it_starts_then_it_sweeps_only_when_there_is_work(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch, pending: bool
) -> None:
    """No pending file or snapshot: entering the client costs no worker thread."""
    if not pending:
        delete_pending(actor.config_dir, AGENT, _stray(actor)[0])
    hops: list[str] = []

    async def _hop(_client: object, _fn: object) -> None:
        hops.append("sweep")

    monkeypatch.setattr("rine._client.with_sync_http", _hop)

    async with RineClient(config_dir=actor.config_dir, api_url="https://rine.network"):
        pass

    assert hops == (["sweep"] if pending else [])
