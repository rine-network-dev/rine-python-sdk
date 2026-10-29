"""The settlement hold: a commit's own beat never settles, and the hold is thread-safe."""

from __future__ import annotations

import sys
import threading
import time
from typing import TYPE_CHECKING, Any

import pytest

from rine._mls.api import MlsCommit
from rine._mls.commit import post_mls_commit_bundle
from rine._mls.commit_wire import MlsCommitAccepted
from rine._mls.heartbeat import reset_mls_heartbeat_gate
from rine._mls.seat_sweep import KeyPackageRotation, RotationSettlement, settle_rotation
from tests.hold_world import rotated
from tests.rotation_world import G1

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _fresh_gate() -> None:
    reset_mls_heartbeat_gate()


@pytest.fixture
def _fast_thread_switching() -> Iterator[None]:
    """Make the interpreter switch threads as often as it can, to widen any race window."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(previous)


def test_post_mls_commit_bundle_when_the_beat_runs_then_no_settlement_starts(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The caller has not applied its own commit yet, so a settlement would read it as a peer's."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    started: list[str] = []

    def settle(_actor: Any, *, background: bool) -> RotationSettlement:
        started.append("settle")
        return RotationSettlement(KeyPackageRotation.REPUBLISHED)

    monkeypatch.setattr(
        "rine._mls.commit.mls_commit", lambda *_a: MlsCommitAccepted(epoch=2, confirmed=True)
    )
    monkeypatch.setattr("rine._mls.seat_sweep._settle", settle)
    monkeypatch.setattr("rine._mls.heartbeat.ensure_mls_key_packages", lambda *_a: None)
    monkeypatch.setattr("rine._mls.heartbeat.sweep_pending_escrow", lambda _actor: None)
    bundle = MlsCommit(commit=b"", group_info=b"", epoch=1, cipher_suite=1)
    assert post_mls_commit_bundle(actor, G1, bundle, {}).epoch == 2
    assert started == []
    settle_rotation(actor)
    assert started == ["settle"]


@pytest.mark.usefixtures("_fast_thread_switching")
def test_settle_rotation_when_threads_race_then_exactly_one_settlement_runs(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The async client settles from worker threads, so check-then-hold must be atomic."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    threads = 16
    started = threading.Barrier(threads)
    ran: list[int] = []

    def settle(_actor: Any, *, background: bool) -> RotationSettlement:
        ran.append(1)
        time.sleep(0.2)
        return RotationSettlement(KeyPackageRotation.REPUBLISHED)

    def attempt() -> None:
        started.wait(timeout=5)
        results.append(settle_rotation(actor))

    results: list[RotationSettlement] = []
    monkeypatch.setattr("rine._mls.seat_sweep._settle", settle)
    workers = [threading.Thread(target=attempt) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=10)
    assert len(ran) == 1
    assert [r.key_packages for r in results].count(KeyPackageRotation.NOT_HELD) == threads - 1
