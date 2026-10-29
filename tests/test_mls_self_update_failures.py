"""What a self-update reports when its commit cannot be built: deferred, or final.

The real ``rine-mls`` core runs; only the server is a stub. Only a failure no retry can
change is final: a commit another process still holds pending, or a build that died on the
network, stays deferred so the rotation marker waits and the sweep tries again.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.binding import CommitPendingError, MlsCoreError, SignerLeafMismatchError
from rine._mls.group_access import open_mls_group
from rine._mls.self_update import self_update_group
from rine._seat_update import SeatDeferReason, SeatFailReason, SeatUpdateStatus
from rine.errors import APIConnectionError
from tests.hold_world import rotated
from tests.rotation_world import G1, A

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def _refuse_with(monkeypatch: pytest.MonkeyPatch, err: Exception) -> None:
    def refuse(*_a: Any, **_k: Any) -> None:
        raise err

    monkeypatch.setattr("rine._mls.self_update.admit_refused_peers", refuse)


def test_self_update_when_the_core_cannot_sign_for_the_seat_then_it_is_seat_unhealable(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A seat whose signer differs from its leaf can only be removed and re-invited."""
    _server, _d1, _dr, actor = rotated(tmp_path)

    _refuse_with(monkeypatch, SignerLeafMismatchError("signer differs"))
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.FAILED
    assert seat.reason is SeatFailReason.SEAT_UNHEALABLE
    assert seat.detail == "signer differs"


def test_self_update_when_the_core_refuses_the_commit_then_it_is_failed_refused(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any other refusal of the core is reported with its text."""
    _server, _d1, _dr, actor = rotated(tmp_path)

    _refuse_with(monkeypatch, MlsCoreError("no"))
    seat = self_update_group(actor, G1)
    assert seat.reason is SeatFailReason.REFUSED
    assert seat.detail == "no"


def test_self_update_when_another_process_holds_a_pending_commit_then_it_awaits_the_ack(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A commit already pending is a wait, never a final refusal."""
    _server, d1, _dr, actor = rotated(tmp_path)
    _refuse_with(monkeypatch, CommitPendingError("a commit is pending"))
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.DEFERRED
    assert seat.reason is SeatDeferReason.AWAITING_ACK
    assert seat.epoch == open_mls_group(d1, A, G1).epoch() + 1


def test_self_update_when_the_build_dies_on_the_network_then_it_is_deferred_unreachable(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Admitting a peer reads it, and a read that failed may succeed on the next beat."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    _refuse_with(monkeypatch, APIConnectionError("no route"))
    seat = self_update_group(actor, G1)
    assert seat.status is SeatUpdateStatus.DEFERRED
    assert seat.reason is SeatDeferReason.UNREACHABLE
    assert seat.detail == "no route"
