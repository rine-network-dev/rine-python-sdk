"""Settling a rotation: republish the KeyPackages, move every seat, remember how far.

The real ``rine-mls`` core runs; only the server is a stub. ``A`` rotates to
generation 1 on device ``d1`` and sits in one group (``G1``) that device holds
state for, and in another (``G2``) it holds none for.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._agent_rotate_seats import rotate_agent_with_seats
from rine._crypto.keys import save_agent_keys
from rine._mls.rotation_marker import RotationMarker, read_rotation_marker, write_rotation_marker
from rine._mls.seat_sweep import KeyPackageRotation, settle_rotation
from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdate,
    SeatUpdateStatus,
    deferred,
    failed,
)
from rine.errors import RineApiError
from rine.testing import WORLD
from rine.types import AgentRead
from tests.hold_world import leaf_key, new_key, rotated
from tests.rotation_world import G1, A

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")

_AGENT = {
    "id": A,
    "name": "rotated",
    "handle": "rotated@acme.rine.network",
    "human_oversight": True,
    "incoming_policy": "accept_all",
    "outgoing_policy": "send_all",
    "created_at": "2024-01-01T00:00:00Z",
}


def test_settle_rotation_when_the_host_holds_the_state_then_it_republishes_and_moves_the_seat(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A full settlement reports both halves and remembers the generation."""
    server, d1, _dr, actor = rotated(tmp_path)
    settled = settle_rotation(actor)
    assert settled.key_packages is KeyPackageRotation.REPUBLISHED
    assert [(s.group_id, s.status) for s in settled.group_seats] == [
        (G1, SeatUpdateStatus.UPDATED)
    ]
    assert read_rotation_marker(d1, A) == RotationMarker(key_packages=1, seats=1)
    assert server.uploads == [A]
    assert leaf_key(d1, A, G1, A) == new_key()


def test_settle_rotation_when_the_marker_is_current_then_it_does_nothing(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A settled generation costs no sweep and no republish."""
    server, d1, _dr, actor = rotated(tmp_path)
    write_rotation_marker(d1, A, RotationMarker(key_packages=1, seats=1))
    settled = settle_rotation(actor)
    assert settled.key_packages is KeyPackageRotation.CURRENT
    assert settled.group_seats == []
    assert server.uploads == []
    assert server.commit_posts == 0
    assert leaf_key(d1, A, G1, A) != new_key()


def test_settle_rotation_when_the_host_holds_no_store_then_it_is_not_held(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """Without an MLS store here there is nothing to republish or move."""
    server, _d1, _dr, actor = rotated(tmp_path)
    elsewhere = type(actor)(client=server, config_dir=str(tmp_path / "empty"), agent_id=A)
    settled = settle_rotation(elsewhere)
    assert settled.key_packages is KeyPackageRotation.NOT_HELD
    assert settled.group_seats == []
    assert server.uploads == []


def test_settle_rotation_when_it_is_re_entered_then_the_inner_call_is_not_held(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep opens groups and an open settles; the guard ends that recursion."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    inner: list[Any] = []

    def sweep(inner_actor: Any) -> list[SeatUpdate]:
        inner.append(settle_rotation(inner_actor))
        return []

    monkeypatch.setattr("rine._mls.seat_sweep.self_update_stale_leaves", sweep)
    settle_rotation(actor)
    assert len(inner) == 1
    assert inner[0].key_packages is KeyPackageRotation.NOT_HELD
    assert inner[0].group_seats == []


def test_settle_rotation_when_a_seat_is_deferred_then_the_seat_marker_waits(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A deferred seat is tried again; an unanswered post is found absent and dropped first, then rebuilt."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.fail_posts = [RineApiError(503, "unavailable")]
    first = settle_rotation(actor)
    assert first.group_seats[0].reason is SeatDeferReason.UNREACHABLE
    assert read_rotation_marker(d1, A) == RotationMarker(key_packages=1, seats=0)
    second = settle_rotation(actor)
    # The server never saw the commit: the sync finds it absent, drops it, and says so
    # as an unreachable seat with no detail (the commit was not posted).
    assert second.group_seats[0].reason is SeatDeferReason.UNREACHABLE
    assert second.group_seats[0].detail is None
    assert read_rotation_marker(d1, A).seats == 0
    third = settle_rotation(actor)
    assert third.group_seats[0].status is SeatUpdateStatus.UPDATED
    assert read_rotation_marker(d1, A) == RotationMarker(key_packages=1, seats=1)
    assert server.uploads == [A]


def test_settle_rotation_when_a_seat_failed_then_the_seat_marker_advances(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed seat is settled: only a person can help, and retrying cannot."""
    _server, d1, _dr, actor = rotated(tmp_path)
    monkeypatch.setattr(
        "rine._mls.seat_sweep.self_update_group",
        lambda a, gid: failed(gid, SeatFailReason.SEAT_UNHEALABLE),
    )
    settled = settle_rotation(actor)
    assert settled.group_seats[0].reason is SeatFailReason.SEAT_UNHEALABLE
    assert read_rotation_marker(d1, A).seats == 1


def test_settle_rotation_when_the_republish_fails_then_it_is_pending_and_the_seats_still_move(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """The two halves advance their marker fields independently."""
    server, d1, _dr, actor = rotated(tmp_path)
    server.fail_upload = RineApiError(503, "unavailable")
    settled = settle_rotation(actor)
    assert settled.key_packages is KeyPackageRotation.PENDING
    assert settled.group_seats[0].status is SeatUpdateStatus.UPDATED
    assert read_rotation_marker(d1, A) == RotationMarker(key_packages=0, seats=1)


def test_settle_rotation_when_the_keys_cannot_be_read_then_it_is_pending_with_an_unreachable_seat(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Settling never raises: an unexpected failure is a deferral the caller can show."""
    _server, _d1, _dr, actor = rotated(tmp_path)

    def broken(config_dir: str, agent_id: str) -> Any:
        raise OSError("keys unreadable")

    monkeypatch.setattr("rine._mls.seat_sweep.load_agent_keys", broken)
    settled = settle_rotation(actor)
    assert settled.key_packages is KeyPackageRotation.PENDING
    assert settled.group_seats == [
        deferred(None, SeatDeferReason.UNREACHABLE, detail="keys unreadable")
    ]


def test_rotate_agent_with_seats_when_the_host_holds_state_then_the_result_carries_the_settlement(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rotation verb reports the republish and every seat beside the agent."""
    server, d1, _dr, _actor = rotated(tmp_path)
    save_agent_keys(d1, A, WORLD.keys(A, 0))
    monkeypatch.setattr(
        "rine._agent_rotate_seats.rotate_agent_keys",
        lambda *_a: (save_agent_keys(d1, A, WORLD.keys(A, 1)), AgentRead.model_validate(_AGENT))[
            1
        ],
    )
    result = rotate_agent_with_seats(server, d1, None, A)
    assert str(result.id) == A
    assert result.key_packages is KeyPackageRotation.REPUBLISHED
    assert [(s.group_id, s.status) for s in result.group_seats] == [(G1, SeatUpdateStatus.UPDATED)]
    assert leaf_key(d1, A, G1, A) == new_key()
