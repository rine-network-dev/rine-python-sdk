"""A background seat sweep that left a seat deferred waits before it tries again.

The heartbeat settles a rotation on every MLS operation, so a group that cannot take the
update yet (an open group holding it for acknowledgement) would be retried on every beat.
The wait doubles from 60 s to an hour, applies to the heartbeat's own settlement only, and is
forgotten by a sweep that settled everything.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.actor import MlsActor
from rine._mls.seat_sweep import settle_rotation
from rine._mls.seat_sweep_backoff import (
    BACKOFF_BASE_S,
    BACKOFF_MAX_S,
    note_sweep,
    reset_seat_sweep_backoff,
    sweep_must_wait,
)
from rine._seat_update import SeatDeferReason, SeatUpdateStatus
from tests.hold_world import rotated
from tests.rotation_world import G1

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


class Clock:
    now = 1000.0


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> type[Clock]:
    reset_seat_sweep_backoff()
    Clock.now = 1000.0
    monkeypatch.setattr("rine._mls.seat_sweep_backoff._now", lambda: Clock.now)
    return Clock


def _actor() -> MlsActor:
    return MlsActor(client=None, config_dir="/cfg", agent_id="agent")


def test_sweep_must_wait_when_a_sweep_deferred_then_the_wait_doubles_up_to_the_cap(
    clock: type[Clock],
) -> None:
    actor = _actor()
    waits = []
    for _ in range(9):
        note_sweep(actor, deferred=True)
        start = clock.now
        clock.now = start + 1
        assert sweep_must_wait(actor)
        # Find the wait by stepping the clock to the moment the sweep may run again.
        lo, hi = 1.0, BACKOFF_MAX_S + 1
        while hi - lo > 0.01:
            mid = (lo + hi) / 2
            clock.now = start + mid
            lo, hi = (mid, hi) if sweep_must_wait(actor) else (lo, mid)
        waits.append(round(hi))
        clock.now = start
    assert waits[:4] == [60, 120, 240, 480]
    assert waits[-1] == BACKOFF_MAX_S
    assert BACKOFF_BASE_S == 60


def test_sweep_must_wait_when_a_sweep_settled_then_the_wait_is_forgotten(
    clock: type[Clock],
) -> None:
    actor = _actor()
    note_sweep(actor, deferred=True)
    note_sweep(actor, deferred=False)
    assert not sweep_must_wait(actor)
    note_sweep(actor, deferred=True)
    clock.now += BACKOFF_BASE_S - 1
    assert sweep_must_wait(actor)


def test_settle_rotation_when_the_heartbeat_sweeps_a_deferred_seat_then_it_waits_a_minute(
    tmp_path: Any, mls_escrow_stub: Any, clock: type[Clock]
) -> None:
    server, _d1, _dr, actor = rotated(tmp_path, open_group=True)
    first = settle_rotation(actor, background=True)
    assert first.group_seats[0].reason is SeatDeferReason.AWAITING_ACK
    posts = server.commit_posts
    clock.now += BACKOFF_BASE_S - 1
    assert settle_rotation(actor, background=True).group_seats == []
    assert server.commit_posts == posts
    clock.now += 2
    again = settle_rotation(actor, background=True)
    assert again.group_seats[0].status is SeatUpdateStatus.DEFERRED


def test_settle_rotation_when_a_person_asks_then_the_backoff_does_not_apply(
    tmp_path: Any, mls_escrow_stub: Any, clock: type[Clock]
) -> None:
    _server, _d1, _dr, actor = rotated(tmp_path, open_group=True)
    settle_rotation(actor, background=True)
    asked = settle_rotation(actor)
    assert asked.group_seats[0].reason is SeatDeferReason.AWAITING_ACK


def test_settle_rotation_when_the_seat_settles_then_the_next_background_sweep_is_not_held(
    tmp_path: Any, mls_escrow_stub: Any, clock: type[Clock]
) -> None:
    server, d1, _dr, actor = rotated(tmp_path, open_group=True)
    settle_rotation(actor, background=True)
    assert sweep_must_wait(actor)
    server.confirm(G1)
    clock.now += BACKOFF_BASE_S + 1
    settled = settle_rotation(actor, background=True)
    assert [seat.status for seat in settled.group_seats] == [SeatUpdateStatus.CURRENT]
    assert not sweep_must_wait(actor)
