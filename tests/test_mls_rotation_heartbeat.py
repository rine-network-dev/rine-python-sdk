"""The key-package heartbeat settles a pending rotation before it counts the pool."""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.heartbeat import mls_heartbeat, reset_mls_heartbeat_gate
from rine._mls.rotation_marker import RotationMarker, read_rotation_marker
from rine.testing import WORLD
from tests.hold_world import leaf_key, rotated
from tests.rotation_world import G1, A

pytestmark = pytest.mark.usefixtures("real_roster_read")


@pytest.fixture(autouse=True)
def _fresh_gate() -> None:
    reset_mls_heartbeat_gate()


def test_mls_heartbeat_when_the_agent_has_rotated_then_the_beat_moves_its_leaf(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A host that never ran the rotation verb still settles on its next beat."""
    _server, d1, _dr, actor = rotated(tmp_path)
    mls_heartbeat(actor, "gated")
    assert leaf_key(d1, A, G1, A) == WORLD.keys(A, 1).mls.public_key
    assert read_rotation_marker(d1, A) == RotationMarker(key_packages=1, seats=1)


def test_mls_heartbeat_when_it_beats_then_the_settlement_runs_before_the_top_up(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The top-up must not count a pool that still holds the previous generation's halves."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    order: list[str] = []
    monkeypatch.setattr(
        "rine._mls.seat_sweep.settle_rotation",
        lambda _actor, *, background: order.append(f"settle background={background}"),
    )
    monkeypatch.setattr(
        "rine._mls.heartbeat.ensure_mls_key_packages", lambda *_a: order.append("top-up")
    )
    monkeypatch.setattr("rine._mls.heartbeat.sweep_pending_escrow", lambda _actor: None)
    mls_heartbeat(actor, "gated")
    assert order == ["settle background=True", "top-up"]


def test_mls_heartbeat_when_the_settlement_raises_then_the_top_up_still_runs(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Maintenance never blocks maintenance."""
    _server, _d1, _dr, actor = rotated(tmp_path)
    ran: list[str] = []

    def explode(_actor: Any, *, background: bool) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("rine._mls.seat_sweep.settle_rotation", explode)
    monkeypatch.setattr("rine._mls.heartbeat.ensure_mls_key_packages", lambda *_a: ran.append("x"))
    monkeypatch.setattr("rine._mls.heartbeat.sweep_pending_escrow", lambda _actor: None)
    mls_heartbeat(actor, "gated")
    assert ran == ["x"]
