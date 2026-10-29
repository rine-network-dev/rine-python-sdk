"""The seat sweep: which groups it moves, and what stops it from starting.

The real ``rine-mls`` core runs; only the server is a stub. ``A`` rotates to
generation 1 on device ``d1`` and sits in one group (``G1``) that device holds
state for, and in another (``G2``) it holds none for.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._mls.seat_sweep import self_update_stale_leaves
from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdateStatus,
    deferred,
    failed,
)
from rine.errors import RineApiError
from tests.hold_world import rotated
from tests.rotation_world import G1, G2, A

pytestmark = pytest.mark.usefixtures("real_roster_read", "heartbeat_settles_nothing")


def test_self_update_stale_leaves_when_the_disk_key_is_not_the_published_one_then_key_not_current(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A host holding a superseded key never self-updates."""
    server, _d1, _dr, actor = rotated(tmp_path)
    server.publish(A, 2)
    assert self_update_stale_leaves(actor) == [failed(None, SeatFailReason.KEY_NOT_CURRENT)]
    assert server.commit_posts == 0


def test_self_update_stale_leaves_when_the_key_read_fails_then_unreachable(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed chain-verified read is a deferral, not a refusal."""
    server, _d1, _dr, actor = rotated(tmp_path)
    served = server.get

    def get(path: str, **kwargs: Any) -> dict[str, Any]:
        if path == "/agents/keys":
            raise RineApiError(503, "unavailable")
        return served(path, **kwargs)

    monkeypatch.setattr(server, "get", get)
    (only,) = self_update_stale_leaves(actor)
    assert (only.group_id, only.status, only.reason) == (
        None,
        SeatUpdateStatus.DEFERRED,
        SeatDeferReason.UNREACHABLE,
    )


def test_self_update_stale_leaves_when_the_listing_fails_then_unreachable(
    tmp_path: Any, mls_escrow_stub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed group listing is a deferral, never 'in no groups'."""
    server, _d1, _dr, actor = rotated(tmp_path)
    served = server.get

    def get(path: str, **kwargs: Any) -> dict[str, Any]:
        if path == "/groups":
            raise RineApiError(503, "unavailable")
        return served(path, **kwargs)

    monkeypatch.setattr(server, "get", get)
    (only,) = self_update_stale_leaves(actor)
    assert only == deferred(None, SeatDeferReason.UNREACHABLE, detail="503: unavailable")


def test_self_update_stale_leaves_when_a_group_has_no_local_state_then_it_is_skipped(
    tmp_path: Any, mls_escrow_stub: Any
) -> None:
    """A group the server lists without local state here belongs to a Welcome."""
    server, _d1, _dr, actor = rotated(tmp_path)
    server.rosters[G2] = [A]
    seats = self_update_stale_leaves(actor)
    assert [s.group_id for s in seats] == [G1]
