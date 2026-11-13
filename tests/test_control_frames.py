"""``without_hidden_frames``: the one row filter every model-facing wrapper shares."""

from __future__ import annotations

from dataclasses import dataclass

from rine import without_hidden_frames


@dataclass(frozen=True)
class _Row:
    id: int
    type: str


def test_without_hidden_frames_when_rows_mix_types_then_only_key_material_goes_and_order_holds() -> None:
    rows = [
        _Row(1, "rine.v1.text"),
        _Row(2, "rine.v1.sender_key_distribution"),
        _Row(3, "rine.v1.group_invite"),
    ]
    assert [r.id for r in without_hidden_frames(rows)] == [1, 3]
