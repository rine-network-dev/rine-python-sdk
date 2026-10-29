"""What a group recovery says about where the agent's own leaf stands."""

from __future__ import annotations

import pytest

from rine._group_recovery import KeyPackageTopUp
from rine._mls.resync import MlsRecoveryResult
from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdate,
    SeatUpdateStatus,
    deferred,
    failed,
)
from rine._seat_words import RECOVERY_EVICTED, seat_update_line
from rine.format import describe_mls_recovery

GROUP = "11111111-0000-4000-8000-0000000000a1"


def _result(**fields: object) -> MlsRecoveryResult:
    return MlsRecoveryResult(
        regime="mls",
        rung="replay",
        from_epoch=1,
        epoch=2,
        behind=1,
        processed=1,
        evicted=False,
        **fields,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "seat",
    [None, SeatUpdate(GROUP, SeatUpdateStatus.CURRENT, epoch=4)],
    ids=["no self-update ran", "leaf already current"],
)
def test_seat_update_line_when_there_is_nothing_to_say_then_it_is_empty(
    seat: SeatUpdate | None,
) -> None:
    """An unchanged group prints exactly what it printed before."""
    assert seat_update_line(seat) == ""


def test_seat_update_line_when_the_leaf_moved_then_it_names_the_epoch() -> None:
    """The success sentence."""
    seat = SeatUpdate(GROUP, SeatUpdateStatus.UPDATED, epoch=7)
    assert seat_update_line(seat) == "Its leaf now carries the agent's current key (epoch 7)."


@pytest.mark.parametrize(
    ("reason", "epoch", "sentence"),
    [
        (
            SeatDeferReason.EPOCH_RACE,
            None,
            "Its leaf still carries an earlier key: another commit landed first; "
            "the next sync retries.",
        ),
        (
            SeatDeferReason.UNREACHABLE,
            None,
            "Its leaf still carries an earlier key: the update could not be posted; "
            "the next sync retries.",
        ),
        (
            SeatDeferReason.AWAITING_ACK,
            9,
            "Its leaf moves to the agent's current key once a member acknowledges the update "
            "(epoch 9); until then it carries the earlier key.",
        ),
        (
            SeatDeferReason.ROLLED_BACK,
            None,
            "Its leaf still carries an earlier key: the group rolled the update back before "
            "a member acknowledged it; the next sync retries.",
        ),
    ],
)
def test_seat_update_line_when_the_move_is_deferred_then_it_says_why(
    reason: SeatDeferReason, epoch: int | None, sentence: str
) -> None:
    """Each deferral has its own sentence, and a retry is promised only where one exists."""
    assert seat_update_line(deferred(GROUP, reason, epoch=epoch)) == sentence


@pytest.mark.parametrize(
    ("reason", "detail", "sentence"),
    [
        (SeatFailReason.EVICTED, None, RECOVERY_EVICTED),
        (
            SeatFailReason.SEAT_UNHEALABLE,
            "signer differs",
            "Its leaf carries a key this agent cannot sign for; a member must remove the agent "
            "and invite it again.",
        ),
        (
            SeatFailReason.KEY_NOT_CURRENT,
            None,
            "Its leaf was not moved: this device holds an earlier key generation than the "
            "agent's current one.",
        ),
        (
            SeatFailReason.REFUSED,
            "no room",
            "Its leaf was not moved: the update was refused: no room",
        ),
    ],
)
def test_seat_update_line_when_the_move_failed_then_it_says_what_a_person_can_do(
    reason: SeatFailReason, detail: str | None, sentence: str
) -> None:
    """A failure is never retried by the product, so each says what is left."""
    assert seat_update_line(failed(GROUP, reason, detail)) == sentence


def test_seat_update_line_when_a_refusal_has_no_detail_then_it_says_none_was_reported() -> None:
    """The refused sentence never ends on an empty clause."""
    assert seat_update_line(failed(GROUP, SeatFailReason.REFUSED)).endswith(
        "the update was refused: no reason was reported"
    )


def test_describe_mls_recovery_when_the_leaf_moved_then_the_sentence_follows_the_head() -> None:
    """Appended, never prepended: the head stays what drivers anchor on."""
    said = describe_mls_recovery(
        "#ops", _result(seat=SeatUpdate(GROUP, SeatUpdateStatus.UPDATED, epoch=2))
    )
    head, _, tail = said.partition("\n")
    assert head.startswith("Replayed 1 commit(s) for group #ops")
    assert tail == "Its leaf now carries the agent's current key (epoch 2)."


def test_describe_mls_recovery_when_a_seat_and_a_top_up_meet_then_the_seat_comes_first() -> None:
    """The composition order is shared with the TypeScript twin."""
    said = describe_mls_recovery(
        "#ops",
        _result(
            seat=SeatUpdate(GROUP, SeatUpdateStatus.UPDATED, epoch=2),
            key_packages=KeyPackageTopUp(outcome="failed", detail="down"),
        ),
    )
    lines = said.split("\n")
    assert lines[1] == "Its leaf now carries the agent's current key (epoch 2)."
    assert "down" in lines[2]


def test_describe_mls_recovery_when_the_leaf_is_current_then_nothing_is_added() -> None:
    """A current leaf adds no line."""
    said = describe_mls_recovery("#ops", _result(seat=SeatUpdate(GROUP, SeatUpdateStatus.CURRENT)))
    assert "\n" not in said
