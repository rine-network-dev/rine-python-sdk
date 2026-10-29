"""The seat vocabulary is one set of bytes on both client stacks.

A rotation reports, per group, what became of the agent's own leaf. The report is
read by operators and agents on every surface, so the Python SDK and ``rine-core``
must say the same words: the statuses and reasons, every recovery sentence, the
refusals, and the marker file the two stacks share on one host. The TypeScript
sources are read, never restated, so there is one copy to drift from.

Lives in ``tests/contract/`` because that is the directory ``ci.sh`` runs for this
package; ``rine-sdk/tests/`` at large is gated only by the publish train.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rine._mls.seat_sweep import KeyPackageRotation
from rine._recover_reseat import ReseatStatus
from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdate,
    SeatUpdateStatus,
)
from rine._seat_words import _DEFERRED, _FAILED, RECOVERY_EVICTED, seat_update_line
from tests.contract.ts_twin import (
    CORE_SRC,
    as_ts_template,
    constant,
    literals,
    object_members,
    sentence_table,
    snake,
    source,
)

if TYPE_CHECKING:
    from enum import StrEnum

pytestmark = pytest.mark.skipif(not CORE_SRC.is_dir(), reason="rine-core is not checked out")

AGENT = "a1a1a1a1-0000-4000-8000-000000000001"
GROUP = "11111111-0000-4000-8000-0000000000a1"
EPOCH_SENTINEL = 31337


@pytest.mark.parametrize(
    ("ts_name", "enum"),
    [
        ("SeatUpdateStatus", SeatUpdateStatus),
        ("SeatDeferReason", SeatDeferReason),
        ("SeatFailReason", SeatFailReason),
        ("KeyPackageRotation", KeyPackageRotation),
    ],
)
def test_the_seat_vocabularies_when_compared_with_the_typescript_twin_then_they_are_equal(
    ts_name: str, enum: type[StrEnum]
) -> None:
    """Every status and reason has the same name and the same wire string."""
    ts = {
        snake(key): value
        for key, value in object_members(source("mls-seat-update.ts"), ts_name).items()
    }
    assert ts == {member.name: member.value for member in enum}


def test_the_deferred_and_failed_sentences_when_compared_with_the_twin_then_they_are_equal() -> (
    None
):
    """Each recovery sentence is the twin's entry for the same reason, byte for byte."""
    ts = source("mls-seat-sentences.ts")
    eviction = SeatFailReason.EVICTED.name
    ts_failed = sentence_table(ts, "FAILED", "SeatFailReason")
    # The eviction entry is the shared constant, pinned by its own test below.
    assert ts_failed.pop(eviction) == ""
    assert sentence_table(ts, "DEFERRED", "SeatDeferReason") == {
        reason.name: as_ts_template(template) for reason, template in _DEFERRED.items()
    }
    assert ts_failed == {
        reason.name: as_ts_template(template)
        for reason, template in _FAILED.items()
        if reason is not SeatFailReason.EVICTED
    }


def test_the_reseat_statuses_when_compared_with_the_typescript_twin_then_they_are_equal() -> None:
    """A recovery reports each group's outcome with the same wire strings on both stacks."""
    ts = object_members(source("recover-reseat.ts"), "ReseatStatus")
    assert sorted(ts.values()) == sorted(member.value for member in ReseatStatus)


def test_the_updated_sentence_when_compared_with_the_typescript_twin_then_it_is_equal() -> None:
    """The success sentence differs only in the epoch's spelling."""
    line = seat_update_line(SeatUpdate(GROUP, SeatUpdateStatus.UPDATED, epoch=EPOCH_SENTINEL))
    assert line.replace(str(EPOCH_SENTINEL), "${seat.epoch}") in source("mls-seat-sentences.ts")


def test_the_eviction_sentence_when_compared_with_the_typescript_twin_then_it_is_equal() -> None:
    """One eviction sentence, whichever stack appends it."""
    ts = source("mls-seat-sentences.ts")
    assert literals(constant(ts, "MLS_EVICTED_BY_COMMIT")) == RECOVERY_EVICTED
    assert _FAILED[SeatFailReason.EVICTED] == RECOVERY_EVICTED
