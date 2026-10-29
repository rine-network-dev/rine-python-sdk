"""The typed escrow report: how reports fold together, which key failure defers."""

from __future__ import annotations

from types import SimpleNamespace

from rine._mls.escrow_keys import BranchRevokedError
from rine._mls.escrow_report import (
    EscrowDeferral,
    EscrowReport,
    deferral_for,
    report_from_backlog,
)
from rine.errors import CryptoError
from tests.escrow_outcomes import GAP


def test_merge_when_both_sides_report_then_gaps_concatenate_and_counts_sum() -> None:
    first = EscrowReport(gaps=(GAP,), queued=2, dropped=1, backlogged=1)
    second = EscrowReport(gaps=(GAP,), queued=3, backlogged=2)

    merged = first.merge(second)

    assert merged.gaps == (GAP, GAP)
    assert (merged.queued, merged.dropped, merged.backlogged) == (5, 1, 3)


def test_merge_when_both_sides_defer_then_the_first_reason_stands() -> None:
    revoked = EscrowReport(deferral=EscrowDeferral.BRANCH_REVOKED)
    unavailable = EscrowReport(deferral=EscrowDeferral.KEY_UNAVAILABLE)

    assert revoked.merge(unavailable).deferral == EscrowDeferral.BRANCH_REVOKED
    assert EscrowReport().merge(unavailable).deferral == EscrowDeferral.KEY_UNAVAILABLE


def test_advance_when_the_same_group_drains_again_then_the_newer_counts_replace_the_older() -> (
    None
):
    first = EscrowReport(
        gaps=(GAP,), deferral=EscrowDeferral.KEY_UNAVAILABLE, queued=3, dropped=1, backlogged=1
    )
    later = EscrowReport(queued=5, dropped=1, backlogged=1)

    advanced = first.advance(later)

    assert advanced.gaps == (GAP,)
    assert (advanced.queued, advanced.dropped, advanced.backlogged) == (5, 1, 2)
    assert advanced.deferral is None


def test_deferral_for_when_the_branch_is_revoked_then_names_it_else_the_key_is_unavailable() -> (
    None
):
    assert deferral_for(BranchRevokedError()) == EscrowDeferral.BRANCH_REVOKED
    assert deferral_for(CryptoError("no key")) == EscrowDeferral.KEY_UNAVAILABLE


def test_report_from_backlog_when_given_a_backlog_then_carries_queued_and_dropped() -> None:
    backlog = SimpleNamespace(queued=4, dropped=2)

    assert report_from_backlog(backlog) == EscrowReport(queued=4, dropped=2)  # type: ignore[arg-type]
    assert report_from_backlog(None) == EscrowReport()
