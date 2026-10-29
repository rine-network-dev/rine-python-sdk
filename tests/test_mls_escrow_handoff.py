"""A loss the background sweep found is reported once, by the next drain or sync result."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_gap import DrainGap, EscrowLoss, LocatedGap
from rine._mls.escrow_handoff import note_unreported, reset_escrow_handoff, take_unreported
from rine._mls.escrow_store import PendingEscrow, write_pending
from rine._mls.escrow_sweep import reset_escrow_sweep_gate, sweep_pending_escrow
from rine._mls.sync import sync_mls_group
from rine._mls.sync_api import MlsHandshakeFeed
from rine.errors import PrincipalRevokedError, RevokedScope
from tests.test_mls_escrow_drain import AGENT, GROUP, _fresh_group
from tests.test_mls_escrow_sweep import STRAY
from tests.test_mls_escrow_sweep import _cold_state as _cold_state  # the autouse fixture
from tests.test_mls_escrow_sweep import actor as actor  # the fixture

if TYPE_CHECKING:
    from rine._mls.heartbeat import MlsActor

LOST = DrainGap(3, EscrowLoss.AGENT_REVOKED)
GROUP_FP = b"\x06" * 16


@pytest.fixture(autouse=True)
def _empty_handoff() -> None:
    reset_escrow_handoff()


def _sweep_into_the_handoff(actor: MlsActor) -> None:
    """Revoke the agent under a sweep: it files the gaps of GROUP and STRAY and leaves the news."""
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 3, GROUP_FP, b"sealed-group"))
    actor.client.escrow_error = PrincipalRevokedError(RevokedScope.AGENT)
    sweep_pending_escrow(actor)
    actor.client.escrow_error = None


def test_take_unreported_when_gaps_were_noted_then_each_group_gets_only_its_own_once() -> None:
    """Taking clears one group's news for that agent only, in the order it was noted."""
    other = DrainGap(4, EscrowLoss.REFUSED)
    note_unreported("/c", AGENT, [LocatedGap(GROUP, LOST), LocatedGap(STRAY, other)])
    note_unreported("/c", AGENT, [LocatedGap(GROUP, other)])
    note_unreported("/c", "another-agent", [LocatedGap(GROUP, LOST)])

    assert take_unreported("/c", AGENT, GROUP) == (LOST, other)
    assert take_unreported("/c", AGENT, GROUP) == ()
    assert take_unreported("/c", AGENT, STRAY) == (other,)
    assert take_unreported("/c", "another-agent", GROUP) == (LOST,)


def test_drain_escrow_when_the_sweep_lost_an_epoch_then_the_next_carrying_outcome_reports_it_once(
    actor: MlsActor,
) -> None:
    """The heartbeat drops the sweep's result, so the loss reaches the caller on the next drain."""
    _sweep_into_the_handoff(actor)
    group = _fresh_group(actor)

    first = drain_escrow(actor, GROUP, group, carry_unreported=True)
    second = drain_escrow(actor, GROUP, group, carry_unreported=True)

    assert LOST in first.gaps
    assert LOST in first.report().gaps
    assert LOST not in second.gaps


def test_drain_escrow_when_another_group_lost_an_epoch_then_this_groups_outcome_does_not_report_it(
    actor: MlsActor,
) -> None:
    """A recovery row for one group never names an epoch another group lost."""
    _sweep_into_the_handoff(actor)

    outcome = drain_escrow(actor, GROUP, _fresh_group(actor), carry_unreported=True)

    assert [g for g in outcome.gaps if g.epoch == 3].count(LOST) == 1
    assert take_unreported(actor.config_dir, AGENT, STRAY) == (LOST,)


def test_drain_escrow_when_a_send_drains_between_the_sweep_and_a_reported_sync_then_it_reports(
    actor: MlsActor,
) -> None:
    """A drain whose outcome is dropped must not consume the news the later result carries."""
    _sweep_into_the_handoff(actor)
    group = _fresh_group(actor)

    dropped = drain_escrow(actor, GROUP, group)
    reported = drain_escrow(actor, GROUP, group, carry_unreported=True)

    assert LOST not in dropped.gaps
    assert LOST in reported.gaps


def test_sync_mls_group_when_the_sweep_lost_an_epoch_then_a_carrying_idle_sync_reports_it(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An idle sync drains nothing, so it takes the news itself; a sync that drops it does not."""
    _fresh_group(actor)
    reset_escrow_sweep_gate()
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 3, GROUP_FP, b"sealed-group"))
    actor.client.escrow_error = PrincipalRevokedError(RevokedScope.AGENT)
    monkeypatch.setattr("rine._mls.sync.fetch_handshake_feed", lambda *a: MlsHandshakeFeed())

    dropped = sync_mls_group(actor.client, actor.config_dir, AGENT, GROUP)
    first = sync_mls_group(actor.client, actor.config_dir, AGENT, GROUP, carry_unreported=True)
    second = sync_mls_group(actor.client, actor.config_dir, AGENT, GROUP, carry_unreported=True)

    assert dropped.escrow.gaps == ()
    assert LOST in first.escrow.gaps
    assert first.processed == 0
    assert second.escrow.gaps == ()
