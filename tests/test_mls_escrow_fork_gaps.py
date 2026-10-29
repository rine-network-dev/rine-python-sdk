"""A gap marker belongs to one fork of an epoch: it is kept, never shared and cleared on store."""

from __future__ import annotations

import errno
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from rine._mls.escrow_answer import EscrowCode
from rine._mls.escrow_drain import escrow_fp_for
from rine._mls.escrow_gap import DrainGap, EscrowLoss, give_up_pending, parse_gap_name, write_gap
from rine._mls.escrow_head import EscrowHead, write_head
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_store import PendingEscrow, pending_dir, write_pending
from rine._mls.escrow_sweep import sweep_pending_escrow
from rine.errors import CryptoError, EscrowGapError
from tests.test_mls_escrow_drain import AGENT
from tests.test_mls_escrow_sweep import NO_FORK_FP, STRAY, _refusal
from tests.test_mls_escrow_sweep import _cold_state as _cold_state  # the autouse fixture
from tests.test_mls_escrow_sweep import actor as actor  # the fixture

if TYPE_CHECKING:
    from rine._mls.heartbeat import MlsActor
    from rine.errors import RineApiError

FORK_A = b"\x0a" * 16
FORK_B = b"\x0b" * 16


def _names(actor: MlsActor, group_id: str) -> list[str]:
    directory = pending_dir(actor.config_dir, AGENT, group_id)
    return sorted(n for n in os.listdir(directory) if n.endswith(".gap"))


def _give_up(actor: MlsActor, fp: bytes, loss: EscrowLoss) -> None:
    give_up_pending(actor.config_dir, AGENT, PendingEscrow(STRAY, 3, fp, b"sealed"), loss)


def test_give_up_pending_when_a_fork_is_given_up_then_only_that_forks_marker_exists(
    actor: MlsActor,
) -> None:
    """The marker is named for the fork, so another fork of the epoch is not marked."""
    _give_up(actor, FORK_A, EscrowLoss.REFUSED)

    assert _names(actor, STRAY) == [f"3-{FORK_A.hex()}.gap"]


def test_write_gap_when_a_fork_is_lost_again_then_the_first_reason_stays(actor: MlsActor) -> None:
    """A later loss of the same fork never rewrites why it was first lost."""
    gap = DrainGap(3, EscrowLoss.REFUSED)
    write_gap(actor.config_dir, AGENT, STRAY, gap, FORK_A)

    write_gap(actor.config_dir, AGENT, STRAY, DrainGap(3, EscrowLoss.BRANCH_REVOKED), FORK_A)

    assert read_gap(actor.config_dir, AGENT, STRAY, 3, FORK_A) is EscrowLoss.REFUSED


def test_write_gap_when_an_epoch_has_no_known_fork_then_the_first_reason_stays(
    actor: MlsActor,
) -> None:
    """The fork-less marker is written once too."""
    write_gap(actor.config_dir, AGENT, STRAY, DrainGap(9, EscrowLoss.UNREADABLE))

    write_gap(actor.config_dir, AGENT, STRAY, DrainGap(9, EscrowLoss.AGENT_REVOKED))

    assert read_gap(actor.config_dir, AGENT, STRAY, 9, NO_FORK_FP) is EscrowLoss.UNREADABLE


@pytest.mark.parametrize("answer", [None, _refusal(409, EscrowCode.SLOT_TAKEN)])
def test_sweep_when_a_fork_is_stored_then_its_marker_goes_and_the_other_forks_stays(
    actor: MlsActor, answer: RineApiError | None
) -> None:
    """Storing a fork clears its own marker, whether uploaded now or already held."""
    _give_up(actor, FORK_A, EscrowLoss.REFUSED)
    _give_up(actor, FORK_B, EscrowLoss.BRANCH_REVOKED)
    write_pending(actor.config_dir, AGENT, PendingEscrow(STRAY, 3, FORK_A, b"sealed-again"))
    actor.client.put_error = answer

    sweep_pending_escrow(actor)

    assert _names(actor, STRAY) == [f"3-{FORK_B.hex()}.gap"]
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, FORK_B) is EscrowLoss.BRANCH_REVOKED


def test_escrow_fp_for_when_another_fork_was_given_up_then_the_stored_fork_still_sends(
    actor: MlsActor,
) -> None:
    """A marker for fork A never turns fork B's stored epoch into a gap."""
    _give_up(actor, FORK_A, EscrowLoss.REFUSED)
    write_head(actor.config_dir, AGENT, STRAY, EscrowHead(3, FORK_B))
    group: Any = SimpleNamespace(epoch=lambda: 3, epoch_fingerprint=lambda: FORK_B)

    assert escrow_fp_for(actor, STRAY, group) == FORK_B


def test_escrow_fp_for_when_only_another_fork_has_a_gap_then_the_send_is_retryable(
    actor: MlsActor,
) -> None:
    """Fork A's loss at the epoch never reads as a permanent loss on the live fork B."""
    _give_up(actor, FORK_A, EscrowLoss.REFUSED)
    group: Any = SimpleNamespace(epoch=lambda: 3, epoch_fingerprint=lambda: FORK_B)

    with pytest.raises(CryptoError) as caught:
        escrow_fp_for(actor, STRAY, group)
    assert not isinstance(caught.value, EscrowGapError)


def test_escrow_fp_for_when_the_live_fork_has_a_gap_then_the_send_names_the_loss(
    actor: MlsActor,
) -> None:
    _give_up(actor, FORK_B, EscrowLoss.BRANCH_REVOKED)
    group: Any = SimpleNamespace(epoch=lambda: 3, epoch_fingerprint=lambda: FORK_B)

    with pytest.raises(EscrowGapError) as caught:
        escrow_fp_for(actor, STRAY, group)
    assert caught.value.reason is EscrowLoss.BRANCH_REVOKED


def test_escrow_fp_for_when_the_head_names_another_fork_of_the_epoch_then_it_does_not_vouch(
    actor: MlsActor,
) -> None:
    write_head(actor.config_dir, AGENT, STRAY, EscrowHead(3, FORK_A))
    group: Any = SimpleNamespace(epoch=lambda: 3, epoch_fingerprint=lambda: FORK_B)

    with pytest.raises(CryptoError) as caught:
        escrow_fp_for(actor, STRAY, group)
    assert not isinstance(caught.value, EscrowGapError)


def test_give_up_pending_when_the_marker_exists_then_the_gap_reports_the_reason_on_disk(
    actor: MlsActor,
) -> None:
    """A repeated give-up reports the loss the disk will keep naming, not the new one."""
    write_gap(actor.config_dir, AGENT, STRAY, DrainGap(3, EscrowLoss.REFUSED), FORK_A)

    gap = give_up_pending(
        actor.config_dir,
        AGENT,
        PendingEscrow(STRAY, 3, FORK_A, b"sealed"),
        EscrowLoss.BRANCH_REVOKED,
    )

    assert gap == DrainGap(3, EscrowLoss.REFUSED)
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, FORK_A) is EscrowLoss.REFUSED


@pytest.mark.parametrize("code", [errno.EPERM, errno.ENOTSUP, errno.EXDEV])
def test_write_gap_when_the_filesystem_has_no_hard_links_then_the_marker_is_still_exclusive(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The first reason is kept by an exclusive create where a link is refused."""

    def refuse(*_: Any) -> None:
        raise OSError(code, "no hard links")

    monkeypatch.setattr(os, "link", refuse)

    write_gap(actor.config_dir, AGENT, STRAY, DrainGap(3, EscrowLoss.REFUSED), FORK_A)
    write_gap(actor.config_dir, AGENT, STRAY, DrainGap(3, EscrowLoss.BRANCH_REVOKED), FORK_A)

    assert read_gap(actor.config_dir, AGENT, STRAY, 3, FORK_A) is EscrowLoss.REFUSED
    assert not [n for n in os.listdir(pending_dir(actor.config_dir, AGENT, STRAY)) if ".tmp" in n]


def test_write_gap_when_a_link_fails_for_another_reason_then_the_error_propagates(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a missing hard-link facility falls back; a full disk is still a failure."""

    def refuse(*_: Any) -> None:
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr(os, "link", refuse)

    with pytest.raises(OSError, match="disk full"):
        write_gap(actor.config_dir, AGENT, STRAY, DrainGap(3, EscrowLoss.REFUSED), FORK_A)


@pytest.mark.parametrize(
    ("name", "parsed"),
    [
        ("0.gap", (0, None)),
        (f"{10**14}.gap", (10**14, None)),
        (f"3-{FORK_A.hex()}.gap", (3, FORK_A.hex())),
        ("01.gap", None),
        (f"{10**15}.gap", None),
        (f"01-{FORK_A.hex()}.gap", None),
        (f"3-{FORK_A.hex()[:-1]}.gap", None),
    ],
)
def test_parse_gap_name_when_the_epoch_is_not_canonical_then_names_no_marker(
    name: str, parsed: tuple[int, str | None] | None
) -> None:
    """A marker spells its epoch as a pending file does: no leading zero, at most 15 digits."""
    assert parse_gap_name(name) == parsed
