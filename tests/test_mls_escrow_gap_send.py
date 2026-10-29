"""A send at a gap epoch is a typed refusal, and a too_many_leaves gap reclaims once."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from rine._mls import messages
from rine._mls.binding import EscrowGapReason
from rine._mls.escrow_drain import escrow_fp_for
from rine._mls.escrow_gap import DrainGap, write_gap
from rine._mls.escrow_head import EscrowHead, write_head
from rine._mls.escrow_leaves import reset_gap_reclamation
from rine.errors import CryptoError, EscrowGapError
from tests.test_mls_escrow_drain import AGENT, GROUP, _fresh_group, actor  # noqa: F401

if TYPE_CHECKING:
    from rine._mls.heartbeat import MlsActor

FP = b"\x0a" * 16


@pytest.fixture(autouse=True)
def _fresh_reclamation() -> None:
    reset_gap_reclamation()


def test_escrow_fp_for_when_the_epoch_is_a_recorded_gap_then_raises_the_typed_error(
    actor: MlsActor,  # noqa: F811
) -> None:
    """The marker, not prose, tells the caller which epoch lacks escrow and why."""
    group = _fresh_group(actor)
    write_gap(actor.config_dir, AGENT, GROUP, DrainGap(group.epoch(), EscrowGapReason.MALFORMED))

    with pytest.raises(EscrowGapError) as caught:
        escrow_fp_for(actor, GROUP, group)

    assert isinstance(caught.value, CryptoError)
    assert (caught.value.group_id, caught.value.epoch) == (GROUP, group.epoch())
    assert caught.value.reason == EscrowGapReason.MALFORMED


def test_escrow_fp_for_when_the_head_names_another_fork_and_no_marker_exists_then_it_is_retryable(
    actor: MlsActor,  # noqa: F811
) -> None:
    """On a real group, a head that is not the live fork's neither vouches nor names a loss."""
    group = _fresh_group(actor)
    other = bytes(byte ^ 0xFF for byte in group.epoch_fingerprint())
    write_head(actor.config_dir, AGENT, GROUP, EscrowHead(group.epoch(), other))

    with pytest.raises(CryptoError) as caught:
        escrow_fp_for(actor, GROUP, group)

    assert not isinstance(caught.value, EscrowGapError)


def test_escrow_fp_for_when_head_is_another_fork_and_marker_is_fork_less_then_it_names_the_loss(
    actor: MlsActor,  # noqa: F811
) -> None:
    """The fork-less marker of the live epoch still names a permanent loss."""
    group = _fresh_group(actor)
    other = bytes(byte ^ 0xFF for byte in group.epoch_fingerprint())
    write_head(actor.config_dir, AGENT, GROUP, EscrowHead(group.epoch(), other))
    write_gap(actor.config_dir, AGENT, GROUP, DrainGap(group.epoch(), EscrowGapReason.MALFORMED))

    with pytest.raises(EscrowGapError) as caught:
        escrow_fp_for(actor, GROUP, group)

    assert caught.value.reason == EscrowGapReason.MALFORMED


class _Sends:
    """Stands in for the drain: ``escrow_fp_for`` raises the queued gaps, then answers."""

    def __init__(self, *gaps: EscrowGapReason) -> None:
        self.gaps = list(gaps)
        self.reclaims = 0

    def escrow_fp_for(self, _actor: Any, group_id: str, group: Any) -> bytes:
        if self.gaps:
            raise EscrowGapError(group_id, group.epoch(), self.gaps.pop(0))
        return FP

    def reclaim(self, *_args: Any) -> None:
        self.reclaims += 1


def _send(actor: MlsActor, monkeypatch: pytest.MonkeyPatch, sends: _Sends) -> Any:  # noqa: F811
    monkeypatch.setattr(messages, "drain_escrow", lambda *_a: None)
    monkeypatch.setattr(messages, "escrow_fp_for", sends.escrow_fp_for)
    monkeypatch.setattr("rine._mls.escrow_leaves.reclaim_orphan_leaves", sends.reclaim)
    group = SimpleNamespace(id=GROUP)
    return messages._encrypt(actor.client, actor.config_dir, AGENT, group, {"text": "hi"})


def test_encrypt_when_the_tree_is_past_the_bound_then_it_reclaims_once_and_sends(
    actor: MlsActor,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reclamation commit may install an epoch that escrows, so the send looks again."""
    _fresh_group(actor)
    sends = _Sends(EscrowGapReason.TOO_MANY_LEAVES)

    result = _send(actor, monkeypatch, sends)

    assert sends.reclaims == 1
    assert result.escrow_fp is not None


def test_encrypt_when_the_gap_survives_the_reclaim_then_it_raises_and_never_reclaims_again(
    actor: MlsActor,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One O(N) reclamation per group per process, however often the send is retried."""
    _fresh_group(actor)
    sends = _Sends(EscrowGapReason.TOO_MANY_LEAVES, EscrowGapReason.TOO_MANY_LEAVES)

    with pytest.raises(EscrowGapError) as first:
        _send(actor, monkeypatch, sends)
    sends.gaps.append(EscrowGapReason.TOO_MANY_LEAVES)
    with pytest.raises(EscrowGapError):
        _send(actor, monkeypatch, sends)

    assert first.value.reason == EscrowGapReason.TOO_MANY_LEAVES
    assert sends.reclaims == 1


@pytest.mark.parametrize(
    "reason",
    [EscrowGapReason.CONTEXT_TOO_LARGE, EscrowGapReason.MALFORMED, EscrowGapReason.QUEUE_OVERFLOW],
)
def test_encrypt_when_the_gap_is_not_a_leaf_count_then_it_raises_without_reclaiming(
    actor: MlsActor,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    reason: EscrowGapReason,
) -> None:
    """Only an oversized tree can be cured by removing orphans."""
    _fresh_group(actor)
    sends = _Sends(reason)

    with pytest.raises(EscrowGapError):
        _send(actor, monkeypatch, sends)

    assert sends.reclaims == 0
