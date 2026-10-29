"""The escrow drain's secret hygiene, overflow and back-off, against the real core.

Only the HTTP boundary is stubbed, as in :mod:`tests.test_mls_escrow_drain`.
"""

from __future__ import annotations

from typing import Any

import pytest

from rine._crypto.keys import load_agent_keys, save_agent_keys
from rine._mls.binding import EscrowGapReason, open_mls_client
from rine._mls.escrow_drain import drain_escrow, upload_pending_escrow
from rine._mls.escrow_keys import drop_escrow_keys, resolve_escrow_key
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_seal import seal_taken, zero
from rine._mls.escrow_store import PendingEscrow, list_pending, write_pending
from rine._mls.group_access import mls_group_id_bytes
from rine._mls.heartbeat import MlsActor
from rine.testing import WORLD, write_agent_identity
from tests.test_mls_escrow_drain import (
    AGENT,
    GROUP,
    FakeClient,
    _fresh_group,
    _GroupProxy,
    _puts,
    _refusal,
    _two_pending,
)
from tests.test_mls_escrow_sweep import NO_FORK_FP


@pytest.fixture
def actor(tmp_path: Any) -> MlsActor:
    """An actor whose leaf keys are on disk and whose org is pinned."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    client = FakeClient()
    client.key_pins.pin_own_agent(AGENT, WORLD.org_id)
    return MlsActor(client=client, config_dir=config_dir, agent_id=AGENT)


@pytest.fixture(autouse=True)
def _cold_key_cache() -> None:
    drop_escrow_keys()


PEER = "00000000-1111-2222-3333-555555555555"
QUEUE_CAP = 32


class _RecordingGroup(_GroupProxy):
    """Keeps the take the drain made, so the test can look at the plaintexts after it."""

    def __init__(self, group: Any) -> None:
        """Wrap ``group`` and remember every take."""
        super().__init__(group)
        self.takes: list[Any] = []

    def take_escrow_exports(self) -> Any:
        """Take for real and keep a reference to the result."""
        take = self._group.take_escrow_exports()
        self.takes.append(take)
        return take


def test_drain_escrow_when_the_exports_are_sealed_then_every_plaintext_is_zeroed(
    actor: MlsActor,
) -> None:
    """The take's plaintext is the only copy of the epoch's secrets, so it ends as zeros."""
    group = _RecordingGroup(_fresh_group(actor))

    outcome = drain_escrow(actor, GROUP, group)

    exports = [e for take in group.takes for e in take.exports]
    assert outcome.sealed == len(exports) >= 1
    for export in exports:
        assert len(export.plaintext) > 0
        assert not any(export.plaintext)


def test_seal_taken_when_a_write_fails_then_every_plaintext_is_still_zeroed(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fault after the first export must not leave the later ones' secrets in memory."""
    taken = _overflowed_group(actor, 2).take_escrow_exports().exports
    assert len(taken) >= 3
    real = write_pending
    calls: list[int] = []

    def flaky(config_dir: str, agent_id: str, pending: PendingEscrow) -> None:
        calls.append(pending.epoch)
        if len(calls) == 2:
            raise OSError("disk full")
        real(config_dir, agent_id, pending)

    monkeypatch.setattr("rine._mls.escrow_seal.write_pending", flaky)
    key = resolve_escrow_key(actor)
    keys = load_agent_keys(actor.config_dir, AGENT)

    with pytest.raises(OSError, match="disk full"):
        seal_taken(actor, GROUP, key, keys, taken)

    assert len(calls) == 2
    assert all(not any(e.plaintext) for e in taken)


def test_zero_when_given_a_secret_then_overwrites_it_in_place() -> None:
    """The native side hands out one object per export, so the zeroing must be in place."""
    secret = bytearray(b"\x07" * 8)
    alias = secret

    zero(secret)

    assert alias == bytearray(8)


def _overflowed_group(actor: MlsActor, installs: int) -> Any:
    """A group that installed ``installs`` epochs with no drain in between."""
    save_agent_keys(actor.config_dir, PEER, WORLD.keys(PEER))
    peer = open_mls_client(actor.config_dir, PEER)
    group = open_mls_client(actor.config_dir, AGENT).create_group(mls_group_id_bytes(GROUP))
    while group.epoch() < installs:
        group.add_member(peer.generate_key_package())
        member = next(
            m for m in group.member_identities() if m.index != group.current_member_index()
        )
        group.remove_member(member.index)
    return group


def test_drain_escrow_when_the_queue_overflowed_then_the_lost_epochs_are_filed_as_gaps(
    actor: MlsActor,
) -> None:
    """Epochs the core had to drop are reported and filed, not silently missing."""
    group = _overflowed_group(actor, QUEUE_CAP + 3)

    outcome = drain_escrow(actor, GROUP, group)

    assert outcome.sealed == QUEUE_CAP
    lost = [g for g in outcome.gaps if g.reason == EscrowGapReason.QUEUE_OVERFLOW]
    assert len(lost) == group.epoch() + 1 - QUEUE_CAP
    for gap in lost:
        assert (
            read_gap(actor.config_dir, AGENT, GROUP, gap.epoch, NO_FORK_FP)
            == EscrowGapReason.QUEUE_OVERFLOW
        )


def test_write_pending_when_the_slot_already_has_a_file_then_the_first_bytes_win(
    actor: MlsActor,
) -> None:
    """Sealing is randomised, so a second writer must never replace the first one's row."""
    fp = b"\x03" * 16

    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 4, fp, b"first"))
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 4, fp, b"second"))

    assert [p.sealed for p in list_pending(actor.config_dir, AGENT, GROUP)] == [b"first"]


@pytest.mark.parametrize("status", [429, 500, 503])
def test_upload_pending_escrow_when_the_server_is_overloaded_then_the_loop_stops_and_keeps_files(
    actor: MlsActor, status: int
) -> None:
    """A 429 or 5xx is about the server, not the file: nothing is parked, nothing else is tried."""
    _two_pending(actor)
    actor.client.put_errors = {0: _refusal(status, "overloaded")}

    outcome = upload_pending_escrow(actor, GROUP)

    assert (outcome.uploaded, len(outcome.failures)) == (0, 1)
    assert len(_puts(actor)) == 1
    assert [p.epoch for p in list_pending(actor.config_dir, AGENT, GROUP)] == [0, 1]


def test_drain_escrow_when_the_server_is_overloaded_then_other_groups_are_not_swept(
    actor: MlsActor,
) -> None:
    """An overloaded server would only fail every other group's files too."""
    stray = "99999999-8888-7777-6666-555555555555"
    write_pending(actor.config_dir, AGENT, PendingEscrow(stray, 3, b"\x05" * 16, b"sealed"))
    actor.client.put_error = _refusal(503, "unavailable")

    outcome = drain_escrow(actor, GROUP, _fresh_group(actor))

    assert len(outcome.failures) == 1
    assert len(list_pending(actor.config_dir, AGENT, stray)) == 1
    assert all(f"/groups/{stray}/" not in path for path, _ in _puts(actor))
