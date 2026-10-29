"""The MLS read-escrow drain: seal, persist, save, upload.

These drive the real ``rine-mls`` core — the group, its epoch-0 escrow exports
and the snapshot that re-yields them are genuine — so the crash-safety argument
is asserted against the store rather than against a mock. Only the HTTP boundary
is stubbed.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from rine._actor import AGENT_HEADER
from rine._crypto.ed25519_strict import verify_ed25519_strict
from rine._crypto.escrow import EscrowSlot, EscrowUploader, uploader_signature_input
from rine._crypto.keys import load_agent_keys
from rine._mls.binding import open_mls_client
from rine._mls.escrow_answer import EscrowCode
from rine._mls.escrow_drain import drain_escrow, escrow_fp_for, upload_pending_escrow
from rine._mls.escrow_head import EscrowHead, read_head, write_head
from rine._mls.escrow_keys import BranchRevokedError, drop_escrow_keys, resolve_escrow_key
from rine._mls.escrow_report import EscrowDeferral
from rine._mls.escrow_store import (
    PendingEscrow,
    list_pending,
    write_pending,
)
from rine._mls.group_access import load_mls_group, mls_group_id_bytes
from rine._mls.heartbeat import MlsActor
from rine._principal import agent_principal
from rine._utils import from_base64url
from rine.errors import CryptoError, RineApiError
from rine.testing import WORLD, write_agent_identity
from tests.test_crypto.world import KeyServer

if TYPE_CHECKING:
    from rine._crypto._key_pins import KeyPins
    from rine.testing import World

AGENT = "00000000-1111-2222-3333-444444444444"
GROUP = "11111111-2222-3333-4444-555555555555"


def _epoch_of(path: str) -> int:
    """The epoch a ``/groups/{id}/mls/escrow/{epoch}`` path names."""
    return int(path.rsplit("/", 1)[1])


class FakeClient:
    """A sync client serving the escrow routes from a :class:`World`."""

    def __init__(self, world: World = WORLD) -> None:
        """Serve one world's keys and escrow key, recording every call."""
        self._keys = KeyServer(world)
        self.key_pins: KeyPins = self._keys.key_pins
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.escrow_error: RineApiError | None = None
        self.put_error: Exception | None = None
        self.put_errors: dict[int, Exception] = {}
        self.principal = agent_principal(AGENT)

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer a key or escrow-key read, recording the call."""
        self.calls.append((path, kwargs))
        if path.endswith("/keys"):
            return self._keys.get(path, **kwargs)
        if self.escrow_error is not None:
            raise self.escrow_error
        return self._keys.world.escrow_response()

    def put(self, path: str, **kwargs: Any) -> None:
        """Record an escrow upload, raising the error this epoch is set to raise."""
        self.calls.append((path, kwargs))
        error = self.put_errors.get(_epoch_of(path), self.put_error)
        if error is not None:
            raise error


class _GroupProxy:
    """Delegates every group call, counting saves and optionally failing the first."""

    def __init__(self, group: Any, *, fail_first_save: Exception | None = None) -> None:
        """Wrap ``group``, raising ``fail_first_save`` on the first ``save``."""
        self._group = group
        self._fail_first_save = fail_first_save
        self.saves = 0

    def __getattr__(self, name: str) -> Any:
        """Delegate everything but ``save`` to the wrapped group."""
        return getattr(self._group, name)

    def save(self) -> Any:
        """Save the wrapped group, failing the first call when asked to."""
        self.saves += 1
        if self.saves == 1 and self._fail_first_save is not None:
            raise self._fail_first_save
        return self._group.save()


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Every test starts from a cold escrow-key cache."""
    drop_escrow_keys()


@pytest.fixture
def actor(tmp_path: Any) -> MlsActor:
    """An actor whose leaf keys are on disk and whose org is pinned."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    client = FakeClient()
    client.key_pins.pin_own_agent(AGENT, WORLD.org_id)
    return MlsActor(client=client, config_dir=config_dir, agent_id=AGENT)


def _fresh_group(actor: MlsActor) -> Any:
    """A real native group at epoch 0, reloaded so its epoch-0 exports are pending.

    The snapshot keeps the exports until the next ``save``, so a group that was
    created and saved re-yields them on the next load — which is exactly the
    state a crash between seal and save leaves behind.
    """
    client = open_mls_client(actor.config_dir, AGENT)
    client.create_group(mls_group_id_bytes(GROUP)).save()
    group = load_mls_group(client, GROUP)
    assert group is not None
    return group


def _puts(actor: MlsActor) -> list[tuple[str, dict[str, Any]]]:
    """Every PUT this actor's client has recorded."""
    return [(path, kwargs) for path, kwargs in actor.client.calls if path.startswith("/groups/")]


def test_drain_escrow_when_the_group_is_fresh_then_seals_and_uploads_every_export(
    actor: MlsActor,
) -> None:
    """A fresh group's epoch-0 exports are sealed, uploaded and remembered."""
    group = _fresh_group(actor)

    outcome = drain_escrow(actor, GROUP, group)

    assert outcome.sealed >= 1
    assert outcome.uploaded == outcome.sealed
    assert outcome.failures == ()
    assert outcome.deferred is None
    assert list_pending(actor.config_dir, AGENT, GROUP) == []
    puts = _puts(actor)
    assert len(puts) == outcome.uploaded
    for path, kwargs in puts:
        assert path == f"/groups/{GROUP}/mls/escrow/{_epoch_of(path)}"
        assert set(kwargs["json_body"]) == {"fp", "sealed", "key_gen", "sig"}
        assert kwargs["extra_headers"] == {AGENT_HEADER: AGENT}
    head = read_head(actor.config_dir, AGENT, GROUP)
    assert head is not None
    assert head.epoch == group.epoch()
    by_epoch = {_epoch_of(path): kwargs["json_body"] for path, kwargs in puts}
    assert head.fp == from_base64url(by_epoch[head.epoch]["fp"])


def test_drain_escrow_when_killed_between_seal_and_save_then_uploads_exactly_once(
    actor: MlsActor,
) -> None:
    """A crash before ``save`` re-yields the exports, so the slot uploads once."""
    proxy = _GroupProxy(_fresh_group(actor), fail_first_save=RuntimeError("killed"))

    with pytest.raises(RuntimeError, match="killed"):
        drain_escrow(actor, GROUP, proxy)

    pending = list_pending(actor.config_dir, AGENT, GROUP)
    assert pending
    assert _puts(actor) == []
    reloaded = load_mls_group(open_mls_client(actor.config_dir, AGENT), GROUP)
    assert reloaded is not None

    second = drain_escrow(actor, GROUP, reloaded)

    assert second.sealed == 0
    assert second.uploaded == len(pending)
    assert list_pending(actor.config_dir, AGENT, GROUP) == []
    puts = _puts(actor)
    assert len(puts) == len(pending)
    slots = {(_epoch_of(path), from_base64url(kwargs["json_body"]["fp"])) for path, kwargs in puts}
    assert slots == {(p.epoch, p.fp) for p in pending}


def test_drain_escrow_when_the_upload_fails_then_keeps_the_file_for_the_next_drain(
    actor: MlsActor,
) -> None:
    """A network failure is reported, the sealed bytes stay, and a retry uploads them."""
    group = _fresh_group(actor)
    actor.client.put_error = ConnectionError("network down")

    outcome = drain_escrow(actor, GROUP, group)

    assert outcome.sealed >= 1
    assert outcome.uploaded == 0
    assert len(outcome.failures) == 1
    assert isinstance(outcome.failures[0], ConnectionError)
    assert len(list_pending(actor.config_dir, AGENT, GROUP)) == outcome.sealed

    actor.client.put_error = None
    second = drain_escrow(actor, GROUP, group)

    assert second.sealed == 0
    assert second.uploaded == outcome.sealed
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


def test_upload_pending_escrow_when_one_file_409s_then_the_next_is_still_uploaded(
    actor: MlsActor,
) -> None:
    """A 409 is the server's answer about one file, so the loop reaches the next."""
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 0, b"\x01" * 16, b"sealed-0"))
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 1, b"\x02" * 16, b"sealed-1"))
    actor.client.put_errors = {0: RineApiError(409, "escrow_missing")}

    outcome = upload_pending_escrow(actor, GROUP)

    assert outcome.uploaded == 1
    assert len(outcome.failures) == 1
    assert outcome.failures[0].status == 409
    remaining = list_pending(actor.config_dir, AGENT, GROUP)
    assert [(p.epoch, p.fp) for p in remaining] == [(0, b"\x01" * 16)]


def _refusal(status: int, code: str) -> RineApiError:
    return RineApiError(status, code, json.dumps({"error": code}))


def _two_pending(actor: MlsActor) -> None:
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 0, b"\x01" * 16, b"sealed-0"))
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 1, b"\x02" * 16, b"sealed-1"))


def test_upload_pending_escrow_when_the_slot_is_already_taken_then_the_file_counts_as_stored(
    actor: MlsActor,
) -> None:
    """The slot holds this agent's own row, which is all the send gate asks for."""
    _two_pending(actor)
    actor.client.put_errors = {0: _refusal(409, EscrowCode.SLOT_TAKEN)}

    outcome = upload_pending_escrow(actor, GROUP)

    assert outcome.uploaded == 2
    assert outcome.failures == ()
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


@pytest.mark.parametrize(
    "refusal",
    [
        _refusal(403, EscrowCode.NO_SEAT),
        _refusal(404, EscrowCode.GROUP_NOT_FOUND),
        _refusal(409, EscrowCode.FORK_LIMIT),
    ],
)
def test_upload_pending_escrow_when_the_server_refuses_for_good_then_the_file_is_not_retried(
    actor: MlsActor, refusal: RineApiError
) -> None:
    """A refusal that can never change is reported once, then parked out of every drain."""
    _two_pending(actor)
    actor.client.put_errors = {0: refusal}

    first = upload_pending_escrow(actor, GROUP)
    second = upload_pending_escrow(actor, GROUP)

    assert (first.uploaded, len(first.failures)) == (1, 1)
    assert (second.uploaded, second.failures) == (0, ())
    assert list_pending(actor.config_dir, AGENT, GROUP) == []
    assert len(_puts(actor)) == 2


def test_drain_escrow_when_the_key_is_unavailable_then_defers_and_keeps_the_exports(
    actor: MlsActor,
) -> None:
    """No verified key, branch not revoked: save without taking, so the next drain has them."""
    proxy = _GroupProxy(_fresh_group(actor))
    actor.client.escrow_error = RineApiError(503, "unavailable")

    outcome = drain_escrow(actor, GROUP, proxy)

    assert outcome.deferred is not None
    assert (outcome.sealed, outcome.uploaded, outcome.gaps) == (0, 0, ())
    assert outcome.backlog is not None
    assert outcome.backlog.queued >= 1
    assert proxy.saves == 1
    assert list_pending(actor.config_dir, AGENT, GROUP) == []

    actor.client.escrow_error = None
    second = drain_escrow(actor, GROUP, proxy)

    assert second.deferred is None
    assert second.sealed >= 1
    assert second.uploaded == second.sealed


def test_drain_escrow_when_the_branch_is_revoked_then_the_exports_stay_queued(
    actor: MlsActor,
) -> None:
    """A 410 never discards exports: they stay queued and the drain reports the reason."""
    proxy = _GroupProxy(_fresh_group(actor))
    actor.client.escrow_error = RineApiError(410, "branch revoked")

    outcome = drain_escrow(actor, GROUP, proxy)

    assert isinstance(outcome.deferred, BranchRevokedError)
    assert outcome.report().deferral == EscrowDeferral.BRANCH_REVOKED
    assert outcome.gaps == ()
    assert outcome.backlog is not None
    assert outcome.backlog.queued >= 1
    assert list_pending(actor.config_dir, AGENT, GROUP) == []

    actor.client.escrow_error = None
    second = drain_escrow(actor, GROUP, proxy)

    assert second.deferred is None
    assert second.sealed >= 1
    assert second.uploaded == second.sealed


def test_upload_pending_escrow_when_the_key_rotated_then_signs_under_the_new_generation(
    actor: MlsActor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The signature is recomputed at upload time, under the CURRENT key generation."""
    sealed = b"sealed-bytes"
    fp = b"\x07" * 16
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 0, fp, sealed))
    real = load_agent_keys(actor.config_dir, AGENT)
    monkeypatch.setattr(
        "rine._mls.escrow_drain.load_agent_keys", lambda *_a, **_k: replace(real, key_gen=2)
    )

    outcome = upload_pending_escrow(actor, GROUP)

    assert outcome.uploaded == 1
    body = _puts(actor)[-1][1]["json_body"]
    assert body["key_gen"] == 2
    key = resolve_escrow_key(actor)
    signed = uploader_signature_input(
        key.org_id, key.branch, EscrowSlot(GROUP, 0, fp), EscrowUploader(AGENT, 2), sealed
    )
    assert verify_ed25519_strict(real.signing.public_key, signed, from_base64url(body["sig"]))


def test_upload_pending_escrow_when_files_are_waiting_then_uploads_them_without_a_group(
    actor: MlsActor,
) -> None:
    """The upload half takes no group: it neither takes exports nor saves anything."""
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 3, b"\x03" * 16, b"sealed-3"))

    outcome = upload_pending_escrow(actor, GROUP)

    assert outcome.sealed == 0
    assert outcome.uploaded == 1
    assert outcome.failures == ()
    assert list_pending(actor.config_dir, AGENT, GROUP) == []


def test_upload_pending_escrow_when_the_key_cannot_be_resolved_then_raises(
    actor: MlsActor,
) -> None:
    """A revoked branch refuses the upload and leaves the file where it is."""
    write_pending(actor.config_dir, AGENT, PendingEscrow(GROUP, 0, b"\x04" * 16, b"sealed-4"))
    actor.client.escrow_error = RineApiError(410, "branch revoked")

    with pytest.raises(BranchRevokedError):
        upload_pending_escrow(actor, GROUP)

    assert len(list_pending(actor.config_dir, AGENT, GROUP)) == 1


def test_escrow_fp_for_when_the_head_matches_the_epoch_then_returns_the_fp(
    actor: MlsActor,
) -> None:
    """A drained epoch's fp is what a sender must carry."""
    group = _fresh_group(actor)
    drain_escrow(actor, GROUP, group)
    head = read_head(actor.config_dir, AGENT, GROUP)
    assert head is not None

    assert escrow_fp_for(actor, GROUP, group) == head.fp


def test_escrow_fp_for_when_there_is_no_head_then_raises(actor: MlsActor) -> None:
    """An undrained epoch has no fp, so a send would be unreadable to the org."""
    with pytest.raises(CryptoError):
        escrow_fp_for(actor, GROUP, _fresh_group(actor))


def test_escrow_fp_for_when_the_head_epoch_differs_then_raises(actor: MlsActor) -> None:
    """A head for another epoch is not this epoch's fp."""
    group = _fresh_group(actor)
    write_head(actor.config_dir, AGENT, GROUP, EscrowHead(group.epoch() + 1, b"\x09" * 16))

    with pytest.raises(CryptoError):
        escrow_fp_for(actor, GROUP, group)


def test_drain_escrow_when_the_group_moved_to_another_fork_below_the_head_then_the_head_follows(
    actor: MlsActor,
) -> None:
    """A resync onto another fork can land below the old head; the drain proves the live pair."""
    group = _fresh_group(actor)
    write_head(actor.config_dir, AGENT, GROUP, EscrowHead(group.epoch() + 2, b"\x0a" * 16))
    live = EscrowHead(group.epoch(), group.epoch_fingerprint())

    drain_escrow(actor, GROUP, group)

    assert read_head(actor.config_dir, AGENT, GROUP) == live
    assert escrow_fp_for(actor, GROUP, group) == live.fp
