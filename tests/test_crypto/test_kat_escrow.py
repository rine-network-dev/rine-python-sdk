"""Known-answer tests for the MLS read escrow."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rine._crypto import _mlkem
from rine._crypto.certs import VerifiedAgentKeys
from rine._crypto.escrow_key import VerifiedEscrowKey
from rine._crypto.derive_nodes import derive_agent, derive_branch, derive_org
from rine._crypto.escrow import (
    EscrowForgedError,
    EscrowInvalidError,
    EscrowSlot,
    EscrowUploader,
    SealedEscrow,
    check_epoch_read_secrets,
    open_escrow,
    seal_escrow,
    sign_escrow,
    uploader_signature_input,
)
from rine.errors import CryptoError
from tests.test_crypto.kat import load_kat


STORED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _uploader_keys(
    agent_id: str, org_id: str, branch: str, key_gen: int, signing_public_key: bytes, **over: Any
) -> VerifiedAgentKeys:
    """The uploader's chain-verified keys; only the signing key matters to an escrow open."""
    return VerifiedAgentKeys(
        agent_id, org_id, branch, key_gen, signing_public_key, b"", b"", b"", **over
    )


def _escrow() -> dict[str, Any]:
    return load_kat()["mls_escrow"]


class _World:
    """The fixture's uploader, branch and slot, rebuilt from root 0."""

    def __init__(self) -> None:
        escrow = _escrow()
        root = bytes.fromhex(load_kat()["roots"]["roots"][0]["entropy"])
        org = derive_org(root)
        self.org_id = escrow["slot"]["org_id"]
        self.branch_name = escrow["slot"]["branch"]
        self.branch = derive_branch(org.r_read, org.r_sign, self.branch_name)
        self.kem_pk, self.kem_sk = _mlkem.key_pair_from_seed(self.branch.escrow_kem_seed)
        uploader = escrow["uploader"]
        node = derive_agent(
            self.branch.b_read, self.branch.b_sign, uploader["agent_id"], uploader["gen"]
        )
        self.uploader = EscrowUploader(uploader["agent_id"], uploader["gen"])
        self.uploader_seed = node.ed_seed
        self.uploader_pk = node.ed_pk
        self.uploader_keys = _uploader_keys(
            uploader["agent_id"], self.org_id, self.branch_name, uploader["gen"], node.ed_pk
        )
        slot = escrow["slot"]
        self.slot = EscrowSlot(slot["group_id"], slot["epoch"], bytes.fromhex(slot["fp"]))
        self.key = VerifiedEscrowKey(
            self.org_id, self.branch_name, self.branch.escrow_x_pk, self.kem_pk
        )

    def signed(self, sealed: bytes) -> SealedEscrow:
        sig = Ed25519PrivateKey.from_private_bytes(self.uploader_seed).sign(
            uploader_signature_input(
                self.org_id, self.branch_name, self.slot, self.uploader, sealed
            )
        )
        return SealedEscrow(sealed, sig)

    def open(
        self, escrow: SealedEscrow, slot: EscrowSlot | None = None, branch: str | None = None
    ) -> bytes:
        return open_escrow(
            self.branch.escrow_x_sk,
            self.kem_sk,
            self.org_id,
            branch or self.branch_name,
            slot or self.slot,
            self.uploader,
            self.uploader_keys,
            STORED_AT,
            escrow,
            current_key_gen=self.uploader.key_gen,
        )


@pytest.fixture
def world() -> _World:
    return _World()


def test_uploader_signature_input_and_signature_match_the_vector(world: _World) -> None:
    vector = _escrow()
    sealed = bytes.fromhex(vector["seal"]["sealed"])
    signed = uploader_signature_input(
        world.org_id, world.branch_name, world.slot, world.uploader, sealed
    )
    assert signed.hex() == vector["uploader_sig"]["input"]
    assert world.signed(sealed).uploader_sig.hex() == vector["uploader_sig"]["signature"]
    signature = sign_escrow(world.key, world.slot, world.uploader, world.uploader_seed, sealed)
    assert signature.hex() == vector["uploader_sig"]["signature"]


def test_the_vector_seal_opens_to_the_vector_plaintext(world: _World) -> None:
    vector = _escrow()
    escrow = SealedEscrow(
        bytes.fromhex(vector["seal"]["sealed"]), bytes.fromhex(vector["uploader_sig"]["signature"])
    )
    assert world.open(escrow).hex() == vector["plaintext"]["bytes"]


def test_seal_then_open_round_trips(world: _World) -> None:
    plaintext = bytes.fromhex(_escrow()["plaintext"]["bytes"])
    sealed = seal_escrow(world.key, world.slot, world.uploader, plaintext)
    assert world.open(world.signed(sealed)) == plaintext


@pytest.mark.parametrize("name", ["wrong_group", "wrong_epoch", "wrong_branch"])
def test_open_under_another_context_is_refused_and_names_the_uploader(
    world: _World, name: str
) -> None:
    case = next(c for c in _escrow()["negatives"]["open_under"] if c["name"] == name)
    ctx = case["ctx"]
    slot = EscrowSlot(ctx["group_id"], ctx["epoch"], bytes.fromhex(ctx["fp"]))
    sealed = bytes.fromhex(_escrow()["seal"]["sealed"])
    with pytest.raises(EscrowInvalidError) as err:
        open_escrow(
            world.branch.escrow_x_sk,
            world.kem_sk,
            ctx["org_id"],
            ctx["branch"],
            slot,
            world.uploader,
            world.uploader_keys,
            STORED_AT,
            SealedEscrow(sealed, _sign_for(world, ctx, slot, sealed)),
            current_key_gen=world.uploader.key_gen,
        )
    assert err.value.uploader_agent_id == world.uploader.agent_id


def _sign_for(world: _World, ctx: dict[str, Any], slot: EscrowSlot, sealed: bytes) -> bytes:
    """A valid uploader signature for the (wrong) slot, so only the AEAD can refuse."""
    return Ed25519PrivateKey.from_private_bytes(world.uploader_seed).sign(
        uploader_signature_input(ctx["org_id"], ctx["branch"], slot, world.uploader, sealed)
    )


def test_a_signature_over_another_slot_is_forged_and_names_nobody(world: _World) -> None:
    case = _escrow()["negatives"]["signature_over_other_slot"]
    escrow = SealedEscrow(
        bytes.fromhex(_escrow()["seal"]["sealed"]), bytes.fromhex(case["signature"])
    )
    with pytest.raises(EscrowForgedError) as err:
        world.open(escrow)
    assert not isinstance(err.value, EscrowInvalidError)


@pytest.mark.parametrize("name", ["wrong_version", "wrong_suite"])
def test_a_signed_copy_with_a_bad_plaintext_is_invalid(world: _World, name: str) -> None:
    case = next(c for c in _escrow()["negatives"]["bad_plaintexts"] if c["name"] == name)
    escrow = world.signed(bytes.fromhex(case["sealed"]))
    with pytest.raises(EscrowInvalidError):
        world.open(escrow)
    with pytest.raises(CryptoError):
        check_epoch_read_secrets(bytes.fromhex(case["plaintext"]))
    with pytest.raises(CryptoError):
        seal_escrow(world.key, world.slot, world.uploader, bytes.fromhex(case["plaintext"]))


def _open_with(
    world: _World, keys: VerifiedAgentKeys, stored_at: datetime, current_gen: int | None = None
) -> bytes:
    sealed = bytes.fromhex(_escrow()["seal"]["sealed"])
    escrow = SealedEscrow(sealed, bytes.fromhex(_escrow()["uploader_sig"]["signature"]))
    return open_escrow(
        world.branch.escrow_x_sk,
        world.kem_sk,
        world.org_id,
        world.branch_name,
        world.slot,
        world.uploader,
        keys,
        stored_at,
        escrow,
        current_key_gen=world.uploader.key_gen if current_gen is None else current_gen,
    )


@pytest.mark.parametrize("offset", [timedelta(seconds=-1), timedelta(0)])
def test_open_when_the_row_predates_the_supersession_then_it_opens(
    world: _World, offset: timedelta
) -> None:
    keys = replace(world.uploader_keys, superseded_at=STORED_AT)
    assert _open_with(world, keys, STORED_AT + offset).hex() == _escrow()["plaintext"]["bytes"]


def test_open_when_the_row_was_stored_after_the_supersession_then_it_is_forged(
    world: _World,
) -> None:
    keys = replace(world.uploader_keys, superseded_at=STORED_AT)
    with pytest.raises(EscrowForgedError, match="superseded"):
        _open_with(world, keys, STORED_AT + timedelta(microseconds=1))


def test_open_when_a_superseded_generation_carries_no_stamp_then_it_is_forged(
    world: _World,
) -> None:
    with pytest.raises(EscrowForgedError, match="superseded"):
        _open_with(world, world.uploader_keys, STORED_AT, world.uploader.key_gen + 1)


@pytest.mark.parametrize("offset", [timedelta(seconds=-1), timedelta(0)])
def test_open_when_the_row_predates_the_revocation_then_it_opens(
    world: _World, offset: timedelta
) -> None:
    keys = replace(world.uploader_keys, revoked_at=STORED_AT)
    assert _open_with(world, keys, STORED_AT + offset).hex() == _escrow()["plaintext"]["bytes"]


def test_open_when_the_row_was_stored_after_the_revocation_then_it_is_forged(
    world: _World,
) -> None:
    keys = replace(world.uploader_keys, revoked_at=STORED_AT)
    with pytest.raises(EscrowForgedError, match="revoked"):
        _open_with(world, keys, STORED_AT + timedelta(seconds=1))


def test_open_when_the_revocation_precedes_the_supersession_then_the_earlier_bound_wins(
    world: _World,
) -> None:
    keys = replace(
        world.uploader_keys,
        revoked_at=STORED_AT - timedelta(hours=1),
        superseded_at=STORED_AT + timedelta(hours=1),
    )
    with pytest.raises(EscrowForgedError, match="revoked"):
        _open_with(world, keys, STORED_AT, world.uploader.key_gen + 1)


def test_open_when_the_keys_are_another_generation_then_it_is_forged(world: _World) -> None:
    keys = replace(world.uploader_keys, key_gen=world.uploader.key_gen + 1)
    with pytest.raises(EscrowForgedError, match="generation"):
        _open_with(world, keys, STORED_AT)


@pytest.mark.parametrize("field", ["branch", "org_id"])
def test_open_when_the_keys_name_another_branch_or_org_then_it_is_invalid(
    world: _World, field: str
) -> None:
    keys = replace(world.uploader_keys, **{field: "other"})
    with pytest.raises(EscrowInvalidError) as err:
        _open_with(world, keys, STORED_AT)
    assert err.value.uploader_agent_id == world.uploader.agent_id
