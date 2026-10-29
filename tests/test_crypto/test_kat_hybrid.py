"""Known-answer tests for ``hpke-hybrid-v2`` and the ``SealContext`` union.

The vectors live in the shared ``org-root-v1.json`` fixture, so the Python and
TypeScript stacks are replayed against the same bytes. The fixture's ``seal``
section pins the key schedule and the AAD; ``open_negatives`` pins every
refusal, including the retired ``0x03`` version byte.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rine._crypto import _mlkem, hybrid
from rine._crypto.hybrid import (
    AgentMessage,
    BranchBundle,
    MlsEscrow,
    SealContext,
    derive_key,
    seal,
    seal_context_aad,
)
from rine.errors import CryptoError
from tests.test_crypto.kat import load_kat


def _hybrid() -> dict[str, Any]:
    """Return the fixture's ``hybrid_v2`` section."""
    return load_kat()["hybrid_v2"]


def _build_ctx(kind: str, args: dict[str, Any]) -> SealContext:
    """Build a :data:`SealContext` from a fixture ``kind`` and its ``args``."""
    if kind == "AgentMessage":
        return AgentMessage(recipient_agent_id=args["recipient_agent_id"])
    if kind == "BranchBundle":
        return BranchBundle(org_id=args["org_id"], branch=args["branch"])
    if kind == "MlsEscrow":
        return MlsEscrow(
            org_id=args["org_id"],
            branch=args["branch"],
            group_id=args["group_id"],
            epoch=args["epoch"],
            uploader_agent_id=args["uploader_agent_id"],
            fp=bytes.fromhex(args["fp"]),
        )
    raise AssertionError(f"unknown context kind: {kind}")


def _recipient_keys(recipient: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    """Return ``(x25519_sk, x25519_pk, mlkem_pk, mlkem_sk)`` for a recipient."""
    root = load_kat()["roots"]["roots"][recipient["root"]]
    agent = next(a for a in root["agents"] if a["id"] == recipient["agent_id"])
    gen = next(g for g in agent["gens"] if g["gen"] == recipient["gen"])
    mlkem_pk, mlkem_sk = _mlkem.key_pair_from_seed(bytes.fromhex(gen["ml_kem_768"]["seed"]))
    return (
        bytes.fromhex(gen["x25519"]["sk"]),
        bytes.fromhex(gen["x25519"]["pk"]),
        mlkem_pk,
        mlkem_sk,
    )


class TestSealContextAad:
    """Every fixture context encodes to its pinned AAD bytes."""

    def test_aad_matches_fixture(self) -> None:
        """Each ``aad`` entry re-encodes byte-for-byte."""
        for entry in _hybrid()["aad"]:
            ctx = _build_ctx(entry["kind"], entry["args"])
            assert seal_context_aad(ctx).hex() == entry["aad"], entry["kind"]


class TestSeal:
    """The fixture's seal vector replays through the key schedule and AEAD."""

    def test_key_schedule_and_open(self) -> None:
        """The derived key, AAD, decapsulation and open all match the fixture."""
        entry = _hybrid()["seal"]
        ctx = _build_ctx(entry["ctx"]["kind"], entry["ctx"])
        x_sk, recipient_pk, _, kem_sk = _recipient_keys(entry["recipient"])

        assert (
            derive_key(
                bytes.fromhex(entry["ss_ml_kem"]),
                bytes.fromhex(entry["ss_x25519"]),
                bytes.fromhex(entry["ephemeral_pk"]),
                recipient_pk,
            ).hex()
            == entry["key"]
        )
        assert seal_context_aad(ctx).hex() == entry["aad"]
        assert (
            _mlkem.decapsulate(bytes.fromhex(entry["ml_kem_ciphertext"]), kem_sk).hex()
            == entry["ss_ml_kem"]
        )
        assert hybrid.open(x_sk, kem_sk, bytes.fromhex(entry["wire"]), ctx) == (
            entry["plaintext_utf8"].encode()
        )


class TestOpenNegatives:
    """Every fixture negative is refused with a ``CryptoError``."""

    def test_every_negative_is_refused(self) -> None:
        """Each negative wire is refused under its context."""
        entry = _hybrid()["seal"]
        x_sk, _, _, kem_sk = _recipient_keys(entry["recipient"])
        for negative in _hybrid()["open_negatives"]:
            assert negative["expect"] == "refuse"
            ctx = _build_ctx(negative["ctx"]["kind"], negative["ctx"])
            with pytest.raises(CryptoError):
                hybrid.open(x_sk, kem_sk, bytes.fromhex(negative["wire"]), ctx)


class TestMlKemModulus:
    """The ML-KEM modulus vectors: the control encapsulates, the negative does not."""

    def test_control_encapsulates(self) -> None:
        """A well-formed encapsulation key produces a ciphertext and secret."""
        control = load_kat()["signatures"]["ml_kem_modulus"]["control"]
        assert control["expect"] == "accept"
        ciphertext, shared_secret = _mlkem.encapsulate(bytes.fromhex(control["ek"]))
        assert len(ciphertext) == _mlkem.CIPHERTEXT_SIZE
        assert len(shared_secret) == _mlkem.SHARED_SECRET_SIZE

    def test_negative_is_refused(self) -> None:
        """A coefficient at or above q is refused by the wheel."""
        negative = load_kat()["signatures"]["ml_kem_modulus"]["negative"]
        assert negative["expect"] == "refuse"
        with pytest.raises(_mlkem.MlKemError):
            _mlkem.encapsulate(bytes.fromhex(negative["ek"]))


def _fresh_keys() -> tuple[bytes, bytes, bytes, bytes]:
    """Return ``(x_sk, x_pk, mlkem_pk, mlkem_sk)`` for a fresh recipient."""
    x_sk = X25519PrivateKey.generate()
    mlkem_pk, mlkem_sk = _mlkem.generate_key_pair()
    return x_sk.private_bytes_raw(), x_sk.public_key().public_bytes_raw(), mlkem_pk, mlkem_sk


def _contexts() -> list[SealContext]:
    """Return one fresh context of each kind."""
    return [
        AgentMessage(recipient_agent_id="8558188f-7713-44e4-824d-c2e060c9c5e1"),
        BranchBundle(org_id="f89b5784-b1da-832f-8db2-4e46a5cec787", branch="main"),
        MlsEscrow(
            org_id="f89b5784-b1da-832f-8db2-4e46a5cec787",
            branch="main",
            group_id="b56ab59d-d286-4c64-9d82-722fc43b948d",
            epoch=7,
            uploader_agent_id="8558188f-7713-44e4-824d-c2e060c9c5e1",
            fp=bytes.fromhex("4808b1392700ffe4bbf28bb30ee5e821"),
        ),
    ]


class TestRoundTrip:
    """Fresh keys round-trip through seal and open for every context kind."""

    @pytest.mark.parametrize("index", [0, 1, 2])
    def test_round_trip(self, index: int) -> None:
        """A sealed payload opens under the same context."""
        x_sk, x_pk, mlkem_pk, mlkem_sk = _fresh_keys()
        ctx = _contexts()[index]
        plaintext = b"round trip plaintext"
        wire = seal(x_pk, mlkem_pk, plaintext, ctx)
        assert wire[0] == hybrid.VERSION_HYBRID == 0x04
        assert hybrid.open(x_sk, mlkem_sk, wire, ctx) == plaintext

    def test_flipped_ciphertext_byte_is_refused(self) -> None:
        """A single flipped byte in the AEAD body fails authentication."""
        x_sk, x_pk, mlkem_pk, mlkem_sk = _fresh_keys()
        ctx = _contexts()[0]
        wire = bytearray(seal(x_pk, mlkem_pk, b"tamper me", ctx))
        wire[-1] ^= 0x01
        with pytest.raises(CryptoError):
            hybrid.open(x_sk, mlkem_sk, bytes(wire), ctx)

    def test_different_context_of_same_kind_is_refused(self) -> None:
        """A payload sealed for one agent does not open for another."""
        x_sk, x_pk, mlkem_pk, mlkem_sk = _fresh_keys()
        wire = seal(
            x_pk,
            mlkem_pk,
            b"bound",
            AgentMessage(recipient_agent_id="00000000-0000-4000-8000-00000000000a"),
        )
        with pytest.raises(CryptoError):
            hybrid.open(
                x_sk,
                mlkem_sk,
                wire,
                AgentMessage(recipient_agent_id="00000000-0000-4000-8000-00000000000b"),
            )

    @pytest.mark.parametrize(
        "ctx",
        [
            AgentMessage(recipient_agent_id="agent\x00a"),
            AgentMessage(recipient_agent_id="00000000-0000-4000-8000-00000000000A"),
            BranchBundle(org_id="00000000-0000-4000-8000-00000000000a", branch="Bad Branch"),
        ],
    )
    def test_non_canonical_context_ids_are_refused_at_seal(self, ctx: SealContext) -> None:
        """AAD builders refuse ids that are not canonical NUL-free UUIDs or branch names."""
        _, x_pk, mlkem_pk, _ = _fresh_keys()
        with pytest.raises(CryptoError):
            seal(x_pk, mlkem_pk, b"x", ctx)

    def test_retired_version_byte_is_refused(self) -> None:
        """A payload whose first byte is ``0x03`` is refused by version."""
        x_sk, x_pk, mlkem_pk, mlkem_sk = _fresh_keys()
        ctx = _contexts()[0]
        wire = bytearray(seal(x_pk, mlkem_pk, b"retired", ctx))
        wire[0] = 0x03
        with pytest.raises(CryptoError, match="0x03"):
            hybrid.open(x_sk, mlkem_sk, bytes(wire), ctx)

    def test_sealing_twice_differs(self) -> None:
        """Fresh KEM randomness makes two seals of one plaintext differ."""
        _, x_pk, mlkem_pk, _ = _fresh_keys()
        ctx = _contexts()[0]
        first = seal(x_pk, mlkem_pk, b"same plaintext", ctx)
        second = seal(x_pk, mlkem_pk, b"same plaintext", ctx)
        assert first != second
