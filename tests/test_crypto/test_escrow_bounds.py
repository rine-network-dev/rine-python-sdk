"""The escrow leaf bound: 1000 leaves are accepted, 1001 are refused, and 1000 fit the server."""

from __future__ import annotations

import pytest

from rine._crypto.escrow import (
    ESCROW_CIPHER_SUITE,
    MAX_ESCROW_CONTEXT_LENGTH,
    MAX_ESCROW_LEAVES,
    EscrowSlot,
    EscrowUploader,
    check_epoch_read_secrets,
    seal_escrow,
)
from rine._crypto.escrow_key import VerifiedEscrowKey
from rine.errors import CryptoError
from rine.testing import WORLD

#: The server's ``MAX_SEALED_BYTES``: the largest sealed escrow it stores.
SERVER_MAX_SEALED_BYTES = 40960
_FIXED_PREFIX = 71
_LEAF_ENTRY_SIZE = 36


def _read_secrets(leaves: int, context_length: int = 0) -> bytes:
    """An EpochReadSecrets v1 plaintext with ``leaves`` leaf entries."""
    header = bytes([1]) + ESCROW_CIPHER_SUITE.to_bytes(2, "big")
    header += (1024).to_bytes(4, "big") + bytes(_FIXED_PREFIX - len(header) - 4)
    context = bytes(context_length)
    return (
        header
        + context_length.to_bytes(4, "big")
        + context
        + leaves.to_bytes(4, "big")
        + bytes(_LEAF_ENTRY_SIZE * leaves)
    )


def test_check_epoch_read_secrets_when_the_tree_has_the_bound_then_accepts() -> None:
    assert MAX_ESCROW_LEAVES == 1000
    check_epoch_read_secrets(_read_secrets(MAX_ESCROW_LEAVES))


def test_check_epoch_read_secrets_when_the_tree_exceeds_the_bound_then_refuses() -> None:
    with pytest.raises(CryptoError, match="too many leaves"):
        check_epoch_read_secrets(_read_secrets(MAX_ESCROW_LEAVES + 1))


@pytest.mark.parametrize("tree_leaves", [0, 3, 4096, 0xFFFFFFFF])
def test_check_epoch_read_secrets_when_the_tree_size_is_unbounded_then_refuses(
    tree_leaves: int,
) -> None:
    plaintext = bytearray(_read_secrets(1))
    plaintext[3:7] = tree_leaves.to_bytes(4, "big")

    with pytest.raises(CryptoError, match="tree size"):
        check_epoch_read_secrets(plaintext)


def test_seal_escrow_when_the_worst_case_is_sealed_then_it_fits_the_server_bound() -> None:
    """1000 leaves and a maximum context: the largest blob the client can ever upload."""
    key = VerifiedEscrowKey(
        org_id=WORLD.org_id,
        branch=WORLD.branch.name,
        x25519_public_key=WORLD.branch.escrow_x_pk,
        ml_kem_public_key=WORLD.branch.escrow_kem_pk,
    )
    slot = EscrowSlot("11111111-2222-3333-4444-555555555555", 0, b"\x01" * 16)
    uploader = EscrowUploader("00000000-1111-2222-3333-444444444444", 1)

    sealed = seal_escrow(
        key, slot, uploader, _read_secrets(MAX_ESCROW_LEAVES, MAX_ESCROW_CONTEXT_LENGTH)
    )

    assert len(sealed) <= SERVER_MAX_SEALED_BYTES
