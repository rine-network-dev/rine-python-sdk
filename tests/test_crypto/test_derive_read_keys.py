"""The read-only key helpers and ``branch_from_secrets`` match the full builders."""

from __future__ import annotations

import pytest

from rine._crypto import _mlkem
from rine._crypto.derive_nodes import (
    agent_read_keys,
    branch_from_secrets,
    derive_agent,
    derive_branch,
    escrow_read_keys,
)
from rine.errors import CryptoError
from rine.testing import WORLD

AGENT = "00000000-1111-2222-3333-444444444444"


def test_agent_read_keys_equal_the_agent_node() -> None:
    node = derive_agent(WORLD.branch.b_read, WORLD.branch.b_sign, AGENT, 1)
    x_sk, kem_sk = agent_read_keys(WORLD.branch.b_read, AGENT, 1)
    assert x_sk == node.x_sk
    assert kem_sk == _mlkem.key_pair_from_seed(node.kem_seed)[1]


def test_escrow_read_keys_equal_the_branch_node() -> None:
    x_sk, kem_sk = escrow_read_keys(WORLD.branch.b_read)
    assert x_sk == WORLD.branch.escrow_x_sk
    assert kem_sk == _mlkem.key_pair_from_seed(WORLD.branch.escrow_kem_seed)[1]


def test_branch_from_secrets_equals_derive_branch() -> None:
    node = branch_from_secrets(WORLD.branch.name, WORLD.branch.b_read, WORLD.branch.b_sign)
    assert node == WORLD.branch


@pytest.mark.parametrize("gen", [-1, True, "0"])
def test_agent_read_keys_refuse_a_bad_generation(gen: object) -> None:
    with pytest.raises(CryptoError, match="invalid generation"):
        agent_read_keys(WORLD.branch.b_read, AGENT, gen)  # type: ignore[arg-type]


@pytest.mark.parametrize("secrets", [(b"short", WORLD.branch.b_sign), (WORLD.branch.b_read, b"")])
def test_branch_from_secrets_refuses_a_short_secret(secrets: tuple[bytes, bytes]) -> None:
    with pytest.raises(CryptoError, match="32 bytes"):
        branch_from_secrets(WORLD.branch.name, *secrets)


def test_branch_from_secrets_refuses_a_bad_name() -> None:
    with pytest.raises(CryptoError, match="branch name"):
        branch_from_secrets("Bad Name", WORLD.branch.b_read, WORLD.branch.b_sign)


def test_derive_branch_still_matches_branch_from_secrets() -> None:
    assert derive_branch(WORLD.org.r_read, WORLD.org.r_sign, WORLD.branch.name) == WORLD.branch
