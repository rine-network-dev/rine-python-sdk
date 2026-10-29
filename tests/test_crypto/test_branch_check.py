"""The held branch secrets are proven against the branch certificate."""

from __future__ import annotations

from typing import Any

import pytest

from rine._crypto.branch_check import HELD_BRANCH_INVALID, HeldBranchError, verify_held_branch
from rine._crypto.derive_nodes import branch_from_secrets
from rine.testing import WORLD, World

OTHER = World(branch_name="other")
OTHER_ORG = World(root=bytes(range(1, 33)))


def _response(world: World = WORLD) -> dict[str, Any]:
    """A chain-valid escrow-key response, which carries the branch certificate."""
    return world.escrow_response()


def test_genuine_secrets_pass() -> None:
    branch = verify_held_branch(_response(), WORLD.branch, WORLD.org_id)
    assert (branch.org_id, branch.name) == (WORLD.org_id, WORLD.branch.name)


def test_a_wrong_read_half_is_refused() -> None:
    node = branch_from_secrets(WORLD.branch.name, OTHER.branch.b_read, WORLD.branch.b_sign)
    with pytest.raises(HeldBranchError, match="read half"):
        verify_held_branch(_response(), node, WORLD.org_id)


def test_a_wrong_signing_half_is_refused() -> None:
    node = branch_from_secrets(WORLD.branch.name, WORLD.branch.b_read, OTHER.branch.b_sign)
    with pytest.raises(HeldBranchError, match="signing half"):
        verify_held_branch(_response(), node, WORLD.org_id)


def test_another_org_is_refused() -> None:
    with pytest.raises(HeldBranchError, match="another org"):
        verify_held_branch(_response(), WORLD.branch, OTHER_ORG.org_id)


def test_a_response_naming_another_branch_is_refused() -> None:
    with pytest.raises(HeldBranchError, match="another branch"):
        verify_held_branch(_response(OTHER), WORLD.branch, WORLD.org_id)


def test_a_malformed_response_is_refused() -> None:
    with pytest.raises(HeldBranchError, match=HELD_BRANCH_INVALID):
        verify_held_branch({}, WORLD.branch, WORLD.org_id)
