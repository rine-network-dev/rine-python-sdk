"""The MLS credential is the agent id, and only chain-verified identities may be seated."""

from __future__ import annotations

import pytest

from rine._crypto.keys import save_agent_keys
from rine._mls.binding import (
    AllowedIdentities,
    MlsCoreError,
    credential_identity,
    local_allowed_identities,
    open_mls_client,
)
from rine.errors import CryptoError
from rine.testing import WORLD

ALICE = "00000000-1111-2222-3333-444444444444"
BOB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GROUP = b"\x01" * 16


@pytest.fixture
def config_dir(tmp_config_dir: str) -> str:
    for agent_id in (ALICE, BOB):
        save_agent_keys(tmp_config_dir, agent_id, WORLD.keys(agent_id))
    return tmp_config_dir


def test_the_credential_identity_is_the_ascii_of_the_canonical_agent_id() -> None:
    identity = credential_identity(ALICE.upper())
    assert identity == ALICE.encode("ascii")
    assert len(identity) == 36


def test_a_credential_identity_for_a_non_agent_id_is_refused() -> None:
    with pytest.raises(CryptoError):
        credential_identity("not-an-agent")


def test_the_local_allowed_set_holds_every_saved_agent_with_its_mls_key(config_dir: str) -> None:
    allowed = local_allowed_identities(config_dir)
    for agent_id in (ALICE, BOB):
        assert allowed.contains(credential_identity(agent_id), WORLD.keys(agent_id).mls.public_key)
    assert not allowed.contains(credential_identity(ALICE), WORLD.keys(BOB).mls.public_key)


def test_the_client_leaf_key_is_the_derived_mls_key(config_dir: str) -> None:
    client = open_mls_client(config_dir, ALICE)
    assert client.agent_id() == ALICE.encode("ascii")
    assert client.leaf_public_key() == WORLD.keys(ALICE).mls.public_key


def test_a_client_seats_an_allowed_agent_and_refuses_one_outside_its_set(config_dir: str) -> None:
    bob_package = open_mls_client(config_dir, BOB).generate_key_package()
    seated = open_mls_client(config_dir, ALICE).create_group(GROUP)
    seated.add_member(bob_package)

    only_alice = AllowedIdentities()
    only_alice.insert(credential_identity(ALICE), WORLD.keys(ALICE).mls.public_key, 0)
    strict = open_mls_client(config_dir, ALICE, allowed=only_alice)
    other_group = strict.create_group(b"\x02" * 16)
    with pytest.raises(MlsCoreError):
        other_group.add_member(bob_package)
