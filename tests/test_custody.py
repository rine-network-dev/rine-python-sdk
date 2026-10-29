"""Which principal a directory acts as, and which key signs for it.

The runtime dir and the owner dir are built with the real helpers, so every
resolution reads the same ``profiles.json``, ``root.key`` and branch key files
production reads. A second world stands in for a different org's owner dir.
"""

from __future__ import annotations

import os

import pytest

from rine import RineClient, SyncRineClient
from rine._custody import (
    BranchSecrets,
    Custody,
    Signer,
    load_custody,
    local_agent_ids,
    resolve_auth,
)
from rine._principal import agent_principal, branch_principal, org_principal
from rine._profiles import add_profile_if_absent
from rine._types import Profile
from rine._utils import to_base64url
from rine.errors import ConfigError
from rine.testing import WORLD, World, write_agent_identity, write_owner

AGENT_ID = "00000000-1111-2222-3333-444444444444"
OTHER_WORLD = World(root=bytes(range(1, 33)))


def _runtime_dir(tmp_path, name: str = "runtime") -> str:
    """A runtime dir holding the fixed agent's leaf keys and profile."""
    config_dir = str(tmp_path / name)
    write_agent_identity(config_dir, AGENT_ID)
    return config_dir


def _owner_dir(tmp_path, world: World = WORLD, name: str = "owner") -> str:
    """An owner dir holding ``world``'s root and org profile."""
    owner_dir = str(tmp_path / name)
    write_owner(owner_dir, world=world)
    return owner_dir


def _write_branch_files(config_dir: str, name: str, read: bytes, sign: bytes) -> None:
    """Write a delegate's two branch secrets under ``branch/<name>/``."""
    folder = os.path.join(config_dir, "branch", name)
    os.makedirs(folder, exist_ok=True)
    for filename, secret in (("read.key", read), ("sign.key", sign)):
        with open(os.path.join(folder, filename), "w") as f:
            f.write(to_base64url(secret))


def test_resolve_auth_when_agent_profile_and_no_root_then_agent_signer(tmp_path):
    """A runtime dir with no owner root acts as its agent, caching beside its keys."""
    config_dir = _runtime_dir(tmp_path)
    owner_dir = str(tmp_path / "empty-owner")
    resolved = resolve_auth(config_dir, owner_dir)
    assert resolved is not None
    assert resolved.signer == Signer(
        agent_principal(AGENT_ID), WORLD.keys(AGENT_ID).signing.private_key
    )
    assert resolved.cache_dir == config_dir
    assert resolved.org_id == WORLD.org_id


def test_resolve_auth_when_owner_root_same_org_then_org_signer(tmp_path):
    """The owner dir's root and profile win for the default profile of the same org."""
    config_dir = _runtime_dir(tmp_path)
    owner_dir = _owner_dir(tmp_path)
    resolved = resolve_auth(config_dir, owner_dir)
    assert resolved is not None
    assert resolved.signer == Signer(org_principal(WORLD.org_id), WORLD.org.ed_seed)
    assert resolved.cache_dir == owner_dir


def test_resolve_auth_when_owner_root_other_org_then_agent_signer(tmp_path):
    """A second org's root never signs the first org's runtime dir."""
    config_dir = _runtime_dir(tmp_path)
    owner_dir = _owner_dir(tmp_path, world=OTHER_WORLD)
    resolved = resolve_auth(config_dir, owner_dir)
    assert resolved is not None
    assert resolved.signer.principal == agent_principal(AGENT_ID)
    assert resolved.cache_dir == config_dir


def test_resolve_auth_when_named_profile_only_in_runtime_then_runtime_signer(tmp_path):
    """A named profile is looked up in the runtime dir first."""
    config_dir = _runtime_dir(tmp_path)
    add_profile_if_absent(
        config_dir,
        "x",
        Profile(org_id=WORLD.org_id, principal=str(agent_principal(AGENT_ID))),
    )
    owner_dir = str(tmp_path / "empty-owner")
    resolved = resolve_auth(config_dir, owner_dir, profile="x")
    assert resolved is not None
    assert resolved.signer.principal == agent_principal(AGENT_ID)
    assert resolved.cache_dir == config_dir


def test_resolve_auth_when_profile_org_differs_from_its_principal_then_refuses(tmp_path):
    """The profile's org id is what own agents get pinned to, so it must match the principal."""
    owner_dir = str(tmp_path / "owner")
    write_owner(owner_dir, world=WORLD)
    forged = str(tmp_path / "runtime")
    add_profile_if_absent(
        forged,
        "default",
        Profile(org_id=OTHER_WORLD.org_id, principal=str(org_principal(WORLD.org_id))),
    )
    with pytest.raises(ConfigError, match="does not match"):
        resolve_auth(forged, owner_dir)


def test_resolve_auth_when_root_derives_another_org_than_the_profile_names_then_refuses(tmp_path):
    """A branch profile signed from ``root.key`` must name the org that root derives."""
    config_dir = str(tmp_path / "runtime")
    owner_dir = _owner_dir(tmp_path)
    add_profile_if_absent(
        config_dir,
        "ci",
        Profile(
            org_id=OTHER_WORLD.org_id,
            principal=str(branch_principal(OTHER_WORLD.org_id, "main")),
        ),
    )
    with pytest.raises(ConfigError, match="does not match"):
        resolve_auth(config_dir, owner_dir, profile="ci")


def test_resolve_auth_when_profile_nowhere_then_none(tmp_path):
    """A name no directory holds resolves to nothing."""
    config_dir = _runtime_dir(tmp_path)
    owner_dir = str(tmp_path / "empty-owner")
    assert resolve_auth(config_dir, owner_dir, profile="nowhere") is None


def test_resolve_auth_when_both_dirs_empty_then_none(tmp_path):
    """No profile anywhere means this process holds no identity to act as."""
    assert resolve_auth(str(tmp_path / "runtime"), str(tmp_path / "owner")) is None


def test_load_custody_when_owner_root_then_branch_derived_from_root(tmp_path):
    """The owner root derives the branch, matching the world's own derivation."""
    config_dir = str(tmp_path / "runtime")
    owner_dir = _owner_dir(tmp_path)
    custody = load_custody(config_dir, owner_dir, "main")
    assert custody == Custody(WORLD.org_id, BranchSecrets.from_node(WORLD.branch))
    assert custody.branch.ed_seed == WORLD.branch.ed_seed
    assert custody.branch.reader_seed == WORLD.branch.reader_seed


def test_load_custody_when_delegate_files_then_same_branch_seeds(tmp_path):
    """A delegate's two secrets derive the same branch seeds as the root does."""
    config_dir = str(tmp_path / "runtime")
    _write_branch_files(config_dir, "main", WORLD.branch.b_read, WORLD.branch.b_sign)
    add_profile_if_absent(
        config_dir,
        "default",
        Profile(
            org_id=WORLD.org_id,
            principal=str(agent_principal(AGENT_ID)),
            branch="main",
            agent_id=AGENT_ID,
        ),
    )
    owner_dir = str(tmp_path / "empty-owner")
    custody = load_custody(config_dir, owner_dir, "main")
    assert custody.org_id == WORLD.org_id
    assert custody.branch.ed_seed == WORLD.branch.ed_seed
    assert custody.branch.reader_seed == WORLD.branch.reader_seed


def test_load_custody_when_no_key_material_then_config_error(tmp_path):
    """Neither a root nor delegate files is a refusal naming what is missing."""
    with pytest.raises(ConfigError, match="No key material"):
        load_custody(str(tmp_path / "runtime"), str(tmp_path / "owner"), "main")


def test_load_custody_when_delegate_file_wrong_length_then_config_error(tmp_path):
    """A branch key file that is not 32 bytes is refused as corrupt."""
    config_dir = str(tmp_path / "runtime")
    _write_branch_files(config_dir, "main", bytes(16), WORLD.branch.b_sign)
    with pytest.raises(ConfigError, match="Corrupt branch key file"):
        load_custody(config_dir, str(tmp_path / "owner"), "main")


def test_local_agent_ids_when_keys_dir_holds_ids_then_lists_them(tmp_path):
    """The ids under ``keys/`` are listed, and a non-UUID name is ignored."""
    config_dir = _runtime_dir(tmp_path)
    os.makedirs(os.path.join(config_dir, "keys", "not-a-uuid"), exist_ok=True)
    assert local_agent_ids(config_dir) == [AGENT_ID]


def test_local_agent_ids_when_keys_dir_missing_then_empty(tmp_path):
    """A config dir with no ``keys/`` holds no agent ids."""
    assert local_agent_ids(str(tmp_path / "runtime")) == []


def test_resolve_auth_when_no_owner_dir_then_agent_signer_whatever_the_host_holds(tmp_path):
    """``None`` is "never read an owner dir": the populated one beside it is ignored."""
    config_dir = _runtime_dir(tmp_path)
    _owner_dir(tmp_path)
    resolved = resolve_auth(config_dir, None)
    assert resolved is not None
    assert resolved.signer.principal == agent_principal(AGENT_ID)
    assert resolved.cache_dir == config_dir


def test_load_custody_when_no_owner_dir_and_no_branch_files_then_config_error(tmp_path):
    """An agent-only process cannot derive a branch: it holds no root."""
    config_dir = _runtime_dir(tmp_path)
    with pytest.raises(ConfigError):
        load_custody(config_dir, None, "main")


@pytest.mark.parametrize("client_class", [RineClient, SyncRineClient])
def test_client_when_agent_only_and_host_owner_dir_populated_then_acts_as_the_agent(
    tmp_path, monkeypatch, client_class
):
    """A host that onboarded holds ``root.key``; an agent runtime still signs as its agent."""
    config_dir = _runtime_dir(tmp_path)
    monkeypatch.setenv("RINE_OWNER_DIR", _owner_dir(tmp_path))

    default = client_class(config_dir=config_dir, api_url="http://rine.test")
    agent_only = client_class(config_dir=config_dir, api_url="http://rine.test", agent_only=True)

    assert default._http._auth.resolved().signer.principal == org_principal(WORLD.org_id)
    assert agent_only._http._auth.resolved().signer.principal == agent_principal(AGENT_ID)


def test_client_when_agent_only_with_an_owner_dir_then_config_error(tmp_path):
    """The two options contradict each other, so the client refuses rather than choosing."""
    with pytest.raises(ConfigError):
        SyncRineClient(config_dir=str(tmp_path), owner_dir=str(tmp_path / "o"), agent_only=True)
