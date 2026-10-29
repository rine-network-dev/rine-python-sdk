"""Which identity a client's whoami check and start-up escrow sweep act for."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine import SyncRineClient
from rine.testing import WORLD, write_agent_identity, write_owner
from tests.test_mls_escrow_drain import AGENT

if TYPE_CHECKING:
    from pathlib import Path


def _client(config_dir: Path, owner_dir: Path) -> SyncRineClient:
    return SyncRineClient(
        config_dir=str(config_dir), owner_dir=str(owner_dir), api_url="https://rine.network"
    )


def test_local_org_id_when_only_the_owner_dir_holds_a_profile_then_it_names_that_org(
    tmp_path: Path,
) -> None:
    """The org comes from the resolved auth, which prefers the owner dir's profile."""
    write_owner(str(tmp_path / "owner"))

    with _client(tmp_path / "cfg", tmp_path / "owner") as client:
        assert client._local_org_id() == WORLD.org_id


def test_escrow_sweep_agent_when_an_agent_profile_resolves_then_it_is_that_agent(
    tmp_path: Path,
) -> None:
    """An agent principal acts as itself, so the sweep is limited to its own files."""
    write_agent_identity(str(tmp_path / "cfg"), AGENT)

    with _client(tmp_path / "cfg", tmp_path / "owner") as client:
        assert client._escrow_sweep_agent() == AGENT


def test_escrow_sweep_agent_when_the_org_root_resolves_then_every_local_agent_may_be_swept(
    tmp_path: Path,
) -> None:
    """An org principal may act for any of its agents."""
    write_owner(str(tmp_path / "owner"))
    write_agent_identity(str(tmp_path / "cfg"), AGENT)

    with _client(tmp_path / "cfg", tmp_path / "owner") as client:
        assert client._escrow_sweep_agent() is None


def test_escrow_sweep_agent_when_no_identity_resolves_then_it_is_none(tmp_path: Path) -> None:
    """No identity: nothing is swept for a named agent."""
    with _client(tmp_path / "cfg", tmp_path / "owner") as client:
        assert client._escrow_sweep_agent() is None
