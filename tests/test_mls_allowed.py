"""The peer-aware MLS allowed set: seeding, admission and the group read."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from rine._mls.allowed import admit_group_peers, admit_peers
from rine._mls.binding import MlsCoreError, allowed_for, credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes
from rine._mls.heartbeat import MlsActor
from rine.testing import WORLD, World, write_agent_identity
from tests.test_crypto.world import KeyServer

AGENT = "00000000-1111-2222-3333-444444444444"
PEER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SIBLING = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP = "11111111-2222-3333-4444-555555555555"

Tamper = Callable[[dict[str, Any]], dict[str, Any]]


class FakeClient:
    """A sync client serving the batch key read, the group tree and single reads."""

    def __init__(self, world: World = WORLD) -> None:
        """Serve one world's keys, recording every call."""
        self._keys = KeyServer(world)
        self.key_pins = self._keys.key_pins
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.tamper: Tamper | None = None
        self.members: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []

    @property
    def _keys_cache(self) -> Any:
        return self._keys._keys_cache

    def _body(self, agent_id: str) -> dict[str, Any]:
        gen = self._keys.published.get(agent_id, 0)
        body = self._keys.world.keys_response(agent_id, gen)
        return self.tamper(body) if self.tamper else body

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer a batch key read, a group tree read, or a single key read."""
        self.calls.append((path, kwargs))
        if path == "/agents/keys":
            ids = str((kwargs.get("params") or {}).get("ids", "")).split(",")
            return {"keys": {i: self._body(i) for i in ids if i}}
        if path.endswith("/members"):
            return {"items": self.members}
        if path.endswith("/requests"):
            return {"items": self.requests}
        return self._keys.get(path, **kwargs)

    def batch_reads(self) -> int:
        """How many batch key reads this client has served."""
        return sum(1 for path, _ in self.calls if path == "/agents/keys")


@pytest.fixture
def actor(tmp_path: Any) -> MlsActor:
    """An actor whose own leaf keys are on disk."""
    config_dir = str(tmp_path)
    write_agent_identity(config_dir, AGENT)
    return MlsActor(client=FakeClient(), config_dir=config_dir, agent_id=AGENT)


def test_allowed_for_when_called_twice_then_returns_the_same_seeded_set(actor: MlsActor) -> None:
    """One object per (config dir, agent), seeded with the local pairs."""
    first = allowed_for(actor.config_dir, AGENT)
    assert first is allowed_for(actor.config_dir, AGENT)
    assert first.contains(credential_identity(AGENT), WORLD.keys(AGENT).mls.public_key)
    assert allowed_for(actor.config_dir, PEER) is not first


def test_open_mls_client_when_no_allowed_argument_then_uses_the_shared_set(
    actor: MlsActor,
) -> None:
    """A pair inserted after the client was opened is in the set the client holds."""
    open_mls_client(actor.config_dir, AGENT)
    allowed_for(actor.config_dir, AGENT).insert(
        credential_identity(PEER), WORLD.keys(PEER).mls.public_key, 0
    )
    assert allowed_for(actor.config_dir, AGENT).contains(
        credential_identity(PEER), WORLD.keys(PEER).mls.public_key
    )


def test_admit_peers_when_the_peer_rotated_then_inserts_every_generation(
    actor: MlsActor,
) -> None:
    """key_gen 2 inserts generations 0, 1 and 2."""
    actor.client._keys.publish(PEER, 2)

    inserted = admit_peers(actor, [PEER])

    allowed = allowed_for(actor.config_dir, AGENT)
    assert inserted == [PEER]
    for gen in range(3):
        assert allowed.contains(credential_identity(PEER), WORLD.keys(PEER, gen).mls.public_key)


def test_admit_peers_when_the_batch_entry_fails_the_chain_then_skips_the_peer(
    actor: MlsActor,
) -> None:
    """A peer whose batch entry does not chain is never inserted."""
    actor.client.tamper = lambda body: {
        **body,
        "agent_certificate": WORLD.keys_response(SIBLING)["agent_certificate"],
    }

    inserted = admit_peers(actor, [PEER])

    assert inserted == []
    assert not allowed_for(actor.config_dir, AGENT).contains(
        credential_identity(PEER), WORLD.keys(PEER).mls.public_key
    )


def test_admit_peers_when_a_history_generation_fails_the_chain_then_skips_only_it(
    actor: MlsActor,
) -> None:
    """The generations that verify are inserted; the one that does not is skipped."""
    actor.client._keys.publish(PEER, 2)
    actor.client._keys.tamper = lambda body: (
        {**body, "agent_certificate": WORLD.keys_response(SIBLING)["agent_certificate"]}
        if body["key_gen"] == 1
        else body
    )

    inserted = admit_peers(actor, [PEER])

    allowed = allowed_for(actor.config_dir, AGENT)
    assert inserted == [PEER]
    for gen in (0, 2):
        assert allowed.contains(credential_identity(PEER), WORLD.keys(PEER, gen).mls.public_key)
    assert not allowed.contains(credential_identity(PEER), WORLD.keys(PEER, 1).mls.public_key)


def test_admit_peers_when_the_agent_is_local_then_fetches_nothing(actor: MlsActor) -> None:
    """A local agent's pairs are already in the seeded set."""
    inserted = admit_peers(actor, [AGENT])

    assert inserted == []
    assert actor.client.batch_reads() == 0


def test_admit_group_peers_when_members_and_outstanding_then_admits_both(
    actor: MlsActor,
) -> None:
    """Members and every live voucher are admitted, the pending one included."""
    actor.client.members = [{"agent_id": PEER}]
    actor.client.requests = [
        {"agent_id": SIBLING, "status": "invited", "invited_by": PEER},
        {"agent_id": "cccccccc-dddd-eeee-ffff-000000000000", "status": "pending"},
    ]

    admit_group_peers(actor, GROUP)

    allowed = allowed_for(actor.config_dir, AGENT)
    for agent_id in (PEER, SIBLING, "cccccccc-dddd-eeee-ffff-000000000000"):
        assert allowed.contains(credential_identity(agent_id), WORLD.keys(agent_id).mls.public_key)


def test_add_members_when_the_key_package_leaf_is_not_the_certified_key_then_the_core_refuses(
    actor: MlsActor, tmp_path: Any
) -> None:
    """A claimed KeyPackage whose leaf key differs from the chain-verified one is refused.

    The server could hand back a KeyPackage minted under its own key for the
    peer's id; the allowed set holds only chain-verified ``(id, key)`` pairs, so
    the core refuses the leaf.
    """
    peer_dir = str(tmp_path / "peer")
    write_agent_identity(peer_dir, PEER)
    key_package = open_mls_client(peer_dir, PEER).generate_key_packages(1)[0]
    mine = allowed_for(actor.config_dir, AGENT)
    mine.insert(credential_identity(PEER), WORLD.keys(SIBLING).mls.public_key, 0)
    group_id = mls_group_id_bytes(GROUP)

    with pytest.raises(MlsCoreError):
        open_mls_client(actor.config_dir, AGENT).create_group_with_members(group_id, [key_package])

    mine.insert(credential_identity(PEER), WORLD.keys(PEER).mls.public_key, 0)
    group = open_mls_client(actor.config_dir, AGENT).create_group_with_members(
        group_id, [key_package]
    )
    assert group.last_commit() is not None
