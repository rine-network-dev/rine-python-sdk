"""Siblings in one config dir admit each other's superseded leaves, in a fresh process.

These drive the real ``rine-mls`` core. Agents ``A`` and ``B`` share a config
dir; ``A`` rotates its key after it was seated in a group, so the tree holds
``A``'s generation-0 leaf while the disk holds generation 1. A process that
started after the rotation seeds only the current pair, so without the history
admission it refuses ``A``'s commits and the Welcomes built on ``A``'s old leaf.
"""

from __future__ import annotations

import pytest

from rine._crypto.keys import save_agent_keys
from rine._mls.allowed import admit_peers
from rine._mls.binding import allowed_for, credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.heartbeat import MlsActor
from rine._mls.sync import sync_mls_group
from rine._mls.welcomes import process_mls_welcomes
from rine._mls.wire import mls_to_base64
from rine.testing import WORLD
from tests.rotation_world import (
    G1,
    G2,
    A,
    B,
    C,
    R,
    Server,
    admit,
    fresh_process,
    rotate,
    world,
)

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")


@pytest.fixture(autouse=True)
def _cold_process():
    fresh_process()
    yield
    fresh_process()


def a_commits_add_c(server: Server, d1: str, dc: str) -> None:
    """The rotated ``A`` commits an Add of ``C`` (with an UpdatePath) and posts it."""
    admit(d1, A, (C, 0))
    kp_c = open_mls_client(dc, C, allowed=allowed_for(dc, C)).generate_key_package()
    group = open_mls_group(d1, A, G1)
    bundle = group.add_member(kp_c)
    group.save()
    server.post_commit(G1, bundle)
    server.rosters[G1].append(C)


def _holds(config_dir: str, actor: str, agent: str, gen: int) -> bool:
    return allowed_for(config_dir, actor).contains(
        credential_identity(agent), WORLD.keys(agent, gen).mls.public_key
    )


def test_sync_when_a_fresh_sibling_meets_a_rotated_agents_commit_then_applies_it(tmp_path):
    """The commit is signed by the rotated agent's old leaf; a fresh sibling must accept it."""
    server, d1, _dr, dc = world(tmp_path, G1, [A, B])
    rotate(server, d1, A)
    fresh_process()
    a_commits_add_c(server, d1, dc)
    fresh_process()

    result = sync_mls_group(server, d1, B, G1)

    assert result.epoch == 2
    assert server.nacks == []
    assert _holds(d1, B, A, 0)


def test_welcome_when_a_fresh_sibling_is_seated_beside_a_rotated_agent_then_installs_it(
    tmp_path, real_roster_read
):
    """The Welcome's tree holds the rotated agent's old leaf; the sibling must still open it."""
    server, d1, dr, _dc = world(tmp_path, G2, [A])
    rotate(server, d1, A)
    kp_b = open_mls_client(d1, B, allowed=allowed_for(d1, B)).generate_key_package()
    group = open_mls_group(dr, R, G2)
    bundle = group.add_member(kp_b)
    group.save()
    server.post_commit(G2, bundle)
    server.rosters[G2].append(B)
    server.welcomes[B] = [{"id": "wb", "group_id": G2, "blob": mls_to_base64(bundle.welcomes[0])}]
    fresh_process()

    process_mls_welcomes(server, d1, B, for_group=G2)

    assert open_mls_group(d1, B, G2).epoch() == bundle.epoch


def test_welcome_when_sealed_to_the_actors_superseded_key_package_then_it_is_dropped_not_installed(
    tmp_path, real_roster_read
):
    """The leaf is the agent's own under a rotated-away key, which no reclaim removes."""
    d1, dr = str(tmp_path / "d1"), str(tmp_path / "r")
    save_agent_keys(d1, A, WORLD.keys(A, 0))
    save_agent_keys(dr, R, WORLD.keys(R, 0))
    server = Server()
    server.rosters[G2] = [R, A]
    admit(dr, R, (A, 0))
    kp = open_mls_client(d1, A, allowed=allowed_for(d1, A)).generate_key_package()
    group = open_mls_client(dr, R, allowed=allowed_for(dr, R)).create_group_with_members(
        mls_group_id_bytes(G2), [kp]
    )
    bundle = group.last_commit()
    group.save()
    server.group_info[G2] = (bundle.group_info, bundle.epoch)
    server.welcomes[A] = [{"id": "wa", "group_id": G2, "blob": mls_to_base64(bundle.welcomes[0])}]
    rotate(server, d1, A)
    fresh_process()

    result = process_mls_welcomes(server, d1, A, for_group=G2)

    assert result.group_ids == ()
    assert result.discarded == 1
    with pytest.raises(Exception, match=G2):
        open_mls_group(d1, A, G2)


def test_admit_peers_when_the_local_sibling_is_generation_zero_then_reads_nothing(tmp_path):
    """No history exists below generation 0, so a common local agent costs no read."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A, B])
    actor = MlsActor(client=server, config_dir=d1, agent_id=B)

    admit_peers(actor, [A])

    assert [call for call in server.calls if call.startswith("GET /agents/")] == []


def test_admit_peers_when_the_local_sibling_rotated_then_admits_only_its_history(tmp_path):
    """The current pair is already seeded from disk; each older generation is read once."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A, B])
    rotate(server, d1, A)
    fresh_process()
    actor = MlsActor(client=server, config_dir=d1, agent_id=B)

    inserted = admit_peers(actor, [A])

    reads = [call for call in server.calls if call.startswith("GET /agents/")]
    assert inserted == [A]
    assert len(reads) == 1
    assert "'gen': 0" in reads[0]
    assert _holds(d1, B, A, 0)
    assert _holds(d1, B, A, 1)


def test_admit_peers_when_the_actor_rotated_then_leaves_its_own_history_out_by_default(tmp_path):
    """A leaf sealed to the actor's own old key installs a seat it reads but never writes."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A, B])
    rotate(server, d1, A)
    fresh_process()
    actor = MlsActor(client=server, config_dir=d1, agent_id=A)

    inserted = admit_peers(actor, [A])

    assert inserted == []
    assert not _holds(d1, A, A, 0)


def test_admit_peers_when_asked_for_the_actors_own_history_then_admits_it(tmp_path):
    """The explicit opt-in is the only way the actor's own old generations enter its set."""
    server, d1, _dr, _dc = world(tmp_path, G1, [A, B])
    rotate(server, d1, A)
    fresh_process()
    actor = MlsActor(client=server, config_dir=d1, agent_id=A)

    inserted = admit_peers(actor, [A], include_self_history=True)

    assert inserted == [A]
    assert _holds(d1, A, A, 0)
