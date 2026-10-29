"""A group whose admission loses the epoch race once, built on the real ``rine-mls`` core.

ADMIN and PEER hold a group and PEER seats JOINER in the commit that wins the race. Only the
HTTP boundary is stubbed, so the commit the client rebuilds over is genuine.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from rine._crypto.keys import save_agent_keys
from rine._mls.binding import credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.tree import GroupTree
from rine.errors import RineApiError
from rine.testing import WORLD

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit

ADMIN = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
JOINER = "33333333-3333-3333-3333-333333333333"
OTHER = "44444444-4444-4444-4444-444444444444"
GROUP_ID = "55555555-5555-5555-5555-555555555555"


def epoch_conflict() -> RineApiError:
    # The server's own 409, carried as the wire body: the flows branch on the
    # machine-readable `error` key, never on the detail sentence.
    return RineApiError(409, "stale epoch", '{"error": "epoch_conflict"}')


def race_world(tmp_config_dir: str, monkeypatch: pytest.MonkeyPatch) -> list[MlsCommit]:
    """ADMIN and PEER hold a group; PEER seats JOINER in the commit that wins.

    PEER joins on its real Welcome, so it holds real state and its Add is a real
    commit — not a blob shaped like one.
    """
    for agent_id in (ADMIN, PEER, JOINER, OTHER):
        save_agent_keys(tmp_config_dir, agent_id, WORLD.keys(agent_id))

    founding = open_mls_client(tmp_config_dir, ADMIN).create_group_with_members(
        mls_group_id_bytes(GROUP_ID),
        [open_mls_client(tmp_config_dir, PEER).generate_key_package()],
    )
    bundle = founding.last_commit()
    assert bundle is not None
    founding.save()
    peer_group = open_mls_client(tmp_config_dir, PEER).join_from_welcome(bundle.welcomes[0])
    # A DIFFERENT KeyPackage than the admission under test will claim for the
    # same agent, which is the whole premise of the recheck.
    winning = peer_group.add_members(
        [open_mls_client(tmp_config_dir, JOINER).generate_key_package()]
    )
    peer_group.save()

    posted: list[MlsCommit] = []
    refused: list[bool] = []

    def _commit(_actor: Any, _group_id: str, commit: MlsCommit, _headers: dict[str, str]) -> int:
        # The race, once: the first commit of the run loses the CAS, and
        # whatever the client rebuilds after catching up is accepted.
        if not refused:
            refused.append(True)
            raise epoch_conflict()
        posted.append(commit)
        return commit.epoch

    def _sync(_client: Any, config_dir: str, agent_id: str, group_id: str) -> None:
        group = open_mls_group(config_dir, agent_id, group_id)
        group.apply_commit(winning.commit)
        group.save()

    identities = {
        agent_id.lower(): credential_identity(agent_id) for agent_id in (PEER, JOINER, OTHER)
    }

    def _claim(_client: Any, batch: list[str], _headers: dict[str, str]) -> dict[str, bytes]:
        return {
            agent_id.lower(): open_mls_client(tmp_config_dir, agent_id).generate_key_package()
            for agent_id in batch
        }

    def _verified(_client: Any, ids: list[str], _headers: dict[str, str]) -> dict[str, Any]:
        return {
            i.lower(): SimpleNamespace(mls_public_key=WORLD.keys(i).mls.public_key) for i in ids
        }

    monkeypatch.setattr("rine._mls.admission_loop.fetch_verified_batch_keys", _verified)
    monkeypatch.setattr("rine._mls.admission_state.post_mls_commit", _commit)
    monkeypatch.setattr("rine._mls.admission_retry.sync_mls_group", _sync)
    monkeypatch.setattr("rine._mls.admission_loop.claim_founding_key_packages", _claim)
    monkeypatch.setattr("rine._mls.add_members.mls_heartbeat", lambda *_a: None)
    monkeypatch.setattr(
        "rine._mls.add_members.read_group_tree",
        lambda *_a: GroupTree(member_ids=(ADMIN, PEER), invited_ids=()),
    )
    for module in ("rine._mls.add_members", "rine._mls.admission_recheck"):
        monkeypatch.setattr(f"{module}.fetch_agent_identities", lambda _c, ids: identities)
    return posted
