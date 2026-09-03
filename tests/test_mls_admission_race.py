"""Python side — an admission that loses the epoch race catches up and rebuilds.

Driven against the real ``rine-mls`` core: the group, the ratchet tree, the
Welcome the peer joins on and the commit that wins the race are all genuine, and
only the HTTP boundary is stubbed. That is what makes the file worth having.
Admission was the one MLS commit verb on this stack with no sync-and-retry —
join, removal, reclamation and resync all had one — so ``group
resume-admission``, the verb an operator reaches for precisely when other members
are committing, reported the race instead of resolving it.

🔴 The half a mock cannot reach: the commit that won the race may have seated
somebody from this batch. A KeyPackage claim is exclusive per PACKAGE, not per
agent, so the peer below admits ``JOINER`` on a different one of the ten it
published, just as validly. Rebuilding the Add over that leaf is a duplicate
identity, which the core refuses out of the commit BUILDER — before the post,
outside the retry's ``except`` — and takes the whole admission down with the
report unwritten. Only a real tree fails that way.

The TypeScript twin is "drops a joiner the winning commit already seated"
(``rine-core/test/mls-admission.test.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from rine._crypto.keys import generate_agent_keys, save_agent_keys
from rine._mls.add_members import add_mls_group_members
from rine._mls.binding import open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.tree import GroupTree
from rine.errors import RineApiError
from rine.types import GroupRead

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit

ADMIN = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
JOINER = "33333333-3333-3333-3333-333333333333"
OTHER = "44444444-4444-4444-4444-444444444444"
GROUP_ID = "55555555-5555-5555-5555-555555555555"


def _group_read() -> GroupRead:
    return GroupRead.model_validate(
        {
            "id": GROUP_ID,
            "name": "standup",
            "handle": "#standup@acme.rine.network",
            "org_id": "66666666-6666-6666-6666-666666666666",
            "visibility": "private",
            "created_at": "2026-04-11T12:00:00Z",
            "mls_group_id": "latched",
        }
    )


def _conflict() -> RineApiError:
    # The server's own 409, carried as the wire body: the flows branch on the
    # machine-readable `error` key, never on the detail sentence.
    return RineApiError(409, "stale epoch", '{"error": "epoch_conflict"}')


@pytest.fixture
def race(tmp_config_dir, monkeypatch) -> list[MlsCommit]:
    """ADMIN and PEER hold a group; PEER seats JOINER in the commit that wins.

    PEER joins on its real Welcome, so it holds real state and its Add is a real
    commit — not a blob shaped like one.
    """
    for agent_id in (ADMIN, PEER, JOINER, OTHER):
        save_agent_keys(tmp_config_dir, agent_id, generate_agent_keys())

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
            raise _conflict()
        posted.append(commit)
        return commit.epoch

    def _sync(
        _client: Any,
        config_dir: str,
        agent_id: str,
        group_id: str,
        *,
        cipher_suite: int | None = None,
    ) -> None:
        group = open_mls_group(config_dir, agent_id, group_id, cipher_suite=cipher_suite)
        group.apply_commit(winning.commit)
        group.save()

    identities = {
        agent_id.lower(): open_mls_client(tmp_config_dir, agent_id).public_key()
        for agent_id in (PEER, JOINER, OTHER)
    }

    def _claim(_client: Any, batch: list[str], _headers: dict[str, str]) -> dict[str, bytes]:
        return {
            agent_id.lower(): open_mls_client(tmp_config_dir, agent_id).generate_key_package()
            for agent_id in batch
        }

    monkeypatch.setattr("rine._mls.admission_state.post_mls_commit", _commit)
    monkeypatch.setattr("rine._mls.admission_retry.sync_mls_group", _sync)
    monkeypatch.setattr("rine._mls.admission_loop.claim_founding_key_packages", _claim)
    monkeypatch.setattr("rine._mls.add_members.mls_heartbeat", lambda *_a: None)
    monkeypatch.setattr("rine._mls.add_members.read_group", lambda *_a: _group_read())
    monkeypatch.setattr(
        "rine._mls.add_members.read_group_tree",
        lambda *_a: GroupTree(member_ids=(ADMIN, PEER), invited_ids=()),
    )
    for module in ("rine._mls.add_members", "rine._mls.admission_recheck"):
        monkeypatch.setattr(f"{module}.fetch_agent_identities", lambda _c, ids: identities)
    return posted


class TestALostEpochRaceIsCaughtUpOn:
    def test_the_joiner_the_winning_commit_seated_is_dropped_and_the_rest_land(
        self, tmp_config_dir, race
    ):
        result = add_mls_group_members(None, tmp_config_dir, ADMIN, GROUP_ID, [JOINER, OTHER])

        # `already_in_group`, not `added`: this client did not seat them, it lost
        # to the client that did. Their claimed KeyPackage is spent either way.
        by_id = {outcome.agent_id: outcome for outcome in result.outcomes}
        assert by_id[JOINER].status == "skipped"
        assert by_id[JOINER].reason == "already_in_group"
        assert by_id[OTHER].status == "added"
        assert result.added == 1
        assert result.commits == 1
        assert [welcome.agent_id for welcome in race[-1].welcomes] == [OTHER]

    def test_a_batch_seated_whole_is_reported_and_nothing_is_posted(self, tmp_config_dir, race):
        # Nothing left to add is not a failure and not an empty commit: the
        # admission records what the race did and returns, so the batches after
        # it still run.
        result = add_mls_group_members(None, tmp_config_dir, ADMIN, GROUP_ID, [JOINER])

        assert result.added == 0
        assert result.commits == 0
        assert result.outcomes[0].reason == "already_in_group"
        assert race == []

    def test_a_second_conflict_is_the_callers_and_not_a_third_attempt(
        self, tmp_config_dir, race, monkeypatch
    ):
        # One catch-up, never a loop: an unbounded retry against an advancing
        # epoch is a self-DoS, and the second refusal is the one the operator
        # has to hear about.
        attempts: list[int] = []

        def _always_conflict(*_a: Any, **_kw: Any) -> int:
            attempts.append(1)
            raise _conflict()

        monkeypatch.setattr("rine._mls.admission_state.post_mls_commit", _always_conflict)

        with pytest.raises(RineApiError):
            add_mls_group_members(None, tmp_config_dir, ADMIN, GROUP_ID, [OTHER])

        assert len(attempts) == 2
