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

from typing import Any

import pytest

from rine._mls.add_members import add_mls_group_members
from rine.errors import RineApiError
from tests.escrow_outcomes import DEFERRED, DEFERRED_REPORT
from tests.mls_race_world import ADMIN, GROUP_ID, JOINER, OTHER, epoch_conflict

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")


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

    def test_the_escrow_drain_of_the_landed_commit_is_carried_in_the_result(
        self, tmp_config_dir, race, monkeypatch
    ):
        monkeypatch.setattr("rine._mls.admission_state.drain_escrow", lambda *_a, **_k: DEFERRED)

        result = add_mls_group_members(None, tmp_config_dir, ADMIN, GROUP_ID, [OTHER])

        assert result.escrow == DEFERRED_REPORT

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
            raise epoch_conflict()

        monkeypatch.setattr("rine._mls.admission_state.post_mls_commit", _always_conflict)

        with pytest.raises(RineApiError):
            add_mls_group_members(None, tmp_config_dir, ADMIN, GROUP_ID, [OTHER])

        assert len(attempts) == 2
