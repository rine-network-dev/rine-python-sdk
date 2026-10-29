"""``groups.sync()`` — which recovery a group gets, and what it reports.

The decision is the whole subject. It is made from the group row the server
returned, and never from whether local state happens to load: absent state is a
symptom shared by an MLS member whose store was deleted and by every member of
an open group, and a build that branched on it told the second to ask an admin
to remove and re-invite them — advice about a ratchet tree their group has not
got.

Nothing here mocks the client's own branch. The sender-key arms run the real
distribution scan against a real distribution DM (``group_message_fixture``),
so "installed one key" means a key was actually ingested; only the MLS ladder is
substituted, because it needs a founded group and is driven for real in
``test_mls_resync.py``.

Both clients are covered for all three arms: the sync and async bodies are
hand-mirrored by design, so a test that covers one proves nothing about the
other.
"""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
import respx

from rine._crypto.sender_keys_helpers import mark_sender_keys_retired
from rine._group_recovery import KeyPackageTopUp, SenderKeyRecoveryResult
from rine._mls.resync import MlsRecoveryResult
from rine._seat_update import SeatUpdate, SeatUpdateStatus
from rine.format import (
    MLS_NEVER_FOUNDED_NOTE,
    describe_mls_recovery,
    mls_never_founded_sync,
)

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

REPLAYED = MlsRecoveryResult(
    regime="mls",
    rung="replay",
    from_epoch=4,
    epoch=9,
    behind=5,
    processed=5,
    evicted=False,
)


def _group_row(**over: object) -> dict:
    return {
        "id": GROUP_ID,
        "name": "ops",
        "handle": "#ops@myorg.rine.network",
        "enrollment_policy": "open",
        "visibility": "private",
        "created_at": "2024-01-01T00:00:00Z",
        "mls_enabled": False,
        "mls_group_id": None,
        "mls_pending": False,
        "mls_cipher_suite": None,
        **over,
    }


def _mock_group(**over: object):
    """The existence check every arm goes through, and its answer.

    🔴 The roster is registered here too, and it is a cost rather than a
    convenience: ``sync(GROUP_ID)`` resolves the id against ``GET /groups``
    before it reads anything, so an id no group of this org carries is refused
    with the caller's own list instead of travelling to the wire. Without the
    roster every arm below refuses at the resolve and none of them is reached.
    """
    respx.get(f"{API}/groups").mock(
        return_value=httpx.Response(200, json={"items": [_group_row(**over)]})
    )
    return respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_group_row(**over))
    )


def _empty_scan(agent_id: str):
    """An inbox holding no sender-key distributions at all."""
    return respx.get(
        f"{API}/agents/{agent_id}/messages",
        params={"type": "rine.v1.sender_key_distribution"},
    ).mock(return_value=httpx.Response(200, json={"items": []}))


def _scan_page(agent_id: str, row_id: str, total: int):
    """One page of the distribution listing, and what the SERVER says it holds.

    The scan asks for ``limit=100`` and follows no cursor, so ``total`` above the
    page length is the part of the inbox the pass never opened — the exact
    shortfall, already in the response, at no extra request.
    """
    return respx.get(
        f"{API}/agents/{agent_id}/messages",
        params={"type": "rine.v1.sender_key_distribution"},
    ).mock(return_value=httpx.Response(200, json={"items": [{"id": row_id}], "total": total}))


def _fake_ladder(monkeypatch, result: MlsRecoveryResult = REPLAYED) -> list[tuple]:
    """Stand in for the MLS ladder, recording what it was asked to recover.

    Also stands in for the key-package top-up that rides ahead of the ladder,
    reporting a healthy pool so it adds nothing to the answer. Not optional: the
    top-up publishes at the transport, so an MLS arm that stubbed only the ladder
    would read a mocked-transport failure back as part of its result and every
    assertion here would be about that. What the top-up itself does — that it
    really runs, really reaches the wire, and really rides on the refusal — is
    ``tests/contract/test_group_sync_topup_contract.py``, against the real one,
    which is where the gate that ci.sh runs lives.
    """
    calls: list[tuple] = []

    def _recover(client, config_dir, agent_id, group_id):
        calls.append((config_dir, agent_id, group_id))
        return result

    monkeypatch.setattr("rine._resources.group_sync.recover_mls_group_or_reseat", _recover)
    monkeypatch.setattr(
        "rine._resources.group_sync.top_up_key_packages",
        lambda _actor: KeyPackageTopUp(outcome="healthy"),
    )
    monkeypatch.setattr(
        "rine._resources.group_sync.self_update_group",
        lambda _actor, group_id: SeatUpdate(group_id, SeatUpdateStatus.CURRENT),
    )
    return calls


class TestSyncGroupSenderKey:
    @respx.mock
    def test_sync_when_a_key_is_waiting_then_it_is_installed_and_nothing_is_committed(
        self, sync_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group()

        result = sync_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=1, retired=False)

    @respx.mock
    def test_sync_when_nothing_is_waiting_then_it_reports_installing_nothing(
        self, sync_client, mock_group_message_routes, agent_id
    ):
        # An empty distribution inbox is not an error and not a refusal: it is
        # the ordinary answer for a member whose peers have all already sent.
        # Registered AFTER the shared fixture's routes: respx keys a route by its
        # pattern, so the identical pattern is re-answered rather than shadowed.
        mock_group_message_routes()
        _empty_scan(agent_id)
        _mock_group()

        result = sync_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=0, retired=False)

    @respx.mock
    def test_sync_when_the_server_counts_more_than_the_page_then_the_shortfall_is_reported(
        self, sync_client, mock_group_message_routes, group_message_fixture, agent_id
    ):
        # Past the one page the scan reads, keys are never installed and the
        # messages they cover stay sealed. The count is the server's own total
        # minus the page, so it is free — the pass is not run twice for it.
        mock_group_message_routes()
        _scan_page(agent_id, group_message_fixture.distribution_row["id"], 137)
        _mock_group()

        result = sync_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(
            regime="sender-key", ingested=1, retired=False, unscanned=136
        )

    @respx.mock
    def test_sync_when_the_page_holds_the_whole_listing_then_no_shortfall_is_reported(
        self, sync_client, mock_group_message_routes, group_message_fixture, agent_id
    ):
        # ``None``, never ``0``: this result is projected into JSON by the tools
        # that wrap it, and a zero there is a number reporting that nothing
        # happened.
        mock_group_message_routes()
        _scan_page(agent_id, group_message_fixture.distribution_row["id"], 1)
        _mock_group()

        result = sync_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=1, retired=False)

    @respx.mock
    def test_sync_when_the_shortfall_is_real_then_the_prose_states_it(
        self, sync_client, mock_group_message_routes, group_message_fixture, agent_id
    ):
        # What the operator actually reads, and the reason the number is carried
        # at all. It states the count and then states what the count is NOT: the
        # listing holds every distribution this agent was ever sent, so most of
        # what is behind the page is material installed long ago, and a version
        # of this sentence that called those rows unopened and hinted at a
        # missing key among them was false about both.
        mock_group_message_routes()
        _scan_page(agent_id, group_message_fixture.distribution_row["id"], 137)
        _mock_group()

        said = describe_mls_recovery("#ops", sync_client.groups.sync(GROUP_ID))

        assert "136 older sender-key distribution(s)" in said
        assert "a count of rows this pass did not read" in said
        assert "not a count of keys it is missing" in said
        assert "stayed unopened" not in said

    @respx.mock
    def test_sync_when_there_is_no_shortfall_then_the_prose_says_nothing_of_one(
        self, sync_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group()

        said = describe_mls_recovery("#ops", sync_client.groups.sync(GROUP_ID))

        assert "did not read" not in said
        assert "older sender-key distribution(s)" not in said

    def test_prose_when_a_shortfall_and_a_never_founded_note_meet_then_each_keeps_its_place(
        self,
    ):
        # The three-clause composition, which nothing asserted: the shortfall
        # clause, then the next action, then the note on its own line. Built
        # from the result rather than through respx because the subject is the
        # renderer's ordering and not the scan.
        #
        # 🔴 The note ends on the founding verb and lands AFTER the sentence
        # sending the reader to the group's messages. That order is deliberate
        # and it is the ordering the TypeScript twin composes; it is pinned here
        # so a change to it is a decision somebody takes rather than a side
        # effect of appending one more clause.
        warned = mls_never_founded_sync("tool-group-reclaim")
        said = describe_mls_recovery(
            "#ops",
            SenderKeyRecoveryResult(
                regime="sender-key",
                ingested=2,
                retired=False,
                unscanned=136,
                mls_never_founded_note=warned,
            ),
        )

        head, _, note = said.partition("\n")
        assert note == warned
        assert note.endswith("then run the sync again.")
        assert head.index("136 older sender-key distribution(s)") < head.index(
            "This sync is finished"
        )
        assert head.endswith("read the group's own messages next.")

    @respx.mock
    def test_sync_when_the_scan_has_run_then_the_prose_names_the_next_action(
        self, sync_client, mock_group_message_routes
    ):
        # The g4 defect: the answer ended on a description of state and a model
        # handed it to its user as if it were what the group said, never reading
        # the group. Both halves are said out loud now.
        mock_group_message_routes()
        _mock_group()

        said = describe_mls_recovery("#ops", sync_client.groups.sync(GROUP_ID))

        assert "This sync is finished" in said
        assert "nothing here is a message from the group" in said
        assert "read the group's own messages next" in said

    @respx.mock
    def test_sync_when_this_agent_retired_the_group_then_nothing_is_installed(
        self, sync_client, mock_group_message_routes, tmp_config_dir, agent_id
    ):
        # The marker is spent by MEMBERSHIP, so a server that no longer
        # names this agent a member keeps the refusal — and the remedy is an
        # invitation, not another sync.
        mock_group_message_routes()
        _mock_group()
        mark_sender_keys_retired(tmp_config_dir, agent_id, GROUP_ID)
        members = respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        result = sync_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=0, retired=True)
        assert members.called, "membership is the server's to state, so it is asked"

    @respx.mock
    def test_sync_when_the_server_still_seats_this_agent_then_the_retirement_lifts(
        self, sync_client, mock_group_message_routes, tmp_config_dir, agent_id
    ):
        # The read path's half of the lift: a re-admitted agent that reads before
        # it ever sends must be able to take its new peers' keys.
        mock_group_message_routes()
        _mock_group()
        mark_sender_keys_retired(tmp_config_dir, agent_id, GROUP_ID)
        respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={"items": [{"agent_id": agent_id}]})
        )

        result = sync_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=1, retired=False)


class TestSyncGroupMls:
    @respx.mock
    def test_sync_when_the_group_is_mls_then_the_ladder_runs_and_is_tagged_mls(
        self, sync_client, mock_group_message_routes, monkeypatch, agent_id
    ):
        mock_group_message_routes()
        _mock_group(mls_group_id="latched", mls_enabled=True)
        calls = _fake_ladder(monkeypatch)

        result = sync_client.groups.sync(GROUP_ID)

        # Equal, not identical: the arm re-mints the ladder's result to hang the
        # top-up on it, and a healthy pool hangs nothing; the seat is the stubbed
        # self-update's, which found the leaf already current.
        assert result == replace(REPLAYED, seat=SeatUpdate(GROUP_ID, SeatUpdateStatus.CURRENT))
        assert result.regime == "mls"
        assert calls == [(sync_client._config_dir, agent_id, GROUP_ID)]

    @respx.mock
    def test_sync_when_the_leaf_moves_then_the_seat_outcome_rides_on_the_result(
        self, sync_client, mock_group_message_routes, monkeypatch
    ):
        """The seat outcome of a self-update reaches the caller on the sync result."""
        mock_group_message_routes()
        _mock_group(mls_group_id="latched", mls_enabled=True)
        _fake_ladder(monkeypatch)
        moved = SeatUpdate(GROUP_ID, SeatUpdateStatus.UPDATED, epoch=5)
        monkeypatch.setattr(
            "rine._resources.group_sync.self_update_group", lambda _actor, _group_id: moved
        )

        result = sync_client.groups.sync(GROUP_ID)

        assert result.seat == moved
        assert "Its leaf now carries the agent's current key (epoch 5)." in describe_mls_recovery(
            "#ops", result
        )

    @respx.mock
    def test_sync_when_the_recovery_evicted_the_agent_then_no_self_update_runs(
        self, sync_client, mock_group_message_routes, monkeypatch
    ):
        """An evicted agent has no leaf to move, so no self-update is attempted."""
        mock_group_message_routes()
        _mock_group(mls_group_id="latched", mls_enabled=True)
        _fake_ladder(monkeypatch, replace(REPLAYED, evicted=True))
        attempts: list[str] = []
        monkeypatch.setattr(
            "rine._resources.group_sync.self_update_group",
            lambda _actor, group_id: attempts.append(group_id),
        )

        result = sync_client.groups.sync(GROUP_ID)

        assert attempts == []
        assert result.seat is None

    @respx.mock
    def test_sync_when_the_group_is_mls_then_no_distribution_scan_runs(
        self, sync_client, mock_group_message_routes, monkeypatch, agent_id
    ):
        # The two recoveries share nothing. An MLS group's missing epochs are not
        # repaired by ingesting sender keys, and paying for that scan would be a
        # read nobody asked for.
        mock_group_message_routes()
        scan = _empty_scan(agent_id)
        _mock_group(mls_group_id="latched", mls_enabled=True)
        _fake_ladder(monkeypatch)

        sync_client.groups.sync(GROUP_ID)

        assert not scan.called


class TestSyncGroupMlsInitInFlight:
    @respx.mock
    def test_sync_when_the_mls_init_is_in_flight_then_it_refuses_by_name(
        self, sync_client, mock_group_message_routes, monkeypatch
    ):
        # 🔴 The case a two-way branch reads as sender-key: no latch yet, but the
        # group is really MLS. Running an ingest here is a wrong ACTION, not a
        # wrong sentence.
        mock_group_message_routes()
        _mock_group(mls_enabled=True, mls_pending=True)
        calls = _fake_ladder(monkeypatch)

        with pytest.raises(ValueError, match="still founding its MLS state"):
            sync_client.groups.sync(GROUP_ID)

        assert calls == []

    @respx.mock
    def test_sync_when_the_mls_init_is_in_flight_then_it_names_the_wait(
        self, sync_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group(mls_enabled=True, mls_pending=True)

        with pytest.raises(ValueError) as excinfo:
            sync_client.groups.sync(GROUP_ID)

        said = str(excinfo.value)
        assert "#ops@myorg.rine.network" in said
        assert "no sender keys to install" in said
        assert "run the sync again then" in said


class TestSyncGroupNeverFounded:
    """🔴 A closed group whose ratchet tree was never founded.

    Its four MLS columns are field for field an open group's, so the latch alone
    sent it to the distribution scan and reported "Recovered group …" for a group
    whose encryption never started. The only durable record that it was meant to
    run MLS is the intent pair the server keeps from create time.
    """

    @respx.mock
    def test_sync_when_the_tree_was_never_founded_then_it_installs_and_warns(
        self, sync_client, mock_group_message_routes, monkeypatch
    ):
        # 🔴 This group is NOT frozen server-side: the server accepts sender-key
        # sends into it, so keys for it really are waiting and the scan really
        # does install them. Refusing ahead of the scan cost an operator those
        # keys to buy a sentence. The scan here is the real one, against a real
        # distribution DM.
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)
        calls = _fake_ladder(monkeypatch)

        result = sync_client.groups.sync(GROUP_ID)

        assert result.regime == "sender-key"
        assert result.ingested == 1
        assert "ratchet tree was never founded" in result.mls_never_founded_note
        # The one recovery this group does NOT have: there is no epoch ladder to
        # walk without a tree.
        assert calls == []

    @respx.mock
    def test_sync_when_the_tree_was_never_founded_then_the_prose_carries_the_warning(
        self, sync_client, mock_group_message_routes
    ):
        # What the operator actually reads. The head sentence is byte-identical
        # to the one a plain sender-key group gets — two matrix drivers anchor
        # `^` on it — and the warning rides on its own line.
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)

        said = describe_mls_recovery("#ops", sync_client.groups.sync(GROUP_ID))

        head, note = said.split("\n")
        assert head.startswith("Recovered group #ops: installed 1 sender key(s)")
        assert note.startswith(MLS_NEVER_FOUNDED_NOTE)

    @respx.mock
    def test_sync_when_the_tree_was_never_founded_then_it_names_this_sdk_s_verb(
        self, sync_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)

        said = sync_client.groups.sync(GROUP_ID).mls_never_founded_note

        assert "was created to run MLS" in said
        assert "sealed with sender keys" in said
        assert "Run resume_admission() on it to found its MLS state" in said

    @respx.mock
    def test_sync_when_the_surface_has_another_spelling_then_it_names_that_one(
        self, sync_client, mock_group_message_routes
    ):
        # The three framework wrappers expose this operation as
        # `rine_group_reclaim` and have no `resume_admission` tool, so naming the
        # method would send a model to a verb it cannot call.
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)

        said = sync_client.groups.sync(
            GROUP_ID, repair="tool-group-reclaim"
        ).mls_never_founded_note

        assert "Run rine_group_reclaim on it to found its MLS state" in said
        assert "resume_admission" not in said

    @respx.mock
    def test_sync_when_the_tree_was_never_founded_and_nothing_waits_then_it_still_warns(
        self, sync_client, mock_group_message_routes, agent_id
    ):
        # The warning is about the GROUP and is orthogonal to what the scan did,
        # so an empty inbox carries it too. Registered AFTER the shared fixture's
        # routes: respx re-answers an identical pattern rather than shadowing it.
        mock_group_message_routes()
        _empty_scan(agent_id)
        _mock_group(enrollment_policy="closed", mls_enabled=True)

        result = sync_client.groups.sync(GROUP_ID)

        assert result.ingested == 0
        assert result.mls_never_founded_note is not None

    @respx.mock
    def test_sync_when_the_tree_was_never_founded_and_keys_are_retired_then_it_still_warns(
        self, sync_client, mock_group_message_routes, tmp_config_dir, agent_id
    ):
        # The third of the three answers the scan can produce. Its own remedy —
        # the retry that lifts the retirement — is stated first, and the warning
        # about the tree follows it.
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)
        mark_sender_keys_retired(tmp_config_dir, agent_id, GROUP_ID)
        respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        result = sync_client.groups.sync(GROUP_ID)

        assert result.retired is True
        assert result.mls_never_founded_note is not None

    @respx.mock
    def test_sync_when_an_open_group_has_no_latch_then_it_recovers_with_no_warning(
        self, sync_client, mock_group_message_routes
    ):
        # 🔴 The regression this arm most plausibly causes: an open group has the
        # same null latch, carries `mls_enabled` from birth, and is a sender-key
        # group by design — a warning keyed off the latch alone would tell every
        # open group it was created to run MLS.
        mock_group_message_routes()
        _mock_group(enrollment_policy="open", mls_enabled=True)

        result = sync_client.groups.sync(GROUP_ID)

        assert result.regime == "sender-key"
        assert result.mls_never_founded_note is None

    @respx.mock
    def test_sync_when_a_closed_group_opted_out_of_mls_then_it_recovers_with_no_warning(
        self, sync_client, mock_group_message_routes
    ):
        # `mls_enabled` false on a closed group is legal on the wire and means
        # the group really does run sender keys; reading the policy alone would
        # warn it for ever about MLS it never asked for.
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=False)

        result = sync_client.groups.sync(GROUP_ID)

        assert result.regime == "sender-key"
        assert result.mls_never_founded_note is None

    @respx.mock
    def test_sync_when_the_group_is_mls_then_the_answer_carries_no_such_field(
        self, sync_client, mock_group_message_routes, monkeypatch
    ):
        # A founded MLS group is untouched by any of this: its result type has
        # no warning field at all, which is what keeps a consumer from reading
        # one arm's shape onto the other.
        mock_group_message_routes()
        _mock_group(mls_enabled=True, mls_group_id="mls-abc")
        _fake_ladder(monkeypatch)

        result = sync_client.groups.sync(GROUP_ID)

        assert result == replace(REPLAYED, seat=SeatUpdate(GROUP_ID, SeatUpdateStatus.CURRENT))
        assert not hasattr(result, "mls_never_founded_note")


class TestSyncGroupExistenceCheck:
    @respx.mock
    def test_sync_when_the_group_id_is_unknown_then_the_resolve_refuses_before_the_ladder(
        self, sync_client, mock_group_message_routes, monkeypatch
    ):
        # The claim here is unchanged — an unknown id is answered by what
        # exists, never by a refusal about lost MLS state
        # — and the read that answers it is the RESOLVE's, not ``sync``'s own:
        # the id rung reads this row first, and a 404 there ends the verb with a
        # sentence composed from the roster below. The recovery ladder is not
        # entered either way, which is the half a wrong refusal would break.
        mock_group_message_routes()
        roster = respx.get(f"{API}/groups").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        read = respx.get(f"{API}/groups/{GROUP_ID}").mock(
            return_value=httpx.Response(404, json={"detail": "Group not found"})
        )
        calls = _fake_ladder(monkeypatch)

        with pytest.raises(Exception) as excinfo:
            sync_client.groups.sync(GROUP_ID)

        assert "not found" in str(excinfo.value).lower()
        assert GROUP_ID in str(excinfo.value)
        assert read.called
        assert roster.called
        assert calls == []


class TestAsyncGroupSync:
    @respx.mock
    async def test_sync_when_a_key_is_waiting_then_the_async_client_installs_it(
        self, async_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group()

        result = await async_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=1, retired=False)
        await async_client.close()

    @respx.mock
    async def test_sync_when_the_server_counts_more_than_the_page_then_the_async_client_agrees(
        self, async_client, mock_group_message_routes, group_message_fixture, agent_id
    ):
        # The two client bodies are hand-mirrored, so the shortfall landing on one
        # of them proves nothing about the other.
        mock_group_message_routes()
        _scan_page(agent_id, group_message_fixture.distribution_row["id"], 137)
        _mock_group()

        result = await async_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(
            regime="sender-key", ingested=1, retired=False, unscanned=136
        )
        await async_client.close()

    @respx.mock
    async def test_sync_when_this_agent_retired_the_group_then_the_async_client_agrees(
        self, async_client, mock_group_message_routes, tmp_config_dir, agent_id
    ):
        # ⚠️ The arm that is silently absent without the explicit retirement
        # gate: Python's scan takes no group id, so without this call a retired
        # group would report a plain ingest of zero and the two stacks would
        # disagree about a re-admitted member.
        mock_group_message_routes()
        _mock_group()
        mark_sender_keys_retired(tmp_config_dir, agent_id, GROUP_ID)
        respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        result = await async_client.groups.sync(GROUP_ID)

        assert result == SenderKeyRecoveryResult(regime="sender-key", ingested=0, retired=True)
        await async_client.close()

    @respx.mock
    async def test_sync_when_the_group_is_mls_then_the_async_client_runs_the_ladder(
        self, async_client, mock_group_message_routes, monkeypatch, agent_id
    ):
        mock_group_message_routes()
        _mock_group(mls_group_id="latched", mls_enabled=True)
        calls = _fake_ladder(monkeypatch)

        result = await async_client.groups.sync(GROUP_ID)

        assert result == replace(REPLAYED, seat=SeatUpdate(GROUP_ID, SeatUpdateStatus.CURRENT))
        assert calls == [(async_client._config_dir, agent_id, GROUP_ID)]
        await async_client.close()

    @respx.mock
    async def test_sync_when_the_mls_init_is_in_flight_then_the_async_client_refuses(
        self, async_client, mock_group_message_routes, monkeypatch
    ):
        mock_group_message_routes()
        _mock_group(mls_enabled=True, mls_pending=True)
        calls = _fake_ladder(monkeypatch)

        with pytest.raises(ValueError, match="still founding its MLS state"):
            await async_client.groups.sync(GROUP_ID)

        assert calls == []
        await async_client.close()

    @respx.mock
    async def test_sync_when_the_tree_was_never_founded_then_the_async_client_installs_and_warns(
        self, async_client, mock_group_message_routes, monkeypatch
    ):
        # The sync and async bodies are hand-mirrored by design, so an arm added
        # to one proves nothing about the other.
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)
        calls = _fake_ladder(monkeypatch)

        result = await async_client.groups.sync(GROUP_ID)

        assert result.regime == "sender-key"
        assert result.ingested == 1
        assert "ratchet tree was never founded" in result.mls_never_founded_note
        assert calls == []
        await async_client.close()

    @respx.mock
    async def test_sync_when_the_tree_was_never_founded_then_the_async_client_takes_the_repair(
        self, async_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group(enrollment_policy="closed", mls_enabled=True)

        result = await async_client.groups.sync(GROUP_ID, repair="tool-group-reclaim")

        assert "Run rine_group_reclaim on it" in result.mls_never_founded_note
        await async_client.close()

    @respx.mock
    async def test_sync_when_an_open_group_has_no_latch_then_the_async_client_recovers(
        self, async_client, mock_group_message_routes
    ):
        mock_group_message_routes()
        _mock_group(enrollment_policy="open", mls_enabled=True)

        result = await async_client.groups.sync(GROUP_ID)

        assert result.regime == "sender-key"
        assert result.mls_never_founded_note is None
        await async_client.close()
