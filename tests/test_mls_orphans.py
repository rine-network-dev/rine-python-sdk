"""Leaf reclamation: the leaves nobody is entitled to, and the ones that only look it.

These drive the real ``rine-mls`` core — only the server is mocked — so every
leaf, commit and ratchet-tree fact here is genuine and a test fails when the
orphan set is computed from the wrong population.

The load-bearing one is
``test_reclaim_when_an_invitee_has_not_accepted_yet_then_its_leaf_survives``: an
invitation takes its ratchet-tree leaf the moment its Welcome is minted and its
holder gets no member row until they join, so a pass computed from members alone
evicts every agent who has not accepted yet.

The TypeScript twin is ``rine-core/test/mls-orphans.test.ts``, test for test.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._crypto.keys import save_agent_keys
from rine._mls import (
    DEFAULT_CIPHER_SUITE,
    load_mls_group,
    mls_group_id_bytes,
    open_mls_client,
    orphan_leaves,
    reclaim_orphan_leaves,
)
from rine._mls.admission import (
    MlsAdmissionResult,
    MlsReclamation,
    MlsReclamationDecline,
)
from rine._mls.binding import CommitPendingError, allowed_for, credential_identity
from rine._mls.group_access import open_mls_group
from rine._mls.tree import leaf_index
from rine.admission_words import describe_mls_admission
from rine.errors import MlsError
from rine.testing import WORLD
from tests.escrow_outcomes import DEFERRED, DEFERRED_REPORT
from tests.mls_peers import RefusesOnce

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
NO_SHOW_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
REFUSED_ID = "55555555-6666-7777-8888-999999999999"

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": "99999999-0000-1111-2222-333333333333",
    "mls_pending": False,
    "mls_cipher_suite": DEFAULT_CIPHER_SUITE,
}


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _found_with(tmp_config_dir, agent_id, seated: list[str]):
    """This agent founds the group with `seated` already in its ratchet tree.

    Every seated agent's keys are saved beside the founder's: the core refuses a
    leaf whose ``(agent id, leaf key)`` pair is outside the client's allowed set,
    which is every agent whose keys live in the config dir.
    """
    for other in seated:
        save_agent_keys(tmp_config_dir, other, WORLD.keys(other))
    admin = open_mls_client(tmp_config_dir, agent_id)
    group = admin.create_group_with_members(
        mls_group_id_bytes(GROUP_ID),
        [open_mls_client(tmp_config_dir, other).generate_key_package() for other in seated],
    )
    group.save()
    return {other: credential_identity(other) for other in seated}


def _mock_server(*, members: list[str], live: list[dict], unreadable: set[str]):
    """The four reads and the one write a reclamation pass makes."""
    _mock_token()
    respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_GROUP_PAYLOAD)
    )
    respx.get(f"{API}/groups/{GROUP_ID}/members").mock(
        return_value=httpx.Response(200, json={"items": [{"agent_id": m} for m in members]})
    )
    respx.get(f"{API}/groups/{GROUP_ID}/requests").mock(
        return_value=httpx.Response(200, json={"items": live})
    )

    def _keys(request: httpx.Request) -> httpx.Response:
        wanted = (request.url.params.get("ids") or "").split(",")
        keys = {
            agent: WORLD.keys_response(agent)
            for agent in wanted
            if agent and agent not in unreadable
        }
        return httpx.Response(200, json={"keys": keys})

    respx.get(f"{API}/agents/keys").mock(side_effect=_keys)

    def _accept(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(200, json={"epoch": body["epoch"], "delivered_to": 1})

    return respx.post(f"{API}/groups/{GROUP_ID}/mls/commit").mock(side_effect=_accept)


def _local(tmp_config_dir, agent_id):
    return load_mls_group(open_mls_client(tmp_config_dir, agent_id), GROUP_ID)


def _invitation(agent_id: str, inviter: str) -> dict:
    return {"agent_id": agent_id, "status": "invited", "invited_by": inviter}


def _nomination(agent_id: str, nominator: str) -> dict:
    """A member's nomination: pending like a self-application, and sponsored."""
    return {"agent_id": agent_id, "status": "pending", "invited_by": nominator}


class TestTheSetItself:
    def test_orphan_leaves_when_an_identity_is_unaccounted_for_then_its_leaf_is_named(
        self, tmp_config_dir, saved_agent_keys, agent_id
    ):
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        group = _local(tmp_config_dir, agent_id)

        orphans = orphan_leaves(group, [credential_identity(agent_id)])

        assert [leaf.index for leaf in orphans] == [leaf_index(group, identities[NO_SHOW_ID])]

    def test_orphan_leaves_when_nobody_is_entitled_then_this_agents_own_leaf_survives(
        self, tmp_config_dir, saved_agent_keys, agent_id
    ):
        # The degenerate input. An admin that self-evicts can neither commit nor
        # recover, so its own leaf is excluded structurally rather than by
        # trusting the membership read.
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        group = _local(tmp_config_dir, agent_id)

        orphans = orphan_leaves(group, [])

        assert [leaf.index for leaf in orphans] == [leaf_index(group, identities[NO_SHOW_ID])]


class TestThePass:
    @respx.mock
    def test_reclaim_when_an_invitee_has_not_accepted_yet_then_its_leaf_survives(
        self, sync_client, tmp_config_dir, agent_id
    ):
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        identities[agent_id] = credential_identity(agent_id)
        posted = _mock_server(
            members=[agent_id],
            live=[_invitation(NO_SHOW_ID, agent_id)],
            unreadable=set(),
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert posted.call_count == 0
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is not None

    @respx.mock
    def test_reclaim_when_a_nomination_is_awaiting_a_vote_then_its_leaf_survives(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """``live`` is ``pending`` plus ``invited``, and both entitle.

        The entitled set is read from ``?outstanding=live`` and is deliberately
        the WIDER of the two voucher populations, so a nomination is covered by
        the same read that covers an invitation. Narrowing it to the rows a
        resume may admit would evict every agent the electorate still owes
        an answer to.
        """
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        identities[agent_id] = credential_identity(agent_id)
        posted = _mock_server(
            members=[agent_id],
            live=[_nomination(NO_SHOW_ID, agent_id)],
            unreadable=set(),
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert posted.call_count == 0
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is not None

    @respx.mock
    def test_reclaim_when_a_voucher_lapsed_and_was_reaped_then_its_leaf_is_retired(
        self, sync_client, tmp_config_dir, agent_id, mls_escrow_stub
    ):
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        identities[agent_id] = credential_identity(agent_id)
        # The reaper freed the seat: no member row, no live voucher. The leaf is
        # what it left behind.
        posted = _mock_server(members=[agent_id], live=[], unreadable=set())

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (1, 1, 1)
        assert posted.call_count == 1
        # An orphan holds no member row, so the Remove commit carries no Welcome and
        # there is no row for its declared target to delete. It still declares the
        # target: the server closes a seat span only by a declared removal.
        body = json.loads(posted.calls[0].request.content)
        assert body["welcomes"] == []
        assert body["removes"] == [NO_SHOW_ID]
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is None
        assert mls_escrow_stub[-1] == (GROUP_ID, _local(tmp_config_dir, agent_id).epoch())

    @respx.mock
    def test_reclaim_when_a_build_is_refused_for_an_unadmitted_peer_then_it_verifies_and_retries(
        self, sync_client, tmp_config_dir, agent_id, monkeypatch
    ):
        """The refused agent is chain-verified once and the same removal is built again."""
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        identities[agent_id] = credential_identity(agent_id)
        posted = _mock_server(members=[agent_id], live=[], unreadable=set())
        real_open = open_mls_group
        monkeypatch.setattr(
            "rine._mls.orphans.open_mls_group",
            lambda *args: RefusesOnce(real_open(*args), REFUSED_ID),
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (1, 1, 1)
        assert posted.call_count == 1
        assert allowed_for(tmp_config_dir, agent_id).contains(
            credential_identity(REFUSED_ID), WORLD.keys(REFUSED_ID).mls.public_key
        )

    @respx.mock
    def test_reclaim_when_a_key_update_is_awaiting_acknowledgement_then_it_says_to_retry_later(
        self, sync_client, tmp_config_dir, agent_id, monkeypatch
    ):
        """The core's bare refusal names no group and no wait; the pass names both."""
        _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        _mock_server(members=[agent_id], live=[], unreadable=set())
        real_open = open_mls_group

        class _Pending:
            def __init__(self, group):
                self._group = group

            def __getattr__(self, name):
                return getattr(self._group, name)

            def remove_member(self, _leaf):
                raise CommitPendingError("a commit is pending")

        monkeypatch.setattr(
            "rine._mls.orphans.open_mls_group", lambda *args: _Pending(real_open(*args))
        )

        with pytest.raises(MlsError) as caught:
            reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert caught.value.code == "RINE_MLS_COMMIT_PENDING"
        assert GROUP_ID in str(caught.value)

    @respx.mock
    def test_reclaim_when_the_commit_drain_defers_then_the_result_reports_it(
        self, sync_client, tmp_config_dir, agent_id, mls_escrow_stub, monkeypatch
    ):
        monkeypatch.setattr("rine._mls.orphans.drain_escrow", lambda *args, **kwargs: DEFERRED)
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        identities[agent_id] = credential_identity(agent_id)
        _mock_server(members=[agent_id], live=[], unreadable=set())

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert result.escrow.deferral == DEFERRED_REPORT.deferral
        assert result.escrow.gaps == DEFERRED_REPORT.gaps

    @respx.mock
    def test_reclaim_when_a_member_publishes_no_readable_key_then_nothing_is_retired(
        self, sync_client, tmp_config_dir, agent_id
    ):
        revoked = "12121212-3434-5656-7878-909090909090"
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID, revoked])
        identities[agent_id] = credential_identity(agent_id)
        # An INVITATION, not a member row: ``GET /groups/{id}/members`` filters
        # revoked agents out, so a revoked member never reaches this pass at all,
        # while a voucher outlives the revocation of the agent it names. That
        # agent holds a leaf and publishes no key, so its leaf cannot be told
        # apart from the no-show's.
        posted = _mock_server(
            members=[agent_id],
            live=[_invitation(revoked, agent_id)],
            unreadable={revoked},
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert result.declined is not None
        assert result.declined.reason == "identity_unknown"
        assert revoked in result.declined.detail
        assert posted.call_count == 0
        group = _local(tmp_config_dir, agent_id)
        assert leaf_index(group, identities[revoked]) is not None
        assert leaf_index(group, identities[NO_SHOW_ID]) is not None

    @respx.mock
    def test_reclaim_when_a_member_holds_no_leaf_then_the_pass_declines(
        self, sync_client, tmp_config_dir, agent_id
    ):
        """A member the server names whose leaf is not in the tree is not an orphan's owner.

        The pass subtracts the server's roster from the tree's leaves; a roster
        entry with no leaf means the tree and the server disagree about who is
        seated, and a pass that carried on would Remove leaves on a guess.
        """
        unseated = "12121212-3434-5656-7878-909090909090"
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        posted = _mock_server(members=[agent_id, unseated], live=[], unreadable=set())

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert result.declined is not None
        assert result.declined.reason == "identity_unseated"
        assert unseated in result.declined.detail
        assert posted.call_count == 0
        # Nothing was committed, so the no-show's leaf survives too, which a pass
        # that ran would legitimately have retired.
        group = _local(tmp_config_dir, agent_id)
        assert leaf_index(group, identities[NO_SHOW_ID]) is not None

    @respx.mock
    def test_reclaim_when_the_outstanding_read_fails_then_it_declines_by_name(
        self, sync_client, tmp_config_dir, agent_id
    ):
        identities = _found_with(tmp_config_dir, agent_id, [NO_SHOW_ID])
        identities[agent_id] = credential_identity(agent_id)
        posted = _mock_server(members=[agent_id], live=[], unreadable=set())
        # A member that is not an admin cannot read the invitations, and
        # `read_group_tree` degrades rather than raising — so the pass has to
        # refuse, or it evicts every agent who has not accepted yet.
        respx.get(f"{API}/groups/{GROUP_ID}/requests").mock(
            return_value=httpx.Response(403, json={"detail": "Admin only"})
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert result.declined is not None
        assert result.declined.reason == "outstanding_unknown"
        assert posted.call_count == 0
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is not None


class TestTheSentence:
    """What an operator is told. The CLI twin is ``printReclamation``."""

    def _rendered(self, reclamation: MlsReclamation | None) -> str:
        return describe_mls_admission(
            MlsAdmissionResult(epoch=9, commits=1, added=0, outcomes=(), reclamation=reclamation)
        )

    def test_describe_when_no_pass_ran_then_nothing_is_claimed_about_the_tree(self):
        assert "leaf" not in self._rendered(None)

    def test_describe_when_leaves_were_retired_then_the_on_commit_cost_is_stated(self):
        said = self._rendered(MlsReclamation(found=2, reclaimed=2, commits=2, epoch=9))
        assert "Reclaimed 2 of 2" in said
        assert "billed to every member" in said

    def test_describe_when_the_pass_found_nothing_then_it_says_so_rather_than_staying_silent(
        self,
    ):
        # "nobody asked" and "there was nothing there" are different facts, and
        # only one of them means the tree is clean.
        assert "Every leaf belongs" in self._rendered(
            MlsReclamation(found=0, reclaimed=0, commits=0, epoch=9)
        )

    def test_describe_when_the_pass_declined_then_the_stated_reason_is_rendered(self):
        said = self._rendered(
            MlsReclamation(
                found=0,
                reclaimed=0,
                commits=0,
                epoch=9,
                declined=MlsReclamationDecline(
                    reason="identity_unknown", detail="Reclaimed nothing: one is unreadable."
                ),
            )
        )
        assert "one is unreadable" in said
        assert "Every leaf belongs" not in said
