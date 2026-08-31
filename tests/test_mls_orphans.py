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

from rine._crypto.keys import generate_agent_keys, save_agent_keys, signing_public_key_to_jwk
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
from rine._mls.binding import MlsGroup
from rine._mls.tree import leaf_index
from rine.admission_words import describe_mls_admission

#: The tree-query surface lands in ``rine-mls`` 0.1.1, and reaching Python needs
#: a wheel built from it — a ``--native`` artifact build, not a source change.
#: Every installed wheel at the time of writing predates it, so the tests that
#: enumerate a tree are skipped rather than silently passing against a binding
#: that cannot answer. The TypeScript twin runs against a rebuilt napi addon and
#: covers the same set.
#:
#: The two refusal tests are deliberately NOT skipped: a pass that declines
#: returns before it enumerates anything, so they exercise the whole wire —
#: reads, degradation, refusal — on the wheel that is actually installed.
needs_tree_surface = pytest.mark.skipif(
    not hasattr(MlsGroup, "member_identities"),
    reason=(
        "the installed rine-mls wheel predates the tree-query surface "
        "(MlsGroup.member_identities); rebuild it with "
        "./scripts/build-mls-artifacts.sh and reinstall to run these"
    ),
)

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
NO_SHOW_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"

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


def _peer_client(tmp_path, agent: str):
    peer_dir = str(tmp_path / f"peer-{agent}")
    save_agent_keys(peer_dir, agent, generate_agent_keys())
    return open_mls_client(peer_dir, agent)


def _found_with(tmp_config_dir, agent_id, tmp_path, seated: list[str]):
    """This agent founds the group with `seated` already in its ratchet tree."""
    admin = open_mls_client(tmp_config_dir, agent_id)
    peers = {other: _peer_client(tmp_path, other) for other in seated}
    group = admin.create_group_with_members(
        mls_group_id_bytes(GROUP_ID),
        [peer.generate_key_package() for peer in peers.values()],
    )
    group.save()
    return {other: peer.public_key() for other, peer in peers.items()}


def _mock_server(*, members: list[str], live: list[dict], unreadable: set[str], identities):
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
            agent: {"signing_public_key": signing_public_key_to_jwk(identity)}
            for agent, identity in identities.items()
            if agent in wanted and agent not in unreadable
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


@needs_tree_surface
class TestTheSetItself:
    def test_orphan_leaves_when_an_identity_is_unaccounted_for_then_its_leaf_is_named(
        self, tmp_config_dir, saved_agent_keys, agent_id, tmp_path
    ):
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID])
        group = _local(tmp_config_dir, agent_id)

        orphans = orphan_leaves(group, [open_mls_client(tmp_config_dir, agent_id).public_key()])

        assert [leaf.index for leaf in orphans] == [leaf_index(group, identities[NO_SHOW_ID])]

    def test_orphan_leaves_when_nobody_is_entitled_then_this_agents_own_leaf_survives(
        self, tmp_config_dir, saved_agent_keys, agent_id, tmp_path
    ):
        # The degenerate input. An admin that self-evicts can neither commit nor
        # recover, so its own leaf is excluded structurally rather than by
        # trusting the membership read.
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID])
        group = _local(tmp_config_dir, agent_id)

        orphans = orphan_leaves(group, [])

        assert [leaf.index for leaf in orphans] == [leaf_index(group, identities[NO_SHOW_ID])]


class TestThePass:
    @needs_tree_surface
    @respx.mock
    def test_reclaim_when_an_invitee_has_not_accepted_yet_then_its_leaf_survives(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID])
        identities[agent_id] = open_mls_client(tmp_config_dir, agent_id).public_key()
        posted = _mock_server(
            members=[agent_id],
            live=[_invitation(NO_SHOW_ID, agent_id)],
            unreadable=set(),
            identities=identities,
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert posted.call_count == 0
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is not None

    @needs_tree_surface
    @respx.mock
    def test_reclaim_when_a_nomination_is_awaiting_a_vote_then_its_leaf_survives(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        """``live`` is ``pending`` plus ``invited``, and both entitle.

        The entitled set is read from ``?outstanding=live`` and is deliberately
        the WIDER of the two voucher populations, so a nomination is covered by
        the same read that covers an invitation. Narrowing it to the rows a
        resume may admit would evict every agent the electorate still owes
        an answer to.
        """
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID])
        identities[agent_id] = open_mls_client(tmp_config_dir, agent_id).public_key()
        posted = _mock_server(
            members=[agent_id],
            live=[_nomination(NO_SHOW_ID, agent_id)],
            unreadable=set(),
            identities=identities,
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert posted.call_count == 0
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is not None

    @needs_tree_surface
    @respx.mock
    def test_reclaim_when_a_voucher_lapsed_and_was_reaped_then_its_leaf_is_retired(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID])
        identities[agent_id] = open_mls_client(tmp_config_dir, agent_id).public_key()
        # The reaper freed the seat: no member row, no live voucher. The leaf is
        # what it left behind.
        posted = _mock_server(members=[agent_id], live=[], unreadable=set(), identities=identities)

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (1, 1, 1)
        assert posted.call_count == 1
        # An orphan holds no member row, so the Remove commit declares no target
        # and carries no Welcome: no DELETE may ever be authorised by it.
        body = json.loads(posted.calls[0].request.content)
        assert body["welcomes"] == []
        assert body.get("removes", []) == []
        assert leaf_index(_local(tmp_config_dir, agent_id), identities[NO_SHOW_ID]) is None

    @respx.mock
    def test_reclaim_when_a_member_publishes_no_readable_key_then_nothing_is_retired(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        revoked = "12121212-3434-5656-7878-909090909090"
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID, revoked])
        identities[agent_id] = open_mls_client(tmp_config_dir, agent_id).public_key()
        # An INVITATION, not a member row: ``GET /groups/{id}/members`` filters
        # revoked agents out, so a revoked member never reaches this pass at all,
        # while a voucher outlives the revocation of the agent it names. That
        # agent holds a leaf and publishes no key, so its leaf cannot be told
        # apart from the no-show's.
        posted = _mock_server(
            members=[agent_id],
            live=[_invitation(revoked, agent_id)],
            unreadable={revoked},
            identities=identities,
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
    def test_reclaim_when_a_member_rotated_its_signing_key_then_the_pass_declines(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        """A rotation desynchronises the tree from what the server publishes.

        ``POST /agents/{id}/keys`` has no MLS guard, so a rotation leaves the leaf
        carrying the credential the group was founded on while the server names a
        different one. Subtracting by published key would classify this seated
        member's leaf as an orphan and Remove it.
        """
        rotator = "12121212-3434-5656-7878-909090909090"
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID, rotator])
        identities[agent_id] = open_mls_client(tmp_config_dir, agent_id).public_key()
        seated_leaf = identities[rotator]
        # What the server publishes AFTER the rotation: a key no leaf carries.
        identities[rotator] = _peer_client(
            tmp_path, "12121212-3434-5656-7878-909090909091"
        ).public_key()
        posted = _mock_server(
            members=[agent_id, rotator],
            live=[],
            unreadable=set(),
            identities=identities,
        )

        result = reclaim_orphan_leaves(sync_client._http, tmp_config_dir, agent_id, GROUP_ID)

        assert (result.found, result.reclaimed, result.commits) == (0, 0, 0)
        assert result.declined is not None
        assert result.declined.reason == "identity_unseated"
        assert rotator in result.declined.detail
        assert posted.call_count == 0
        # Nothing was committed, so BOTH leaves survive — including the no-show's,
        # which a pass that ran would legitimately have retired.
        group = _local(tmp_config_dir, agent_id)
        assert leaf_index(group, seated_leaf) is not None
        assert leaf_index(group, identities[NO_SHOW_ID]) is not None

    @respx.mock
    def test_reclaim_when_the_outstanding_read_fails_then_it_declines_by_name(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        identities = _found_with(tmp_config_dir, agent_id, tmp_path, [NO_SHOW_ID])
        identities[agent_id] = open_mls_client(tmp_config_dir, agent_id).public_key()
        posted = _mock_server(members=[agent_id], live=[], unreadable=set(), identities=identities)
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
