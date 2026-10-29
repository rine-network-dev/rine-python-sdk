"""The group surface: visibility, rosters, plural invites, removal.

Server mocked, everything else real. Where a wire detail is load-bearing — the
roster field, the plural invite field, the removal epoch being a **query**
parameter — the assertion is on the request the server would have received.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._mls.removal import MlsRemovalCommit
from rine._sender_key_ops import delete_sender_key
from rine.errors import ConflictError, NotFoundError
from rine.format import describe_group_encryption, group_encryption
from rine.group_admission import GroupCreateWithRoster
from rine.types import GroupRead

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
AGENT_ID = "00000000-1111-2222-3333-444444444444"
INVITEE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "cccccccc-dddd-eeee-ffff-000000000000"

_GROUP = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": None,
    "mls_pending": False,
    "mls_cipher_suite": None,
}


def _token() -> None:
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )


def _group_row() -> None:
    """``GET /groups/{id}`` — the one row a group UUID is resolved through.

    Every verb here names its group by id, and the resolve now reads that id's
    own row before the verb's own request: an id this caller cannot read is
    refused there rather than travelling to the wire. It cost nothing before,
    which is why none of these tests mocked the route.

    🔴 The ROW, not ``GET /groups``. This rung began as a roster match, and the
    roster is now read on the refusal path alone — a test that mocks it here is
    describing traffic the client no longer spends.
    """
    respx.get(f"{API}/groups/{GROUP_ID}").mock(return_value=httpx.Response(200, json=_GROUP))


def _agents() -> None:
    """The org's one agent, so the client can name who is acting."""
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": AGENT_ID,
                        "name": "test-agent",
                        "handle": "test-agent@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


def _two_agents() -> None:
    """Two agents, so the actor slot carries a choice the caller has to make."""
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": AGENT_ID,
                        "name": "test-agent",
                        "handle": "test-agent@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    },
                    {
                        "id": OTHER,
                        "name": "bob",
                        "handle": "bob@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    },
                ]
            },
        )
    )


def _no_mls(monkeypatch) -> None:
    """Found nothing: these tests are about the group routes, not about MLS."""
    monkeypatch.setattr(
        "rine._mls.group_init.init_mls_group",
        lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("no MLS in this test")),
    )


class TestVisibilityMustBeStated:
    def test_create_without_visibility_refuses_and_names_both_choices(self, sync_client):
        with pytest.raises(ValueError) as err:
            sync_client.groups.create("test-group")

        said = str(err.value)
        assert '"public"' in said and '"private"' in said
        assert "dir.rine.network" in said
        assert "signal" in said

    @pytest.mark.anyio
    async def test_async_create_without_visibility_refuses_the_same_way(self, async_client):
        with pytest.raises(ValueError, match="dir.rine.network"):
            await async_client.groups.create("test-group")

    @respx.mock
    def test_a_stated_visibility_reaches_the_wire(self, sync_client, monkeypatch):
        _token()
        _no_mls(monkeypatch)
        route = respx.post(f"{API}/groups").mock(
            return_value=httpx.Response(201, json={**_GROUP, "visibility": "public"})
        )

        sync_client.groups.create("test-group", visibility="public")

        assert json.loads(route.calls[0].request.content)["visibility"] == "public"


class TestARosterInvites:
    @respx.mock
    def test_create_with_members_sends_a_roster_and_reports_each_one(
        self, sync_client, monkeypatch
    ):
        _token()
        _no_mls(monkeypatch)
        route = respx.post(f"{API}/groups").mock(
            return_value=httpx.Response(
                201,
                json={
                    "group": _GROUP,
                    "roster": {
                        "invited": 1,
                        "skipped": 1,
                        "entries": [
                            {"agent_id": INVITEE, "status": "invited"},
                            {"agent_id": OTHER, "status": "skipped", "reason": "agent_revoked"},
                        ],
                    },
                },
            )
        )

        group = sync_client.groups.create(
            "test-group", visibility="private", members=[INVITEE, OTHER]
        )

        assert json.loads(route.calls[0].request.content)["members"] == [INVITEE, OTHER]
        assert group.roster is not None
        assert group.roster.invited == 1
        assert group.roster.entries[1].reason == "agent_revoked"
        # A roster invites; it never seats. The group has one member.
        assert group.member_count == 0 or group.member_count == 1

    @respx.mock
    def test_create_without_members_reads_the_response_it_always_read(
        self, sync_client, monkeypatch
    ):
        _token()
        _no_mls(monkeypatch)
        respx.post(f"{API}/groups").mock(return_value=httpx.Response(201, json=_GROUP))

        group = sync_client.groups.create("test-group", visibility="private")

        assert isinstance(group, GroupCreateWithRoster)
        assert group.roster is None
        assert str(group.id) == GROUP_ID


class TestPluralInvite:
    @respx.mock
    def test_invite_many_names_agent_ids_and_returns_per_member_outcomes(self, sync_client):
        _token()
        respx.get(f"{API}/groups/{GROUP_ID}").mock(return_value=httpx.Response(200, json=_GROUP))
        route = respx.post(f"{API}/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(
                201,
                json={
                    "invited": 1,
                    "skipped": 1,
                    "entries": [
                        {"agent_id": INVITEE, "status": "invited"},
                        {"agent_id": OTHER, "status": "skipped", "reason": "already_a_member"},
                    ],
                },
            )
        )

        report = sync_client.groups.invite_many(GROUP_ID, [INVITEE, OTHER])

        body = json.loads(route.calls[0].request.content)
        assert body["agent_ids"] == [INVITEE, OTHER]
        assert "agent_id" not in body
        assert report.invited == 1
        assert report.entries[1].reason == "already_a_member"

    @respx.mock
    def test_singular_invite_still_names_one_agent_and_answers_a_request(self, sync_client):
        _token()
        respx.get(f"{API}/groups/{GROUP_ID}").mock(return_value=httpx.Response(200, json=_GROUP))
        route = respx.post(f"{API}/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(
                201, json={"id": "11111111-2222-3333-4444-555555555555", "status": "invited"}
            )
        )

        result = sync_client.groups.invite(GROUP_ID, INVITEE)

        body = json.loads(route.calls[0].request.content)
        assert body == {"agent_id": INVITEE}
        assert result.status == "invited"
        assert str(result.request_id) == "11111111-2222-3333-4444-555555555555"

    @respx.mock
    def test_an_invite_that_landed_survives_a_group_read_that_does_not(self, sync_client):
        _token()
        # ⚠️ One route, two readers: the id is RESOLVED through
        # ``GET /groups/{id}`` and the post-invite effects read the same route
        # again to see what the group is. Only the second read may fail here —
        # a resolve that faults has nothing to survive, because the invite was
        # never sent.
        answers = iter([httpx.Response(200, json=_GROUP)])
        respx.get(f"{API}/groups/{GROUP_ID}").mock(
            side_effect=lambda _request: next(answers, httpx.Response(500))
        )
        respx.post(f"{API}/groups/{GROUP_ID}/invite").mock(
            return_value=httpx.Response(201, json={"status": "invited"})
        )

        assert sync_client.groups.invite(GROUP_ID, INVITEE).status == "invited"


def _mls_group(policy: str) -> dict:
    """A latched MLS group on the named enrollment policy."""
    return {**_GROUP, "enrollment_policy": policy, "mls_group_id": "latched"}


def _invite_route(policy: str, status: str) -> None:
    """The group read the invite effects start with, and the invite itself."""
    _token()
    _agents()
    respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_mls_group(policy))
    )
    respx.post(f"{API}/groups/{GROUP_ID}/invite").mock(
        return_value=httpx.Response(
            201, json={"id": "11111111-2222-3333-4444-555555555555", "status": status}
        )
    )


def _watch_seating(monkeypatch, client) -> tuple[list[list[str]], list[str]]:
    """Record who the invite seated and who it notified, without doing either.

    The MLS add is stubbed rather than mocked at the wire, because what is being
    asserted is that the client never reaches for a KeyPackage at all — a wire
    mock would prove only that a particular request was not made.
    """
    seated: list[list[str]] = []
    notified: list[str] = []
    monkeypatch.setattr(
        "rine._mls.add_members.add_mls_group_members",
        lambda *args, **_kw: seated.append(list(args[4])),
    )
    monkeypatch.setattr(client, "send", lambda to, *_a, **_kw: notified.append(to))
    return seated, notified


class TestAnInviteToAVotingGroupNominates:
    """A nomination posts no commit; the approving vote does.

    Claiming the nominee's KeyPackage and Welcoming them would hand the group's
    epoch secret to an agent the electorate may still deny, and nothing but the
    manual reclamation pass ever reaches the leaf that consumed. The vote seats
    the member, and seating is what grants the key.

    The notice goes out on every policy: a nominee that cannot see the
    nomination cannot consent to it, and consent is what its own join call
    records.
    """

    @respx.mock
    def test_a_closed_group_still_seats_the_invitee_as_it_always_did(
        self, sync_client, monkeypatch
    ):
        """The control arm. Same call, same group, one field different."""
        _invite_route("closed", "invited")
        seated, notified = _watch_seating(monkeypatch, sync_client)

        sync_client.groups.invite(GROUP_ID, INVITEE)

        assert seated == [[INVITEE]]
        assert notified == [INVITEE]

    @respx.mock
    def test_a_majority_group_notifies_the_nominee_and_seats_nobody(
        self, sync_client, monkeypatch
    ):
        _invite_route("majority", "pending")
        seated, notified = _watch_seating(monkeypatch, sync_client)

        result = sync_client.groups.invite(GROUP_ID, INVITEE)

        assert result.status == "pending"
        assert seated == []
        assert notified == [INVITEE]

    @respx.mock
    def test_a_unanimity_group_seats_nobody_either(self, sync_client, monkeypatch):
        _invite_route("unanimity", "pending")
        seated, _ = _watch_seating(monkeypatch, sync_client)

        sync_client.groups.invite(GROUP_ID, INVITEE)

        assert seated == []

    @pytest.mark.anyio
    @respx.mock
    async def test_the_async_twin_holds_the_same_gate(self, async_client, monkeypatch):
        """The async path writes its own notify loop; the gate must be shared.

        This half has no test that reads its docstring and none that ran its
        seating branch, which makes it the easiest place in the package to ship
        a half-change.
        """
        _invite_route("majority", "pending")
        seated: list[list[str]] = []
        monkeypatch.setattr(
            "rine._mls.add_members.add_mls_group_members",
            lambda *args, **_kw: seated.append(list(args[4])),
        )

        async def _send(to, *_a, **_kw):
            return None

        monkeypatch.setattr(async_client, "send", _send)

        await async_client.groups.invite(GROUP_ID, INVITEE)

        assert seated == []


def _commits(monkeypatch, *, epoch: int, removed_leaf: bool = True) -> None:
    """Stand in for the MLS core's Remove commit, without the compiled wheel."""
    monkeypatch.setattr(
        "rine._mls.removal.remove_mls_group_member",
        lambda *_a, **_kw: MlsRemovalCommit(epoch=epoch, removed_leaf=removed_leaf),
    )


class TestRemovingAMember:
    @respx.mock
    def test_a_group_that_needs_no_commit_is_one_delete(self, sync_client):
        _token()
        _group_row()
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )

        sync_client.groups.remove_member(GROUP_ID, INVITEE)

        assert route.call_count == 1
        assert "mls_removal_epoch" not in str(route.calls[0].request.url)

    @respx.mock
    def test_the_removal_epoch_is_a_query_parameter_naming_the_commits_epoch(
        self, sync_client, monkeypatch
    ):
        _token()
        _group_row()
        _agents()
        calls: list[httpx.Request] = []

        def _delete(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(
                    409,
                    json={
                        "error": "mls_removal_commit_required",
                        "detail": "post the Remove commit first",
                    },
                )
            return httpx.Response(204)

        respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(side_effect=_delete)
        _commits(monkeypatch, epoch=7)

        sync_client.groups.remove_member(GROUP_ID, INVITEE)

        assert len(calls) == 2
        # A query parameter. As a body field the server binds None and refuses
        # the removal for want of the commit the client just posted.
        assert calls[1].url.params["mls_removal_epoch"] == "7"
        assert not calls[1].content

    @respx.mock
    def test_a_kick_that_committed_reports_the_epoch_and_says_what_it_cost(
        self, sync_client, monkeypatch
    ):
        """The kick's sentence is the SDK's, not each surface's own."""
        _token()
        _group_row()
        _agents()
        calls: list[httpx.Request] = []

        def _delete(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(
                    409,
                    json={"error": "mls_removal_commit_required", "detail": "commit first"},
                )
            return httpx.Response(204)

        respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(side_effect=_delete)
        _commits(monkeypatch, epoch=7)

        result = sync_client.groups.remove_member(GROUP_ID, INVITEE)

        assert result.left is False
        assert result.encryption == "mls"
        assert result.mls_removal_epoch == 7
        assert result.mls_removed_leaf is True
        assert result.local_state_retired is False
        assert "epoch 7" in result.message
        assert "ratchet-tree leaf" in result.message

    @respx.mock
    def test_a_removal_stranded_by_a_failed_delete_is_completed_not_refused(
        self, sync_client, monkeypatch
    ):
        """A stranded removal is completed, not refused.

        An earlier attempt's Remove commit landed and its DELETE did not, so the
        target holds no leaf and no second Remove can be built for it. This
        client used to raise here — it could derive an epoch only from a commit
        it could no longer make — and the member row was stuck for good. The
        path-only commit's epoch is what finally lets the DELETE through, and
        the sentence must not claim an eviction that did not happen.
        """
        _token()
        _group_row()
        _agents()
        calls: list[httpx.Request] = []

        def _delete(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(
                    409,
                    json={"error": "mls_removal_commit_required", "detail": "commit first"},
                )
            return httpx.Response(204)

        respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(side_effect=_delete)
        _commits(monkeypatch, epoch=11, removed_leaf=False)

        result = sync_client.groups.remove_member(GROUP_ID, INVITEE)

        assert len(calls) == 2
        assert calls[1].url.params["mls_removal_epoch"] == "11"
        assert result.mls_removal_epoch == 11
        assert result.mls_removed_leaf is False
        # The narrow, true thing: ``removed_leaf=False`` is "no leaf is theirs", and
        # the message says what kept them out.
        assert "no leaf in the ratchet tree is theirs" in result.message
        assert "rotated" not in result.message
        assert "took their ratchet-tree leaf" not in result.message

    @respx.mock
    def test_a_kick_the_server_took_without_a_commit_claims_no_crypto(self, sync_client):
        """A group with no MLS state: the eviction is the delivery filter's."""
        _token()
        _group_row()
        _agents()
        respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.groups.remove_member(GROUP_ID, INVITEE)

        assert result.encryption == "sender-key"
        assert result.mls_removal_epoch is None
        assert result.mls_removed_leaf is None
        assert "no cryptographic eviction" in result.message

    @respx.mock
    def test_a_refusal_that_is_not_about_the_commit_is_not_retried(self, sync_client):
        _token()
        _group_row()
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(409, json={"error": "something_else", "detail": "no"})
        )

        with pytest.raises(ConflictError):
            sync_client.groups.remove_member(GROUP_ID, INVITEE)

        assert route.call_count == 1

    @respx.mock
    def test_an_actor_this_org_does_not_have_removes_under_the_agent_it_does(self, sync_client):
        """A one-agent org has nothing to choose, so it chooses.

        This test used to pin the opposite — a header-less DELETE and a report
        that declined to say whether it was a leave or a kick. That outcome was
        never the safe one: the server swallows a missing actor
        (``get_optional_acting_agent`` yields ``None``), so a same-org member was
        removed under no named identity at all. With one agent in the org there
        is exactly one identity the call could have meant, so the removal is
        attributed to it and the report can speak.
        """
        _token()
        _group_row()
        _agents()  # the org's one agent; "ghost" is not it
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )
        client = sync_client.with_options(agent="ghost")

        result = client.groups.remove_member(GROUP_ID, INVITEE)

        assert route.call_count == 1
        assert route.calls[0].request.headers.get("x-rine-agent") == AGENT_ID
        assert result.left is False
        assert result.local_state_retired is False
        client.close()

    @respx.mock
    @pytest.mark.anyio
    async def test_the_async_twin_also_attributes_it_to_the_one_agent(self, async_client):
        _token()
        _group_row()
        _agents()
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )
        client = async_client.with_options(agent="ghost")

        result = await client.groups.remove_member(GROUP_ID, INVITEE)

        assert route.call_count == 1
        assert route.calls[0].request.headers.get("x-rine-agent") == AGENT_ID
        assert result.left is False
        await client.close()

    @respx.mock
    def test_an_actor_named_on_the_call_resolves_the_same_way(self, sync_client):
        """The per-call slot is not stricter than the ambient one.

        The two used to diverge — the ambient actor was tolerated and a named one
        refused — on the argument that an unattributed DELETE is worse than a
        refusal. Both halves of that argument are gone here: the removal is
        attributed, to the only agent this org has.
        """
        _token()
        _group_row()
        _agents()  # the org's one agent; "opz" is not it
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )

        result = sync_client.groups.remove_member(GROUP_ID, INVITEE, agent="opz")

        assert route.call_count == 1
        assert route.calls[0].request.headers.get("x-rine-agent") == AGENT_ID
        assert result.left is False

    @respx.mock
    def test_a_multi_agent_org_still_removes_nothing_for_an_actor_it_lacks(self, sync_client):
        """🔴 Where a choice exists, the old safety argument still holds in full.

        A refusal here costs a retry; guessing costs a member removed under the
        wrong agent's name. The DELETE must never leave, so this asserts the call
        count and not merely the exception.
        """
        _token()
        _two_agents()
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )

        with pytest.raises(NotFoundError) as caught:
            sync_client.groups.remove_member(GROUP_ID, INVITEE, agent="opz")

        assert route.call_count == 0, "an unattributed removal is worse than a refusal"
        assert "opz" in str(caught.value)

    @respx.mock
    @pytest.mark.anyio
    async def test_the_async_twin_also_removes_nothing_for_a_multi_agent_org(self, async_client):
        _token()
        _two_agents()
        route = respx.delete(f"{API}/groups/{GROUP_ID}/members/{INVITEE}").mock(
            return_value=httpx.Response(204)
        )

        with pytest.raises(NotFoundError):
            await async_client.groups.remove_member(GROUP_ID, INVITEE, agent="opz")

        assert route.call_count == 0


class TestLeavingAnOpenGroup:
    """The verb the shipped sentence was false for, on the group type it lied about."""

    @respx.mock
    def test_the_leave_reports_the_sender_key_wipe_and_what_it_does_not_do(
        self, sync_client, tmp_config_dir
    ):
        """An open group has no cryptographic eviction, and says so."""
        from rine._crypto.sender_keys import generate_sender_key
        from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state

        _token()
        _group_row()
        _agents()
        respx.delete(f"{API}/groups/{GROUP_ID}/members/{AGENT_ID}").mock(
            return_value=httpx.Response(204)
        )
        save_sender_key_state(
            tmp_config_dir, AGENT_ID, GROUP_ID, [generate_sender_key(GROUP_ID, AGENT_ID)]
        )

        result = sync_client.groups.remove_member(GROUP_ID, AGENT_ID)

        assert result.left is True
        assert result.encryption == "sender-key"
        assert result.local_state_retired is True
        assert "no cryptographic eviction" in result.message
        assert "rotating their sender key" in result.message
        assert load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID) == []


class TestRetiringSenderKeyMaterial:
    def test_retiring_a_group_this_agent_holds_nothing_for_is_not_an_error(self, tmp_config_dir):
        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

    def test_the_wipe_takes_the_groups_own_key_its_peers_keys_and_the_cached_ones(
        self, tmp_config_dir
    ):
        from rine._crypto.sender_keys import generate_sender_key
        from rine._crypto.sender_keys_helpers import (
            load_sender_key_states,
            save_sender_key_state,
        )

        own = generate_sender_key(GROUP_ID, AGENT_ID)
        own.skipped_keys = {3: "cached-message-key"}
        peer = generate_sender_key(GROUP_ID, INVITEE)
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [own, peer])
        assert load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)

        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID) == []

    def test_another_groups_material_survives(self, tmp_config_dir):
        from rine._crypto.sender_keys import generate_sender_key
        from rine._crypto.sender_keys_helpers import (
            load_sender_key_states,
            save_sender_key_state,
        )

        other_group = "dddddddd-eeee-ffff-0000-111111111111"
        save_sender_key_state(
            tmp_config_dir, AGENT_ID, GROUP_ID, [generate_sender_key(GROUP_ID, AGENT_ID)]
        )
        save_sender_key_state(
            tmp_config_dir, AGENT_ID, other_group, [generate_sender_key(other_group, AGENT_ID)]
        )

        delete_sender_key(tmp_config_dir, AGENT_ID, GROUP_ID)

        assert load_sender_key_states(tmp_config_dir, AGENT_ID, other_group)

    @respx.mock
    def test_leaving_retires_the_local_material_for_that_group(self, sync_client, tmp_config_dir):
        from rine._crypto.sender_keys import generate_sender_key
        from rine._crypto.sender_keys_helpers import (
            load_sender_key_states,
            save_sender_key_state,
        )

        _token()
        _group_row()
        _agents()
        respx.delete(f"{API}/groups/{GROUP_ID}/members/{AGENT_ID}").mock(
            return_value=httpx.Response(204)
        )
        save_sender_key_state(
            tmp_config_dir, AGENT_ID, GROUP_ID, [generate_sender_key(GROUP_ID, AGENT_ID)]
        )

        sync_client.groups.remove_member(GROUP_ID, AGENT_ID)

        assert load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID) == []


class TestWhatAGroupIsEncryptedWith:
    def test_a_latched_group_is_mls(self):
        group = GroupRead.model_validate({**_GROUP, "mls_group_id": "latch"})

        assert group_encryption(group) == "mls"
        assert "post-quantum" in describe_group_encryption(group)

    def test_an_init_in_flight_is_not_sender_key(self):
        group = GroupRead.model_validate({**_GROUP, "mls_pending": True})

        assert group_encryption(group) == "mls-pending"

    def test_a_failed_init_promises_nothing_about_the_traffic(self):
        # 🔴 Two sentences shipped here and both were false. The first said the
        # group "holds no keys and cannot carry a message"; the second said it
        # "carries sender-key traffic". This row is the reason the second one is
        # false: an init that reached the server before it failed leaves
        # `mls_pending` set, and `POST /messages` then refuses every non-`mls-v1`
        # send with a 409 until the server's own 900 s self-heal clears it. The
        # create response this renders from predates the init, so nothing here
        # can tell that group from one whose init never left the client.
        group = GroupCreateWithRoster.model_validate(
            {**_GROUP, "mls_pending": True, "mls_init": {"reason": "the server refused"}}
        )

        assert group_encryption(group) == "mls-failed"
        said = describe_group_encryption(group)
        assert "did not land" in said
        assert "refuses every non-MLS send" in said
        assert "cannot carry" not in said
        assert "carries sender-key traffic" not in said
        # Rendered by three connectors, none of which has this verb.
        assert "resume_admission()" not in said

    def test_a_tree_that_was_never_founded_gets_both_halves_of_the_answer(self):
        # The same group from any later read: the server nulls `mls_pending` on
        # its own, so nothing but the create-time intent survives to say this
        # group was meant to run MLS.
        group = GroupRead.model_validate({**_GROUP, "mls_enabled": True})

        assert group_encryption(group) == "mls-never-founded"
        said = describe_group_encryption(group)
        assert "Sender Keys" in said
        assert "ratchet tree was never founded" in said

    def test_an_open_group_is_told_it_is_not_post_quantum(self):
        group = GroupRead.model_validate({**_GROUP, "enrollment_policy": "open"})

        assert group_encryption(group) == "sender-key"
        said = describe_group_encryption(group)
        assert "NOT post-quantum" in said
        assert "never founded" not in said
