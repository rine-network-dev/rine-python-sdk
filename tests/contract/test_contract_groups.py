"""SDK-side groups contract: replay server goldens through the real SDK methods.

The join (200→JoinedResult / 202→PendingJoinResult) and invite (voucher vs open)
paths are replayed at method level via respx — the exact status→model dispatch
that shipped broken in 0.6.1 (``_resources/groups.py``). The remaining shapes use
the ``Model.model_validate`` floor: the SDK model must parse the golden
body and populate the fields the SDK relies on (extras it ignores are not breaks).
"""

from __future__ import annotations

import httpx
import respx

from rine.types import (
    GroupMember,
    GroupRead,
    InviteResult,
    JoinedResult,
    JoinRequestRead,
    PendingJoinResult,
    VoteResponse,
)

from ._loader import load

# Valid UUIDs, so the reference never reaches a handle rung. ``join`` still
# short-circuits on one — its ladder targets a group this org holds no seat in by
# definition, so it reads nothing — while ``invite`` takes the SEATED ladder and
# the seated ladder checks the id against ``GET /groups`` first. Mirrors
# tests/test_groups.py.
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
INVITEE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _mock_token() -> None:
    respx.post("https://rine.network/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "test-token", "expires_in": 900})
    )


def _mock_group_row() -> None:
    """``GET /groups/{id}`` — the row the seated resolve reads a UUID through.

    Only the invite tests need it, and that asymmetry is the point: the id read
    belongs to the seated path and must never reach the join ladder.
    """
    respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": GROUP_ID,
                "name": "test-group",
                "handle": "#test-group@myorg.rine.network",
            },
        )
    )


def _mock(method: str, path: str, name: str) -> dict:
    env = load(name)
    getattr(respx, method)(f"https://rine.network{path}").mock(
        return_value=httpx.Response(env["status"], json=env["body"])
    )
    return env


class TestJoinDispatch:
    """The 0.6.1 bug: server 200/202 must dispatch to the right discriminated type."""

    @respx.mock
    def test_open_join_200_dispatches_joined(self, sync_client):
        _mock_token()
        _mock("post", f"/groups/{GROUP_ID}/join", "groups_join_200_open")
        result = sync_client.groups.join(GROUP_ID)
        assert isinstance(result, JoinedResult)
        assert result.status == "joined"
        assert result.member.agent_id is not None
        assert result.member.role == "member"

    @respx.mock
    def test_voucher_join_200_dispatches_joined(self, sync_client):
        _mock_token()
        _mock("post", f"/groups/{GROUP_ID}/join", "groups_join_200_voucher")
        result = sync_client.groups.join(GROUP_ID)
        assert isinstance(result, JoinedResult)
        assert result.member.group_id is not None

    @respx.mock
    def test_vote_gated_join_202_dispatches_pending(self, sync_client):
        _mock_token()
        _mock("post", f"/groups/{GROUP_ID}/join", "groups_join_202")
        result = sync_client.groups.join(GROUP_ID)
        assert isinstance(result, PendingJoinResult)
        assert result.status == "pending"
        assert result.request.id is not None
        assert result.request.status == "pending"


class TestInviteDispatch:
    """invite() maps both server bodies onto InviteResult (id present vs absent)."""

    @respx.mock
    def test_voucher_invite_201_populates_request_id(self, sync_client):
        _mock_token()
        _mock_group_row()
        _mock("post", f"/groups/{GROUP_ID}/invite", "groups_invite_201_voucher")
        result = sync_client.groups.invite(GROUP_ID, INVITEE_ID)
        assert isinstance(result, InviteResult)
        assert result.status == "invited"
        assert result.request_id is not None

    @respx.mock
    def test_open_invite_request_id_none(self, sync_client):
        _mock_token()
        _mock_group_row()
        _mock("post", f"/groups/{GROUP_ID}/invite", "groups_invite_open")
        result = sync_client.groups.invite(GROUP_ID, INVITEE_ID)
        assert isinstance(result, InviteResult)
        assert result.status == "invited"
        assert result.request_id is None


class TestModelParseFloor:
    """The remaining shapes must parse through their SDK model with fields populated."""

    def test_create_parses_group_read(self):
        group = GroupRead.model_validate(load("groups_create_201")["body"])
        assert group.name and group.handle and group.enrollment_policy
        # The group carries the id of its own thread. A brand-new group has no
        # conversation yet, so null must parse as None rather than raise — that absence
        # is "nothing has been said here", never an error.
        assert group.conversation_id is None

    def test_list_item_parses_group_read(self):
        group = GroupRead.model_validate(load("groups_list_200")["body"]["items"][0])
        assert group.id is not None and group.handle
        assert group.conversation_id is None
        # The listing is credential-scoped, so the row has to say which of the org's
        # own agents hold a seat in it — the golden body carries them and the model
        # must land them as ids, not drop them the way pydantic drops any field a
        # model was never told about.
        assert [str(a) for a in group.member_agent_ids] == ["00000000-0000-0000-0000-000000000000"]

    def test_group_read_carries_a_conversation_id_when_the_server_sends_one(self):
        # The other half of that nullable field: when the group has been posted in, the
        # id must survive parsing onto the attribute the surfaces render. Same golden
        # body, with the one field the server fills in once a conversation exists.
        body = dict(load("groups_list_200")["body"]["items"][0])
        body["conversation_id"] = "dddddddd-eeee-ffff-aaaa-bbbbbbbbbbbb"
        assert str(GroupRead.model_validate(body).conversation_id) == body["conversation_id"]

    def test_members_item_parses_group_member(self):
        member = GroupMember.model_validate(load("groups_members_200")["body"]["items"][0])
        assert member.group_id is not None and member.role
        # The roster is authorised for the credential's scope, not for one agent, so a row
        # says whether it is one of the caller's own seats. A marker, never a
        # filter — the renderers mark this row and still print every other one.
        assert member.is_own_org is True

    def test_a_server_that_sends_neither_new_field_still_parses(self):
        """Both fields are additive, so an older server must not break this client.

        The wire-compat floor: strip the two keys the golden bodies now
        carry and the models still validate, landing on the empty answers rather
        than raising. An empty ``member_agent_ids`` reads as "no agent of your org
        is seated here", which is exactly what a server too old to compute it
        knows.
        """
        group_body = {
            k: v
            for k, v in load("groups_list_200")["body"]["items"][0].items()
            if k != "member_agent_ids"
        }
        member_body = {
            k: v
            for k, v in load("groups_members_200")["body"]["items"][0].items()
            if k != "is_own_org"
        }

        assert GroupRead.model_validate(group_body).member_agent_ids == []
        assert GroupMember.model_validate(member_body).is_own_org is False

    def test_requests_item_parses_join_request(self):
        req = JoinRequestRead.model_validate(load("groups_requests_200")["body"]["items"][0])
        assert req.id is not None and req.status == "pending"

    def test_vote_parses_vote_response(self):
        vote = VoteResponse.model_validate(load("groups_vote_200")["body"])
        assert vote.request_id is not None and vote.your_vote == "approve"

    def test_invites_item_parses_enriched_join_request(self):
        req = JoinRequestRead.model_validate(load("groups_invites_200")["body"]["items"][0])
        assert req.status == "invited"
        assert req.group_handle is not None and req.group_name is not None
