"""What ``groups.join`` accepts as a reference, and what it refuses.

Join is the one group verb aimed at a group this org is by definition NOT in,
so the shared ladder every other verb uses — ``GET /groups``, which lists the
groups the org is already seated in — is the one place the target cannot be. A
handle read straight off ``discover_groups()`` came back ``Group not found``
with the server never having refused anything; these tests are that defect, and
the bounds of the fix.

Driven through ``client.groups.join`` rather than through the resolver, because
what a caller has is the verb: a rung that resolved but never reached
``POST /groups/{id}/join`` would pass an implementation test and still not join
anything. Every rung is asserted by the id the join was POSTed to.

🔴 **The two classes below are deliberately the same list of cases.** The sync
and async clients are hand-kept twins with no shared code path, so a case
asserted on one and not the other is a rung nothing guards on the surface the
defect was measured on — hermes, which is async. The near-miss case in
particular is what makes the directory rung legal at all: drop it and
``items[0]`` passes every other test in this file.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from rine._group_join import (
    BARE_NAME_IS_ONLY_AN_INVITATION,
    DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ,
    DIRECTORY_PAGE_LIMIT,
    DIRECTORY_PAGES_FOR_A_JOIN,
    JOIN_TAKES_A_HANDLE_OR_AN_ID,
    NO_SUCH_GROUP_TO_JOIN,
    TWO_INVITATIONS_OF_THAT_NAME,
    directory_query_for_handle,
    is_exact_group_handle,
    is_invitation_of_that_name,
)
from rine._group_ref import GROUP_NOT_FOUND_LEAD, group_local_part
from rine.errors import NotFoundError

API = "https://rine.network"
SEATED_ID = "11111111-1111-1111-1111-111111111111"
INVITED_ID = "22222222-2222-2222-2222-222222222222"
PUBLIC_ID = "33333333-3333-3333-3333-333333333333"
OTHER_ID = "77777777-7777-7777-7777-777777777777"

HANDLE = "#warehouse-restock@gqb.rine.network"
LOCAL_NAME = "warehouse-restock"
OTHER_ORG_HANDLE = "#warehouse-restock@other.rine.network"
NEAR_MISS_HANDLE = "#warehouse-restock-old@other.rine.network"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}

_MEMBER_PAYLOAD = {
    "id": "44444444-4444-4444-4444-444444444444",
    "group_id": PUBLIC_ID,
    "agent_id": "00000000-1111-2222-3333-444444444444",
    "role": "member",
    "joined_at": "2024-01-01T00:00:00Z",
}


def _group_row(group_id: str, handle: str = HANDLE) -> dict[str, Any]:
    return {
        "id": group_id,
        "name": LOCAL_NAME,
        "handle": handle,
        "enrollment_policy": "open",
        "visibility": "public",
        "created_at": "2024-01-01T00:00:00Z",
    }


def _invite_row(group_id: str, handle: str | None = HANDLE) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "55555555-5555-5555-5555-555555555555",
        "group_id": group_id,
        "agent_id": "00000000-1111-2222-3333-444444444444",
        "invited_by": "66666666-6666-6666-6666-666666666666",
        "status": "invited",
        "created_at": "2024-01-01T00:00:00Z",
        # Derived from the handle, never pinned to LOCAL_NAME: the server mints
        # `#{name}@{org}`, so a row whose two fields disagree is a shape this
        # server cannot produce — and a fixture that produces it makes the
        # bare-name refusal untestable.
        "group_name": (handle or f"#{LOCAL_NAME}@x").lstrip("#").split("@")[0],
    }
    if handle is not None:
        row["group_handle"] = handle
    return row


def _seated(items: list[dict[str, Any]]) -> respx.Route:
    """``GET /groups?handle=`` — the groups this org already holds a seat in."""
    return respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": items}))


def _invites(items: list[dict[str, Any]]) -> respx.Route:
    return respx.get(f"{API}/groups/invites").mock(
        return_value=httpx.Response(200, json={"items": items})
    )


def _directory(items: list[dict[str, Any]], total_estimate: int | None = None) -> respx.Route:
    """One directory page, with the server's own ``total_estimate`` field.

    🔴 ``total_estimate``, not ``total``: that is the key
    ``DirectoryGroupSearchResponse`` actually sends, and a fixture that sends
    the other one makes the truncation sentence untestable while every other
    assertion in the file still passes.
    """
    body: dict[str, Any] = {"items": items, "next_cursor": None}
    if total_estimate is not None:
        body["total_estimate"] = total_estimate
    return respx.get(f"{API}/directory/groups").mock(return_value=httpx.Response(200, json=body))


def _directory_pages(total_estimate: int | None) -> respx.Route:
    """A directory with more matching rows than one join is allowed to read.

    Every page carries a cursor and a single non-matching row, so the search
    stops on its page budget rather than on running out of rows.
    """

    def page(_request: httpx.Request) -> httpx.Response:
        body: dict[str, Any] = {
            "items": [_group_row(OTHER_ID, NEAR_MISS_HANDLE)],
            "next_cursor": "more",
        }
        if total_estimate is not None:
            body["total_estimate"] = total_estimate
        return httpx.Response(200, json=body)

    return respx.get(f"{API}/directory/groups").mock(side_effect=page)


def _joins(group_id: str) -> respx.Route:
    return respx.post(f"{API}/groups/{group_id}/join").mock(
        return_value=httpx.Response(200, json={**_MEMBER_PAYLOAD, "group_id": group_id})
    )


def _mock_token() -> None:
    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=_TOKEN_RESPONSE))


def _refusal(err: NotFoundError) -> str:
    """The detail, never ``str(err)``.

    The three Python connectors' ``_not_found_message`` reads ``.detail``, and
    ``str`` carries a ``404: `` prefix that would defeat their ``startswith``
    on the lead phrase.
    """
    return err.detail


class TestJoinReferenceSync:
    @respx.mock
    def test_join_when_given_a_uuid_then_posts_it_without_resolving(self, sync_client):
        _mock_token()
        joined = _joins(PUBLIC_ID)

        assert sync_client.groups.join(PUBLIC_ID).status == "joined"
        assert joined.called

    @respx.mock
    def test_join_when_the_handle_is_a_group_the_org_sits_in_then_the_server_decides(
        self, sync_client
    ):
        """Resolved rather than refused, so the answer is the server's 409, not ours.

        A caller standing inside the group is not a caller who typed the handle
        wrong, and only the server can say so.
        """
        _mock_token()
        _seated([_group_row(SEATED_ID)])
        joined = _joins(SEATED_ID)

        assert sync_client.groups.join(HANDLE).status == "joined"
        assert joined.called

    @respx.mock
    def test_join_when_the_handle_is_an_invitation_then_resolves_off_the_invite(self, sync_client):
        """An invitation mints no membership row, so the seated rung cannot see it."""
        _mock_token()
        _seated([])
        _invites([_invite_row(INVITED_ID)])
        joined = _joins(INVITED_ID)

        assert sync_client.groups.join(HANDLE).status == "joined"
        assert joined.called

    @respx.mock
    def test_join_when_the_handle_is_only_in_the_directory_then_resolves_off_it(self, sync_client):
        """The measured defect: a handle ``discover_groups`` had just printed."""
        _mock_token()
        _seated([])
        _invites([])
        directory = _directory([_group_row(PUBLIC_ID)])
        joined = _joins(PUBLIC_ID)

        assert sync_client.groups.join(HANDLE).status == "joined"
        assert joined.called
        params = directory.calls.last.request.url.params
        assert params["q"] == LOCAL_NAME
        assert params["limit"] == str(DIRECTORY_PAGE_LIMIT)

    @respx.mock
    def test_join_when_it_reads_the_directory_then_the_read_carries_the_token(self, sync_client):
        """🔴 Asserted on the request the LADDER made, not on a helper.

        The TypeScript ladder has always sent the bearer token on this rung, so
        a join disclosed the caller on eve and mastra and nothing on the three
        Python connectors. The route takes no identity either way; what this pins
        is that one verb no longer discloses two different things depending on
        which SDK is running it. The contrast below is half the assertion:
        ``discover_groups`` is the PUBLIC verb and must stay anonymous.
        """
        _mock_token()
        _seated([])
        _invites([])
        directory = _directory([_group_row(PUBLIC_ID)])
        _joins(PUBLIC_ID)

        sync_client.groups.join(HANDLE)
        assert directory.calls.last.request.headers.get("authorization") == "Bearer test-token"

        sync_client.discover_groups(q=LOCAL_NAME)
        assert directory.calls.last.request.headers.get("authorization") is None

    @respx.mock
    def test_join_when_the_directory_row_is_a_different_group_then_refuses(self, sync_client):
        """🔴 The ILIKE is a candidate generator; the handle is what decides.

        ``?q=warehouse-restock`` matches every group whose name or description
        merely contains it. Accepting the first row would be the fuzzy match
        that feeds an irreversible verb, and that is refused.
        """
        _mock_token()
        _seated([])
        _invites([])
        _directory([_group_row(PUBLIC_ID, NEAR_MISS_HANDLE)], total_estimate=1)

        with pytest.raises(NotFoundError):
            sync_client.groups.join(HANDLE)

    @respx.mock
    def test_join_when_a_bare_name_is_one_of_this_agents_invitations_then_joins_it(
        self, sync_client
    ):
        """The one rung a bare name gets, and the reason it is admissible.

        The invitations list is bounded to groups that have already asked for
        this agent, so a match there cannot be a group the caller has no
        business in — which is what the directory could never promise.
        """
        _mock_token()
        seated = _seated([_group_row(SEATED_ID)])
        _invites([_invite_row(INVITED_ID)])
        joined = _joins(INVITED_ID)

        assert sync_client.groups.join(LOCAL_NAME).status == "joined"
        assert joined.called
        assert not seated.called

    @respx.mock
    def test_join_when_a_bare_name_matches_no_invitation_then_refuses_without_widening(
        self, sync_client
    ):
        """🔴 Nothing wider is searched, and the refusal says so."""
        _mock_token()
        seated = _seated([_group_row(SEATED_ID)])
        _invites([_invite_row(INVITED_ID, "#other@gqb.rine.network")])
        directory = _directory([_group_row(PUBLIC_ID)])

        with pytest.raises(NotFoundError) as refused:
            sync_client.groups.join(LOCAL_NAME)

        message = _refusal(refused.value)
        assert message.startswith(GROUP_NOT_FOUND_LEAD)
        assert BARE_NAME_IS_ONLY_AN_INVITATION in message
        assert JOIN_TAKES_A_HANDLE_OR_AN_ID in message
        assert not seated.called
        assert not directory.called

    @respx.mock
    def test_join_when_two_invitations_answer_one_bare_name_then_refuses_rather_than_picks(
        self, sync_client
    ):
        """🔴 A bare name carries no org, and seating the wrong group is final."""
        _mock_token()
        _invites([_invite_row(INVITED_ID), _invite_row(OTHER_ID, OTHER_ORG_HANDLE)])

        with pytest.raises(NotFoundError) as refused:
            sync_client.groups.join(LOCAL_NAME)

        message = _refusal(refused.value)
        assert TWO_INVITATIONS_OF_THAT_NAME in message
        assert HANDLE in message
        assert OTHER_ORG_HANDLE in message

    @respx.mock
    def test_join_when_no_rung_answers_the_handle_then_names_all_three(self, sync_client):
        _mock_token()
        _seated([])
        _invites([])
        _directory([], total_estimate=0)

        with pytest.raises(NotFoundError) as refused:
            sync_client.groups.join(HANDLE)

        message = _refusal(refused.value)
        assert message.startswith(GROUP_NOT_FOUND_LEAD)
        assert NO_SUCH_GROUP_TO_JOIN in message
        assert JOIN_TAKES_A_HANDLE_OR_AN_ID in message

    @respx.mock
    def test_join_when_the_directory_search_hit_its_budget_then_states_the_shortfall(
        self, sync_client
    ):
        """🔴 A bounded search must never report itself as an exhaustive one.

        Two pages of one row each, against a server that says nine rows match:
        seven were never read, so "not a public group in the directory" is a
        claim this join has not earned.
        """
        _mock_token()
        _seated([])
        _invites([])
        directory = _directory_pages(total_estimate=9)

        with pytest.raises(NotFoundError) as refused:
            sync_client.groups.join(HANDLE)

        message = _refusal(refused.value)
        assert DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ.replace("{unread}", "7") in message
        assert NO_SUCH_GROUP_TO_JOIN not in message
        assert len(directory.calls) == DIRECTORY_PAGES_FOR_A_JOIN

    @respx.mock
    def test_join_when_the_server_sends_no_total_then_invents_no_shortfall(self, sync_client):
        """A shortfall invented out of a missing field is worse than none."""
        _mock_token()
        _seated([])
        _invites([])
        _directory_pages(total_estimate=None)

        with pytest.raises(NotFoundError) as refused:
            sync_client.groups.join(HANDLE)

        assert NO_SUCH_GROUP_TO_JOIN in _refusal(refused.value)


class TestJoinReferenceAsync:
    """The async twin is hand-kept, so every case above is asserted here too."""

    @respx.mock
    async def test_join_when_given_a_uuid_then_posts_it_without_resolving(self, async_client):
        _mock_token()
        joined = _joins(PUBLIC_ID)

        result = await async_client.groups.join(PUBLIC_ID)
        assert result.status == "joined"
        assert joined.called
        await async_client.close()

    @respx.mock
    async def test_join_when_the_handle_is_a_group_the_org_sits_in_then_the_server_decides(
        self, async_client
    ):
        _mock_token()
        _seated([_group_row(SEATED_ID)])
        joined = _joins(SEATED_ID)

        result = await async_client.groups.join(HANDLE)
        assert result.status == "joined"
        assert joined.called
        await async_client.close()

    @respx.mock
    async def test_join_when_the_handle_is_an_invitation_then_resolves_off_the_invite(
        self, async_client
    ):
        _mock_token()
        _seated([])
        _invites([_invite_row(INVITED_ID)])
        joined = _joins(INVITED_ID)

        result = await async_client.groups.join(HANDLE)
        assert result.status == "joined"
        assert joined.called
        await async_client.close()

    @respx.mock
    async def test_join_when_the_handle_is_only_in_the_directory_then_resolves_off_it(
        self, async_client
    ):
        _mock_token()
        _seated([])
        _invites([])
        directory = _directory([_group_row(PUBLIC_ID)])
        joined = _joins(PUBLIC_ID)

        result = await async_client.groups.join(HANDLE)
        assert result.status == "joined"
        assert joined.called
        params = directory.calls.last.request.url.params
        assert params["q"] == LOCAL_NAME
        assert params["limit"] == str(DIRECTORY_PAGE_LIMIT)
        await async_client.close()

    @respx.mock
    async def test_join_when_it_reads_the_directory_then_the_read_carries_the_token(
        self, async_client
    ):
        """🔴 The async twin of the sync token assertion; hermes is async."""
        _mock_token()
        _seated([])
        _invites([])
        directory = _directory([_group_row(PUBLIC_ID)])
        _joins(PUBLIC_ID)

        await async_client.groups.join(HANDLE)
        assert directory.calls.last.request.headers.get("authorization") == "Bearer test-token"

        await async_client.discover_groups(q=LOCAL_NAME)
        assert directory.calls.last.request.headers.get("authorization") is None
        await async_client.close()

    @respx.mock
    async def test_join_when_the_directory_row_is_a_different_group_then_refuses(
        self, async_client
    ):
        """🔴 The exactness filter, on the surface the defect was measured on.

        hermes is async. Replace the filter with ``items[0]`` and every other
        test in this class stays green while a join seats this agent in
        whichever group the ILIKE happened to return first.
        """
        _mock_token()
        _seated([])
        _invites([])
        _directory([_group_row(PUBLIC_ID, NEAR_MISS_HANDLE)], total_estimate=1)

        with pytest.raises(NotFoundError):
            await async_client.groups.join(HANDLE)
        await async_client.close()

    @respx.mock
    async def test_join_when_a_bare_name_is_one_of_this_agents_invitations_then_joins_it(
        self, async_client
    ):
        _mock_token()
        seated = _seated([_group_row(SEATED_ID)])
        _invites([_invite_row(INVITED_ID)])
        joined = _joins(INVITED_ID)

        result = await async_client.groups.join(LOCAL_NAME)
        assert result.status == "joined"
        assert joined.called
        assert not seated.called
        await async_client.close()

    @respx.mock
    async def test_join_when_a_bare_name_matches_no_invitation_then_refuses_without_widening(
        self, async_client
    ):
        _mock_token()
        seated = _seated([_group_row(SEATED_ID)])
        _invites([_invite_row(INVITED_ID, "#other@gqb.rine.network")])
        directory = _directory([_group_row(PUBLIC_ID)])

        with pytest.raises(NotFoundError) as refused:
            await async_client.groups.join(LOCAL_NAME)

        message = _refusal(refused.value)
        assert message.startswith(GROUP_NOT_FOUND_LEAD)
        assert BARE_NAME_IS_ONLY_AN_INVITATION in message
        assert JOIN_TAKES_A_HANDLE_OR_AN_ID in message
        assert not seated.called
        assert not directory.called
        await async_client.close()

    @respx.mock
    async def test_join_when_two_invitations_answer_one_bare_name_then_refuses_rather_than_picks(
        self, async_client
    ):
        _mock_token()
        _invites([_invite_row(INVITED_ID), _invite_row(OTHER_ID, OTHER_ORG_HANDLE)])

        with pytest.raises(NotFoundError) as refused:
            await async_client.groups.join(LOCAL_NAME)

        message = _refusal(refused.value)
        assert TWO_INVITATIONS_OF_THAT_NAME in message
        assert HANDLE in message
        assert OTHER_ORG_HANDLE in message
        await async_client.close()

    @respx.mock
    async def test_join_when_no_rung_answers_the_handle_then_names_all_three(self, async_client):
        _mock_token()
        _seated([])
        _invites([])
        _directory([], total_estimate=0)

        with pytest.raises(NotFoundError) as refused:
            await async_client.groups.join(HANDLE)

        message = _refusal(refused.value)
        assert message.startswith(GROUP_NOT_FOUND_LEAD)
        assert NO_SUCH_GROUP_TO_JOIN in message
        assert JOIN_TAKES_A_HANDLE_OR_AN_ID in message
        await async_client.close()

    @respx.mock
    async def test_join_when_the_directory_search_hit_its_budget_then_states_the_shortfall(
        self, async_client
    ):
        _mock_token()
        _seated([])
        _invites([])
        directory = _directory_pages(total_estimate=9)

        with pytest.raises(NotFoundError) as refused:
            await async_client.groups.join(HANDLE)

        message = _refusal(refused.value)
        assert DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ.replace("{unread}", "7") in message
        assert NO_SUCH_GROUP_TO_JOIN not in message
        assert len(directory.calls) == DIRECTORY_PAGES_FOR_A_JOIN
        await async_client.close()

    @respx.mock
    async def test_join_when_the_server_sends_no_total_then_invents_no_shortfall(
        self, async_client
    ):
        _mock_token()
        _seated([])
        _invites([])
        _directory_pages(total_estimate=None)

        with pytest.raises(NotFoundError) as refused:
            await async_client.groups.join(HANDLE)

        assert NO_SUCH_GROUP_TO_JOIN in _refusal(refused.value)
        await async_client.close()


class TestTheRepeatedSigil:
    """🔴 The repeated leading sigil, pinned on both stacks at once.

    These five cases are the ONLY thing standing between this product and the
    round-9 divergence: :func:`rine._group_ref.group_local_part` strips a whole
    run of ``#`` and the TypeScript twin ``groupLocalPart`` stripped one, so
    ``join("##ops")`` was seated on crewai, langchain and hermes and refused on
    eve and mastra — one reference, two answers, decided by which SDK the caller
    happened to be running. Their byte-for-byte twins are the
    ``a repeated leading sigil`` block in
    ``rine-core/test/resolve-group-join.test.ts``; a case added here without its
    twin there re-opens exactly the hole this closes.

    Unit-level, unlike the rest of this file, and deliberately: what diverged is
    a matcher's answer, not a rung's order, and the two stacks share no client to
    drive it through. The last case is the other half of the contract and the
    reason the forgiving spelling is safe — the FILTER did not move. A doubled
    sigil reaches a group only through the invitations rung, which is bounded to
    groups that have already invited this agent.
    """

    def test_local_part_when_the_sigil_repeats_then_names_the_same_group(self):
        assert group_local_part(f"#{HANDLE}") == LOCAL_NAME
        assert group_local_part(f"###{HANDLE}") == LOCAL_NAME

    def test_invitation_when_a_bare_name_doubles_the_sigil_then_still_matches(self):
        assert is_invitation_of_that_name(HANDLE, None, f"##{LOCAL_NAME}") is True

    def test_invitation_when_the_row_is_unenriched_then_matches_the_typed_name(self):
        assert is_invitation_of_that_name(None, LOCAL_NAME, f"##{LOCAL_NAME}") is True

    def test_directory_query_when_the_sigil_repeats_then_asks_for_the_bare_local_part(self):
        assert directory_query_for_handle(f"#{HANDLE}") == LOCAL_NAME

    def test_exactness_when_the_sigil_repeats_then_still_refuses(self):
        assert is_exact_group_handle(HANDLE, f"#{HANDLE}") is False
        assert is_exact_group_handle(f"#{HANDLE}", HANDLE) is False
