"""Where a group row gets the handles it spells its own seats with.

:mod:`rine.group_words` decides the *sentence*; this file pins the *wiring* —
that the four places the SDK mints a :class:`~rine.types.GroupRead` attach the
org's handle map to it, that an unreadable agent list degrades the row to UUIDs
instead of failing the call, and that a listing naming no seat pays for no
lookup at all.

The four sites matter individually because the enrichment is per-call, not on
the model: a site that forgets it renders UUIDs forever, on every surface that
reads through this SDK, and nothing else in the suite would notice.
"""

from __future__ import annotations

import httpx
import respx

from rine.group_words import NO_OWN_AGENTS, own_agents_clause

GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
AGENT_ID = "00000000-1111-2222-3333-444444444444"
SECOND_AGENT_ID = "11111111-2222-3333-4444-555555555555"

_TOKEN_RESPONSE = {"access_token": "test-token", "expires_in": 900}

_SEATED_GROUP = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "member_count": 2,
    "created_at": "2024-01-01T00:00:00Z",
    "member_agent_ids": [AGENT_ID, SECOND_AGENT_ID],
}

_AGENTS = [
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
        "id": SECOND_AGENT_ID,
        "name": "second-agent",
        "handle": "second-agent@myorg.rine.network",
        "human_oversight": True,
        "incoming_policy": "accept_all",
        "outgoing_policy": "send_all",
        "created_at": "2024-01-01T00:00:00Z",
    },
]

BOTH_HANDLES = "test-agent@myorg.rine.network, second-agent@myorg.rine.network"
BOTH_IDS = f"{AGENT_ID}, {SECOND_AGENT_ID}"


def _mock_token() -> None:
    respx.post("https://rine.network/oauth/token").mock(
        return_value=httpx.Response(200, json=_TOKEN_RESPONSE)
    )


def _mock_agents(**kw: object) -> respx.Route:
    return respx.get("https://rine.network/agents").mock(
        return_value=httpx.Response(200, json={"items": _AGENTS}), **kw
    )


def _mock_group_list(group: dict[str, object] | None = None) -> None:
    respx.get("https://rine.network/groups").mock(
        return_value=httpx.Response(200, json={"items": [group or _SEATED_GROUP]})
    )


def _mock_group_row() -> None:
    """``GET /groups/{id}`` — the resolve rung for a verb named by id."""
    respx.get(f"https://rine.network/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_SEATED_GROUP)
    )


def _mock_group_update() -> None:
    respx.patch(f"https://rine.network/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=_SEATED_GROUP)
    )


class TestSyncEnrichment:
    @respx.mock
    def test_list_when_the_org_has_agents_then_the_row_spells_its_seats_as_handles(
        self, sync_client
    ):
        _mock_token()
        _mock_agents()
        _mock_group_list()

        [group] = sync_client.groups.list()

        assert own_agents_clause(group) == BOTH_HANDLES

    @respx.mock
    def test_update_when_the_org_has_agents_then_the_row_it_returns_spells_seats_too(
        self, sync_client
    ):
        # `update` re-reads the group, so it hands back a row a surface renders
        # exactly like a listed one. A site that skipped the labelling would
        # print handles before an edit and UUIDs after it.
        _mock_token()
        _mock_agents()
        _mock_group_row()  # the id is resolved through its own row
        _mock_group_update()

        group = sync_client.groups.update(GROUP_ID, description="edited")

        assert own_agents_clause(group) == BOTH_HANDLES

    @respx.mock
    def test_list_when_the_agent_list_cannot_be_read_then_the_row_falls_back_to_ids(
        self, sync_client
    ):
        # The fallback the design is built around: the lookup itself is total
        # (`member_agent_ids` ⊆ `GET /agents`), so the case worth handling is
        # the list being unreadable, not an id being a stranger. A caller who
        # asked for groups gets groups.
        _mock_token()
        respx.get("https://rine.network/agents").mock(return_value=httpx.Response(503))
        _mock_group_list()

        [group] = sync_client.groups.list()

        assert own_agents_clause(group) == BOTH_IDS

    @respx.mock
    def test_list_when_no_group_names_a_seat_then_the_agent_list_is_never_fetched(
        self, sync_client
    ):
        # Nothing to spell, nothing to pay for. `_fetch_agents` is memoised for
        # the life of the client, but a client whose first call is a seatless
        # group listing would still pay for the first one.
        _mock_token()
        agents = _mock_agents()
        _mock_group_list({**_SEATED_GROUP, "member_agent_ids": []})

        [group] = sync_client.groups.list()

        assert own_agents_clause(group) == NO_OWN_AGENTS
        assert not agents.called

    @respx.mock
    def test_list_when_called_twice_then_the_agent_list_is_fetched_once(self, sync_client):
        # Rendering a group list must not cost a request per call. The
        # memoisation is the client's (`_fetch_agents`), and this is the test
        # that fails if the enrichment ever reaches past it to the HTTP layer.
        _mock_token()
        agents = _mock_agents()
        _mock_group_list()

        sync_client.groups.list()
        sync_client.groups.list()

        assert agents.call_count == 1


class TestAsyncEnrichment:
    @respx.mock
    async def test_list_when_the_org_has_agents_then_the_row_spells_its_seats_as_handles(
        self, async_client
    ):
        _mock_token()
        _mock_agents()
        _mock_group_list()

        [group] = await async_client.groups.list()

        assert own_agents_clause(group) == BOTH_HANDLES

    @respx.mock
    async def test_update_when_the_org_has_agents_then_the_row_it_returns_spells_seats_too(
        self, async_client
    ):
        _mock_token()
        _mock_agents()
        _mock_group_row()  # the id is resolved through its own row
        _mock_group_update()

        group = await async_client.groups.update(GROUP_ID, description="edited")

        assert own_agents_clause(group) == BOTH_HANDLES

    @respx.mock
    async def test_list_when_the_agent_list_cannot_be_read_then_the_row_falls_back_to_ids(
        self, async_client
    ):
        _mock_token()
        respx.get("https://rine.network/agents").mock(return_value=httpx.Response(503))
        _mock_group_list()

        [group] = await async_client.groups.list()

        assert own_agents_clause(group) == BOTH_IDS


class TestAgentHandleMap:
    @respx.mock
    def test_list_when_an_agent_row_is_unusable_then_only_that_name_is_lost(self, sync_client):
        # An agent the server answered oddly is dropped rather than guessed at,
        # and a dropped entry costs one name, never the row.
        _mock_token()
        respx.get("https://rine.network/agents").mock(
            return_value=httpx.Response(
                200, json={"items": [{**_AGENTS[0], "id": "not-a-uuid"}, _AGENTS[1]]}
            )
        )
        _mock_group_list()

        [group] = sync_client.groups.list()

        assert own_agents_clause(group) == f"{AGENT_ID}, second-agent@myorg.rine.network"
