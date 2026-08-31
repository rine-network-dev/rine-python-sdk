"""What a group handle resolves to when its ORG half names nothing.

``GET /groups?handle=`` is an equality test against the stored handle, so a
fabricated org half used to fail HARDER than writing no org at all: the ``@`` is
precisely what routes a reference down the exact branch instead of the ladder,
and ``shipping-labels`` matched where ``#shipping-labels@acme…`` could not. A
spelling carrying strictly more information did strictly worse.

The Python stack has **three** entry points where that mattered — the async
client, its sync twin, and the send path's own resolver, which is sync-only and
reached from both clients — so all three are pinned here rather than one being
taken as evidence for the others. The TypeScript twin is
``rine-core/test/resolve-group-handle.test.ts``; the two stacks share no module,
which is what makes each side's tests the binding.

Only the HTTP boundary is mocked, and the mock behaves like the server: the
filter is equality, the unfiltered list is the org's. That is the whole of what
this decision turns on, so faking it any looser would fake the finding.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from rine._group_send import resolve_group_for_send
from rine.errors import ConfigError, NotFoundError

API = "https://rine.network"

LABELS_ID = "11111111-1111-1111-1111-111111111111"
OPS_ONE_ID = "22222222-2222-2222-2222-222222222222"
OPS_TWO_ID = "33333333-3333-3333-3333-333333333333"

#: The org this caller is actually in. Nothing here answers to ``acme``.
LABELS = {
    "id": LABELS_ID,
    "name": "shipping-labels",
    "handle": "#shipping-labels@gqb.rine.network",
}
OPS_ONE = {"id": OPS_ONE_ID, "name": "ops", "handle": "#ops@one.rine.network"}
OPS_TWO = {"id": OPS_TWO_ID, "name": "ops", "handle": "#ops@two.rine.network"}

WRONG_ORG = "#shipping-labels@acme.rine.network"

_TOKEN = {"access_token": "t", "token_type": "Bearer", "expires_in": 900}


def _serve(groups: list[dict[str, Any]]) -> list[str | None]:
    """Route ``GET /groups`` the way the server routes it, recording each filter.

    Returns the list the routes append to: one entry per call, holding the
    ``handle`` filter or ``None`` for the unfiltered org listing. Asserting on it
    is how "the fallback is a fallback" is told from "every send now costs two
    round trips".
    """
    asked: list[str | None] = []

    def answer(request: httpx.Request) -> httpx.Response:
        wanted = request.url.params.get("handle")
        asked.append(wanted)
        if wanted is None:
            return httpx.Response(200, json={"items": groups})
        return httpx.Response(200, json={"items": [g for g in groups if g["handle"] == wanted]})

    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=_TOKEN))
    respx.get(f"{API}/groups").mock(side_effect=answer)
    return asked


class TestAsyncClient:
    @respx.mock
    async def test_resolve_group_with_an_exact_handle_asks_only_the_server_filter(
        self, async_client
    ):
        asked = _serve([LABELS])

        assert await async_client._resolve_group_async(LABELS["handle"]) == LABELS_ID
        # The fallback is a fallback: a handle that resolves must still cost one
        # round trip, or every send in the product pays for a miss nobody made.
        assert asked == [LABELS["handle"]]
        await async_client.close()

    @respx.mock
    async def test_resolve_group_with_a_wrong_org_half_resolves_the_local_part(self, async_client):
        # The measured shape: local part learned from the conversation, domain
        # copied out of the shipped examples.
        asked = _serve([LABELS])

        assert await async_client._resolve_group_async(WRONG_ORG) == LABELS_ID
        assert asked == [WRONG_ORG, None]
        await async_client.close()

    @respx.mock
    async def test_resolve_group_with_a_wrong_org_half_quotes_what_the_caller_wrote(
        self, async_client
    ):
        # Not the local part it searched on — a caller who wrote a handle and is
        # answered about a string they never typed reads it as the product
        # having lost their reference.
        _serve([LABELS])

        with pytest.raises(NotFoundError) as raised:
            await async_client._resolve_group_async("#payroll@acme.rine.network")
        said = str(raised.value)
        assert "Group not found: #payroll@acme.rine.network." in said
        assert "Group not found: payroll." not in said
        assert "#shipping-labels@gqb.rine.network" in said
        await async_client.close()

    @respx.mock
    async def test_resolve_group_refuses_when_the_local_part_answers_to_two_groups(
        self, async_client
    ):
        # Reachable precisely because the org half was dropped: two orgs may each
        # run a group called ``ops``, and the handle told them apart until it
        # stopped matching. Picking one would act on a group nobody chose.
        _serve([OPS_ONE, OPS_TWO])

        with pytest.raises(ConfigError) as raised:
            await async_client._resolve_group_async("#ops@acme.rine.network")
        assert "#ops@one.rine.network" in str(raised.value)
        assert "#ops@two.rine.network" in str(raised.value)
        await async_client.close()


class TestSyncClient:
    @respx.mock
    def test_resolve_group_with_an_exact_handle_asks_only_the_server_filter(self, sync_client):
        asked = _serve([LABELS])

        assert sync_client._resolve_group_sync(LABELS["handle"]) == LABELS_ID
        assert asked == [LABELS["handle"]]

    @respx.mock
    def test_resolve_group_with_a_wrong_org_half_resolves_the_local_part(self, sync_client):
        asked = _serve([LABELS])

        assert sync_client._resolve_group_sync(WRONG_ORG) == LABELS_ID
        assert asked == [WRONG_ORG, None]

    @respx.mock
    def test_resolve_group_reaches_the_whole_ladder_classifier_peel_included(self, sync_client):
        # Tier 4 already shipped for a bare name. The fallback hands the local
        # part to the same function, so ``#ops-group@…`` peels to ``ops`` here
        # for the same reason ``ops group`` does on the send path.
        _serve([OPS_ONE])

        assert sync_client._resolve_group_sync("#ops-group@acme.rine.network") == OPS_ONE_ID

    @respx.mock
    def test_resolve_group_with_a_wrong_org_half_quotes_what_the_caller_wrote(self, sync_client):
        _serve([LABELS])

        with pytest.raises(NotFoundError) as raised:
            sync_client._resolve_group_sync("#payroll@acme.rine.network")
        said = str(raised.value)
        assert "Group not found: #payroll@acme.rine.network." in said
        assert "Group not found: payroll." not in said


class TestSendPath:
    """``resolve_group_for_send`` — sync-only, and reached from BOTH clients.

    The async client wraps it (``_client.py`` hands ``encrypt_for_group_sync`` to
    a worker thread), so this one function is the send path of every Python
    surface. It takes the raw HTTP client rather than a client object, so these
    hand it ``sync_client._http`` — the very object both clients pass it, rather
    than a second one minted beside it.
    """

    @respx.mock
    def test_an_exact_handle_is_answered_by_the_filter_alone(self, sync_client):
        asked = _serve([LABELS])
        http = sync_client._http

        assert resolve_group_for_send(http, LABELS["handle"])["id"] == LABELS_ID
        assert asked == [LABELS["handle"]]

    @respx.mock
    def test_a_wrong_org_half_resolves_the_local_part(self, sync_client):
        asked = _serve([LABELS])
        http = sync_client._http

        group = resolve_group_for_send(http, WRONG_ORG)

        # The ROW, not the id: the send path addresses ``to_handle``, so what it
        # posts to is the handle the server holds — never the one the caller
        # composed. That is what makes the fallback safe to put on a send.
        assert group["handle"] == "#shipping-labels@gqb.rine.network"
        assert asked == [WRONG_ORG, None]

    @respx.mock
    def test_a_handle_answering_to_nothing_refuses_with_the_roster(self, sync_client):
        _serve([LABELS])
        http = sync_client._http

        with pytest.raises(NotFoundError) as raised:
            resolve_group_for_send(http, "#payroll@acme.rine.network")
        said = str(raised.value)
        assert "Group not found: #payroll@acme.rine.network." in said
        assert "Group not found: payroll." not in said
        assert "#shipping-labels@gqb.rine.network" in said

    @respx.mock
    def test_two_groups_of_that_local_part_refuse_rather_than_pick_one(self, sync_client):
        _serve([OPS_ONE, OPS_TWO])
        http = sync_client._http

        with pytest.raises(ConfigError) as raised:
            resolve_group_for_send(http, "#ops@acme.rine.network")
        assert "#ops@one.rine.network" in str(raised.value)
        assert "#ops@two.rine.network" in str(raised.value)
