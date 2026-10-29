"""The sync and async clients answer a reference identically.

🔴 The tension this exists for: a contract implemented on ONE client passes
every gate in this repo. The two clients hold twin method bodies that were
written apart and drifted apart — the local-part fallback shipped to the async
one and had to be re-derived for the sync one — and nothing anywhere asserted they
agreed.

So this suite never asserts a value on one client alone. Each scenario runs the
same verb, with the same arguments, against the same mocked server on BOTH, and
compares two things:

* the RECORD each answered with, and
* the WIRE TRAFFIC each spent getting there, in order.

The second is half the point. Two clients that agree on the answer and disagree
on what they asked the server have still drifted — a rung reordered on one side
changes the refusal a caller sees the moment the roster is ambiguous, and costs
a round trip on every call in between.

🔴 **This is the deep half, and it lives under ``tests/contract`` so that
``ci.sh`` reaches it.** Stage 4 runs ``rine-sdk/tests/contract`` and nothing
else under ``rine-sdk/tests``; a parity gate outside that directory was reached
only by the ``--python rine-sdk`` publish gate, which is to say by nothing that
runs before a release train. Its sibling ``test_recipient_client_parity.py``
holds the STRUCTURAL half — the derived resolver surface and the golden
comparison — and the two share one mocked server (``_recipient_server.py``) so
they cannot end up driving different ones.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from rine._recipient import GroupTarget, RecipientTarget
from rine.errors import (
    ConfigError,
    GroupIdentityMismatchError,
    InternalServerError,
    NotFoundError,
)

from ._recipient_server import API, TOKEN, mocked_server

GROUP_UUID = "11111111-1111-1111-1111-111111111111"
OPS_TWO_ID = "33333333-3333-3333-3333-333333333333"
KOFI_ID = "44444444-4444-4444-4444-444444444444"

#: The one id in this module with hex LETTERS in it, and that is its whole job.
#:
#: 🔴 Every other uuid here is decimal digits, on which ``.upper()`` is a no-op —
#: a case test written on one of them passes against a case-SENSITIVE matcher and
#: proves nothing. This one was caught by exactly that.
LETTERED_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

OPS = {"id": GROUP_UUID, "name": "ops", "handle": "#ops@acme.rine.network"}
OPS_ELSEWHERE = {"id": OPS_TWO_ID, "name": "ops", "handle": "#ops@two.rine.network"}
ACCOUNTS = {"id": LETTERED_UUID, "name": "accounts", "handle": "#accounts@acme.rine.network"}
WRONG_ORG = "#ops@nowhere.rine.network"

KOFI = {"id": KOFI_ID, "name": "kofi", "handle": "kofi@acme.rine.network"}
AN_AGENT_CALLED_OPS = {"id": KOFI_ID, "name": "ops", "handle": "ops@acme.rine.network"}


async def _twin(
    async_client: Any,
    sync_client: Any,
    verb: str,
    reference: str,
    *,
    groups: list[dict[str, Any]] | None = None,
    agents: list[dict[str, Any]] | None = None,
    refuse_by_id: dict[str, int] | None = None,
) -> tuple[Any, list[str]]:
    """Run one verb on both clients, assert they agreed, and answer for both.

    A failure here is never "the sync client is wrong": it is the two of them
    disagreeing, which is the defect regardless of which one moved.
    """
    groups = [] if groups is None else groups
    agents = [] if agents is None else agents

    with mocked_server(groups, agents, refuse_by_id) as taken:
        try:
            answered = await getattr(async_client, verb)(reference)
        except (ConfigError, NotFoundError) as refused:
            answered = (type(refused), str(refused))
        async_calls = list(taken)
    await async_client.close()

    with mocked_server(groups, agents, refuse_by_id) as taken:
        try:
            twin = getattr(sync_client, verb)(reference)
        except (ConfigError, NotFoundError) as refused:
            twin = (type(refused), str(refused))
        sync_calls = list(taken)

    assert answered == twin, f"{verb}({reference!r}): the two clients answered differently"
    assert async_calls == sync_calls, (
        f"{verb}({reference!r}): the two clients asked the server differently"
    )
    return answered, async_calls


class TestResolveGroup:
    async def test_a_uuid_costs_one_indexed_read_and_answers_with_the_row(
        self, async_client, sync_client
    ):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", GROUP_UUID, groups=[OPS]
        )

        # 🔴 The ABSENCE of ``GET /groups`` is this rung's whole
        # content. A UUID used to be answered by matching it against the unpaginated
        # roster, so every UUID verb paid that listing — which counts members per
        # row — on the RESOLVED path as well as the refused one. Asserting only
        # the answer would let the old shape pass unchanged.
        assert taken == [f"GET /groups/{GROUP_UUID}"]
        assert answered == GroupTarget(
            id=GROUP_UUID, handle=OPS["handle"], spelling=GROUP_UUID, row=OPS
        )

    async def test_a_uuid_no_group_of_this_org_carries_is_refused_with_the_roster(
        self, async_client, sync_client
    ):
        # The product half, which the single-row read does not touch: the refusal
        # is the same sentence, and only WHEN the roster is bought moved. The ORDER is
        # what is asserted, because a roster fetched first would still compose
        # the right words while costing what the amendment exists to stop paying.
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", OPS_TWO_ID, groups=[OPS]
        )

        kind, said = answered
        assert kind is NotFoundError
        # ``_twin`` compares ``str(exc)``, which carries this stack's ``404: ``
        # transport prefix — the composed sentence starts after it.
        assert f"Group not found: {OPS_TWO_ID}." in said
        assert OPS["handle"] in said
        assert taken == [f"GET /groups/{OPS_TWO_ID}", "GET /groups"]

    async def test_a_uuid_answered_403_is_refused_exactly_as_one_answered_404(
        self, async_client, sync_client
    ):
        # 🔴 The disclosure rule. ``GET /groups/{id}`` 403s an id belonging
        # to an org this caller is neither owner of nor seated in, and 404s an id
        # no group carries. Telling the two apart would tell a stranger which
        # unknown ids EXIST — the non-member lookup this stack refuses to offer — so the
        # bytes AND the request pattern have to be identical to the test above.
        # Without this, a later "improve the 403 message" is an information leak
        # nothing would catch.
        forbidden, forbidden_taken = await _twin(
            async_client,
            sync_client,
            "resolve_group",
            OPS_TWO_ID,
            groups=[OPS],
            refuse_by_id={OPS_TWO_ID: 403},
        )
        # The 404 leg runs on the synchronous client alone because ``_twin``
        # closes the asynchronous one, and it does not need both: ``_twin`` has
        # just proved the two clients agree about the 403, and the test above
        # proves they agree about the 404.
        with mocked_server([OPS], []) as taken:
            with pytest.raises(NotFoundError) as missing:
                sync_client.resolve_group(OPS_TWO_ID)
            missing_taken = list(taken)

        assert forbidden == (NotFoundError, str(missing.value))
        assert forbidden_taken == missing_taken

    async def test_a_uuid_the_server_faulted_on_is_not_answered_with_a_roster(
        self, async_client, sync_client
    ):
        # ⚠️ The bound the two arms above need. An outage is not a wrong
        # reference: a blanket catch would turn every 500 into "Group not found",
        # with an unpaginated listing bought on top of it, and the caller would
        # go and check a spelling that was never the problem. Driven by hand
        # rather than through ``_twin``, because the whole claim is that this
        # escapes as ITSELF and ``_twin`` captures only the two refusal types.
        fault = {OPS_TWO_ID: 500}

        with mocked_server([OPS], [], fault) as taken:
            with pytest.raises(InternalServerError):
                await async_client.resolve_group(OPS_TWO_ID)
            async_calls = list(taken)
        await async_client.close()

        with mocked_server([OPS], [], fault) as taken:
            with pytest.raises(InternalServerError):
                sync_client.resolve_group(OPS_TWO_ID)
            sync_calls = list(taken)

        assert async_calls == sync_calls
        # The set, not the list: a 500 is retryable, so the transport asks again
        # — and how many times is the transport's business, not the ladder's. The
        # claim being pinned is that the id route is the ONLY route touched, so a
        # roster was never bought for something that was not an answer about the
        # reference.
        assert set(async_calls) == {f"GET /groups/{OPS_TWO_ID}"}

    async def test_a_uuid_answered_with_another_groups_row_is_refused_on_both_clients(
        self, async_client, sync_client
    ):
        # 🔴 The substitution check. This rung used to pass the caller's id
        # through and no answer could stand in for the group it named; it reads a
        # row now, and five more surfaces route through it, so a substituted
        # body would put every downstream group verb on a group the caller never
        # asked about. Driven by hand rather than through ``_twin``, which
        # captures ``ConfigError`` and ``NotFoundError`` alone — and the whole
        # ruling is that this is NEITHER: a server fault surfaces as a server
        # fault, so ``OPS`` stays in the roster and no roster read is made.
        #
        # The golden fixture pins the SENTENCE across the two stacks
        # (``test_recipient_refusal_golden.py``) and drives the sync client only;
        # what this adds is the async one, which is the parity claim.
        substitute = {GROUP_UUID: OPS_ELSEWHERE}

        with mocked_server([OPS], [], substitute_by_id=substitute) as taken:
            with pytest.raises(GroupIdentityMismatchError) as async_raised:
                await async_client.resolve_group(GROUP_UUID)
            async_calls = list(taken)
        await async_client.close()

        with mocked_server([OPS], [], substitute_by_id=substitute) as taken:
            with pytest.raises(GroupIdentityMismatchError) as sync_raised:
                sync_client.resolve_group(GROUP_UUID)
            sync_calls = list(taken)

        assert str(async_raised.value) == str(sync_raised.value)
        assert async_raised.value.requested_group_id == GROUP_UUID
        assert async_raised.value.answered_group_id == OPS_TWO_ID
        assert async_calls == sync_calls == [f"GET /groups/{GROUP_UUID}"]

    async def test_a_uuid_spelled_in_upper_case_is_the_same_group(self, async_client, sync_client):
        # 🔴 ``UUID_RE`` is case-INSENSITIVE on both stacks and every group route
        # types its path parameter ``group_id: uuid.UUID``, which parses either
        # spelling to the same value — so this reference reached the wire and
        # worked before the id rung read anything. A case-sensitive roster match refused it, with a
        # roster that printed the group it meant: a capability removal wearing a
        # validation fix. The single-row read keeps the capability and deletes the comparison:
        # the caller's spelling goes out on the PATH and the wire folds it, which
        # is why the recorded request carries the upper case. Twin:
        # ``resolve-group-handle.test.ts``'s *"answers a uuid the caller spelled
        # in upper case"*.
        #
        # ``LETTERED_UUID`` and not ``GROUP_UUID``: see its own note.
        said = LETTERED_UUID.upper()
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", said, groups=[ACCOUNTS]
        )

        assert answered.id == LETTERED_UUID, "the record carries the server's spelling"
        assert answered.row == ACCOUNTS
        assert answered.spelling == said, "a refusal must quote what the caller wrote"
        assert taken == [f"GET /groups/{said}"], "the fold belongs to the wire, not to the client"

    async def test_a_uuid_carrying_a_trailing_newline_is_not_read_as_an_id(
        self, async_client, sync_client
    ):
        # 🔴 Python's ``$`` matches BEFORE a trailing newline and JavaScript's
        # does not, so ``is_uuid`` and ``UUID_RE`` classified this one string
        # two different ways. It stopped being cosmetic when the id rung put the id on
        # the PATH: ``httpx`` refuses a newline in a URL with ``InvalidURL``,
        # which is not a ``RineError`` and so escapes this SDK's error hierarchy
        # entirely, while ``rine-core`` composed the roster refusal. A line read
        # off a file or piped into a CLI carries the ``\n`` and nothing strips
        # it. Anchored with ``fullmatch``, both stacks now walk the NAME ladder:
        # the id route is never asked, and the caller gets a sentence.
        #
        # Twin: ``resolve-group-handle.test.ts``'s *"does not read a uuid with a
        # trailing newline as an id"*.
        stray = f"{GROUP_UUID}\n"
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", stray, groups=[OPS]
        )

        kind, said = answered
        assert kind is NotFoundError
        assert taken == ["GET /groups"], "an unanchored match would have asked the id route"
        assert OPS["handle"] in said

    async def test_an_exact_handle_is_answered_by_the_server_filter_alone(
        self, async_client, sync_client
    ):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", OPS["handle"], groups=[OPS]
        )

        assert answered.id == GROUP_UUID
        assert taken == [f"GET /groups?handle={OPS['handle']}"]
        # One round trip, and the record it filled is whole: the filter answers
        # with the group row, so the rung reads the handle out of what it was
        # already handed rather than echoing the caller's spelling.
        assert answered.row == OPS
        assert answered.handle == OPS["handle"]

    async def test_a_wrong_org_half_falls_back_to_the_local_part_ladder(
        self, async_client, sync_client
    ):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", WRONG_ORG, groups=[OPS]
        )

        assert answered.id == GROUP_UUID
        assert answered.row == OPS
        assert answered.handle == "#ops@acme.rine.network"
        # The local-part ladder is a FALLBACK: the filter is still asked first, so a handle that
        # resolves costs one round trip and not two.
        assert taken == [f"GET /groups?handle={WRONG_ORG}", "GET /groups"]

    async def test_a_wrong_org_half_refusal_quotes_what_the_caller_wrote(
        self, async_client, sync_client
    ):
        answered, _ = await _twin(
            async_client,
            sync_client,
            "resolve_group",
            "#payroll@nowhere.rine.network",
            groups=[OPS],
        )

        kind, said = answered
        assert kind is NotFoundError
        assert "Group not found: #payroll@nowhere.rine.network." in said
        assert "Group not found: payroll." not in said

    async def test_a_bare_name_goes_straight_to_the_org_listing(self, async_client, sync_client):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", "ops", groups=[OPS]
        )

        assert answered.row == OPS
        assert answered.spelling == "ops"
        assert taken == ["GET /groups"]

    async def test_a_sigilled_name_without_an_org_takes_the_same_ladder(
        self, async_client, sync_client
    ):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group", "#ops", groups=[OPS]
        )

        assert answered.id == GROUP_UUID
        assert taken == ["GET /groups"]

    async def test_two_groups_of_that_name_refuse_rather_than_pick_one(
        self, async_client, sync_client
    ):
        answered, _ = await _twin(
            async_client, sync_client, "resolve_group", "ops", groups=[OPS, OPS_ELSEWHERE]
        )

        kind, said = answered
        assert kind is ConfigError
        assert "#ops@acme.rine.network" in said
        assert "#ops@two.rine.network" in said


#: Every rung of both group ladders, and whether reaching it costs a read.
#:
#: The table the guarantee is asserted over. ``reads`` is the whole of the
#: claim: a rung that asked the server for a listing HAS the group and must hand
#: it over. Adding a rung means adding a row here, which is the point — the
#: guarantee is stated once and checked against the ladders rather than against
#: whichever rungs somebody remembered.
#:
#: 🔴 **The last row is the JOIN ladder's, and it is what keeps ``reads``
#: honest.** Every member rung reads — the UUID one used to be ``False`` —
#: so a member-only table would have left the ``False`` arm below unreachable,
#: which is a guarantee nobody is checking dressed as one that is. The join
#: ladder still answers a UUID out of the caller's own hand: a join targets a
#: group this org holds no seat in *by definition*, so ``GET /groups`` cannot
#: describe it and the roster refusal must never reach here.
LADDER_RUNGS = (
    ("bare-name", "resolve_group", "ops", True),
    ("sigilled-name", "resolve_group", "#ops", True),
    ("exact-handle", "resolve_group", OPS["handle"], True),
    ("handle-with-the-wrong-org", "resolve_group", WRONG_ORG, True),
    ("uuid-by-its-own-route", "resolve_group", GROUP_UUID, True),
    ("uuid-for-a-join", "resolve_group_for_join", GROUP_UUID, False),
)


class TestTheSeatedRecordIsWholeWhereverTheLadderRead:
    """The guarantee, asserted rather than asserted-to-be-asserted.

    🔴 In full: **every rung of the member ladder performs a read and answers
    with ``handle`` and ``row`` set.** It was pinned as *"always non-null"* and
    this stack did not hold it:
    the exact ``?handle=`` rung threw away the row the filter had just returned,
    and nothing anywhere said so, which is precisely how it shipped.

    The MEMBER ladder's UUID rung was the one stated exception — it read nothing
    and answered with a bare id, while the TypeScript twin already fetched the
    roster and refused an unknown id locally. That asymmetry is closed onto the
    TypeScript shape, so on that ladder there is no exception left. The JOIN
    ladder's UUID rung is still an
    exception and stays one, which is why it is in the table: the non-reading
    arm below is the assertion that a rung answering out of thin air answers
    with NOTHING it did not fetch, and that row is the only thing that arms it.
    """

    @pytest.mark.parametrize(
        ("rung", "entry", "reference", "reads"),
        LADDER_RUNGS,
        ids=[r[0] for r in LADDER_RUNGS],
    )
    async def test_a_rung_when_it_performed_a_read_then_the_record_carries_the_row(
        self, rung: str, entry: str, reference: str, reads: bool, async_client, sync_client
    ) -> None:
        answered, taken = await _twin(async_client, sync_client, entry, reference, groups=[OPS])

        assert answered.id == GROUP_UUID, f"{rung}: resolved to the wrong group"
        if not reads:
            assert taken == [], f"{rung}: is a stated exception because it reads nothing"
            assert answered.row is None and answered.handle is None, (
                f"{rung}: answered with a row it never fetched — say which rung "
                "reads and which does not, in the table above, before moving this"
            )
            return
        assert taken, f"{rung}: expected a read"
        assert answered.row == OPS, f"{rung}: paid for a listing and answered with no row"
        assert answered.handle == OPS["handle"], (
            f"{rung}: answered with no handle, which is the column POST /messages "
            "addresses by exact equality"
        )
        assert answered.spelling == reference, f"{rung}: quoted something other than the caller"


class TestResolveRecipient:
    async def test_a_bare_name_is_guarded_against_the_agent_namespace_first(
        self, async_client, sync_client
    ):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_recipient", "ops", groups=[OPS], agents=[KOFI]
        )

        assert answered == RecipientTarget(
            kind="group",
            id=GROUP_UUID,
            handle="#ops@acme.rine.network",
            spelling="ops",
            row=OPS,
        )
        # The order is the safety argument, not an optimisation: the guard runs
        # before the group tier is reached at all.
        assert taken == ["GET /agents", "GET /groups"]

    async def test_a_bare_name_that_is_also_an_agents_name_refuses(
        self, async_client, sync_client
    ):
        answered, taken = await _twin(
            async_client,
            sync_client,
            "resolve_recipient",
            "ops",
            groups=[OPS],
            agents=[AN_AGENT_CALLED_OPS],
        )

        kind, said = answered
        assert kind is ConfigError
        assert "is the name of an agent of your org" in said
        # It never reached the groups: a caller who meant an agent must not
        # silently post to a group of that name.
        assert taken == ["GET /agents"]

    async def test_a_sigilled_group_skips_the_agent_guard(self, async_client, sync_client):
        answered, taken = await _twin(
            async_client,
            sync_client,
            "resolve_recipient",
            "#ops",
            groups=[OPS],
            agents=[AN_AGENT_CALLED_OPS],
        )

        assert answered.kind == "group"
        # A caller who typed the sigil has said which namespace they mean, so the
        # guard for the ambiguity of an UNSIGILLED word is not run.
        assert taken == ["GET /groups"]

    async def test_a_handle_is_an_agent(self, async_client, sync_client):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_recipient", KOFI["handle"], agents=[KOFI]
        )

        assert answered == RecipientTarget(
            kind="agent",
            id=KOFI_ID,
            handle="kofi@acme.rine.network",
            spelling="kofi@acme.rine.network",
            row=None,
        )
        assert taken == ["GET /.well-known/webfinger"]

    async def test_a_uuid_that_names_a_group_is_that_group_on_both_clients(
        self, async_client, sync_client
    ):
        # 🔴 A group's own id used to be adopted verbatim as an AGENT id on
        # both stacks and fail at the outbound key fetch with "Agent not found",
        # a sentence about the namespace the caller did not name. The row's own
        # handle comes back, which is the column ``POST /messages`` addresses.
        answered, taken = await _twin(
            async_client, sync_client, "resolve_recipient", GROUP_UUID, groups=[OPS]
        )

        assert answered == RecipientTarget(
            kind="group",
            id=GROUP_UUID,
            handle="#ops@acme.rine.network",
            spelling=GROUP_UUID,
            row=OPS,
        )
        # One indexed row and no roster. The recipient slot shares the id READ
        # with the member ladder and never the ladder itself — that one buys
        # ``GET /groups`` on a miss and raises, which here would refuse every
        # agent id in the product.
        assert taken == [f"GET /groups/{GROUP_UUID}"]

    async def test_a_uuid_no_group_answers_to_is_an_agent_after_one_indexed_miss(
        self, async_client, sync_client
    ):
        # The other half of the same arm, and why the group is asked FIRST:
        # ``GET /groups/{id}`` is credential-scoped and ``GET /agents/{id}/keys`` is
        # unauthenticated and global, so agent-first would prefer a stranger's
        # namespace over the caller's own org's. The agent rung is untouched —
        # it still answers with the id and spends no request of its own.
        answered, taken = await _twin(
            async_client, sync_client, "resolve_recipient", KOFI_ID, agents=[KOFI]
        )

        assert answered.kind == "agent"
        assert answered.id == KOFI_ID
        assert answered.handle is None
        # 🔴 The whole cost of the widening, pinned as a list rather than a
        # count, and identical on both clients.
        assert taken == [f"GET /groups/{KOFI_ID}"]

    async def test_a_uuid_the_group_route_403s_falls_through_to_the_agent_rung(
        self, async_client, sync_client
    ):
        # 403 and 404 are one answer by disclosure rule, so a group belonging to
        # another org reaches the agent rung exactly as an unknown id does
        # rather than refusing a spelling that may well name an agent.
        answered, taken = await _twin(
            async_client,
            sync_client,
            "resolve_recipient",
            KOFI_ID,
            agents=[KOFI],
            refuse_by_id={KOFI_ID: 403},
        )

        assert answered.kind == "agent"
        assert answered.id == KOFI_ID
        assert taken == [f"GET /groups/{KOFI_ID}"]

    async def test_a_uuid_the_group_route_faulted_on_is_not_read_as_an_agent(
        self, async_client, sync_client
    ):
        # 🔴 The asymmetry decides this: a wrong GROUP answer is refused by the
        # server's seat gate, a wrong AGENT answer is delivered to somebody. So
        # a 500 has to surface as itself — swallowing it into the agent rung
        # would seal this payload for whoever holds that id. Driven by hand
        # rather than through ``_twin``, because the whole claim is that this
        # escapes as ITSELF and ``_twin`` captures only the two refusal types.
        fault = {KOFI_ID: 500}

        with mocked_server([], [KOFI], fault) as taken:
            with pytest.raises(InternalServerError):
                await async_client.resolve_recipient(KOFI_ID)
            async_calls = list(taken)
        await async_client.close()

        with mocked_server([], [KOFI], fault) as taken:
            with pytest.raises(InternalServerError):
                sync_client.resolve_recipient(KOFI_ID)
            sync_calls = list(taken)

        assert async_calls == sync_calls
        # The set, not the list: a 500 is retryable and how many times the
        # transport asks is not the ladder's business. What is pinned is that no
        # agent read was reached at all.
        assert set(async_calls) == {f"GET /groups/{KOFI_ID}"}

    async def test_a_handle_webfinger_cannot_place_comes_back_unvalidated(
        self, async_client, sync_client
    ):
        # ⚠️ A preserved divergence. The TypeScript twin validates and throws;
        # this stack hands the handle back as though it were an id, and the
        # failure surfaces two calls later from the key store. This stack records the
        # difference rather than closing it — the recipient slot is the one whose
        # wrong answers get DELIVERED, so changing it is a decision.
        answered, _ = await _twin(
            async_client, sync_client, "resolve_recipient", "nobody@acme.rine.network"
        )

        assert answered.kind == "agent"
        assert answered.id == "nobody@acme.rine.network"

    async def test_an_empty_recipient_is_refused_by_the_agent_namespace(
        self, async_client, sync_client
    ):
        # It names nothing in either namespace, and the agent resolver says that
        # far better than a hunt through the caller's groups would.
        answered, taken = await _twin(async_client, sync_client, "resolve_recipient", "")

        kind, said = answered
        assert kind is NotFoundError
        assert "expected a UUID or handle" in said
        assert taken == []


class TestResolveGroupForJoin:
    async def test_a_uuid_is_the_answer_and_carries_no_row(self, async_client, sync_client):
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group_for_join", GROUP_UUID
        )

        assert answered == GroupTarget(id=GROUP_UUID, handle=None, spelling=GROUP_UUID, row=None)
        assert taken == []

    async def test_a_handle_this_org_is_already_seated_in_resolves_on_the_first_rung(
        self, async_client, sync_client
    ):
        # 🔴 Deliberately NOT ``resolve_group``'s ladder: join is the one verb
        # aimed at a group this org is not in, and the seated filter is its FIRST
        # rung rather than its answer. The join ladder is also why `handle` and
        # `row` are nullable at all — it answers with an id on every rung, so it
        # asks for the id projection and not the row.
        answered, taken = await _twin(
            async_client, sync_client, "resolve_group_for_join", OPS["handle"], groups=[OPS]
        )

        assert answered.id == GROUP_UUID
        assert answered.row is None
        assert taken == [f"GET /groups?handle={OPS['handle']}"]


class TestTheEntryPointsAgreeWithTheirPrivateTwins:
    """The id-returning privates are projections, not second resolutions."""

    @respx.mock
    async def test_resolve_group_async_is_resolve_groups_id(self, async_client):
        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [OPS]}))

        assert (
            await async_client._resolve_group_async("ops")
            == (await async_client.resolve_group("ops")).id
        )
        await async_client.close()

    @respx.mock
    def test_resolve_group_sync_is_resolve_groups_id(self, sync_client):
        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [OPS]}))

        assert sync_client._resolve_group_sync("ops") == sync_client.resolve_group("ops").id

    @respx.mock
    async def test_the_bare_send_helper_is_the_recipients_handle(self, async_client):
        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/agents").mock(return_value=httpx.Response(200, json={"items": [KOFI]}))
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [OPS]}))

        assert await async_client._group_handle_for_bare_recipient("ops", None) == (
            "#ops@acme.rine.network"
        )
        await async_client.close()

    @respx.mock
    def test_the_sigil_send_helper_is_the_recipients_handle(self, sync_client):
        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [OPS]}))

        assert sync_client._group_handle_for_sigil_recipient("#ops", None) == (
            "#ops@acme.rine.network"
        )

    @respx.mock
    async def test_the_seated_id_lookup_is_the_seated_rows_id(self, async_client):
        # The id-returning lookup the join ladder takes as its first rung is a
        # projection of the row-returning one, and holds no request of its own —
        # which is why ``GROUP_HANDLE_LOOKUP_SITES`` registers the row method.
        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": [OPS]}))

        row = await async_client._seated_group_row_by_handle(OPS["handle"])
        assert row == OPS
        assert await async_client._seated_group_id_by_handle(OPS["handle"]) == str(row["id"])
        await async_client.close()

    @respx.mock
    def test_the_seated_id_lookup_answers_nothing_when_the_filter_does(self, sync_client):
        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": []}))

        assert sync_client._seated_group_row_by_handle(OPS["handle"]) is None
        assert sync_client._seated_group_id_by_handle(OPS["handle"]) is None
