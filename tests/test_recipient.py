"""What a recipient spelling names, and what a group refusal says about it.

The pure half of recipient resolution — the classification table, the two
records, the refusal composer, and the two drivers the ladders run under. No
HTTP and no client: everything here is input to sentence, which is what makes
these the vectors the TypeScript twin can be held to.

🔴 The composer tests are byte-identity tests against the sentences that already
ship. A refusal that moves by one character is the composer being wrong, not the
expectation being stale: no shipped sentence moves here.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

import rine
from rine._group_ref import (
    GROUP_NOT_FOUND_LEAD,
    GROUP_ROSTER_LEAD,
    MAX_LISTED_GROUPS,
    NEITHER_NAMESPACE_LEAD,
    NO_GROUPS_IN_ORG,
    ambiguous_group_refusal,
    compose_group_refusal,
    is_bare_reference,
    is_sigil_group_reference,
    recipient_group_for_bare_name,
    refuse_if_a_bare_agent_name,
    unknown_group_refusal,
)
from rine._recipient import (
    REF_CLASS_AGENT,
    REF_CLASS_BARE,
    REF_CLASS_EMPTY,
    REF_CLASS_GROUP,
    REF_CLASS_ID,
    GroupTarget,
    RecipientTarget,
    classify_reference,
    group_target,
    group_target_by_id,
)
from rine._recipient_ladder import group_ladder
from rine._recipient_reads import (
    AsyncReferenceReads,
    ReferenceReads,
    walk,
    walk_async,
)
from rine.errors import ConfigError, NotFoundError

A_UUID = "11111111-2222-3333-4444-555555555555"

OPS = {"id": A_UUID, "name": "ops", "handle": "#ops@acme.rine.network"}
FINANCE = {
    "id": "66666666-7777-8888-9999-000000000000",
    "name": "finance",
    "handle": "#finance@acme.rine.network",
}


class TestTheClassificationTable:
    """One table, one order, and the constants that name its answers."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("", REF_CLASS_EMPTY),
            ("   ", REF_CLASS_EMPTY),
            ("\t\n", REF_CLASS_EMPTY),
            ("#ops", REF_CLASS_GROUP),
            ("#ops@acme.rine.network", REF_CLASS_GROUP),
            ("#", REF_CLASS_GROUP),
            ("#   ", REF_CLASS_GROUP),
            ("##ops", REF_CLASS_GROUP),
            (A_UUID, REF_CLASS_ID),
            ("kofi@acme.rine.network", REF_CLASS_AGENT),
            ("kofi@acme", REF_CLASS_AGENT),
            ("ops", REF_CLASS_BARE),
            ("ops chat room", REF_CLASS_BARE),
            ("Quarterly Planning", REF_CLASS_BARE),
        ],
    )
    def test_classify_reference_when_given_a_spelling_answers_its_namespace(self, value, expected):
        assert classify_reference(value) == expected

    def test_classify_reference_when_the_uuid_wears_a_sigil_answers_group_not_id(self):
        # The order between ``#`` and ``id`` is the only pair of arms whose
        # ordering is observable, and the sigil wins: a caller who typed the
        # group sigil has said which namespace they mean, and a group id in the
        # AGENT slot would be delivered to nobody rather than refused.
        assert classify_reference(f"#{A_UUID}") == REF_CLASS_GROUP

    def test_classify_reference_when_a_uuid_is_undashed_answers_bare_not_id(self):
        # ⚠️ A preserved divergence: ``is_uuid`` is the strict dashed pattern
        # on both stacks, and ``parses_as_uuid`` — which this side also has, and
        # which accepts the braced and unhyphenated spellings — is deliberately
        # NOT wired into the table. Widening it here would make Python resolve
        # references the TypeScript stack refuses.
        assert classify_reference(A_UUID.replace("-", "")) == REF_CLASS_BARE

    def test_the_constants_and_the_function_are_one_table(self):
        # The five literals are written twice — once as module-level plain
        # assignments a source-parse gate can read, once in the function's arms,
        # because a bare assignment types as ``str`` and the return type is a
        # ``Literal`` union. This is what stops the two spellings drifting.
        assert {
            REF_CLASS_EMPTY,
            REF_CLASS_GROUP,
            REF_CLASS_ID,
            REF_CLASS_AGENT,
            REF_CLASS_BARE,
        } == {"empty", "group", "id", "agent", "bare"}

    @pytest.mark.parametrize(
        "value",
        ["", "   ", "#", "#ops", "#ops@acme", "##ops", A_UUID, "kofi@acme", "ops", "a b"],
    )
    def test_the_two_send_predicates_are_readings_of_the_table(self, value):
        # They used to restate the table's conjuncts by hand. Re-expressing them
        # over it can only be safe if they answer the same set, so the set is
        # what is asserted rather than the implementation.
        assert is_bare_reference(value) == (classify_reference(value) == REF_CLASS_BARE)
        assert is_sigil_group_reference(value) == (
            classify_reference(value) == REF_CLASS_GROUP and "@" not in value
        )

    def test_a_blank_recipient_belongs_to_neither_send_predicate(self):
        # It names nothing in either namespace, and the agent resolver's
        # "expected a UUID or handle" says that better than a hunt through the
        # org's groups ending in "no group is called ''" would.
        assert not is_bare_reference("")
        assert not is_sigil_group_reference("   ")


class TestTheRecords:
    """What a resolve answers with, and what it never loses."""

    def test_group_target_when_built_from_a_row_carries_the_row_and_the_handle(self):
        target = group_target(OPS, "ops chat")

        assert target == GroupTarget(
            id=A_UUID, handle="#ops@acme.rine.network", spelling="ops chat", row=OPS
        )

    def test_group_target_keeps_the_callers_spelling_not_the_string_that_matched(self):
        # A refusal may quote only what the caller wrote. ``ops chat`` reached
        # ``#ops@…`` through the classifier-noun peel, and answering the caller
        # about ``ops`` would be answering them about a string they never typed.
        assert group_target(OPS, "ops chat").spelling == "ops chat"

    def test_group_target_by_id_answers_with_the_id_alone(self):
        # The record the JOIN ladder answers with, on every one of its rungs: its
        # target is a group this org holds no seat in by definition, so
        # ``GET /groups`` cannot describe it and there is no row to carry. The
        # member ladder's UUID rung used to come through here too, and that
        # was closed onto the TypeScript shape (a roster read, and a whole
        # record). Do not route a member rung back through this.
        assert group_target_by_id(A_UUID, A_UUID) == GroupTarget(
            id=A_UUID, handle=None, spelling=A_UUID, row=None
        )

    @pytest.mark.parametrize("record", [group_target(OPS, "ops"), group_target_by_id("i", "i")])
    def test_a_target_is_frozen_and_slotted(self, record):
        assert dataclasses.is_dataclass(record)
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.id = "somewhere else"
        assert not hasattr(record, "__dict__")

    def test_a_recipient_target_names_which_namespace_answered(self):
        recipient = RecipientTarget(
            kind="group", id=A_UUID, handle="#ops@acme.rine.network", spelling="ops", row=OPS
        )

        assert recipient.kind == "group"
        assert recipient.row is OPS


class TestTheRefusalComposer:
    """One function, and the one thing it refuses to say twice."""

    def test_rule_one_a_detail_alone_ends_in_exactly_one_period(self):
        assert compose_group_refusal("Group not found: ops") == "Group not found: ops."

    @pytest.mark.parametrize("detail", ["Group not found: ops.", "Group not found: ops..."])
    def test_rule_four_a_detail_that_ends_in_a_period_is_passed_through_as_written(self, detail):
        # 🔴 The composer ADDS the stop rule 4 asks for; it does not enforce it
        # by rewriting a tail that is not its own. The tail here is the caller's
        # spelling — ``resolve_group("ops.")`` quotes ``ops.`` — so an ``rstrip``
        # would silently answer a different sentence than the one that ships
        # (``Group not found: ops.. Name one of these groups:``).
        assert compose_group_refusal(detail) == detail

    def test_rule_four_a_spelling_that_ends_in_a_period_keeps_it_under_a_roster(self):
        assert unknown_group_refusal([OPS], "ops.").startswith("Group not found: ops.. ")

    def test_rule_two_candidates_are_appended_through_the_shared_formatter(self):
        said = compose_group_refusal("Group not found: ops", [OPS, FINANCE])

        assert said == (
            f"Group not found: ops. {GROUP_ROSTER_LEAD}\n"
            "  - #ops@acme.rine.network (ops)\n"
            "  - #finance@acme.rine.network (finance)"
        )

    def test_rule_two_an_empty_candidate_list_says_so_rather_than_trailing_off(self):
        assert compose_group_refusal("Group not found: ops", []) == (
            f"Group not found: ops. {NO_GROUPS_IN_ORG}"
        )

    def test_rule_two_reuses_the_cap_rather_than_re_implementing_it(self):
        many = [
            dict(OPS, id=str(i), handle=f"#g{i}@acme.rine.network", name=f"g{i}")
            for i in range(30)
        ]

        said = compose_group_refusal("Group not found: ops", many)

        assert said.count("\n  - ") == MAX_LISTED_GROUPS
        assert said.endswith(f"  … and {30 - MAX_LISTED_GROUPS} more")

    def test_rule_three_a_refusal_that_lists_candidates_drops_the_next_step(self):
        # 🔴 The suppression is the composer's whole reason to be a function.
        # Telling a caller to run the verb whose answer they are already reading
        # is the measured over-suggestion failure, and a model reading it runs
        # that verb instead of picking one of the candidates in front of it.
        said = compose_group_refusal(
            "Group not found: ops", [OPS], next_step="Run groups.list to see your groups"
        )

        assert "groups.list" not in said
        assert said.endswith("  - #ops@acme.rine.network (ops)")

    def test_rule_three_does_not_fire_when_there_are_no_candidates_to_show(self):
        said = compose_group_refusal(
            "Group not found: ops", next_step="Run groups.list to see your groups"
        )

        assert said == "Group not found: ops. Run groups.list to see your groups."

    def test_an_empty_roster_still_counts_as_candidates_for_the_suppression(self):
        # ``[]`` says "there were none", which is itself the answer to the verb a
        # next step would name. ``None`` is the only way to ask for one.
        said = compose_group_refusal("Group not found: ops", [], next_step="Run groups.list")

        assert "groups.list" not in said
        assert said == f"Group not found: ops. {NO_GROUPS_IN_ORG}"


class TestTheShippedSentencesAreUnchanged:
    """Byte-identity: the four refusals now routed through the composer."""

    def test_unknown_group_refusal(self):
        assert unknown_group_refusal([OPS], "payroll") == (
            f"{GROUP_NOT_FOUND_LEAD}: payroll. {GROUP_ROSTER_LEAD}\n"
            "  - #ops@acme.rine.network (ops)"
        )

    def test_unknown_group_refusal_over_an_org_in_no_groups(self):
        assert unknown_group_refusal([], "payroll") == (
            f"{GROUP_NOT_FOUND_LEAD}: payroll. {NO_GROUPS_IN_ORG}"
        )

    def test_ambiguous_group_refusal(self):
        assert ambiguous_group_refusal([OPS, FINANCE], "ops") == (
            "Group name 'ops' is ambiguous — more than one group answers to it. "
            f"{GROUP_ROSTER_LEAD}\n"
            "  - #ops@acme.rine.network (ops)\n"
            "  - #finance@acme.rine.network (finance)"
        )

    def test_the_bare_recipient_refusal(self):
        with pytest.raises(NotFoundError) as raised:
            recipient_group_for_bare_name([OPS], "payroll")

        # ``NotFoundError`` stamps its status on the front; the sentence is what
        # this asserts.
        assert str(raised.value).removeprefix("404: ") == (
            "'payroll' names neither an agent nor a group you can reach. "
            "A bare name is read as a group this "
            "org is seated in, and none of them answers to it. An agent is "
            "addressed in full — its name, an at sign, and its org's domain — "
            "and a group by its whole handle, which is a leading hash and the "
            "same three parts. "
            f"{GROUP_ROSTER_LEAD}\n"
            "  - #ops@acme.rine.network (ops)"
        )
        # 🔴 The two spellings used to be shown as worked examples —
        # ``kofi@acme.rine.network`` and ``#logistics@acme.rine.network``, minted
        # in the module and belonging to nobody. A model reading a refusal reads
        # the concrete string as the answer and sends to it, so the rule is that
        # a refusal names the caller's OWN org or describes the shape, and never
        # invents a third party. This roster is the caller's own; the sentence
        # above must stay a description.
        assert "kofi@" not in str(raised.value)
        assert "#logistics@" not in str(raised.value)
        # 🔴 The lead names NEITHER namespace, because by here both have
        # answered no — the spelling is not an agent identifier and no agent of
        # this org carries it. Opening with a group verdict answered the half
        # the caller had not asked about, and the six surfaces that branch on
        # a lead were widened alongside it; ``GROUP_NOT_FOUND_LEAD`` itself
        # is unchanged and still leads every ``rine_group_*`` refusal.
        assert not str(raised.value).removeprefix("404: ").startswith(GROUP_NOT_FOUND_LEAD)
        assert NEITHER_NAMESPACE_LEAD in str(raised.value)

    def test_the_bare_name_is_an_agent_refusal_keeps_its_next_step(self):
        # It names no candidates, so rule 3 does not fire and the third sentence
        # — the one that tells the caller how to spell the group they meant —
        # survives. A composer that dropped it would have deleted the whole point
        # of the guard.
        agents = [{"name": "ops", "handle": "ops@acme.rine.network", "id": "a"}]

        with pytest.raises(ConfigError) as raised:
            refuse_if_a_bare_agent_name(agents, "ops")

        assert str(raised.value) == (
            "'ops' is the name of an agent of your org, not a group reference. "
            "To message that agent, name it by handle: ops@acme.rine.network. "
            "To post to a group of that name, write it as #ops@acme.rine.network."
        )

    def test_the_bare_name_is_an_agent_refusal_sigils_that_word_for_a_slugless_org(self):
        # The whole sentence, not its tail: the derived arm above still
        # teaches the whole handle, and only the arm with no org to derive from
        # moved — from a labelled `#logistics@acme.rine.network` to the caller's
        # own word under a sigil, which is a spelling and not an example.
        agents = [{"name": "ops", "handle": None, "id": "a"}]

        with pytest.raises(ConfigError) as raised:
            refuse_if_a_bare_agent_name(agents, "ops")

        assert str(raised.value) == (
            "'ops' is the name of an agent of your org, not a group reference. "
            "To message that agent, name it by handle: a. "
            "To post to a group of that name, write it as #ops."
        )


class TestThePublicSurface:
    """Deliverable 5 — what a wrapper package may import instead of re-deriving."""

    @pytest.mark.parametrize(
        "name",
        [
            "REF_CLASS_AGENT",
            "REF_CLASS_BARE",
            "REF_CLASS_EMPTY",
            "REF_CLASS_GROUP",
            "REF_CLASS_ID",
            "GroupTarget",
            "RecipientTarget",
            "classify_reference",
            "is_bare_reference",
            "is_sigil_group_reference",
        ],
    )
    def test_the_name_is_exported_and_declared(self, name):
        # Both halves: a wrapper importing a name absent from ``__all__`` is
        # importing something nobody promised to keep.
        assert hasattr(rine, name)
        assert name in rine.__all__


class TestTheLadderDrivers:
    """The two drivers, and the one exception they must not read as an answer.

    ``StopIteration`` out of the LADDER means the ladder answered. The same
    exception out of a READ means an iterator somewhere ran dry, and a driver
    that cannot tell them apart answers ``None`` — which the caller dereferences
    a stack frame away from the cause, in a suite that is testing something
    else. Any read driven by an iterator raises it: an exhausted
    ``Mock(side_effect=[...])``, a hand-rolled fake over ``next()``.
    """

    @staticmethod
    def _dry() -> list[dict[str, Any]]:
        return next(iter(()))

    @staticmethod
    async def _dry_async() -> list[dict[str, Any]]:
        return next(iter(()))

    def test_a_read_that_raises_stopiteration_is_not_the_ladder_finishing(self):
        reads = ReferenceReads(
            own_groups=self._dry,
            group_by_id=lambda group_id: None,
            seated_by_handle=lambda handle: None,
            own_agents=list,
            agent_id_for=lambda reference: reference,
        )

        with pytest.raises(StopIteration):
            walk(group_ladder("ops"), reads)

    async def test_the_async_driver_refuses_the_same_read_rather_than_answering_none(self):
        # PEP 479 rewrites it on this side, so the exception TYPE differs; what
        # must not differ is that neither driver turns a broken read into a
        # resolved target.
        reads = AsyncReferenceReads(
            own_groups=self._dry_async,
            group_by_id=_no_such_group,
            seated_by_handle=_never_seated,
            own_agents=_no_agents,
            agent_id_for=_agent_id_is_the_reference,
        )

        with pytest.raises(RuntimeError):
            await walk_async(group_ladder("ops"), reads)


async def _no_such_group(group_id: str) -> dict[str, Any] | None:
    return None


async def _never_seated(handle: str) -> str | None:
    return None


async def _no_agents() -> list[dict[str, Any]]:
    return []


async def _agent_id_is_the_reference(reference: str) -> str:
    return reference
