"""Which of an org's agents hold a seat, in words — both halves.

The ``200`` half is :func:`own_agents_clause`, the row's answer to "can I post
here". The ``403`` half is :func:`is_not_a_member`, which decides whether this
stack appends its own spelling of the remedy to the server's refusal.

The refusals below are the sentences ``src/rine/api/group_member_words.py``
really builds, not paraphrases: the clause is pinned across the two stacks by
``tests/test_client-server-contract_group0.py``, and what this file pins is the
part no cross-stack gate can — that the predicate says yes to the three arms of
that refusal and no to the other server sentences carrying the same clause.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from rine.group_words import (
    ACTING_AGENT_SPELLING,
    NO_OWN_AGENTS,
    NOT_A_MEMBER_CLAUSE,
    SEATED_SIBLING_CLAUSE,
    is_not_a_member,
    not_a_member_message,
    own_agents_clause,
)
from rine.types import GroupRead

ARM_ONE_SIBLING = (
    f"agent ops-bot {NOT_A_MEMBER_CLAUSE}; your agent sales-bot is"
    " — retry with X-Rine-Agent: sales@acme.rine.network"
)
ARM_SEVERAL_SIBLINGS = (
    f"agent ops-bot {NOT_A_MEMBER_CLAUSE}; these agents of yours are"
    " — retry with X-Rine-Agent set to one of them:\n  - sales-bot (sales@acme.rine.network)"
)
ARM_NO_SIBLING = (
    f"agent ops-bot {NOT_A_MEMBER_CLAUSE}, and no agent of your org is"
    " — a member must invite one of your agents before this org can act in it"
)

#: Two other server sentences that carry the clause and are not this refusal.
#: ``POST /messages`` refuses the sending **org** (``api/messages.py``), and the
#: Welcome-recipient 422 (``api/mls_schemas.py`` via ``api/mls_helpers.py``)
#: describes somebody the caller was trying to add.
SENDER_REFUSAL = f"Sender {NOT_A_MEMBER_CLAUSE}"
WELCOME_REFUSAL = (
    "2 of this commit's Welcome recipients cannot be addressed: "
    "8f14e45f-ceea-467a-9a0f-1c2d3e4f5a6b is not a known agent, or has been revoked; "
    f"c9f0f895-fb98-4b41-9b4a-1a2b3c4d5e6f {NOT_A_MEMBER_CLAUSE} and holds no "
    "unresolved invitation to it. Post the commit again without them."
)


def _group(**kw: object) -> GroupRead:
    fields: dict[str, object] = {
        "id": "1f2e3d4c-5b6a-4798-8899-aabbccddeeff",
        "name": "ops",
        "handle": "#ops@acme.rine.network",
        "member_count": 3,
        "created_at": "2026-08-11T09:00:00Z",
        "conversation_id": "2f2e3d4c-5b6a-4798-8899-aabbccddeeff",
    }
    fields.update(kw)
    return GroupRead.model_validate(fields)


SEATED = ["3f2e3d4c-5b6a-4798-8899-aabbccddeeff", "4f2e3d4c-5b6a-4798-8899-aabbccddeeff"]
SEATED_HANDLES = {
    UUID(SEATED[0]): "ops-bot@acme.rine.network",
    UUID(SEATED[1]): "billing@acme.rine.network",
}


class TestOwnAgentsClause:
    def test_own_agents_clause_when_agents_are_seated_then_names_their_handles(self) -> None:
        clause = own_agents_clause(_group(member_agent_ids=SEATED), SEATED_HANDLES)

        # Handles rather than ids: the spelling the model already read out of
        # `rine_whoami`, and one `X-Rine-Agent` takes as readily as a UUID — so
        # the row names a seat without having to be joined against a second
        # tool's output first.
        assert clause == "ops-bot@acme.rine.network, billing@acme.rine.network"

    def test_own_agents_clause_when_a_seat_has_no_handle_then_that_one_prints_as_its_id(
        self,
    ) -> None:
        # Per id, not per row. The map is built from the org's own agent list,
        # which contains every seat in a healthy org — but a row degrades one
        # name at a time rather than falling back wholesale.
        clause = own_agents_clause(
            _group(member_agent_ids=SEATED), {UUID(SEATED[0]): "ops-bot@acme.rine.network"}
        )

        assert clause == f"ops-bot@acme.rine.network, {SEATED[1]}"

    def test_own_agents_clause_when_no_handles_were_resolved_then_falls_back_to_ids(
        self,
    ) -> None:
        # What an unreachable `GET /agents` leaves behind. A UUID is still a
        # real, hand-backable value, so the row degrades instead of going blank
        # or raising — which is why the fetch, not the lookup, carries the
        # try/except (`rine._agent_handles`).
        assert own_agents_clause(_group(member_agent_ids=SEATED)) == ", ".join(SEATED)

    def test_own_agents_clause_when_the_sdk_attached_a_map_then_uses_it_unasked(self) -> None:
        # The surfaces call this with one argument: crewai, langchain and hermes
        # render a `GroupRead` the SDK minted and never see a handle map. The
        # map has to travel with the group or those three print ids forever.
        group = _group(member_agent_ids=SEATED)
        group._own_agent_handles = dict(SEATED_HANDLES)

        assert own_agents_clause(group) == "ops-bot@acme.rine.network, billing@acme.rine.network"

    def test_own_agents_clause_when_a_map_is_passed_then_it_beats_the_attached_one(self) -> None:
        group = _group(member_agent_ids=SEATED[:1])
        group._own_agent_handles = {UUID(SEATED[0]): "stale@acme.rine.network"}

        assert own_agents_clause(group, {UUID(SEATED[0]): "fresh@acme.rine.network"}) == (
            "fresh@acme.rine.network"
        )

    def test_own_agents_clause_when_a_map_is_attached_then_it_stays_off_the_wire(self) -> None:
        # The whole reason the map is a private attribute. `member_agent_ids` is
        # UUID-shaped on both stacks, and `refuse_if_not_seated` reads
        # `model_fields_set` to tell an omitted key from an empty list — neither
        # may notice that a client wrote handles down beside them.
        group = _group(member_agent_ids=SEATED)
        before = group.model_fields_set.copy()
        group._own_agent_handles = dict(SEATED_HANDLES)
        dumped = group.model_dump_json()

        assert not any(handle in dumped for handle in SEATED_HANDLES.values())
        assert group.model_fields_set == before
        assert all(isinstance(seat, UUID) for seat in group.member_agent_ids)

    def test_own_agents_clause_when_none_are_seated_then_says_so_rather_than_nothing(
        self,
    ) -> None:
        # The one fact the field exists to carry: `GET /groups` lists a group
        # the org belongs to whether or not any agent of it still holds a seat.
        assert own_agents_clause(_group(member_agent_ids=[])) == NO_OWN_AGENTS

    def test_own_agents_clause_when_the_server_omits_the_field_then_says_none_are_seated(
        self,
    ) -> None:
        # Release order puts a new client in front of an old server, where the
        # field is absent rather than empty. Both render the same way here — the
        # SDK's model defaults it — so no surface prints a `None`.
        assert own_agents_clause(_group()) == NO_OWN_AGENTS


class TestIsNotAMember:
    @pytest.mark.parametrize(
        "detail",
        [ARM_ONE_SIBLING, ARM_SEVERAL_SIBLINGS, ARM_NO_SIBLING],
        ids=["one-sibling", "several-siblings", "no-sibling"],
    )
    def test_is_not_a_member_when_given_any_arm_of_the_refusal_then_is_true(
        self, detail: str
    ) -> None:
        assert is_not_a_member(detail) is True

    @pytest.mark.parametrize(
        "detail",
        [SENDER_REFUSAL, WELCOME_REFUSAL],
        ids=["sender-org-refusal", "welcome-recipient-422"],
    )
    def test_is_not_a_member_when_the_clause_is_about_another_subject_then_is_false(
        self, detail: str
    ) -> None:
        # Both carry the clause and neither is about the acting agent. Saying
        # yes here appends "choose a different acting agent" to a refusal about
        # the org, or about an agent the caller was trying to add.
        assert NOT_A_MEMBER_CLAUSE in detail
        assert is_not_a_member(detail) is False

    def test_is_not_a_member_when_the_error_carried_no_detail_then_is_false(self) -> None:
        assert is_not_a_member(None) is False


class TestNotAMemberMessage:
    @pytest.mark.parametrize(
        "detail",
        [ARM_ONE_SIBLING, ARM_SEVERAL_SIBLINGS],
        ids=["one-sibling", "several-siblings"],
    )
    def test_not_a_member_message_when_a_sibling_is_seated_then_appends_the_spelling(
        self, detail: str
    ) -> None:
        message = not_a_member_message(detail)

        # The server's half names *which* agent is seated, which no client can
        # derive; this stack's half is appended because the header the server
        # names is one no Python surface exposes.
        assert message.startswith(detail)
        assert message.endswith(ACTING_AGENT_SPELLING)

    def test_not_a_member_message_when_no_agent_of_the_org_is_seated_then_appends_nothing(
        self,
    ) -> None:
        # The arm, not the family. `is_not_a_member` claims this refusal too —
        # it is about the acting agent and belongs to this branch — but there is
        # no sibling to act as, so "choose the acting agent with agent=" is a
        # loop with no exit: every spelling it offers resolves to an agent that
        # cannot post there either. The server's remedy is the whole answer.
        assert is_not_a_member(ARM_NO_SIBLING) is True

        assert not_a_member_message(ARM_NO_SIBLING) == ARM_NO_SIBLING
        assert ACTING_AGENT_SPELLING not in not_a_member_message(ARM_NO_SIBLING)

    def test_not_a_member_message_when_choosing_the_arm_then_reads_the_seated_clause(
        self,
    ) -> None:
        # Keyed on the clause that IS there, never on the zero arm's wording:
        # a reworded zero arm then degrades to silence rather than to advice.
        # `rine-core`'s `namesASeatedSibling` discriminates on the same two.
        assert SEATED_SIBLING_CLAUSE in ARM_ONE_SIBLING
        assert SEATED_SIBLING_CLAUSE in ARM_SEVERAL_SIBLINGS
        assert SEATED_SIBLING_CLAUSE not in ARM_NO_SIBLING

        reworded_zero_arm = f"agent ops-bot {NOT_A_MEMBER_CLAUSE}, and neither is anyone else here"
        assert not_a_member_message(reworded_zero_arm) == reworded_zero_arm
