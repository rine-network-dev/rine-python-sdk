"""The sentence and the row every voting surface renders.

Four surfaces print the same request row and two more print the same rule, so
what these tests protect is agreement rather than any one string: a clause that
drifts on one connector is invisible until somebody diffs two packages by hand.

The three cases with teeth are the ones a server can produce and a naive
renderer gets wrong — an electorate that has entirely left the group, an
invitation nobody votes on, and a server old enough to send no eligibility
fields at all.
"""

from __future__ import annotations

from typing import Any

from rine import (
    VOTE_ELECTORATE_RULE,
    describe_vote_counts,
    describe_vote_eligibility,
    may_vote,
    render_request_row,
    vote_eligibility_reason,
)
from rine._constants import VoteEligibilityReason
from rine.types import JoinRequestRead

_BASE: dict[str, Any] = {
    "id": "11111111-2222-3333-4444-555555555555",
    "group_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "agent_id": "99999999-8888-7777-6666-555555555555",
    "status": "pending",
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": "2024-01-08T00:00:00Z",
}

#: A tier-1 row: the electorate was recorded and this caller is in it.
_ELIGIBLE: dict[str, Any] = {
    "quorum_total_members": 9,
    "electorate_size": 3,
    "approvals": 1,
    "denials": 0,
    "approvals_needed": 1,
    "denials_needed": 2,
    "you_may_vote": True,
    "you_may_vote_reason": "in_electorate",
}


def _row(**over: Any) -> JoinRequestRead:
    return JoinRequestRead.model_validate({**_BASE, **_ELIGIBLE, **over})


class TestVoteEligibilityReason:
    def test_reason_when_the_server_states_one_then_it_is_used_verbatim(self):
        assert vote_eligibility_reason(_row(you_may_vote_reason="not_in_electorate")) == (
            "not_in_electorate"
        )

    def test_reason_when_the_server_states_none_on_a_pending_row_then_no_electorate(self):
        """A server without electorates lets any current member vote.

        Reporting ``electorate_not_recorded`` is not a guess: it is exactly what
        that server does, and it is the only answer that does not misdescribe a
        request the caller can in fact vote on.
        """
        row = JoinRequestRead.model_validate(_BASE)
        assert vote_eligibility_reason(row) == "electorate_not_recorded"

    def test_reason_when_the_server_states_none_on_an_invitation_then_not_pending(self):
        row = JoinRequestRead.model_validate({**_BASE, "status": "invited"})
        assert vote_eligibility_reason(row) == "not_pending"

    def test_reason_when_a_new_token_is_stated_then_it_survives_and_refuses_the_vote(self):
        """The tokens the vocabulary grew are server facts, not derived ones.

        Neither turns on anything a row carries — one is about who is asking,
        the other about an electorate that was never recorded — so the
        two-branch derivation is untouched, and neither may leak into the set
        :func:`may_vote` treats as a yes.
        """
        for token in ("is_applicant", "bar_unreachable"):
            row = _row(you_may_vote=None, you_may_vote_reason=token)

            assert vote_eligibility_reason(row) == token
            assert may_vote(row) is False

    def test_reason_when_a_server_predating_them_sends_none_then_the_old_answer_stands(self):
        """Growing the vocabulary must not turn an old server's silence into a no.

        Such a server lets any current member vote on a pending request, and a
        client that read the silence as a refusal would leave every request in a
        majority or unanimity group standing until it expired.
        """
        row = JoinRequestRead.model_validate(_BASE)

        assert vote_eligibility_reason(row) == "electorate_not_recorded"
        assert may_vote(row) is True


class TestDescribeVoteEligibility:
    def test_eligibility_when_the_caller_is_in_the_electorate_then_they_can_vote(self):
        assert describe_vote_eligibility(_row()) == "you can vote"

    def test_eligibility_when_the_caller_joined_later_then_it_says_why_not(self):
        clause = describe_vote_eligibility(
            _row(you_may_vote=False, you_may_vote_reason="not_in_electorate")
        )
        assert clause == "you cannot vote: you were not in the group when this was filed"

    def test_eligibility_when_the_electorate_has_left_then_nobody_is_eligible(self):
        clause = describe_vote_eligibility(
            _row(you_may_vote=False, you_may_vote_reason="electorate_empty", electorate_size=0)
        )
        assert clause == "nobody eligible is still in the group"

    def test_eligibility_when_a_vote_was_already_cast_then_the_clause_names_it(self):
        clause = describe_vote_eligibility(
            _row(
                you_may_vote=False,
                you_may_vote_reason="already_voted",
                your_vote="approve",
            )
        )
        assert clause == "you already voted approve"

    def test_eligibility_when_the_request_is_the_callers_own_then_it_says_so(self):
        """An applicant reading its own request is not a latecomer.

        ``not_in_electorate`` predicted a refusal this caller would never get —
        it is refused for want of membership — and the one-to-one reason to
        status mapping is the invariant the read model rests on.
        """
        clause = describe_vote_eligibility(
            _row(you_may_vote=False, you_may_vote_reason="is_applicant")
        )

        assert clause == "this is your own request"

    def test_eligibility_when_no_electorate_was_recorded_and_the_bar_is_zero(self):
        """Distinct from ``electorate_empty``, which is a claim about a set.

        A row that recorded no electorate has none to have emptied, so saying
        "nobody eligible is still in the group" asserts a fact about a set
        nobody ever wrote.
        """
        clause = describe_vote_eligibility(
            _row(you_may_vote=False, you_may_vote_reason="bar_unreachable")
        )

        assert clause == "nobody can decide this request"

    def test_eligibility_when_the_reason_is_unknown_then_the_token_survives(self):
        """A reason this SDK predates is still the server's answer.

        Swallowing it would render the request as ordinary, which is the one
        thing an unrecognised refusal is not.
        """
        assert describe_vote_eligibility(_row(you_may_vote_reason="quorum_suspended")) == (
            "quorum_suspended"
        )

    def test_eligibility_when_every_declared_reason_is_rendered_then_none_is_a_bare_token(self):
        """The fall-through that keeps an unknown token honest also hides a gap.

        A reason this SDK declares and has no clause for prints as the raw wire
        token in an operator's face, and reads exactly like a token from a newer
        server. This is the guard that tells the two apart — a member added to
        the vocabulary with no clause fails here rather than shipping.
        """
        tokens = [
            v
            for k, v in vars(VoteEligibilityReason).items()
            if not k.startswith("_") and isinstance(v, str)
        ]

        assert len(tokens) == 8
        for token in tokens:
            clause = describe_vote_eligibility(
                _row(you_may_vote_reason=token, your_vote="approve")
            )
            assert clause != token, token


class TestDescribeVoteCounts:
    def test_counts_when_a_request_is_pending_then_both_bars_are_named(self):
        """Both bars, because either of them can decide the request.

        A row that reported only the approval half could not explain an outcome
        that turned on the denials, and both bars fall as members leave.
        """
        assert describe_vote_counts(_row()) == (
            "1 approved, 1 more needed of 3 eligible; 0 denied, 2 more would refuse it"
        )

    def test_counts_when_the_electorate_is_empty_then_there_is_no_bar_to_report(self):
        assert describe_vote_counts(
            _row(electorate_size=0, approvals_needed=None, denials_needed=None)
        ) == ("nobody eligible is still in the group")

    def test_counts_when_the_row_is_an_invitation_then_it_is_not_open_for_voting(self):
        row = JoinRequestRead.model_validate({**_BASE, "status": "invited"})
        assert describe_vote_counts(row) == "not open for voting"

    def test_counts_when_the_server_reports_no_electorate_then_the_number_is_a_dash(self):
        """Tier 2/3 has counts and no electorate. A zero there would be a lie."""
        row = _row(electorate_size=None, approvals=2, approvals_needed=1, denials_needed=1)
        assert describe_vote_counts(row) == (
            "2 approved, 1 more needed of — eligible; 0 denied, 1 more would refuse it"
        )

    def test_counts_when_the_server_reports_no_denial_bar_then_that_number_is_a_dash(self):
        """A server that counts denials and does not size their bar.

        The em-dash rule reaches one field further down: "no denials needed" and
        "this server does not report the denial bar" are different facts, and
        printing ``0`` for the second would state an arithmetic it never sent.
        """
        assert describe_vote_counts(_row(denials_needed=None)) == (
            "1 approved, 1 more needed of 3 eligible; 0 denied, — more would refuse it"
        )

    def test_counts_when_the_server_reports_no_denials_then_the_denial_clause_is_dropped(self):
        """A server that predates denials prints no denial clause at all.

        The same rule the approval half already follows: a clause the server
        reported none of is dropped rather than dashed, because an all-em-dash
        clause is not information.
        """
        clause = describe_vote_counts(_row(denials=None, denials_needed=None))

        assert clause == "1 approved, 1 more needed of 3 eligible"
        assert "would refuse" not in clause

    def test_counts_when_the_server_reports_none_of_it_then_there_is_no_clause(self):
        """A row with no counts prints no counts, on both stacks.

        An all-em-dash clause states an arithmetic the server never sent. The
        TypeScript twin drops the clause here; this stack printed dashes, so the
        same row read differently depending on which SDK was holding it.
        """
        row = _row(
            electorate_size=None,
            approvals=None,
            approvals_needed=None,
            denials=None,
            denials_needed=None,
        )
        assert describe_vote_counts(row) == ""
        assert "more needed of" not in render_request_row(row)


class TestRenderRequestRow:
    def test_row_when_a_request_is_pending_then_every_clause_is_present(self):
        assert render_request_row(_row()) == (
            "11111111-2222-3333-4444-555555555555  "
            "99999999-8888-7777-6666-555555555555  pending  "
            "1 approved, 1 more needed of 3 eligible; 0 denied, 2 more would refuse it  "
            "you can vote  expires 2024-01-08T00:00:00Z"
        )

    def test_row_when_the_electorate_has_left_then_the_clause_is_printed_once(self):
        """The counts clause and the eligibility clause say the same thing here.

        They always do, in exactly the two cases where the counts collapse, so
        printing both reads as a defect and adds nothing.
        """
        row = _row(
            electorate_size=0,
            approvals_needed=None,
            you_may_vote=False,
            you_may_vote_reason="electorate_empty",
        )
        assert render_request_row(row).count("nobody eligible is still in the group") == 1

    def test_row_when_the_row_is_an_invitation_then_it_is_not_open_for_voting_once(self):
        row = JoinRequestRead.model_validate({**_BASE, "status": "invited", "expires_at": None})
        assert render_request_row(row) == (
            "11111111-2222-3333-4444-555555555555  "
            "99999999-8888-7777-6666-555555555555  invited  "
            "not open for voting  expires never"
        )


class TestVoteElectorateRule:
    def test_rule_when_rendered_then_it_names_both_policies_and_the_latecomer(self):
        """One sentence has to predict everything a voter can observe."""
        assert "more than half" in VOTE_ELECTORATE_RULE
        assert "unanimity needs all of them" in VOTE_ELECTORATE_RULE
        assert "an agent who joined afterwards does not vote on it" in VOTE_ELECTORATE_RULE

    def test_rule_when_rendered_then_it_names_the_denial_bar_and_that_it_falls(self):
        """The half a voter could observe and the sentence did not predict.

        The denial bar is computed from the same shrinking electorate, so a
        departure lowers it and a standing denial that fell short can refuse a
        request nobody has voted on since. A rule that named only the approval
        bar left that outcome unexplainable.
        """
        assert (
            "Denials refuse it on that same electorate — half of them under majority, "
            "a single one under unanimity — so both bars fall as members leave."
        ) in VOTE_ELECTORATE_RULE
