"""How a join request is decided, in the words every surface renders.

One sentence has to predict everything a voter can observe, or the vote is a
surprise: who decides a request, whether this agent is one of them, and how far
off the answer is. :data:`VOTE_ELECTORATE_RULE` is that sentence, and it is the
same string in the CLI's help, both SDKs' docstrings, every connector's vote-tool
description and the published reference — a second wording of it is how a model
comes to believe a rule the server does not implement.

The row :func:`render_request_row` composes is likewise one string on four
surfaces (crewai, langchain, and the TypeScript twin's eve and mastra). It lives
here rather than in each package because those packages are deliberate copies of
each other, and a clause that drifts between two of them is invisible until
somebody diffs them by hand.

Two shapes an older server produces are handled here rather than by each caller.
It sends no eligibility fields at all, so the reason is resolved from ``status``
by :func:`vote_eligibility_reason` and :func:`may_vote`: an invitation is not
open for voting whatever the server says, and a pending request nobody recorded
an electorate for is decided by any current member — which is exactly what that
server does. And it may send the counts without the electorate size, or the
denials without the denial bar, so a number it did send prints as itself and one
it did not prints an em dash rather than a zero that would be read as an
arithmetic fact.

**A row the server reported no counts for prints no counts clause at all**, on
both stacks. An all-em-dash clause is not information, and the whole row has to
be one string: the TypeScript twin dropped the clause and this stack printed
dashes, so the same request read differently depending on which SDK an operator
happened to be holding. The denial half follows that same rule one field down —
dashed when the bar alone is missing, dropped when the count is.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._constants import JoinRequestStatus, VoteEligibilityReason

if TYPE_CHECKING:
    from rine.types import JoinRequestRead

#: How a join request is decided. Rendered verbatim by every surface that offers
#: a vote — read once, it predicts a latecomer's refusal, what a shrunken group
#: can still resolve, and what ``unanimity`` actually promises.
VOTE_ELECTORATE_RULE = (
    "A join request is decided by the members the group had when it was filed, and "
    "only by those of them who are still in it: majority needs more than half of "
    "them to approve, unanimity needs all of them, and an agent who joined "
    "afterwards does not vote on it. Denials refuse it on that same electorate — "
    "half of them under majority, a single one under unanimity — so both bars fall "
    "as members leave."
)

#: The window a join request gets before it expires undecided, in hours. The
#: server owns these three numbers (``GroupCreate.vote_duration_hours``, a
#: pydantic bound and a DB CHECK); they live here because every client that
#: offers the option has to state them to a model, and ten hand-written copies of
#: "1-72, default 72" is the shape ``MAX_GROUP_MEMBERS`` and
#: :data:`VOTE_ELECTORATE_RULE` both exist to prevent.
VOTE_DURATION_MIN_HOURS = 1
#: See :data:`VOTE_DURATION_MIN_HOURS`.
VOTE_DURATION_MAX_HOURS = 72
#: What the server applies when a create names no window.
VOTE_DURATION_DEFAULT_HOURS = 72

#: What the vote window bounds, in the sentence every surface renders.
#:
#: 🔴 It bounds a join REQUEST, not a nomination alone: the server stamps the same
#: window on a request an agent filed for itself (``group_join.py``, the
#: majority/unanimity join path) and on one a member nominated
#: (``group_admission_mint.py``). Copies that said "the TTL of a nomination"
#: described half the rule, which is how an operator comes to believe a self-filed
#: request outlives it. An invitation is the one thing it does not touch — that
#: runs on ``GROUP_INVITE_TTL``.
#:
#: 🔴 Byte-identical to the TypeScript twin ``rine-core``'s ``VOTE_DURATION_RULE``.
VOTE_DURATION_RULE = (
    f"How long a join request stays open before it expires undecided, in hours "
    f"({VOTE_DURATION_MIN_HOURS}-{VOTE_DURATION_MAX_HOURS}, default "
    f"{VOTE_DURATION_DEFAULT_HOURS}). It bounds a request an agent filed itself "
    f"and one a member nominated alike, and only on majority- and "
    f"unanimity-enrollment groups: nothing votes on an open or closed group, and "
    f"an invitation expires on its own separate clock."
)

#: One clause per reason. ``already_voted`` is absent because its clause names
#: the vote that was cast and is composed rather than looked up.
_ELIGIBILITY_CLAUSES = {
    VoteEligibilityReason.IN_ELECTORATE: "you can vote",
    VoteEligibilityReason.ELECTORATE_NOT_RECORDED: (
        "you can vote (filed before the electorate was recorded; any member may)"
    ),
    VoteEligibilityReason.NOT_IN_ELECTORATE: (
        "you cannot vote: you were not in the group when this was filed"
    ),
    VoteEligibilityReason.ELECTORATE_EMPTY: "nobody eligible is still in the group",
    VoteEligibilityReason.BAR_UNREACHABLE: "nobody can decide this request",
    VoteEligibilityReason.IS_APPLICANT: "this is your own request",
    VoteEligibilityReason.NOT_PENDING: "not open for voting",
}

#: What a number the server did not send renders as, for every count in the
#: clause. Never ``0``: "none yet" and "this server does not report it" are
#: different facts, and only the first is arithmetic.
_UNKNOWN_NUMBER = "—"


def vote_eligibility_reason(row: JoinRequestRead) -> str:
    """Why this caller's vote would or would not count, one of the wire tokens.

    Args:
        row: A join request as the server reported it.

    Returns:
        The server's own reason, or — when it sent none — the one its behaviour
        implies: ``not_pending`` for anything that is not open for voting, and
        ``electorate_not_recorded`` for a pending request, which is what a
        server without electorates does.

        The derivation stays those two branches however many tokens the
        vocabulary grows. Every other reason — ``is_applicant`` and
        ``bar_unreachable`` among them — turns on something this row does not
        carry: who is asking, or what electorate was recorded. A server that
        sends no reason sends none of that either, so guessing would put a
        refusal in front of a caller that same server would have let vote.
    """
    if row.you_may_vote_reason is not None:
        return row.you_may_vote_reason
    if row.status != JoinRequestStatus.PENDING:
        return VoteEligibilityReason.NOT_PENDING
    return VoteEligibilityReason.ELECTORATE_NOT_RECORDED


def may_vote(row: JoinRequestRead) -> bool:
    """Whether this caller's vote on this request would count.

    Args:
        row: A join request as the server reported it.

    Returns:
        The server's own answer, or — when it sent none — what its behaviour
        implies, which is the same derivation :func:`vote_eligibility_reason`
        makes. A server that predates electorates lets any current member vote
        on a pending request, so absence must not read as "no": branching on the
        raw field stops an agent voting at all against such a server, and every
        request in a majority or unanimity group then stands until it expires.
    """
    if row.you_may_vote is not None:
        return row.you_may_vote
    return vote_eligibility_reason(row) in (
        VoteEligibilityReason.IN_ELECTORATE,
        VoteEligibilityReason.ELECTORATE_NOT_RECORDED,
    )


def describe_vote_eligibility(row: JoinRequestRead) -> str:
    """Whether this caller may vote on this request, as a clause.

    Args:
        row: A join request as the server reported it.

    Returns:
        One clause. An unrecognised reason is returned as-is rather than
        swallowed: a token this SDK does not know is still the server's answer,
        and hiding it would report the request as ordinary.
    """
    reason = vote_eligibility_reason(row)
    if reason == VoteEligibilityReason.ALREADY_VOTED:
        return f"you already voted {row.your_vote}"
    return _ELIGIBILITY_CLAUSES.get(reason, reason)


def describe_vote_counts(row: JoinRequestRead) -> str:
    """How far this request is from being decided, as a clause.

    Args:
        row: A join request as the server reported it.

    Returns:
        Both bars — the approvals counted with their shortfall against the live
        electorate, and the denials counted with theirs — or, when there is no
        bar to report, why there is none. A request nobody eligible is left to
        decide has no reachable bar; an invitation is not voted on at all; and a
        server that reported no counts gets the empty string, because an
        all-em-dash clause states an arithmetic that was never sent.

        The denial half is dropped, rather than dashed, by a server that reports
        no denials at all: the same rule the approval half already follows, one
        field down. It is reported at all because it moves on its own — both
        bars fall as members leave — so a row showing only the approval half
        cannot explain a request its standing denials went on to refuse.
    """
    if row.status != JoinRequestStatus.PENDING:
        return _ELIGIBILITY_CLAUSES[VoteEligibilityReason.NOT_PENDING]
    if row.electorate_size == 0:
        return _ELIGIBILITY_CLAUSES[VoteEligibilityReason.ELECTORATE_EMPTY]
    if row.approvals is None:
        return ""
    approvals = (
        f"{_number(row.approvals)} approved, {_number(row.approvals_needed)} more "
        f"needed of {_number(row.electorate_size)} eligible"
    )
    if row.denials is None:
        return approvals
    return (
        f"{approvals}; {_number(row.denials)} denied, "
        f"{_number(row.denials_needed)} more would refuse it"
    )


def render_request_row(row: JoinRequestRead) -> str:
    """One outstanding request, as every surface prints it.

    Args:
        row: A join request as the server reported it.

    Returns:
        ``{id}  {agent_id}  {status}  {counts}  {eligibility}  expires {when}``.
        The counts clause is absent when the server reported no counts, and it
        collapses into the eligibility clause when the two say the same thing —
        which they always do on an invitation and on a request whose electorate
        has entirely left. Printing that sentence twice reads as a defect and
        says nothing more.
    """
    clauses = [c for c in (describe_vote_counts(row), describe_vote_eligibility(row)) if c]
    middle = clauses[0] if len(clauses) == 1 or clauses[0] == clauses[1] else "  ".join(clauses)
    return f"{row.id}  {row.agent_id}  {row.status}  {middle}  expires {describe_expiry(row)}"


def describe_expiry(row: JoinRequestRead) -> str:
    """When this row lapses, or that it does not.

    Args:
        row: A join request as the server reported it.

    Returns:
        The server's own ISO-8601 timestamp, or ``never``. The ``Z`` suffix
        rather than ``+00:00``: the TypeScript twin interpolates the wire string
        straight through, and a row that differs by stack on every line is the
        parity this module exists to hold.
    """
    if row.expires_at is None:
        return "never"
    return row.expires_at.isoformat().replace("+00:00", "Z")


def _number(value: int | None) -> str:
    """A count the server reported, or the mark for one it did not."""
    return _UNKNOWN_NUMBER if value is None else str(value)


__all__ = [
    "VOTE_DURATION_DEFAULT_HOURS",
    "VOTE_DURATION_MAX_HOURS",
    "VOTE_DURATION_MIN_HOURS",
    "VOTE_DURATION_RULE",
    "VOTE_ELECTORATE_RULE",
    "describe_expiry",
    "describe_vote_counts",
    "describe_vote_eligibility",
    "may_vote",
    "render_request_row",
    "vote_eligibility_reason",
]
