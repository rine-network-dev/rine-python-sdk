"""Which of an org's agents hold a seat in a group, in the words every surface prints.

One question, asked on both sides of the same gate. On the ``200`` path a group
row has to say which of the caller's own agents are seated in it, because
``GET /groups`` is org-scoped and the row alone never did. On the ``403`` path
the refusal has to say the same thing about the agent that was turned away. A
surface that answered the two differently would be describing one fact in two
vocabularies, so both live here.

:func:`own_agents_clause` is the ``200`` half. It lives in the SDK rather than
being restated in ``rine-crewai``, ``rine-langchain`` and ``rine-hermes``
because those three are deliberate copies of each other and already import
:mod:`rine.format` for exactly this reason — three copies of one sentence is
how a model comes to read the same group two ways depending on which framework
it happens to be wearing.

The TypeScript stack restates it three times — ``rine-cli``, ``rine-eve`` and
``rine-mastra`` — and does not have to: all three declare
``@rine-network/core`` as a direct dependency and already import from it at
runtime, so one module *does* reach all three. Consolidating them re-runs three
``--external`` publish gates and the ``rine-core`` → ``rine-ts-sdk`` →
CLI/MCP rebuild chain, which makes it a scheduled refactor; it is recorded as an
open follow-up. What no module bridges is Python and TypeScript, which is why
this constant is copied across that boundary and pinned by
``tests/test_client-server-contract_group0.py`` instead.

A group refusal used to read ``Membership required`` — true, anonymous, and
unusable: it did not say which agent had been refused, whether any agent of the
org was seated, or which one to act as instead. The server now names all three
(``src/rine/api/group_member_words.py``), and every one of its three arms opens
with the same clause so a client can recognise the refusal without parsing the
rest of the sentence.

:data:`NOT_A_MEMBER_CLAUSE` is that clause, and it is a **copy** of the server's
constant, not an import of it: the backend must not import this SDK — they are
separate deployables and both own the top-level ``rine`` package — so the two
literals are bound by ``tests/test_client-server-contract_group0.py`` instead.
``rine-core/src/group-words.ts`` holds the identical string for the TypeScript
stack, for the same reason and under the same gate. A wording change lands in
all three files in the same commit or the gate fails, which is the point.

The remedy the server prints is the **wire** one: set the ``X-Rine-Agent``
header. Nothing on this stack sets that header by hand — the SDK writes it from
``agent=`` or ``RINE_AGENT`` (:mod:`rine._actor`) — so a Python surface that
forwarded the server's sentence unchanged would be telling its caller to reach
for something it has no way to reach. :data:`ACTING_AGENT_SPELLING` is this
stack's spelling of the same remedy, appended rather than substituted: the
server's sentence still names *which* agent to act as, which is the half no
client can work out for itself.

That remedy has an arm it cannot serve, and :data:`NO_SEAT_TO_ACT_AS` is the
sentence for it. When no agent of the org is seated at all there is no agent to
act as, so "choose a different one" is advice with no exit; the refusal names
the one thing that would change the answer instead.

The same arm arrives twice, by two routes, and both have to hold it. A Sender
Keys send is refused by :func:`rine._group_send.refuse_if_not_seated` before any
request is made; a closed/MLS send — the default for new groups — never reaches
that guard, so the fact comes back as the server's own refusal and passes
through :func:`not_a_member_message`. Which is why that function reads
:data:`SEATED_SIBLING_CLAUSE` and appends nothing when it is absent: the arm,
not the family, exactly as ``rine-core``'s ``namesASeatedSibling`` does.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from rine._actor import ACTING_AGENT_ENV, AGENT_HEADER, SDK_ACTOR_SPELLING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from uuid import UUID

    from rine.types import GroupRead

#: What a group no agent of the caller's org is seated in renders as.
#:
#: Printed rather than dropped, on every surface and on every row. A clause a
#: model sees on some rows and not others reads as a rendering fault rather than
#: as a fact about the group — and this particular absence is the one fact the
#: row exists to carry, because ``GET /groups`` lists a group the org is in
#: whether or not any agent of it still holds a seat.
NO_OWN_AGENTS = "(none — no agent of your org is seated in this group)"


def own_agents_clause(g: GroupRead, handles: Mapping[UUID, str] | None = None) -> str:
    """Which of the caller's own agents are seated in this group, as a clause.

    Handles, comma-separated — the spelling a model already read out of
    ``rine_whoami``, and the spelling it can hand straight back.
    ``X-Rine-Agent`` takes a handle as readily as a UUID
    (``src/rine/api/agent_identity.py``), so nothing a caller may do next
    narrows; what changes is that the row no longer has to be joined against a
    second tool's output to find out whose seat it is naming. This reverses a
    deliberate earlier choice — the ids were printed raw *because* they were
    hand-backable — and the reversal costs nothing precisely because both
    spellings are hand-backable at the header. It is the bare NAME that is not:
    the server refuses a non-UUID header value carrying no ``@``, so a name
    would be pasteable on the surfaces that reach this SDK's actor ladder and a
    422 on ``rine-mcp``, ``rine-openclaw`` and every raw HTTP caller.

    The map is resolved client-side from the org's own agent list
    (:mod:`rine._agent_handles`), so nothing new goes on the wire. It is not
    always free, and the cost depends on the caller: one that named an actor
    has already fetched that list to resolve it and the map is memoised off it,
    but one that named none never fetched it, and there ``label_own_agents_*``
    issues the first ``GET /agents`` of the call. It issues none when no seat
    would be spelled anyway (``_seats_to_spell``).

    An id the map cannot answer for — every id, when the list could not be
    fetched at all — prints as the id. That is the honest degradation: the row
    keeps naming a real, usable value rather than going blank or raising.

    The refusal half of this module spells its seats the same way and reaches
    the map by the other route. The group
    :func:`rine._group_send.refuse_if_not_seated` guards on is validated inside
    the send path and never labelled, so that caller fetches a map itself
    (:func:`rine._agent_handles.agent_handles_from_http`) and passes it, once
    the refusal is certain and never on a send that goes through. A failed
    lookup arrives here as an empty map and prints the UUIDs the server sent,
    because a refusal must not become a connection error.

    Args:
        g: The group, as the server reported it.
        handles: UUID-to-handle map to spell the seats with. ``None`` means
            *whatever the SDK attached when it validated this group*, which is
            the normal path; pass one explicitly to spell a group the SDK did
            not mint.

    Returns:
        The handles, or :data:`NO_OWN_AGENTS` when none of the org's agents
        holds a seat. Never an empty string: "none are seated" is the answer,
        not the absence of one.
    """
    if not g.member_agent_ids:
        return NO_OWN_AGENTS
    spelling: Mapping[UUID, str] = handles if handles is not None else (g._own_agent_handles or {})
    return ", ".join(spelling.get(agent_id) or str(agent_id) for agent_id in g.member_agent_ids)


#: The clause every arm of the server's not-a-member refusal opens with.
#:
#: Byte-identical to ``rine.api.group_member_words.NOT_A_MEMBER_CLAUSE`` on the
#: server and to ``NOT_A_MEMBER_CLAUSE`` in ``rine-core/src/group-words.ts``.
#: Match on this, never on a whole refusal: the rest of the sentence names
#: agents and handles and differs on every call.
NOT_A_MEMBER_CLAUSE = "is not a member of this group"

#: Which **arm** of that refusal, where :data:`NOT_A_MEMBER_CLAUSE` says which
#: family.
#:
#: Only the two arms that name an agent to act as carry it. The server composes
#: it from its own header constant so the instruction cannot name a header the
#: server does not read (``src/rine/api/group_member_words.py``); this is a
#: plain literal for the same reason :data:`NOT_A_MEMBER_CLAUSE` is, and is
#: pinned to the server's by ``tests/test_client-server-contract_group0.py``
#: alongside ``rine-core``'s copy.
SEATED_SIBLING_CLAUSE = "retry with X-Rine-Agent"

#: How the acting agent is chosen on the Python stack, said once.
#:
#: The server's refusal names the header; these surfaces do not take one. The
#: two spellings that reach the header from here are the same two
#: :func:`rine._actor.actor_refusal` already prints, so a caller reads one
#: instruction from this SDK whichever refusal it happened to hit.
ACTING_AGENT_SPELLING = (
    f"On this surface the acting agent is chosen with {SDK_ACTOR_SPELLING}= or by setting "
    f"{ACTING_AGENT_ENV} — the SDK writes the {AGENT_HEADER} header itself."
)

#: What the refusal says instead, when the org holds no seat to act as at all.
#:
#: :data:`ACTING_AGENT_SPELLING` tells a caller how to choose a different acting
#: agent, and on this arm there is none to choose. The path proves it rather
#: than guessing: :func:`rine._group_send.resolve_group_for_send` reads
#: ``GET /groups?handle=``, which lists only groups the caller's org holds a
#: seat in, so a total stranger to the group never reaches the refusal — while
#: ``member_agent_ids`` counts non-revoked agents only and the row is listed if
#: *any* agent of the org holds a seat (``src/rine/api/groups.py``). An empty
#: list here therefore means one specific thing: every agent of this org that
#: was seated has been revoked. Naming a header, an env var and a ``agent=``
#: argument to an operator in that position is advice with no exit, and
#: printing :data:`NO_OWN_AGENTS` beside it states the same fact a second time
#: in a second vocabulary. Both are replaced by the remedy that is actually
#: available: somebody already inside the group has to invite an agent of this
#: org back in.
#:
#: The seated arm is untouched — there the sibling to act as exists, and naming
#: it is the half no client can derive.
#:
#: ``rine-core/src/group-words.ts`` states the same remedy for the TypeScript
#: stack and differs by one word ("holds a seat there **either**", which
#: follows a clause this refusal does not carry). That divergence is
#: founder-approved and deliberate: unlike :data:`NOT_A_MEMBER_CLAUSE`, this
#: sentence is not a server literal and is bound by no cross-stack gate.
NO_SEAT_TO_ACT_AS = (
    "No agent of your org holds a seat there, so there is nobody to send as: "
    "a member must invite one of your agents before this org can post to the group."
)


#: The refusal's **shape**, not just its clause.
#:
#: Every arm of ``not_a_member_detail`` opens ``agent <name> <clause>``, and
#: agent names are ``[a-z0-9-]`` (``src/rine/api/schemas.py``), so the name is
#: one whitespace-free token. ``POST /messages`` used to be the awkward case —
#: it answered a bare ``Sender is not a member of this group``, about the org
#: and with no acting-agent remedy — and it no longer exists: that route now
#: refuses through ``require_group_member`` like the others, so it matches here
#: and *should*. One server sentence still carries the clause and is not this
#: refusal: the Welcome-recipient 422 (``src/rine/api/mls_schemas.py``), which
#: renders ``<uuid> is not a member of this group and holds no unresolved
#: invitation to it`` about somebody who is not the caller. Matching the bare
#: clause would append this stack's "choose an acting agent" advice to that one
#: too, and it would name the wrong agent.
_ACTING_AGENT_REFUSAL = re.compile(rf"\bagent \S+ {re.escape(NOT_A_MEMBER_CLAUSE)}")


def is_not_a_member(detail: str | None) -> bool:
    """Whether a refusal is the server's "this agent holds no seat" one.

    Args:
        detail: The ``detail`` of a :class:`rine.errors.RineApiError`, or
            ``None`` for an error that carried none.

    Returns:
        ``True`` when the refusal is about the *acting agent* rather than about
        the org or about some third agent. The distinction is the whole reason
        to look: an org that is in the group and an org that is not both get a
        ``403``, and only the first has a remedy the caller can perform on its
        own.
    """
    return detail is not None and _ACTING_AGENT_REFUSAL.search(detail) is not None


def not_a_member_message(detail: str) -> str:
    """The server's refusal, plus this stack's spelling of the remedy it names.

    🔴 **The arm, not the family.** :func:`is_not_a_member` claims all three
    arms, because all three are about the acting agent and all three belong to
    this branch. Only two of them name a sibling to act as. The third says no
    agent of the org holds a seat at all, and appending "choose the acting agent
    with ``agent=``" to *that* sentence sends the caller round a loop with no
    exit: every spelling it offers resolves to an agent that cannot post there
    either. The server's own remedy — somebody inside the group has to invite
    one of these agents back in — is the whole answer, so it is forwarded alone.

    Which arm is read from :data:`SEATED_SIBLING_CLAUSE` rather than from the
    absence of the zero arm's wording, so a reworded zero arm degrades to
    silence rather than to advice. ``rine-core``'s ``namesASeatedSibling``
    discriminates on the same two clauses for the TypeScript stack.

    The client-side guard on the Sender Keys path answers this case before any
    request (:func:`rine._group_send.refuse_if_not_seated`, which prints
    :data:`NO_SEAT_TO_ACT_AS`). This is the same fact arriving from the server
    instead — which is what a closed/MLS group does, since
    :func:`rine._group_send.encrypt_for_group_sync` returns from the MLS branch
    before that guard runs.

    Args:
        detail: The server's refusal, forwarded whole.

    Returns:
        The server's sentence, never rewritten or summarised — it names the
        seated sibling to act as, which no client can derive — followed by this
        stack's spelling of the remedy when there is a sibling to act as,
        because the header the server names is one no Python surface exposes.
    """
    if SEATED_SIBLING_CLAUSE not in detail:
        return detail
    return f"{detail} {ACTING_AGENT_SPELLING}"


__all__ = [
    "ACTING_AGENT_SPELLING",
    "NOT_A_MEMBER_CLAUSE",
    "NO_OWN_AGENTS",
    "NO_SEAT_TO_ACT_AS",
    "SEATED_SIBLING_CLAUSE",
    "is_not_a_member",
    "not_a_member_message",
    "own_agents_clause",
]
