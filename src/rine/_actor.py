"""The acting-agent contract, in the one place every Python surface reads it.

The twin of ``rine-core/src/actor.ts``. Before this module the wire header was
retyped at ~25 sites in this package alone, nothing read ``RINE_AGENT`` at all,
and the ambiguity refusal used a different sentence from the one the TypeScript
stack prints for the same situation.

It lives beside :mod:`rine._resolve` rather than inside it because that file is
already past this project's ~200-line ceiling, and because the split matches the
TypeScript stack exactly: the contract (header, env var, normalisation, the
refusals) in one file, the resolvers that consume it in the other.

The Python stack holds its own copy of these strings on purpose. The backend
must not import the SDK — they are separate deployables, and both own the
top-level ``rine`` import package — so ``AGENT_HEADER`` here and
``rine.api.agent_identity.HEADER`` on the server are two constants bound by a
test, never one import.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal

from rine.errors import ConfigError, ReplyAttributionError

#: The wire header naming which of an org's agents a request acts as.
AGENT_HEADER = "X-Rine-Agent"

#: The environment variable naming the acting agent, on every surface.
ACTING_AGENT_ENV = "RINE_AGENT"

#: How this stack spells the acting-agent slot — a keyword argument's name.
#:
#: The *spelling*, never a template: the refusals below append ``=`` themselves
#: (``agent=``), and the value they used to carry, ``agent=<name>``, put a
#: bracketed slot in model-facing text — the same shape a model filled with the
#: literal word ``null``. The parameter stays so a wrapper that grows its own
#: refusal names *its* spelling rather than minting a second sentence, which is
#: how the two TypeScript texts drifted.
SDK_ACTOR_SPELLING = "agent"

#: Which rung an actor value came off — the lever the caller can actually move.
#:
#: 🔴 It exists because :func:`ignored_actor_warning` tells a caller what to do
#: next, and rungs 2 and 3 have different answers: *"omit agent"* is
#: unfollowable advice for somebody who passed no ``agent=``, and on a one-agent
#: org that warning is the ONLY channel a stale ``RINE_AGENT`` has left — the
#: refusal that used to carry it no longer happens. A closed
#: :class:`~typing.Literal` rather than a free string, so a third rung has to
#: declare itself. The twin of ``rine-core/src/actor.ts``'s ``ActorOrigin``.
ActorOrigin = Literal["argument", "environment"]


@dataclass(frozen=True, slots=True)
class ResolvedActor:
    """Which agent acted, and anything the caller should be told about it.

    🔴 A **per-call return value**, never a mutable attribute on the client.
    :class:`rine.RineClient` is built to be shared and already caches across
    calls, and ``asyncio.gather(client.send(a), client.send(b))`` interleaves at
    every ``await`` — a ``last_actor_warning`` written while resolving one call
    is read by the wrapper that just finished the other, so the warning is
    attributed to the wrong send or silently overwritten. The twin of
    ``rine-core/src/actor.ts``'s ``ResolvedActor``; the field names are
    deliberate twins (``agent_id`` / ``agentId``), the same way
    :data:`AGENT_HEADER` and its TypeScript copy are.

    🔴 Twins in NAMING and in the two fields above, not field-for-field. The
    TypeScript one carries a third, ``agents``, and this record deliberately has
    no counterpart: ``rine-core``'s ``fetchAgents`` is uncached by design — a
    memo there would outlive a request that package cannot scope — so the list
    has to ride the returned value for an actor resolve and a following bare-name
    recipient resolve to share one ``GET /agents``. Both clients here
    memoise :meth:`_fetch_agents` on the client instead, and the ladder's
    collision guard is handed that same memo as ``own_agents``, so the second
    read is already free and there is nothing for a field to buy. The reasoning
    is kept on the TypeScript declaration; nothing in either suite would see
    these two drift, so a lane adding a field to either must say here what the
    other does instead.
    """

    agent_id: str
    warning: str | None = None

    def note_fields(self) -> dict[str, str]:
        """The warning as a JSON tool-result field, or nothing at all.

        Spread into a model-facing result (``tool_result(**note_fields(), …)``)
        so a surface that renders one renders none when there is nothing to say,
        rather than shipping a ``"warning": null`` key every model has to read.
        """
        return {"warning": self.warning} if self.warning else {}

    def annotate(self, text: str) -> str:
        """``text`` with the warning on its own line, or ``text`` unchanged."""
        return f"{text}\n{self.warning}" if self.warning else text


def normalize_actor(value: Any) -> str | None:
    """The one normalisation rule for an actor value, applied once per rung.

    Trims, and treats empty-after-trim as *absent* so the rung falls through
    rather than refusing — an exported-but-empty ``RINE_AGENT`` is the shipped
    shape of "no actor set" (``rine-eve``'s scaffolder writes a bare
    ``RINE_AGENT=`` line into every project it generates). No case folding: bare
    names already match case-insensitively and handles normalise in
    :func:`rine._resolve.normalize_handle`, so a third rule here could only
    disagree with them.

    A non-string that is not ``None`` refuses rather than stringifying:
    ``str({})`` is ``"{}"``, and hunting for an agent by that name either finds
    nobody or, worse, finds somebody.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(
            f"The acting agent must be a name, handle or UUID (got {type(value).__name__})."
        )
    trimmed = value.strip()
    return trimmed or None


def actor_from_env() -> str | None:
    """Rung 3 of the ladder: the acting agent named by the environment.

    🔴 The only ``RINE_AGENT`` read on the Python stack. Unlike the TypeScript
    stack — where a *surface* calls its twin and no SDK path can reach it — this
    one is called from inside the SDK's base client, deliberately:
    ``rine-crewai``, ``rine-langchain`` and ``rine-hermes`` keep the actor off
    the model-visible schema and have no surface of their own to put a rung on,
    so inheriting it through the client constructor is the whole of the rung.
    """
    return normalize_actor(os.environ.get(ACTING_AGENT_ENV))


def actor_label(agent: dict[str, Any]) -> str:
    """One agent, in the one column set every refusal on this stack prints.

    ``handle`` is nullable on the wire — ``POST /agents`` mints one only when the
    org has a slug — and a ``.get`` *default* does not fire on a key that is
    present and ``None``, so the shipped fallback rendered ``bob (None)``: an
    agent named by nothing ``X-Rine-Agent`` accepts. The UUID is the other value
    that header takes, which is why both twins fall back to exactly it.

    Extracted from :func:`format_actor_list` so a sentence that names ONE agent
    inline — :func:`ignored_actor_warning` — cannot grow a second column set.
    """
    return f"{agent.get('name') or '?'} ({agent.get('handle') or agent.get('id') or '?'})"


def format_actor_list(agents: list[dict[str, Any]]) -> str:
    """The org's agents, one per line, in the one column set every stack prints."""
    return "\n".join(f"  - {actor_label(a)}" for a in agents)


def _name_one_of_them(actor_spelling: str = SDK_ACTOR_SPELLING) -> str:
    """The retry invitation, said once because two refusals end with it."""
    return f"Name one of them with {actor_spelling}=, or set {ACTING_AGENT_ENV}."


def ignored_actor_warning(
    given: str,
    agent: dict[str, Any],
    actor_spelling: str = SDK_ACTOR_SPELLING,
    origin: ActorOrigin = "argument",
) -> str:
    """Told to a caller whose actor value named nobody in a ONE-agent org.

    Not a refusal: the org has exactly one agent, so the slot carries no
    information and there is nothing to choose. The call succeeds as that agent
    and the caller is told three things — what was passed, who acted, and what
    to change — because a model that filled the slot with its own schema's
    placeholder text needs to learn the slot was never load-bearing, not to be
    stopped.

    Fires only from the *failure* path of resolution, so a value that named the
    agent correctly never reaches it: warning on a correct call would teach a
    model that correct behaviour produces complaints.

    🔴 ``origin`` decides which lever the closing clause names (:data:`ActorOrigin`).
    A value the client constructor took off ``RINE_AGENT`` was never in the call,
    so *"omit agent"* names something the caller did not do and withholds the one
    actionable fact there is — that the export is stale.
    """
    if origin == "environment":
        lever = f"{ACTING_AGENT_ENV}={given!r}"
        next_step = (
            f"{ACTING_AGENT_ENV} names no agent this org has — unset it, "
            "or point it at one that exists."
        )
    else:
        lever = f"{actor_spelling}={given!r}"
        next_step = f"Omit {actor_spelling} for a one-agent org."
    return f"Ignored {lever}: this org has one agent, so {actor_label(agent)} acted. {next_step}"


def actor_refusal(agents: list[dict[str, Any]], actor_spelling: str = SDK_ACTOR_SPELLING) -> str:
    """Told to a caller who named no agent in an org that has more than one."""
    if not agents:
        return "No active agents in this org."
    return (
        "This org has more than one agent. Say which one is acting:\n"
        f"{format_actor_list(agents)}\n"
        f"{_name_one_of_them(actor_spelling)}"
    )


def _and_the_agents_there_are(
    lead: str,
    agents: list[dict[str, Any]],
    actor_spelling: str = SDK_ACTOR_SPELLING,
) -> str:
    """One refusal's tail: the org's agents, or the reason there are none.

    🔴 The zero-agent branch is the half a hand-rolled copy of this always drops.
    :func:`format_actor_list` renders an empty org as the empty string, so a
    refusal that appends it unconditionally ends *"Available agents:"* and then
    simply stops — a sentence that trails off exactly where the caller most needs
    to be told there is nothing to choose from. Every refusal that names an actor
    spelling and then the roster ends here, so neither spelling can lose it
    again.

    🔴 The roster arm may say *"more than one agent"* flatly because
    :func:`rine._resolve.resolve_agent` can no longer reach either refusal over a
    ONE-agent roster: a value that names nobody in a one-agent org resolves to
    the sole agent and carries :func:`ignored_actor_warning` instead. Every lead
    that ends here is rendered over 0 or ≥2 agents, and nowhere else.
    """
    if not agents:
        return f"{lead} No active agents in this org."
    return (
        f"{lead} This org has more than one agent, so a call has to name one. "
        f"Available agents:\n{format_actor_list(agents)}\n"
        f"{_name_one_of_them(actor_spelling)}"
    )


def unknown_actor_refusal(agents: list[dict[str, Any]], name: str) -> str:
    """Told to a caller who named an agent this org does not have.

    One sentence whichever value was passed — ``null`` and a misspelled
    colleague get the same answer, because in both cases the caller named
    something this org does not have and the next step is identical. The value
    IS echoed: a caller who cannot see their own typo cannot correct it.

    A hardcoded bogus-word list used to fork this into a second sentence. It was
    deleted: the one-agent org resolves before it could be consulted,
    and the multi-agent org says this either way.
    """
    return _and_the_agents_there_are(f"No agent named '{name}'.", agents)


def unknown_handle_refusal(agents: list[dict[str, Any]], handle: str) -> str:
    """Told to a caller whose actor handle names no agent of this org.

    A handle keeps its own lead sentence rather than borrowing the one above:
    *"named"* is what a caller did with a bare name, and saying it of a handle
    prints the org part back as though it were part of a name. Only the lead
    differs — the tail is shared, so the two spellings of one mistake cannot
    drift into two shapes of answer again.
    """
    return _and_the_agents_there_are(f"No agent with handle '{handle}'.", agents)


def ambiguous_actor_refusal(matches: list[dict[str, Any]], name: str) -> str:
    """Told to a caller whose bare name names more than one agent.

    A bare name is **not** unique in an org, and nothing on the server makes it
    so: ``agents.name`` carries no unique index
    (``src/rine/db/models/org_agent.py`` indexes ``handle``, never ``name``),
    ``POST /agents``' duplicate check is a
    case-sensitive count-then-insert, ``PATCH /agents/{id}`` renames with no
    duplicate check at all in a slugless org, and ``GET /agents`` has no
    ``ORDER BY``. So the list this matched against is unordered and can hold two
    agents whose names differ only in case — which the matcher folds together.

    Picking the first match would name an identity the caller did not choose,
    silently and non-deterministically, on a request that acts as it. The
    candidates are rendered in the one column set every refusal on this stack
    prints, and its fallback is the UUID — the spelling that still distinguishes
    two agents when the org has no slug and neither of them has a handle.
    """
    return (
        f"More than one agent is named '{name}'. Say which one is acting:\n"
        f"{format_actor_list(matches)}\n"
        "A name is not unique in an org — name it by handle or UUID."
    )


def single_actor_value(explicit: Any, alias: Any = None) -> str | None:
    """The one value two spellings of the same rung must agree on.

    Returns the one value both spellings name, or ``None`` when neither was
    given. Refuses when they disagree, naming both — no precedence rule silently
    picks a winner, because the loser is an identity the caller believed they
    were acting as.

    Only same-rung pairs reach here. A keyword argument beating ``RINE_AGENT``,
    or a per-call agent beating a client's constructor default, is *precedence*
    and stays silent.

    Both spellings are rendered ``agent=``/``as=`` regardless of the calling
    surface: the SDK takes a keyword argument and a tool call carries a JSON
    key, and ``agent=bob`` reads correctly for both. There is no third spelling
    to label.

    Disagreement is a literal comparison after :func:`normalize_actor`,
    case-insensitive — never resolve-then-compare. Resolving first would spend up
    to two network round trips before it could decide to refuse, could fail on
    the second value with a different error entirely, and would make the refusal
    non-deterministic offline. The cost is that naming one agent twice, once by
    name and once by handle, is refused; the refusal says exactly that happened.
    """
    first = normalize_actor(explicit)
    second = normalize_actor(alias)
    if first is None:
        return second
    if second is None:
        return first
    if first.lower() != second.lower():
        raise ConfigError(
            f"You named the acting agent twice: agent={first} and as={second}.\nName it once."
        )
    return first


def _same_agent(one: str | None, other: str | None) -> bool:
    """Compare two server-issued agent UUIDs, trimmed and case-folded.

    A caller that carried an id through a surface which upper-cased it must not
    be refused over spelling. The same reason
    :func:`rine._crypto._sender_verify.refuse_if_sender_differs` compares that
    way. A missing id matches nothing, including another missing one.
    """
    if not one or not other:
        return False
    return one.strip().lower() == other.strip().lower()


def refuse_if_not_addressee(
    agent_id: str,
    message_id: str,
    to_agent_id: str | None,
    from_agent_id: str | None = None,
) -> None:
    """Refuse a reply whose acting agent is not the one the original was addressed to.

    A reply is filed from the agent that acts, and it is sealed and signed with
    that agent's keys. Reading the original is authorised for the ORG, so every
    sibling can reach a message addressed to one of them, and nothing upstream
    stops one from answering mail it cannot open. This comparison is what stops
    it, and it is made before anything is encrypted or sent.

    A message with no addressee — a group post — is left alone: there is no one
    agent to compare against, and the server declines a reply to one anyway.

    ``from_agent_id`` changes no verdict; it changes the advice. An agent that
    answers its OWN sent message is not the addressee either, but the addressee
    is the far side's agent, which this caller can never act as — telling it to
    "reply as that agent" would be impossible advice. Passing the original's
    sender lets the refusal say the one thing that is actionable instead. Omit it
    and the refusal falls back to naming the addressee.

    Args:
        agent_id: The acting agent this call resolved.
        message_id: The message being replied to.
        to_agent_id: The original's ``to_agent_id``; ``None`` for a group post.
        from_agent_id: The original's ``from_agent_id``, when the caller has it.

    Raises:
        ReplyAttributionError: The acting agent is not the addressee.
    """
    if not to_agent_id:
        return
    if _same_agent(agent_id, to_agent_id):
        return
    raise ReplyAttributionError(
        message_id,
        agent_id,
        to_agent_id,
        acting_is_sender=_same_agent(agent_id, from_agent_id),
    )
