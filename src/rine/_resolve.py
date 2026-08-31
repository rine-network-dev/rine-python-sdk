"""Handle and agent resolution — WebFinger, UUID, and bare name lookup.

Resolves agent identifiers in multiple formats:
- UUID: passed through directly
- Handle (``name@org`` or ``name@org.rine.network``): resolved via WebFinger
- Bare name: matched case-insensitively against org's agents

A **group** reference is a different vocabulary and resolves in
:mod:`rine._group_ref`, which this module does not import: the two namespaces
answer to the same bare word and the only place they meet is the recipient
guard, which is stated once, there.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, NoReturn

from rine._actor import (
    ActorOrigin,
    ResolvedActor,
    actor_refusal,
    ambiguous_actor_refusal,
    ignored_actor_warning,
    single_actor_value,
    unknown_actor_refusal,
    unknown_handle_refusal,
)
from rine._logging import logger
from rine.errors import ConfigError, NotFoundError

_DEFAULT_DOMAIN = ".rine.network"


def normalize_handle(handle: str) -> str:
    """Append .rine.network when the domain part has no dots (short-form handle)."""
    at_idx = handle.rfind("@")
    if at_idx == -1:
        return handle
    domain = handle[at_idx + 1 :]
    if "." in domain:
        return handle
    return handle + _DEFAULT_DOMAIN


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_UUID_ALIAS_RE = re.compile(
    r"/agents/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I
)


def is_uuid(value: str) -> bool:
    """Check if a string is a valid UUID.

    🔴 ``fullmatch``, never ``match``: Python's ``$`` matches **before** a
    trailing newline and JavaScript's does not, so ``"<uuid>\\n"`` read this as
    an id on one stack and a handle on the other. That spelling is now
    interpolated straight into ``GET /groups/{id}`` — httpx raises
    ``InvalidURL`` on the newline, escaping the SDK's own error hierarchy,
    where the TypeScript twin composes the roster refusal. The anchoring is
    what makes the two classifiers say the same thing.
    """
    return bool(UUID_RE.fullmatch(value))


def parses_as_uuid(value: str) -> bool:
    """Whether the **wire** reads this spelling as a UUID, as written.

    ``uuid.UUID`` parses more spellings than :func:`is_uuid` recognises — the
    dashless, ``urn:uuid:`` and braced forms are all accepted, and always have
    been, by every server slot typed ``uuid.UUID``: the ``X-Rine-Agent`` header
    (``src/rine/api/agent_identity.py``) and every path parameter FastAPI types
    that way, ``GET /conversations/{conversation_id}/messages`` included.

    This is the predicate any *client-side pre-flight* must ask, because a
    pre-flight is only allowed to refuse what the wire would have refused
    anyway. :func:`is_uuid` stays strict on purpose — it decides recipient and
    group resolution, where a UUID means "skip WebFinger" rather than "the wire
    will cope" — so refusing on it would turn a dashless id the product has
    always accepted into a local refusal, which is a capability removal.

    🔴 ``AttributeError`` and ``TypeError`` are caught alongside ``ValueError``
    because the caller is often a **tool argument**, not a typed parameter:
    ``rine-hermes`` hands ``args.get("conversation_id")`` straight through with
    no pydantic layer, so a model that emits ``123`` reaches ``uuid.UUID`` with
    an int and raises ``AttributeError: 'int' object has no attribute
    'replace'``. The handler's blanket ``except Exception`` then renders that as
    an internal-looking error in place of the refusal this predicate exists to
    produce. The question asked here is "does the wire read this as a UUID", and
    for a non-string the answer is no, not a traceback.
    """
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def is_wire_agent_id(value: str) -> bool:
    """Whether ``X-Rine-Agent`` reads this spelling as an agent **id**, as written.

    The **server's** rule, restated: ``_resolve_agent_header`` tries
    ``uuid.UUID(header_value)`` first (``src/rine/api/agent_identity.py``), so
    the answer is :func:`parses_as_uuid` — the four spellings that function
    documents all reach an agent.

    That gap is why this is not "has no ``@`` and is not a UUID". Deciding
    "resolve it first" with the stricter predicate turns a dashless UUID, which
    the wire has always accepted, into a client-side ``NotFoundError`` for an
    agent *name* nobody was looking for.

    🔴 A **handle** is deliberately not one of these spellings, even though the
    header takes one. An acting agent must be an agent the caller owns, so a
    handle is looked up in the caller's own agent list exactly as a name is
    (:func:`resolve_agent`); leaving it to the wire would answer an actor this
    org does not own with a ``422`` about a header — *"Agent x@org not found or
    not owned by this org"*, naming no agent — instead of the one refusal that
    lists the agents there are.
    """
    return parses_as_uuid(value)


def _resolve_handle_from_webfinger(data: dict[str, Any]) -> str | None:
    """Extract agent UUID from WebFinger response aliases."""
    for alias in data.get("aliases", []):
        m = _UUID_ALIAS_RE.search(str(alias))
        if m:
            return m.group(1)
    return None


def resolve_handle_sync(api_url: str, handle: str) -> str:
    """Resolve a handle to agent UUID via WebFinger (sync).

    Args:
        api_url: API base URL.
        handle: Agent handle (e.g. ``name@org`` or ``name@org.rine.network``).

    Returns:
        Agent UUID string, or original handle if WebFinger fails.
    """
    import httpx

    handle = normalize_handle(handle)
    try:
        resp = httpx.get(
            f"{api_url}/.well-known/webfinger",
            params={"resource": f"acct:{handle}"},
            timeout=10,
        )
        if resp.is_success:
            uuid = _resolve_handle_from_webfinger(resp.json())
            if uuid:
                return uuid
    except Exception:
        logger.debug("WebFinger resolution failed for %s", handle, exc_info=True)
    return handle


async def resolve_handle_async(api_url: str, handle: str) -> str:
    """Resolve a handle to agent UUID via WebFinger (async).

    Args:
        api_url: API base URL.
        handle: Agent handle (e.g. ``name@org`` or ``name@org.rine.network``).

    Returns:
        Agent UUID string, or original handle if WebFinger fails.
    """
    import httpx

    handle = normalize_handle(handle)
    try:
        async with httpx.AsyncClient(timeout=10) as http:
            resp = await http.get(
                f"{api_url}/.well-known/webfinger",
                params={"resource": f"acct:{handle}"},
            )
            if resp.is_success:
                uuid = _resolve_handle_from_webfinger(resp.json())
                if uuid:
                    return uuid
    except Exception:
        logger.debug("WebFinger resolution failed for %s", handle, exc_info=True)
    return handle


def invalid_agent_identifier(value: str) -> str:
    """What the agent resolver says to a spelling that is neither UUID nor handle.

    A function rather than the same f-string twice, and it is the gate that
    decides it rather than taxonomy. This gate's fixture takes pure input →
    sentence; :func:`resolve_to_uuid_sync` and :func:`resolve_to_uuid_async`
    reach WebFinger on their other arm, so an inline literal in either is
    compared across the two stacks by nothing. That is precisely how the
    one-byte divergence — this sentence terminated on TypeScript and
    unterminated here — went unnoticed with every suite green. It also ends the
    older, smaller hazard the async body used to carry a comment about: two
    raise sites of one sentence, one of which an edit can miss.
    The TypeScript twin is ``invalidAgentIdentifierRefusal``
    (``rine-core/src/resolve-agent.ts``); the bytes are identical.

    🔴 A placeholder domain may teach a spelling in a tool DESCRIPTION and
    may never appear in a REFUSAL. ``kofi@acme.rine.network`` used to stand
    here, and measurement settled it: given a printed domain, a model moves the
    local part with the conversation and leaves the domain where it found it. A
    ``<slot>`` is not the alternative — ``check-model-facing-examples.mjs``'s
    ``template-org`` rule forbids it for the same reason, one measurement
    earlier. So the
    sentence names the three PARTS of a handle instead of printing one, which is
    the only form that can be neither copied nor filled in wrong. ``expected a
    UUID or handle`` is preserved verbatim because four assertions read it as a
    substring; the tail is what moved.
    """
    return (
        f"Invalid agent identifier '{value}': expected a UUID or handle written "
        "in full — an agent's name, an at sign, and its org's domain."
    )


def resolve_to_uuid_sync(api_url: str, value: str) -> str:
    """Resolve a value (UUID, handle, or bare name) to UUID (sync).

    Args:
        api_url: API base URL.
        value: UUID string, handle, or bare name.

    Returns:
        Agent UUID string.

    Raises:
        NotFoundError: If value format is unrecognizable.
    """
    if is_uuid(value):
        return value
    if "@" in value:
        return resolve_handle_sync(api_url, normalize_handle(value))
    raise NotFoundError(invalid_agent_identifier(value))


async def resolve_to_uuid_async(api_url: str, value: str) -> str:
    """Resolve a value to UUID (async).

    Args:
        api_url: API base URL.
        value: UUID string, handle, or bare name.

    Returns:
        Agent UUID string.

    Raises:
        NotFoundError: If value format is unrecognizable.
    """
    if is_uuid(value):
        return value
    if "@" in value:
        return await resolve_handle_async(api_url, normalize_handle(value))
    raise NotFoundError(invalid_agent_identifier(value))


def _match_bare_name(agents: list[dict[str, Any]], name: str) -> str | None:
    """The one agent carrying that name, or ``None`` — never the first of two.

    A bare name is not unique in an org — :func:`rine._actor.ambiguous_actor_refusal`
    documents the four ways a duplicate is reachable on today's server — and this
    answer decides which identity a request *acts as*, so a silent pick between
    two candidates is a wrong identity rather than a slow one. Ambiguity is the
    one verdict this returns by raising: it is a real refusal on any roster, and
    no fallback may swallow it.
    """
    lower = name.lower()
    matches = [a for a in agents if str(a.get("name") or "").lower() == lower]
    if len(matches) == 1:
        return str(matches[0]["id"])
    if matches:
        raise ConfigError(ambiguous_actor_refusal(matches, name))
    return None


def _match_handle(agents: list[dict[str, Any]], handle: str) -> str | None:
    """The agent carrying that handle, or ``None``.

    Both spellings of a short-form handle match the stored one: the wanted handle
    and each candidate are normalized (``bot@acme`` → ``bot@acme.rine.network``)
    before comparison.
    """
    want = normalize_handle(handle).lower()
    for agent in agents:
        candidate = str(agent.get("handle") or "")
        if candidate and normalize_handle(candidate).lower() == want:
            return str(agent["id"])
    return None


def _find_in_agents(agents: list[dict[str, Any]], target: str) -> str | None:
    """The agent a caller's actor value names, or ``None`` when it names nobody.

    🔴 The verdict, without the refusal. :func:`resolve_agent` has to know that
    a value matched nothing *before* it can decide whether that is a refusal or
    a one-agent fallback, and a ``try``/``except`` around a raising resolver
    would make an exception the control flow of the happy path. The matching
    lives here once, and :func:`_refuse_unresolved_actor` states the same
    dispatch for the sentence.
    """
    if "@" in target:
        return _match_handle(agents, target)
    return _match_bare_name(agents, target)


def _refuse_unresolved_actor(agents: list[dict[str, Any]], target: str) -> NoReturn:
    """Refuse a value that named nobody, in the spelling the caller used.

    The twin of ``refuseUnresolvedActor`` (``rine-core/src/resolve-agent.ts``),
    and factored out for the reason that one is: the ``@`` predicate choosing a
    MATCHER in :func:`_find_in_agents` also chooses a REFUSAL, and two copies of
    it drift — a spelling taught to one and not the other matches correctly and
    is then refused in the other spelling's words. That pair is
    load-bearing: three Python wrappers branch on which of the two leads came
    back, so the wrong lead is a behaviour change and not a cosmetic one.
    """
    if "@" in target:
        raise NotFoundError(unknown_handle_refusal(agents, target))
    raise NotFoundError(unknown_actor_refusal(agents, target))


def resolve_agent(
    agents: list[dict[str, Any]],
    explicit: str | None = None,
    as_flag: str | None = None,
    origin: ActorOrigin = "argument",
) -> ResolvedActor:
    """Resolve an agent from an already-fetched agent list.

    Rungs 1 and 4 of the ladder, on a list the caller already holds: the value
    the caller named, then the org's only active agent. ``explicit`` and
    ``as_flag`` are the **same rung** — two spellings of one thing — so naming
    both with values that disagree refuses rather than letting one win.
    Rung 3, ``RINE_AGENT``, is applied by the client constructor before this is
    ever reached, so this function reads no environment and touches no disk.

    🔴 **A one-agent org never refuses over this slot.** There is exactly
    one answer, so a value that names nobody is not a choice the caller got
    wrong — it is a parameter that could not carry information. The sole agent
    acts and :func:`rine._actor.ignored_actor_warning` rides back on the result.
    The warning is also logged, because on ``rine-crewai``, ``rine-langchain``
    and ``rine-mastra``-style hosts the actor is fixed at construction and the
    only audience that can act on it is the operator.

    🔴 **A UUID never falls back.** Ignoring a caller-supplied id and acting as
    somebody else is a silent identity substitution; a model that does not know
    the value emits a *word*, not a UUID; and it is the one rung that costs no
    ``GET /agents``. So a bogus UUID still fails, at the server, on any roster.

    🔴 ``origin`` is which rung that value came off, and it changes only the
    warning's closing clause — but that clause is the whole of its usefulness.
    The constructor collapses rungs 2 and 3 into one attribute, so this function
    cannot tell a ``RINE_AGENT`` export from an ``agent=`` the caller typed, and
    telling somebody to omit an argument they never passed spends the one
    channel a stale export has left (:data:`rine._actor.ActorOrigin`).

    Args:
        agents: List of org's agents.
        explicit: Explicit agent identifier (UUID, handle, or name).
        as_flag: The same value under its retired spelling.
        origin: Which rung ``explicit`` came off — the client passes
            ``"environment"`` for a value it took from ``RINE_AGENT``.

    Returns:
        The resolved agent UUID, and the warning a one-agent fallback produced.

    Raises:
        ConfigError: If the two spellings disagree, or disambiguation is needed.
        NotFoundError: If the value names nobody in an org that has a choice.
    """
    target = single_actor_value(explicit, as_flag)
    if target:
        if is_uuid(target):
            return ResolvedActor(target)
        found = _find_in_agents(agents, target)
        if found is not None:
            return ResolvedActor(found)
        if len(agents) == 1:
            warning = ignored_actor_warning(target, agents[0], origin=origin)
            logger.warning("%s", warning)
            return ResolvedActor(str(agents[0]["id"]), warning)
        _refuse_unresolved_actor(agents, target)

    if len(agents) == 1:
        return ResolvedActor(str(agents[0]["id"]))

    if len(agents) == 0:
        raise ConfigError(f"{actor_refusal(agents)} Create one: client.create_agent('my-agent')")

    raise ConfigError(actor_refusal(agents))
