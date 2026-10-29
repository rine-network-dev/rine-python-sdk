"""The five reads a reference resolution can need, and the two things that run one.

A ladder in :mod:`rine._recipient_ladder` is a generator: it yields the wire
read it needs and is handed the answer back. A generator cannot await, and it
does not have to — the DRIVER awaits. :func:`walk` runs one against the synchronous client and
:func:`walk_async` against the asynchronous one, so between those two clients
there is no copy of a tier, of a fallback order, or of a refusal.

That last clause is the point. The contract offers a ``GroupFetcher`` protocol
or a pure ``_ladder_over(groups, ref)`` helper as the two ways to reach one
implementation. Neither reaches far enough: a protocol whose methods are
``async def`` cannot be satisfied by the sync client, and a pure helper over an
already-fetched list leaves the RUNG ORDER — ask ``?handle=`` first, list the groups the key can see only if it answered nothing — behind in each client, which is
exactly the half that drifted (the local-part fallback shipped to the async
client and had to be re-derived for the sync one). Yielding the read moves the
order into the shared body too.

The precedent is :class:`rine._group_join.DirectoryHandleScan`, which holds the
join scan's entire policy while both clients hold only its fetch. This is the
same seam, for a walk with more than one read in it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from rine._logging import logger
from rine.errors import GroupIdentityMismatchError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

    from rine.errors import RineApiError

_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class OwnGroups:
    """Ask for ``GET /groups`` — every group the key can see."""


@dataclass(frozen=True, slots=True)
class GroupById:
    """Ask for ``GET /groups/{id}`` — the one group an id names, or ``None``.

    A request of its own rather than a match against :class:`OwnGroups`. The id
    rung first shipped as a match against the unpaginated roster, which made
    *"pay the list only on the refusal path"* unbuildable — the roster WAS how a
    resolved id was told from a refused one — and ``list_groups`` counts members
    per row, so every UUID group verb paid an N+1 listing on the SUCCESS path.

    Answered with the ROW, on the same terms as :class:`SeatedByHandle`: the
    route returns a whole group and the ladder needs its handle.

    🔴 **``None`` covers 404 AND 403, and the ladder must not be able to tell
    them apart.** See :func:`group_read_refused`.
    """

    group_id: str


#: The statuses ``GET /groups/{id}`` answers with when this caller may not read
#: the group. Frozen as a set rather than spelled at each client, because the
#: two clients being able to disagree about it is the whole hazard this
#: constant exists for.
_UNREADABLE_GROUP_STATUSES = frozenset({403, 404})


def group_read_refused(error: RineApiError) -> bool:
    """Whether ``GET /groups/{id}`` declined to serve this caller the group.

    🔴 **404 and 403 answer the same, and that is a disclosure rule rather than
    a simplification.** The route 404s an id no group carries and 403s one
    belonging to an org this caller is neither owner of nor seated in
    (``has_read_access``, ``src/rine/api/group_scope.py``). Separating them
    would tell a stranger which unknown ids EXIST, which is the non-member
    lookup this stack refuses to offer — so both become ``None`` and one refusal
    is composed for both.

    ⚠️ Every other status is somebody else's business. A 500, a 429 or a
    transport fault is not *"no group of that id"*, and swallowing it here would
    tell a caller their reference was wrong about an outage.

    Args:
        error: What the read raised.

    Returns:
        ``True`` when the caller may not read that group, so the id rung falls
        through to its refusal; ``False`` when the error must be re-raised.
    """
    return error.status in _UNREADABLE_GROUP_STATUSES


def answered_group_id(row: dict[str, Any]) -> str | None:
    """The group id a ``GET /groups/{id}`` body names, or ``None`` for none.

    🔴 **A group id is a JSON string or it is absent, and this is the only place
    that decides which.** The refusal below is held byte-symmetric with
    TypeScript's, and ``str(x)`` agrees with JavaScript's ``String(x)`` on
    strings and on nothing else: ``False``/``false``, ``{}``/``[object
    Object]``, ``['x']``/``x``. Coercing whatever arrived would therefore
    compose a different sentence on each stack for the same body — and the
    producer here is a server answering badly, which is the whole premise.
    Anything that is not a string is reported as *no id* rather than rendered,
    exactly as ``readableGroupById`` does in ``rine-core/src/resolve-group.ts``.

    Args:
        row: The body the group route answered with.

    Returns:
        The id it named, or ``None`` when it named nothing usable.
    """
    named = row.get("id")
    return named if isinstance(named, str) else None


def refuse_a_substituted_group(asked: str, answered: str | None) -> None:
    """Refuse a ``GET /groups/{id}`` answer that names a group nobody asked about.

    🔴 **This is not defensive tidiness.** The UUID rung used to pass the
    caller's id straight through, so no server answer could stand in for the
    group it named. Now the body is what every group verb acts on — and five
    more surfaces route through this ladder — so a row naming another group
    would make all of them act on that group while the caller believed it had
    addressed its own.

    A :class:`~rine.errors.GroupIdentityMismatchError` and deliberately NOT the
    roster refusal :func:`~rine._group_ref.unknown_group_refusal` composes: no
    status said this, the fault is the server's, and answering it with *"Group
    not found"* would send a caller off to re-spell a reference that was right.
    TypeScript twin: ``readableGroupById`` in ``rine-core/src/resolve-group.ts``,
    byte-for-byte on the sentence.

    🔴 Takes the ANSWERED ID and not the row, so that
    :func:`rine._mls.api.read_group` — which holds a validated
    :class:`~rine.models.GroupRead` and once carried its own copy of this rule —
    shares it. That read is where the cost was measured: the id it returns
    scopes an MLS Welcome pass, so a substituted row withholds a Welcome this
    client REFUSED instead of raising it. What turns a body into an answered id
    is :func:`answered_group_id`.

    The comparison folds case, because the REQUEST does not: every group route
    types its path parameter ``group_id: uuid.UUID``, so an upper-cased id names
    the same group on the wire and the row comes back in the server's spelling.
    ``None`` is a mismatch rather than a :class:`TypeError`.

    Args:
        asked: The id the caller put on the path.
        answered: The id the server's answer named, or ``None`` for none.

    Raises:
        GroupIdentityMismatchError: The answer names a different group, or none.
    """
    if answered is None or answered.lower() != asked.lower():
        raise GroupIdentityMismatchError(asked, answered)


@dataclass(frozen=True, slots=True)
class SeatedByHandle:
    """Ask for ``GET /groups?handle=`` — an exact, key-scoped handle match.

    Answered with the ROW, not the id. The filter returns a whole group and the
    ladder needs the handle out of it: a rung that answered with an id alone
    made :class:`rine._recipient.GroupTarget` come back half-empty from a read
    that had already paid for the other half.
    """

    handle: str


@dataclass(frozen=True, slots=True)
class OwnAgents:
    """Ask for ``GET /agents`` — this org's agents, for the bare-name guard."""


@dataclass(frozen=True, slots=True)
class AgentIdFor:
    """Ask the agent namespace what a reference resolves to."""

    reference: str


LookupRequest = OwnGroups | GroupById | SeatedByHandle | OwnAgents | AgentIdFor
"""Every read a reference resolution can need — a closed set, on purpose.

A ladder that could ask for anything would be a client again. Five requests is
also the whole audit surface: no rung reaches the wire, so what a resolution can
COST is read off this union rather than traced through two client classes.
"""


@dataclass(frozen=True, slots=True)
class ReferenceReads:
    """The five reads, bound to a synchronous client."""

    own_groups: Callable[[], list[dict[str, Any]]]
    group_by_id: Callable[[str], dict[str, Any] | None]
    seated_by_handle: Callable[[str], dict[str, Any] | None]
    own_agents: Callable[[], list[dict[str, Any]]]
    agent_id_for: Callable[[str], str]


@dataclass(frozen=True, slots=True)
class AsyncReferenceReads:
    """The same five reads, bound to an asynchronous client.

    A second class rather than a generic one because the field NAMES are what
    :func:`_asked_for` dispatches on, and it dispatches over both in one body —
    so what is duplicated here is five type signatures and no logic, and the two
    clients cannot answer the same request differently.
    """

    own_groups: Callable[[], Awaitable[list[dict[str, Any]]]]
    group_by_id: Callable[[str], Awaitable[dict[str, Any] | None]]
    seated_by_handle: Callable[[str], Awaitable[dict[str, Any] | None]]
    own_agents: Callable[[], Awaitable[list[dict[str, Any]]]]
    agent_id_for: Callable[[str], Awaitable[str]]


def _asked_for(request: LookupRequest, reads: ReferenceReads | AsyncReferenceReads) -> Any:
    """Which read a request wants, called — a value, or a thing to await.

    The one mapping from request to read. Both drivers go through it, so a sixth
    request cannot be wired up for one client and forgotten for the other.
    """
    match request:
        case OwnGroups():
            return reads.own_groups()
        case GroupById(group_id=group_id):
            return reads.group_by_id(group_id)
        case SeatedByHandle(handle=handle):
            return reads.seated_by_handle(handle)
        case OwnAgents():
            return reads.own_agents()
        case AgentIdFor(reference=reference):
            return reads.agent_id_for(reference)


def walk(steps: Generator[LookupRequest, Any, _T], reads: ReferenceReads) -> _T:
    """Run a ladder against a synchronous client.

    🔴 Only the ``send`` is guarded. ``StopIteration`` out of the LADDER means
    the ladder answered; the same exception out of a READ means an iterator
    somewhere ran dry, and catching it here would report that as an answer of
    ``None`` — which the caller then dereferences a stack frame away from the
    cause. A read is any callable the client handed over, and a test double
    driven by ``side_effect=[...]`` raises exactly this.
    """
    answer: Any = None
    while True:
        try:
            request = steps.send(answer)
        except StopIteration as done:
            resolved: _T = done.value
            return resolved
        answer = _asked_for(request, reads)


async def walk_async(steps: Generator[LookupRequest, Any, _T], reads: AsyncReferenceReads) -> _T:
    """Run a ladder against an asynchronous client.

    The refusals a rung raises are ordinary exceptions and they propagate
    through the ``send`` below untouched, which is why no arm of this driver
    knows what a refusal says. The guard is as narrow as :func:`walk`'s, for the
    same reason: PEP 479 rewrites a ``StopIteration`` that escapes a coroutine,
    but the two drivers must refuse the same input in the same way rather than
    one of them being saved by the interpreter.
    """
    answer: Any = None
    while True:
        try:
            request = steps.send(answer)
        except StopIteration as done:
            resolved: _T = done.value
            return resolved
        answer = await _asked_for(request, reads)


def note_group_id_recipient(reference: str, handle: str) -> None:
    """Say that a UUID recipient was read as a group, not as an agent.

    A group's own id addresses the group, and a UUID is the one spelling
    that reaches both namespaces — so a caller who believed it held an agent id
    would otherwise have a message sealed to every member org of a group with
    nothing said about it. No silent acceptance: the substitution is announced
    wherever it is made.

    Quotes the caller's own spelling and the handle it resolved to, and nothing
    else. A third handle in this sentence, or an ``@org`` slot the caller never
    typed, is how the template-org rule gets broken.

    It lives here, beside the walk, for the reason the module docstring gives:
    the two clients hold no copy of a rung, a fallback, a refusal — and none of
    this sentence either. It is deliberately NOT hoisted into ``rine-core``'s
    shared prose; each surface says it in its own idiom, and this one's idiom is
    the ``rine`` logger, because a library that writes to stderr behind its
    caller's back is a library that cannot be embedded.
    """
    logger.warning(
        "%r is a group id, so this was addressed to the group %r, not to an agent.",
        reference,
        handle,
    )


__all__ = [
    "AgentIdFor",
    "AsyncReferenceReads",
    "GroupById",
    "LookupRequest",
    "OwnAgents",
    "OwnGroups",
    "ReferenceReads",
    "SeatedByHandle",
    "answered_group_id",
    "group_read_refused",
    "note_group_id_recipient",
    "refuse_a_substituted_group",
    "walk",
    "walk_async",
]
