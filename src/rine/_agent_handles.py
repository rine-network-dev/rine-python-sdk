"""How a row spells one of the caller's own agents, and where that spelling lives.

``member_agent_ids`` is a list of UUIDs on the wire and stays one: it is the
identity the server keyed the seat under, both SDKs validate it as UUID-shaped,
and nothing here writes into it. What a *model* reads, though, is a row — and a
row of raw UUIDs has to be joined against ``rine_whoami`` before it names
anybody. This module builds the map that lets a row spell those ids the way the
model already knows them, and attaches it **beside** the model rather than on
it. The refusal that stops an unseated Sender Keys send spells its seats from
the same map, built the same way, and gets it from
:func:`agent_handles_from_http` because it holds no client to memoise one.

"Beside" is literal, and it is what makes "no wire change" enforceable rather
than aspirational. The map lands on a pydantic PRIVATE attribute of
:class:`rine.types.GroupRead`, which by construction is absent from
``model_dump``, ``model_dump_json``, the JSON schema and ``model_fields_set``.
So a client-side enrichment cannot be serialised back out, cannot be mistaken
for something the server said, and — the one that matters — cannot disturb
:func:`rine._group_send.refuse_if_not_seated`, whose whole guard is the
difference between an omitted ``member_agent_ids`` and an empty one.

The spelling is the **handle**, never the bare name.
``src/rine/api/agent_identity.py`` refuses a non-UUID ``X-Rine-Agent`` that
carries no ``@``, so a printed handle is a value every surface can hand
straight back — including ``rine-mcp``, ``rine-openclaw`` and any raw HTTP
caller, none of which reach this SDK's actor ladder. A printed bare name would
be pasteable on some surfaces and a 422 on others.

The lookup is total in a healthy org: ``member_agent_ids`` is the org's own
non-revoked seated agents and ``GET /agents`` returns every non-revoked agent
of the org, unpaginated, so the first set is a subset of the second. That is
why the fallback lives around the FETCH rather than around each id — the case
worth handling is "the agent list could not be read at all", not "this id is a
stranger".
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from rine.types import GroupRead

logger = logging.getLogger(__name__)


def agent_handle_map(agents: Iterable[dict[str, Any]]) -> dict[UUID, str]:
    """``GET /agents`` as a UUID-to-handle map.

    Args:
        agents: The agent dicts ``_fetch_agents`` returns.

    Returns:
        One entry per agent that carries both a parseable id and a handle. An
        agent the server answered oddly is dropped rather than guessed at:
        anything the map does not answer for renders as its UUID, so a missing
        entry costs one name and never the row.
    """
    mapped: dict[UUID, str] = {}
    for agent in agents:
        handle = str(agent.get("handle") or "")
        if not handle:
            continue
        try:
            mapped[UUID(str(agent.get("id")))] = handle
        except (TypeError, ValueError):
            continue
    return mapped


def agent_handles_from_http(http: Any) -> dict[UUID, str]:
    """The same map, read straight off the wire rather than off a client.

    The labellers below spell a group *listing* and read the SDK client's
    memoised agent list. This spells a *refusal*, and it reads the wire because
    :func:`rine._group_send.refuse_if_not_seated` is reached holding the raw
    HTTP client and no SDK client at all. That is true on **both** stacks — the
    async client runs the same sync send path on a worker thread against a
    short-lived ``SyncHttpClient`` (:func:`rine._mls.bridge.with_sync_http`),
    whose ``_fetch_agents`` is a coroutine it cannot await from there — so
    putting the fetch beside the refusal is what makes the two clients spell
    that refusal identically instead of only the sync one.

    It is called at the moment the refusal is composed and never on a send that
    goes through, so a successful send pays nothing for it. What it costs a
    refusal is one request on a client that has just completed ``GET /groups``
    under the same timeout and the same retry ladder — reachability is already
    established by the time this is reached, which is why the sentence cannot
    be left waiting on a server the caller has not already heard from.

    Nothing here fails loudly. The caller is already raising the one sentence
    its operator can act on, and a courtesy lookup that turned that into a
    connection error would take it away.

    Args:
        http: The sync HTTP client this call is already using.

    Returns:
        One entry per agent carrying both a parseable id and a handle; an empty
        map for every failure, which renders as the UUIDs the server sent —
        the same degradation an unlabelled row makes.
    """
    try:
        data = http.get("/agents")
        items = data.get("items", data) if isinstance(data, dict) else data
        return agent_handle_map(items)
    except Exception:
        logger.debug("Could not spell the refused group's seats as handles", exc_info=True)
        return {}


def _seats_to_spell(groups: Sequence[GroupRead]) -> bool:
    """Whether any of these groups names a seat at all.

    Asked before the fetch, not after: ``_fetch_agents`` is memoised for the
    life of the client, but a client whose first call is a group list holding no
    seats would still pay for the first one. Nothing is spelled here, so nothing
    is fetched.
    """
    return any(g.member_agent_ids for g in groups)


def label_own_agents_sync(client: Any, groups: Sequence[GroupRead]) -> None:
    """Attach the org's handle map to every group that names a seat (sync).

    Args:
        client: The SDK client, for its memoised ``_fetch_agents``.
        groups: The groups this call just validated. Mutated in place; they are
            this call's own objects and nothing else holds them yet.
    """
    if not _seats_to_spell(groups):
        return
    try:
        handles = agent_handle_map(client._fetch_agents())
    except Exception:
        # Every failure, deliberately: an unreadable agent list must degrade a
        # row to UUIDs, which are still real and still usable, rather than turn
        # a group listing into an error. The reason is logged rather than
        # raised because the caller asked for groups, not for agents.
        logger.debug("Could not spell own agents as handles", exc_info=True)
        return
    for group in groups:
        group._own_agent_handles = handles


async def label_own_agents_async(client: Any, groups: Sequence[GroupRead]) -> None:
    """Attach the org's handle map to every group that names a seat (async).

    The sync twin's contract, on the async client. See
    :func:`label_own_agents_sync`.

    Args:
        client: The SDK client, for its memoised ``_fetch_agents``.
        groups: The groups this call just validated, mutated in place.
    """
    if not _seats_to_spell(groups):
        return
    try:
        handles = agent_handle_map(await client._fetch_agents())
    except Exception:
        logger.debug("Could not spell own agents as handles", exc_info=True)
        return
    for group in groups:
        group._own_agent_handles = handles


__all__ = [
    "agent_handle_map",
    "agent_handles_from_http",
    "label_own_agents_async",
    "label_own_agents_sync",
]
