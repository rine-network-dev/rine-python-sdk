"""Leaving a group, under the name a reader looks for.

Departure and eviction were the same call until now: a member left by invoking
:meth:`remove_member` on itself, so an operator searching this SDK for "leave"
found nothing, and nothing watching the API surface could tell a departure from
being thrown out. The mechanics are unchanged — this resolves who is acting and
hands the same removal the same work — so there is one removal path, not two.

The acting agent is resolved **strictly**: :mod:`rine._resources.group_members`
degrades on an unresolvable actor and attempts the removal anyway, which is
right for a kick, because the server has its own opinion about who may remove
whom. A leave has no such fallback. An org with two active agents and no
``agent`` named cannot say *whose* departure this is, the server reads the call
as a kick, and an MLS group refuses a kick until a Remove commit is posted that
nobody can mint for their own removal. So the resolution error is left to
propagate rather than caught.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._resources.group_members import remove_group_member, remove_group_member_async

if TYPE_CHECKING:
    from rine.group_removal import GroupRemovalResult


def leave_group(client: Any, handle_or_id: str, *, agent: str | None) -> GroupRemovalResult:
    """Leave a group as the acting agent (sync).

    Args:
        client: The sync client.
        handle_or_id: Group handle, bare name, or UUID.
        agent: Which agent is leaving. Required of an org with more than one
            active agent; a single-agent org resolves without it.

    Returns:
        What the departure did, in the same shape a removal answers with.
    """
    acting_agent_id = client._resolve_agent_id(agent)
    return remove_group_member(client, handle_or_id, acting_agent_id, agent=agent)


async def leave_group_async(
    client: Any, handle_or_id: str, *, agent: str | None
) -> GroupRemovalResult:
    """Async counterpart of :func:`leave_group`.

    Args:
        client: The async client.
        handle_or_id: Group handle, bare name, or UUID.
        agent: Which agent is leaving. Required of an org with more than one
            active agent; a single-agent org resolves without it.

    Returns:
        What the departure did, in the same shape a removal answers with.
    """
    acting_agent_id = await client._resolve_agent_id(agent)
    return await remove_group_member_async(client, handle_or_id, acting_agent_id, agent=agent)


__all__ = ["leave_group", "leave_group_async"]
