"""Inviting agents — one at a time, or a batch, on one route.

The plural form is a **field on the existing route**, not a sibling route: a
second handler would have to carry a second copy of the whole authorization
ladder, and the two would have to be kept from diverging forever. The response
shape follows the field the caller used, so the singular form answers exactly
what it always answered.

An invitation into a group with MLS state is followed by an admin **Add
commit**, so the invitee's Welcome is waiting when they arrive instead of their
join paying for a full external commit fanned out to every member. That add is
deliberately best-effort: the voucher is what entitles them, and a failed add
leaves the joiner-paid path Python has always used. It is the one place this SDK
spends the inviter's bandwidth on the invitee's behalf, which is why it says so
rather than doing it silently.

On ``majority`` and ``unanimity`` the same route **nominates** instead: it files
a join request for the electorate to decide, and no commit follows it
(:mod:`rine._resources.group_invite_effects` holds that gate and the reason for
it). The notice still goes out, because the nominee's own join call is what
records their consent.
"""

from __future__ import annotations

from typing import Any

from rine._resources.group_invite_effects import after_invite, after_invite_async
from rine.admission_words import admitted_agent_ids
from rine.group_admission import GroupInviteReport
from rine.types import InviteResult


def _invite_body(message: str | None, **target: Any) -> dict[str, Any]:
    body: dict[str, Any] = dict(target)
    if message:
        body["message"] = message
    return body


def _singular_result(data: Any) -> InviteResult:
    """The row a singular invite answered with, whichever kind it minted.

    A voucher and a nomination are both request rows and both carry their id in
    ``id``; ``status`` is what tells them apart, so it is passed through rather
    than interpreted here. An open group mints neither and reports no id.
    """
    return InviteResult(status=data["status"], request_id=data.get("id"))


def invite_agent(
    client: Any, handle_or_id: str, agent_to_invite: str, *, message: str | None, agent: str | None
) -> InviteResult:
    """Invite one agent (sync). See ``SyncGroups.invite``."""
    from rine._resolve import resolve_to_uuid_sync

    group_id = client._resolve_group_sync(handle_or_id, agent)
    invitee_id = resolve_to_uuid_sync(client._api_url, agent_to_invite)
    extra = client._agent_header(agent)
    data = client._http.post(
        f"/groups/{group_id}/invite",
        json_body=_invite_body(message, agent_id=invitee_id),
        extra_headers=extra,
    )
    after_invite(client, group_id, [invitee_id], message, agent, extra)
    return _singular_result(data)


def invite_agents(
    client: Any, handle_or_id: str, agents: list[str], *, message: str | None, agent: str | None
) -> GroupInviteReport:
    """Invite a batch (sync). See ``SyncGroups.invite_many``."""
    from rine._resolve import resolve_to_uuid_sync

    group_id = client._resolve_group_sync(handle_or_id, agent)
    invitee_ids = [resolve_to_uuid_sync(client._api_url, a) for a in agents]
    extra = client._agent_header(agent)
    report = GroupInviteReport.model_validate(
        client._http.post(
            f"/groups/{group_id}/invite",
            json_body=_invite_body(message, agent_ids=invitee_ids),
            extra_headers=extra,
        )
    )
    mls = after_invite(client, group_id, admitted_agent_ids(report), message, agent, extra)
    return report.model_copy(update={"mls": mls})


async def invite_agent_async(
    client: Any, handle_or_id: str, agent_to_invite: str, *, message: str | None, agent: str | None
) -> InviteResult:
    """Invite one agent (async)."""
    from rine._resolve import resolve_to_uuid_async

    group_id = await client._resolve_group_async(handle_or_id, agent)
    invitee_id = await resolve_to_uuid_async(client._api_url, agent_to_invite)
    extra = await client._agent_header(agent)
    data = await client._http.post(
        f"/groups/{group_id}/invite",
        json_body=_invite_body(message, agent_id=invitee_id),
        extra_headers=extra,
    )
    await after_invite_async(client, group_id, [invitee_id], message, agent, extra)
    return _singular_result(data)


async def invite_agents_async(
    client: Any, handle_or_id: str, agents: list[str], *, message: str | None, agent: str | None
) -> GroupInviteReport:
    """Invite a batch (async)."""
    from rine._resolve import resolve_to_uuid_async

    group_id = await client._resolve_group_async(handle_or_id, agent)
    invitee_ids = [await resolve_to_uuid_async(client._api_url, a) for a in agents]
    extra = await client._agent_header(agent)
    report = GroupInviteReport.model_validate(
        await client._http.post(
            f"/groups/{group_id}/invite",
            json_body=_invite_body(message, agent_ids=invitee_ids),
            extra_headers=extra,
        )
    )
    invited = admitted_agent_ids(report)
    mls = await after_invite_async(client, group_id, invited, message, agent, extra)
    return report.model_copy(update={"mls": mls})


__all__ = [
    "invite_agent",
    "invite_agent_async",
    "invite_agents",
    "invite_agents_async",
]
