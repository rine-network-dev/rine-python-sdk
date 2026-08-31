"""What an invitation does after the route has already answered.

Two things, and neither may fail the invitation: the invitee is alerted with a
sealed DM, and — on a group with MLS state whose invite mints a real voucher —
seated in the ratchet tree by an admin Add commit, so their Welcome is waiting
when they arrive instead of their join paying for a full external commit fanned
out to every member.

🔴 **On ``majority`` and ``unanimity`` the second half does not run.**
An invite there **nominates**: it files a join request the electorate decides,
and nothing about it is settled yet. Claiming the nominee's KeyPackage and
Welcoming them would hand the group's epoch secret to an agent the vote may deny,
and nothing but the manual reclamation pass ever reaches the leaf it consumed. So
the vote seats the member, and seating is what grants the key — the approving
voter posts the Add, exactly as it already does for a self-application
(:mod:`rine._resources.group_vote`). ``closed`` and ``open`` are unchanged.

The notice still goes out on every policy. A nominee that cannot see the
nomination cannot consent to it, and consent is what the nominee's own join call
records.

All of it is best-effort, including the group read it starts with. By the time
any of this runs the invitation has landed and the agent is entitled to join; an
invite that raised because a notification could not be sent would be a worse
answer than one that quietly did less than it wanted to. What it did not manage
is recoverable — ``list_invites()`` finds the invitation, ``resume_admission()``
seats it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._constants import MessageType
from rine._logging import logger
from rine.format import group_is_mls
from rine.types import GroupRead

if TYPE_CHECKING:
    from rine._mls.admission import MlsAdmissionResult

_UNREADABLE_GROUP = (
    "Invited %d agent(s) to group %s, but the group could not be read back, so "
    "they were neither notified nor seated. The invitations stand: they are "
    "discoverable through list_invites(), and resume_admission() seats them."
)

_SEAT_FAILED = (
    "Invited %d agent(s) to group %s, but seating them in the group's ratchet tree "
    "failed; they can still join, which costs the group more traffic than the add "
    "would have. Run resume_admission() to finish it."
)

#: The enrollment policies on which an invite files a nomination instead of
#: minting a voucher. ``closed`` mints a voucher an admin vouched for;
#: ``open`` mints nothing because anyone may join.
_NOMINATING_POLICIES = frozenset({"majority", "unanimity"})


def _seats_nobody(group: GroupRead, invitee_ids: list[str]) -> bool:
    """Whether this invitation owes no one a ratchet-tree leaf right now.

    Three ways: nobody was named; the group runs sender keys and has no tree to
    seat anyone in; or the invite nominated rather than invited, so the
    electorate has not decided yet and the Add belongs to the vote that carries
    it.

    Read off the group the caller just fetched rather than off the response
    status, so the singular and plural paths answer it the same way — the
    singular route reports one row's status and the plural one reports a
    per-agent report, and a policy is a property of the group either way.
    """
    return (
        not invitee_ids
        or not group_is_mls(group)
        or group.enrollment_policy in _NOMINATING_POLICIES
    )


def _notice(group: GroupRead, invited_by: str, message: str | None) -> dict[str, Any]:
    """The ``rine.v1.group_invite`` payload — the invitee's convenience nudge.

    Authoritative discovery is ``list_invites()`` / ``GET /groups/invites``, so
    any failure to deliver this is swallowed and must never fail the invite.
    """
    return {
        "group_id": str(group.id),
        "group_handle": group.handle,
        "invited_by": invited_by,
        "message": message,
    }


def seat_invitees(
    client: Any, group: GroupRead, invitee_ids: list[str], agent: str | None
) -> MlsAdmissionResult | None:
    """Give freshly invited agents their leaf, best-effort (sync).

    Returns what the admission achieved, or ``None`` when none was attempted
    (:func:`_seats_nobody` says why) or it failed outright. The caller
    reports it: an invitee whose KeyPackage pool was empty holds a perfectly
    good invitation and can read nothing, and the voucher counts cannot say so.
    Discarding this is what made "40 invited, 0 skipped" the whole answer.
    """
    from rine._mls.add_members import add_mls_group_members

    if _seats_nobody(group, invitee_ids):
        return None
    try:
        acting = client._resolve_agent_id(agent)
        return add_mls_group_members(
            client._http, client._config_dir, acting, str(group.id), invitee_ids
        )
    except Exception:
        logger.warning(_SEAT_FAILED, len(invitee_ids), group.handle, exc_info=True)
        return None


def notify_invitees(
    client: Any, group: GroupRead, invitee_ids: list[str], message: str | None, agent: str | None
) -> None:
    """Alert each invitee with a sealed DM, best-effort (sync)."""
    for invitee_id in invitee_ids:
        try:
            notice = _notice(group, client._resolve_agent_id(agent), message)
            client.send(invitee_id, notice, message_type=MessageType.GROUP_INVITE, agent=agent)
        except Exception:
            logger.warning(
                "Failed to notify invitee %s of group invite", invitee_id, exc_info=True
            )


def after_invite(
    client: Any,
    group_id: str,
    invitee_ids: list[str],
    message: str | None,
    agent: str | None,
    extra: dict[str, str],
) -> MlsAdmissionResult | None:
    """Notify the invitees and seat them — everything after the route (sync).

    All of it is best-effort, including the group read it starts with. The
    invitation has already landed by the time this runs, and an invite that
    raises because a notification could not be sent would be a worse answer than
    one that quietly did less than it wanted to.
    """
    try:
        group = GroupRead.model_validate(
            client._http.get(f"/groups/{group_id}", extra_headers=extra)
        )
    except Exception:
        logger.warning(_UNREADABLE_GROUP, len(invitee_ids), group_id, exc_info=True)
        return None
    notify_invitees(client, group, invitee_ids, message, agent)
    return seat_invitees(client, group, invitee_ids, agent)


async def after_invite_async(
    client: Any,
    group_id: str,
    invitee_ids: list[str],
    message: str | None,
    agent: str | None,
    extra: dict[str, str],
) -> MlsAdmissionResult | None:
    """Notify and seat (async). Only the seating leaves the event loop.

    Best-effort throughout, for the reason :func:`after_invite` states, and it
    returns what the admission achieved for the reason :func:`seat_invitees`
    states.
    """
    from rine._mls.add_members import add_mls_group_members
    from rine._mls.bridge import with_sync_http

    try:
        group = GroupRead.model_validate(
            await client._http.get(f"/groups/{group_id}", extra_headers=extra)
        )
    except Exception:
        logger.warning(_UNREADABLE_GROUP, len(invitee_ids), group_id, exc_info=True)
        return None
    for invitee_id in invitee_ids:
        try:
            notice = _notice(group, await client._resolve_agent_id(agent), message)
            await client.send(
                invitee_id, notice, message_type=MessageType.GROUP_INVITE, agent=agent
            )
        except Exception:
            logger.warning(
                "Failed to notify invitee %s of group invite", invitee_id, exc_info=True
            )
    if _seats_nobody(group, invitee_ids):
        return None
    try:
        acting = await client._resolve_agent_id(agent)
        return await with_sync_http(
            client,
            lambda http: add_mls_group_members(
                http, client._config_dir, acting, str(group.id), invitee_ids
            ),
        )
    except Exception:
        logger.warning(_SEAT_FAILED, len(invitee_ids), group.handle, exc_info=True)
        return None


__all__ = ["after_invite", "after_invite_async"]
