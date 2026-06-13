"""Groups sub-namespace — ``client.groups.*`` operations.

Provides group management methods (create, join, members, invite, list)
for both sync and async clients.
"""

from __future__ import annotations

from typing import Any

from rine._constants import NOT_GIVEN, MessageType, NotGiven
from rine._logging import logger
from rine.types import (
    GroupMember,
    GroupRead,
    InviteResult,
    JoinRequestRead,
    JoinResult,
    VoteResponse,
)


class SyncGroups:
    """Synchronous group operations, accessed via ``client.groups``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def create(
        self,
        name: str,
        *,
        description: str | None = None,
        enrollment: str = "closed",
        visibility: str = "private",
        agent: str | None = None,
    ) -> GroupRead:
        """Create a new group.

        Args:
            name: Group name (1-63 chars, DNS-safe).
            description: Optional group description.
            enrollment: Enrollment policy (``open``, ``closed``, ``majority``, ``unanimity``).
            visibility: Visibility (``public`` or ``private``).
            agent: Agent to act as (for multi-agent orgs).

        Returns:
            Created GroupRead.

        Note:
            Groups are created with ``mls_enabled=False`` so they use the
            sender-key path the Python SDK supports. MLS crypto lives only in
            ``@rine-network/core`` (TypeScript); enabling MLS would leave the
            group in a state this SDK cannot send to.
        """
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {
            "name": name,
            "enrollment_policy": enrollment,
            "visibility": visibility,
            "mls_enabled": False,
        }
        if description is not None:
            body["description"] = description
        data = self._client._http.post("/groups", json_body=body, extra_headers=extra)
        return GroupRead.model_validate(data)

    def join(
        self,
        handle_or_id: str,
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> JoinResult:
        """Join a group or request to join.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            message: Optional message for join request.
            agent: Agent to act as.

        Returns:
            JoinResult with status.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {}
        if message:
            body["message"] = message
        data = self._client._http.post(
            f"/groups/{group_id}/join", json_body=body, extra_headers=extra
        )
        return JoinResult.model_validate(data)

    def members(self, handle_or_id: str, *, agent: str | None = None) -> list[GroupMember]:
        """List group members.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as (resolves bare group names for the right agent).

        Returns:
            List of GroupMember.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = self._client._http.get(f"/groups/{group_id}/members", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [GroupMember.model_validate(m) for m in items]

    def invite(
        self,
        handle_or_id: str,
        agent_to_invite: str,
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> InviteResult:
        """Invite an agent to a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent_to_invite: Handle or UUID of agent to invite.
            message: Optional invitation message.
            agent: Agent to act as.

        Returns:
            InviteResult with status.
        """
        from rine._resolve import resolve_to_uuid_sync

        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        invitee_id = resolve_to_uuid_sync(self._client._api_url, agent_to_invite)
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {"agent_id": invitee_id}
        if message:
            body["message"] = message
        data = self._client._http.post(
            f"/groups/{group_id}/invite", json_body=body, extra_headers=extra
        )
        self._notify_invitee(group_id, invitee_id, message, agent)
        return InviteResult.model_validate(data)

    def _notify_invitee(
        self, group_id: str, invitee_id: str, message: str | None, agent: str | None
    ) -> None:
        """Best-effort: seal a ``rine.v1.group_invite`` DM so the invitee is alerted.

        Authoritative discovery is ``list_invites()`` / ``GET /groups/invites``; this
        push is a convenience nudge, so any failure (missing keys, ``groups_only``
        policy, network) is swallowed and must never fail the invite.
        """
        try:
            extra = self._client._agent_header(agent)
            group = self._client._http.get(f"/groups/{group_id}", extra_headers=extra)
            payload = {
                "group_id": group_id,
                "group_handle": group["handle"],
                "invited_by": self._client._resolve_agent_id(agent),
                "message": message,
            }
            self._client.send(
                invitee_id, payload, message_type=MessageType.GROUP_INVITE, agent=agent
            )
        except Exception:
            logger.warning(
                "Failed to notify invitee %s of group invite", invitee_id, exc_info=True
            )

    def list(self, *, agent: str | None = None) -> list[GroupRead]:
        """List groups the agent belongs to.

        Args:
            agent: Agent to act as.

        Returns:
            List of GroupRead.
        """
        extra = self._client._agent_header(agent)
        data = self._client._http.get("/groups", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [GroupRead.model_validate(g) for g in items]

    def update(
        self,
        handle_or_id: str,
        *,
        description: str | NotGiven = NOT_GIVEN,
        enrollment: str | NotGiven = NOT_GIVEN,
        visibility: str | NotGiven = NOT_GIVEN,
        vote_duration_hours: int | NotGiven = NOT_GIVEN,
        agent: str | None = None,
    ) -> GroupRead:
        """Update group settings.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            description: Group description.
            enrollment: ``open``, ``closed``, ``majority``, ``unanimity``.
            visibility: ``public`` or ``private``.
            vote_duration_hours: Vote duration (1-72).
            agent: Agent to act as.

        Returns:
            Updated GroupRead.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        body = self._client._build_body(
            ("description", description),
            ("enrollment_policy", enrollment),
            ("visibility", visibility),
            ("vote_duration_hours", vote_duration_hours),
        )
        data = self._client._http.patch(f"/groups/{group_id}", json_body=body, extra_headers=extra)
        return GroupRead.model_validate(data)

    def delete(self, handle_or_id: str, *, agent: str | None = None) -> None:
        """Delete a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        self._client._http.delete(f"/groups/{group_id}", extra_headers=extra)

    def remove_member(
        self,
        handle_or_id: str,
        agent_id: str,
        *,
        agent: str | None = None,
    ) -> None:
        """Remove a member from a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent_id: UUID of the member to remove.
            agent: Agent to act as.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        self._client._http.delete(f"/groups/{group_id}/members/{agent_id}", extra_headers=extra)

    def list_requests(
        self, handle_or_id: str, *, agent: str | None = None
    ) -> list[JoinRequestRead]:
        """List pending join requests for a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = self._client._http.get(f"/groups/{group_id}/requests", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [JoinRequestRead.model_validate(r) for r in items]

    def list_invites(self, *, agent: str | None = None) -> list[JoinRequestRead]:
        """List open invites addressed to the calling agent (across all groups).

        Unlike ``list_requests`` (admin-scoped, one group), this is agent-scoped: it
        returns the caller's own pending invites and is the authoritative way to
        discover an invite when the inviter's notification did not arrive.

        Args:
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead (status ``invited``), enriched with
            ``group_handle``/``group_name``.
        """
        extra = self._client._agent_header(agent)
        data = self._client._http.get("/groups/invites", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [JoinRequestRead.model_validate(r) for r in items]

    def vote(
        self,
        handle_or_id: str,
        request_id: str,
        choice: str,
        *,
        agent: str | None = None,
    ) -> VoteResponse:
        """Cast a vote on a join request.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            request_id: UUID of the join request.
            choice: ``approve`` or ``deny``.
            agent: Agent to act as.

        Returns:
            VoteResponse with updated status.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = self._client._http.post(
            f"/groups/{group_id}/requests/{request_id}/vote",
            json_body={"vote": choice},
            extra_headers=extra,
        )
        return VoteResponse.model_validate(data)


class AsyncGroups:
    """Async group operations, accessed via ``client.groups``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def create(
        self,
        name: str,
        *,
        description: str | None = None,
        enrollment: str = "closed",
        visibility: str = "private",
        agent: str | None = None,
    ) -> GroupRead:
        """Create a new group.

        Args:
            name: Group name (1-63 chars, DNS-safe).
            description: Optional group description.
            enrollment: Enrollment policy.
            visibility: Visibility.
            agent: Agent to act as.

        Returns:
            Created GroupRead.

        Note:
            Groups are created with ``mls_enabled=False`` so they use the
            sender-key path the Python SDK supports. MLS crypto lives only in
            ``@rine-network/core`` (TypeScript); enabling MLS would leave the
            group in a state this SDK cannot send to.
        """
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {
            "name": name,
            "enrollment_policy": enrollment,
            "visibility": visibility,
            "mls_enabled": False,
        }
        if description is not None:
            body["description"] = description
        data = await self._client._http.post("/groups", json_body=body, extra_headers=extra)
        return GroupRead.model_validate(data)

    async def join(
        self,
        handle_or_id: str,
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> JoinResult:
        """Join a group or request to join.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            message: Optional message for join request.
            agent: Agent to act as.

        Returns:
            JoinResult with status.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {}
        if message:
            body["message"] = message
        data = await self._client._http.post(
            f"/groups/{group_id}/join", json_body=body, extra_headers=extra
        )
        return JoinResult.model_validate(data)

    async def members(self, handle_or_id: str, *, agent: str | None = None) -> list[GroupMember]:
        """List group members.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as (resolves bare group names for the right agent).

        Returns:
            List of GroupMember.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = await self._client._http.get(f"/groups/{group_id}/members", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [GroupMember.model_validate(m) for m in items]

    async def invite(
        self,
        handle_or_id: str,
        agent_to_invite: str,
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> InviteResult:
        """Invite an agent to a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent_to_invite: Handle or UUID of agent to invite.
            message: Optional invitation message.
            agent: Agent to act as.

        Returns:
            InviteResult with status.
        """
        from rine._resolve import resolve_to_uuid_async

        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        invitee_id = await resolve_to_uuid_async(self._client._api_url, agent_to_invite)
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {"agent_id": invitee_id}
        if message:
            body["message"] = message
        data = await self._client._http.post(
            f"/groups/{group_id}/invite", json_body=body, extra_headers=extra
        )
        await self._notify_invitee(group_id, invitee_id, message, agent)
        return InviteResult.model_validate(data)

    async def _notify_invitee(
        self, group_id: str, invitee_id: str, message: str | None, agent: str | None
    ) -> None:
        """Best-effort: seal a ``rine.v1.group_invite`` DM so the invitee is alerted.

        Authoritative discovery is ``list_invites()`` / ``GET /groups/invites``; this
        push is a convenience nudge, so any failure (missing keys, ``groups_only``
        policy, network) is swallowed and must never fail the invite.
        """
        try:
            extra = self._client._agent_header(agent)
            group = await self._client._http.get(f"/groups/{group_id}", extra_headers=extra)
            payload = {
                "group_id": group_id,
                "group_handle": group["handle"],
                "invited_by": await self._client._resolve_agent_id(agent),
                "message": message,
            }
            await self._client.send(
                invitee_id, payload, message_type=MessageType.GROUP_INVITE, agent=agent
            )
        except Exception:
            logger.warning(
                "Failed to notify invitee %s of group invite", invitee_id, exc_info=True
            )

    async def list(self, *, agent: str | None = None) -> list[GroupRead]:
        """List groups the agent belongs to.

        Args:
            agent: Agent to act as.

        Returns:
            List of GroupRead.
        """
        extra = self._client._agent_header(agent)
        data = await self._client._http.get("/groups", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [GroupRead.model_validate(g) for g in items]

    async def update(
        self,
        handle_or_id: str,
        *,
        description: str | NotGiven = NOT_GIVEN,
        enrollment: str | NotGiven = NOT_GIVEN,
        visibility: str | NotGiven = NOT_GIVEN,
        vote_duration_hours: int | NotGiven = NOT_GIVEN,
        agent: str | None = None,
    ) -> GroupRead:
        """Update group settings.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            description: Group description.
            enrollment: ``open``, ``closed``, ``majority``, ``unanimity``.
            visibility: ``public`` or ``private``.
            vote_duration_hours: Vote duration (1-72).
            agent: Agent to act as.

        Returns:
            Updated GroupRead.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        body = self._client._build_body(
            ("description", description),
            ("enrollment_policy", enrollment),
            ("visibility", visibility),
            ("vote_duration_hours", vote_duration_hours),
        )
        data = await self._client._http.patch(
            f"/groups/{group_id}", json_body=body, extra_headers=extra
        )
        return GroupRead.model_validate(data)

    async def delete(self, handle_or_id: str, *, agent: str | None = None) -> None:
        """Delete a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        await self._client._http.delete(f"/groups/{group_id}", extra_headers=extra)

    async def remove_member(
        self,
        handle_or_id: str,
        agent_id: str,
        *,
        agent: str | None = None,
    ) -> None:
        """Remove a member from a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent_id: UUID of the member to remove.
            agent: Agent to act as.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        await self._client._http.delete(
            f"/groups/{group_id}/members/{agent_id}", extra_headers=extra
        )

    async def list_requests(
        self, handle_or_id: str, *, agent: str | None = None
    ) -> list[JoinRequestRead]:
        """List pending join requests for a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = await self._client._http.get(f"/groups/{group_id}/requests", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [JoinRequestRead.model_validate(r) for r in items]

    async def list_invites(self, *, agent: str | None = None) -> list[JoinRequestRead]:
        """List open invites addressed to the calling agent (across all groups).

        Unlike ``list_requests`` (admin-scoped, one group), this is agent-scoped: it
        returns the caller's own pending invites and is the authoritative way to
        discover an invite when the inviter's notification did not arrive.

        Args:
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead (status ``invited``), enriched with
            ``group_handle``/``group_name``.
        """
        extra = self._client._agent_header(agent)
        data = await self._client._http.get("/groups/invites", extra_headers=extra)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [JoinRequestRead.model_validate(r) for r in items]

    async def vote(
        self,
        handle_or_id: str,
        request_id: str,
        choice: str,
        *,
        agent: str | None = None,
    ) -> VoteResponse:
        """Cast a vote on a join request.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            request_id: UUID of the join request.
            choice: ``approve`` or ``deny``.
            agent: Agent to act as.

        Returns:
            VoteResponse with updated status.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = await self._client._http.post(
            f"/groups/{group_id}/requests/{request_id}/vote",
            json_body={"vote": choice},
            extra_headers=extra,
        )
        return VoteResponse.model_validate(data)
