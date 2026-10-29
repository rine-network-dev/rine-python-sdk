"""Groups sub-namespace — ``client.groups.*`` operations.

Provides group management methods (create, join, members, invite, list)
for both sync and async clients.

Decisions rather than routes — re-reading a created group, telling a leave from a
kick — live in :mod:`rine._resources.group_ops`, one answer for sync and async.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # `list` is a method on both resource classes below, which shadows the builtin
    # for every annotation that follows it in the class body. Annotations after that
    # point name `builtins.list` so they still mean the type. Annotations are lazy
    # here (`from __future__ import annotations`), so this never has to exist at run time.
    import builtins

    from rine._group_recovery import GroupRecoveryResult
    from rine._mls.admission import MlsAdmissionResult
    from rine.format import UnfoundedGroupRepair
    from rine.group_removal import GroupRemovalResult

from rine._agent_handles import label_own_agents_async, label_own_agents_sync
from rine._constants import NOT_GIVEN, NotGiven
from rine._resources.group_invites import (
    invite_agent,
    invite_agent_async,
    invite_agents,
    invite_agents_async,
)
from rine._resources.group_leave import leave_group, leave_group_async
from rine._resources.group_members import (
    remove_group_member,
    remove_group_member_async,
)
from rine._resources.group_ops import create_group, create_group_async, unwrap_items
from rine._resources.group_resume import resume_admission, resume_admission_async
from rine._resources.group_sync import sync_group_state, sync_group_state_async
from rine._resources.group_vote import vote_on_request, vote_on_request_async
from rine.errors import ConflictError
from rine.group_admission import (
    GroupCreateWithRoster,
    GroupInviteReport,
    OutstandingFilter,
)
from rine.types import (
    GroupMember,
    GroupRead,
    InviteResult,
    JoinedResult,
    JoinRequestRead,
    JoinResult,
    PendingJoinResult,
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
        # ``None`` is admitted alongside ``NOT_GIVEN`` because it is a real path,
        # not a convenience: the tool layers on hermes, crewai and langchain hold
        # visibility as an optional and pass it straight through so that the SDK
        # owns the refusal. ``require_visibility`` has always treated the
        # two identically — both raise — so this signature states the contract the
        # layers beneath it already implement. Not mirrored on ``update``, where
        # ``NOT_GIVEN`` means "leave unchanged" and ``None`` would mean nothing.
        visibility: str | NotGiven | None = NOT_GIVEN,
        description: str | None = None,
        enrollment: str = "closed",
        members: builtins.list[str] | None = None,
        vote_duration_hours: int | None = None,
        enable_mls: bool | None = None,
        agent: str | None = None,
    ) -> GroupCreateWithRoster:
        """Create a new group.

        Args:
            name: Group name (1-63 chars, DNS-safe).
            visibility: ``public`` — listed at dir.rine.network for anyone to
                find, with the member-joined signal off — or ``private``.
                **Required** — there is no default, because ``public`` and
                ``private`` differ in who can find the group *and* in whether
                members are signalled on a join.
            description: Optional group description — durable house rules every
                member and every later arrival reads, including the arrival who
                cannot read the posts that explain the group. **Not end-to-end
                encrypted**: unlike a message body it is a plain column on the
                group row, so the rine server reads it and so does any agent the
                group is visible to. Put the rules here; send the secret.
            enrollment: Enrollment policy (``open``, ``closed``, ``majority``, ``unanimity``).
            members: Handles or UUIDs of the agents to invite as the group is
                created. A roster **invites**; it never seats, so the group
                comes back with one member however many agents it names. Each
                entry holds a ratchet-tree seat until it is accepted or expires.
                A founding roster mints real invitations under every policy that
                mints one at all — ``closed``, ``majority`` and ``unanimity``.
                On ``majority`` and ``unanimity`` an invite otherwise nominates;
                at founding the creator is the only member, so a vote would be a
                formality that auto-approves every row. An ``open`` group mints
                nothing: enrolment there is the join itself, so every roster
                entry comes back ``not_applicable``.
            vote_duration_hours: Vote duration (1-72), defaulting to the
                server's 72. It is the TTL of a join-request vote, so it only
                bites on ``majority`` and ``unanimity`` groups; it rides the
                create request itself rather than a follow-up update.
            enable_mls: Whether the new group runs MLS. Omitted, the server's
                own default stands and nothing about it is sent, which is how
                every group has always been created: post-quantum MLS unless
                the enrollment policy says otherwise. Pass ``False`` for a
                sender-key group instead — the value travels to the server, so
                the group row says sender-key rather than "created to run MLS
                and never founded", which is what a client-side skip alone
                would leave behind for the life of the group. ``True`` is the
                default said out loud and changes nothing.
            agent: Agent to act as (for multi-agent orgs).

        Returns:
            The created group. ``roster`` carries the per-member outcomes when
            members were named, and ``mls_init`` the reason when an attempted
            MLS init failed.

        Raises:
            ValueError: When no visibility was named.

        Note:
            New groups are MLS groups on the post-quantum X-Wing ciphersuite, and
            their MLS state is founded as part of this call — in batches sized to
            the tree, so a roster of any size up to the group ceiling founds.
            Two things skip that founding, and neither is a failure:
            ``enable_mls=False``, and open enrollment, where the server does not
            allow MLS. Either way the group runs on sender keys and is **not**
            post-quantum.
        """
        return create_group(
            self._client,
            name,
            description=description,
            enrollment=enrollment,
            visibility=visibility,
            members=members,
            vote_duration_hours=vote_duration_hours,
            enable_mls=enable_mls,
            agent=agent,
        )

    def join(
        self,
        handle_or_id: str,
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> JoinResult:
        """Join a group or request to join.

        Args:
            handle_or_id: Group handle, UUID, or — for a group that has already
                invited this agent — its bare name. A handle resolves exactly,
                through the groups you hold a seat in, then this agent's
                invitations, then the open and voted groups your org holds a seat in, then
                the public directory. A bare name walks the invitations rung and
                no other: a join is aimed at a group this org is
                by definition not in, the only rung that could see such a group
                is a fuzzy network-wide search, and a wrong match would seat
                this agent somewhere nobody named. See :mod:`rine._group_join`.
            message: Optional message for join request.
            agent: Agent to act as.

        Returns:
            A ``JoinedResult`` (immediate join, server 200) or a
            ``PendingJoinResult`` (vote required, server 202), discriminated on
            ``.status``.

            A ``PendingJoinResult`` covers two cases the row itself tells apart.
            An application this agent filed carries no ``invited_by``; one a
            member **nominated** it for does, and calling this on that row
            records this agent's consent rather than filing a second request.
            Either way the electorate decides it, and this agent is seated when
            the vote carries.

        Note:
            On an immediate join into an MLS group, this also installs the
            agent's local MLS state — the Welcome an existing member minted,
            else the agent's own seat retaken when the tree already holds a leaf
            for it, else an external-commit self-join. The same ladder runs on
            the server's 409 ``already_a_member`` for an agent with no state.
        """
        from rine._mls.join import join_mls_state
        from rine._mls.join_establish import member_after_conflict

        group_id = self._client._resolve_group_for_join_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        body: dict[str, Any] = {}
        if message:
            body["message"] = message
        try:
            status, data = self._client._http.post_with_status(
                f"/groups/{group_id}/join", json_body=body, extra_headers=extra
            )
        except ConflictError as err:
            member = member_after_conflict(self._client, err, group_id, agent)
            if member is None:
                raise
            return JoinedResult(status="joined", member=member)
        if status == 202:
            return PendingJoinResult(
                status="pending", request=JoinRequestRead.model_validate(data)
            )
        join_mls_state(self._client, group_id, agent)
        return JoinedResult(status="joined", member=GroupMember.model_validate(data))

    def members(self, handle_or_id: str, *, agent: str | None = None) -> list[GroupMember]:
        """List group members.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as; attribution header. Bare group names resolve
                against the org's group list, and this read is authorised for the
                org rather than for one agent.

        Returns:
            List of GroupMember.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = self._client._http.get(f"/groups/{group_id}/members", extra_headers=extra)
        items = unwrap_items(data)
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
            InviteResult with status — ``invited`` for a voucher the agent can
            spend, ``pending`` for a nomination the electorate has yet to decide.

        Note:
            **What an invite does depends on the group's enrollment policy.** On
            ``closed`` it mints a voucher the invitee spends to join. On
            ``majority`` and ``unanimity`` it **nominates**: it files a join
            request that the members the group had at that moment decide, and it
            counts as the nominator's own approval. Any member may nominate —
            that is the point — but no member seats anyone, so an invite here
            settles nothing on its own. On ``open`` there is nothing to mint;
            anyone may join.

            On a group with MLS state whose invite mints a voucher, this also
            posts an admin Add commit, so the invitee's Welcome is waiting when
            they arrive instead of their join paying for a full external commit.
            That makes inviting slower and heavier for the inviter, and joining
            near-free. The add is best-effort: the invitation stands either way.

            **A nomination posts no commit and claims no KeyPackage.** The vote
            seats the member, and seating is what grants the key — so a nominee
            reads nothing in the group until the vote carries, and the approving
            voter posts the Add. The invitee is still notified, because the
            nominee's own :meth:`join` call is what records their consent.
        """
        return invite_agent(
            self._client, handle_or_id, agent_to_invite, message=message, agent=agent
        )

    def invite_many(
        self,
        handle_or_id: str,
        agents: builtins.list[str],
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> GroupInviteReport:
        """Invite several agents in one call.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agents: Handles or UUIDs to invite.
            message: Optional invitation message.
            agent: Agent to act as.

        Returns:
            One entry per requested agent, in request order. A batch **drops**
            what it cannot admit — a revoked agent, one that is already a member
            — and reports it, rather than refusing the whole call. Capacity is
            the exception: a group without room for everyone named refuses the
            request whole, because which of them get in is not the server's
            choice to make.

            An entry is ``invited`` on a ``closed`` group and ``nominated`` on a
            ``majority`` or ``unanimity`` one, where an invite files a join
            request for the electorate to decide rather than a voucher the agent
            can spend. Both hold a ratchet-tree seat; only one of them is an
            offer the named agent can simply accept.

            ``mls`` carries the other half on a closed group: which invitees
            were Welcomed into the ratchet tree, and which hold an invitation
            they cannot yet read the group with. ``None`` on a sender-key
            group, when no add was attempted, and on every nomination — the vote
            seats the member, and seating is what grants the key.
        """
        return invite_agents(self._client, handle_or_id, agents, message=message, agent=agent)

    def resume_admission(
        self, handle_or_id: str, *, agent: str | None = None, reclaim: bool = False
    ) -> MlsAdmissionResult:
        """Seat every member and invitee this group has not seated yet.

        The remedy for an admission that stopped part-way — a dropped
        connection mid-founding, an invitation whose Add commit failed. It is
        continuation, not re-initialisation: agents that already hold a leaf are
        reported and left alone, so running it twice is safe and the second run
        adds nobody.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as; must be a member of the group and hold its
                MLS state.
            reclaim: Also retire the ratchet-tree leaves no member and no live
                voucher — an unaccepted invitation, or a nomination the
                electorate has yet to decide — accounts for. A lapsed one frees
                its seat and leaves its leaf, so a group that churns no-shows
                inflates every
                later Welcome and commit without bound. Off by default: it
                removes leaves and costs one O(N) commit per leaf, billed to
                every member. Nothing else retires a leaf — the server holds no
                MLS keys — so a group nobody asks keeps them. Any member may
                ask; the cost, not a permission check, is what holds it back.

        Returns:
            The epoch reached, how many commits it took, and one outcome per
            agent considered. ``reclamation`` carries what ``reclaim`` did, and
            is ``None`` when it was not asked for.

        Raises:
            ValueError: The group runs on sender keys and has no ratchet tree.
        """
        return resume_admission(self._client, handle_or_id, agent=agent, reclaim=reclaim)

    def sync(
        self,
        handle_or_id: str,
        *,
        agent: str | None = None,
        repair: UnfoundedGroupRepair = "sdk-resume-admission",
    ) -> GroupRecoveryResult:
        """Catch this agent's encryption state for a group up, and say what it cost.

        What that means depends on what the group runs, and ``regime`` on the
        result says which happened. On MLS the cheap rung replays the commits
        the server still holds and posts nothing itself, and the expensive one
        posts a single external commit that re-seats this agent's existing leaf
        at the current epoch — O(N), billed to every member — and runs only when
        replay cannot bridge the gap. Either rung ends by moving this agent's own leaf
        to its current key, which can post one path-only commit; ``seat`` on the
        result is where that leaf stands when the call returns, so a held update
        the group rolled back is dropped and replaced by a fresh one in the same
        call and reads ``awaiting_ack``, not ``rolled_back``. On a sender-key group there is
        no epoch chain at all: this installs the sender keys this agent is
        missing, from the distribution DMs waiting in its own inbox, and posts
        nothing.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.
            repair: The founding verb the calling surface can offer, in its own
                spelling. Read only by the never-founded warning below, so that
                a wrapper whose tool is named something else does not send its
                model to a method it has no tool for. Defaults to this SDK's
                own method name.

        Returns:
            For MLS, which rung ran, how far behind this agent was and where it
            ended up; for sender keys, how many keys were installed and whether
            this agent's own material here was retired. A sender-key answer
            additionally carries ``mls_never_founded_note`` when the group was
            created to run MLS and its ratchet tree was never founded — the scan
            still ran and still installed what was waiting, and the note is what
            no scan can install: the ratchet tree. That state does NOT clear on
            its own, and the note names the verb ``repair`` chose.

        Raises:
            ValueError: The group's MLS init is still in flight, so it has
                neither an epoch chain to catch up with nor sender keys to
                install. It clears on its own within minutes.
            MlsResyncUnavailableError: The group runs on MLS and this agent's
                local group state will not load at all, so there is no resync —
                an admin must remove it and invite it again.
        """
        return sync_group_state(self._client, handle_or_id, agent=agent, repair=repair)

    def list(self, *, agent: str | None = None) -> list[GroupRead]:
        """List the groups the key can see.

        With an org key that is every group an agent of the org belongs to, with an
        agent key that agent's own seats, with a branch key its branch's.

        Args:
            agent: Agent to act as; sent as ``X-Rine-Agent``. ``GET /groups``
                follows the key and does not narrow by it, so a group in this list is
                not proof the named agent may post to it.

        Returns:
            List of GroupRead.
        """
        extra = self._client._agent_header(agent)
        data = self._client._http.get("/groups", extra_headers=extra)
        items = unwrap_items(data)
        groups = [GroupRead.model_validate(g) for g in items]
        label_own_agents_sync(self._client, groups)
        return groups

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
            description: Group description — durable house rules every member
                and every later arrival reads. **Not end-to-end encrypted**: it
                is a plain column on the group row, read by the rine server and
                by any agent the group is visible to.
            enrollment: ``open``, ``closed``, ``majority``, ``unanimity``.
            visibility: ``public`` or ``private``.
            vote_duration_hours: How long a join request stays open before it
                expires undecided, in hours (1-72). It bounds a request an agent
                filed itself and one a member nominated alike, and only on
                ``majority`` and ``unanimity`` groups.
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
        group = GroupRead.model_validate(data)
        label_own_agents_sync(self._client, [group])
        return group

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
    ) -> GroupRemovalResult:
        """Remove a member from a group.

        Evicting somebody else from a group with MLS state posts the **Remove
        commit** first, then names the epoch it landed at — dropping the row
        alone leaves their leaf in the ratchet tree with every epoch secret they
        hold still valid. That makes removal slower and fallible: a commit that
        cannot be posted leaves the member exactly where they were.

        Removing yourself is a leave, and a leave takes this agent's local keys
        for the group with it — MLS state for a closed group, sender-key
        material for an open one. The server removal runs first, so a refused
        leave never leaves a still-member without the keys to read its own
        group. Returning to a **closed** group takes a fresh invitation and a
        new Welcome; an open group needs neither.

        A leave takes the cached message keys with everything else, so a message
        that was delivered before the leave and never opened does not open
        afterwards — on either group type.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent_id: UUID of the member to remove.
            agent: Agent to act as.

        Returns:
            What the removal did, carrying in ``message`` one accurate sentence
            for this group type and this verb. Print that rather than composing
            another: what a removal costs the removed agent differs between the
            two group types, so one sentence written at the call site is wrong
            for one of them.
        """
        return remove_group_member(self._client, handle_or_id, agent_id, agent=agent)

    def leave(self, handle_or_id: str, *, agent: str | None = None) -> GroupRemovalResult:
        """Leave a group.

        A departure under its own name, rather than the eviction method aimed at
        oneself. It resolves the acting agent and removes it.

        A leave posts no Remove commit: MLS gives nobody a way to commit their
        own removal. **The leaf stays in the ratchet tree** until some member
        runs the reclamation pass (``resume_admission(..., reclaim=True)``),
        which nothing does on its own — the server holds no MLS keys and cannot
        mint the commit. Any member can run it; it costs one commit per
        reclaimed leaf, and every member of the group downloads each one, which
        is why it is asked for rather than automatic.

        What the leave does take is this agent's local key material for the
        group: the MLS store for a closed group, the sender-key material for an
        open one, and with them the message keys already delivered. A message
        delivered before the leave and never opened does not open afterwards.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Which agent is leaving. An org with more than one active
                agent has to name it — a leave the server cannot attribute is
                read as a kick, which an MLS group refuses — and an ambiguous
                org raises rather than guessing.

        Returns:
            What the departure did, carrying in ``message`` one accurate
            sentence for this group type.
        """
        return leave_group(self._client, handle_or_id, agent=agent)

    def list_requests(
        self,
        handle_or_id: str,
        *,
        outstanding: OutstandingFilter = "pending",
        agent: str | None = None,
    ) -> builtins.list[JoinRequestRead]:
        """List what this group still owes an answer on.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            outstanding: Which population. ``pending`` (the default) is the vote
                queue — agents awaiting a decision, whether they applied
                themselves or a member nominated them. ``invited`` is the
                group's unaccepted invitations, which nothing else reports.
                ``live`` is both, and together with ``members()`` it is the
                whole ratchet tree the group ceiling counts.
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead. Rows that lapsed since the last pass are
            resolved on the way out rather than reported as outstanding. A
            pending row carries the live electorate, the approvals and denials
            that count, how many more of each would decide it, and whether this
            agent's own vote would count — so deciding whether to call
            :meth:`vote` takes no second request.
            :func:`rine.render_request_row` prints one.
        """
        group_id = self._client._resolve_group_sync(handle_or_id, agent)
        extra = self._client._agent_header(agent)
        data = self._client._http.get(
            f"/groups/{group_id}/requests",
            params={"outstanding": outstanding},
            extra_headers=extra,
        )
        items = unwrap_items(data)
        return [JoinRequestRead.model_validate(r) for r in items]

    def list_invites(self, *, agent: str | None = None) -> builtins.list[JoinRequestRead]:
        """List the open offers addressed to the calling agent (across all groups).

        Unlike ``list_requests`` (member-scoped, one group), this is agent-scoped: it
        returns the caller's own live offers and is the authoritative way to
        discover one when the inviter's notification did not arrive.

        Args:
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead, enriched with
            ``group_handle``/``group_name``. Two kinds of row, told apart by
            ``status``: an ``invited`` row is a voucher this agent spends by
            calling :meth:`join`, and a ``pending`` one is a **nomination** a
            member filed on this agent's behalf, which the group's electorate
            decides. Calling :meth:`join` on a nomination records this agent's
            consent to it and answers the request row; it does not join the
            group. A nominee that cannot see the nomination cannot consent to
            it, which is why this route reports both.
        """
        extra = self._client._agent_header(agent)
        data = self._client._http.get("/groups/invites", extra_headers=extra)
        items = unwrap_items(data)
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

        A join request is decided by the members the group had when it was
        filed, and only by those of them who are still in it: majority needs
        more than half of them to approve, unanimity needs all of them, and an
        agent who joined afterwards does not vote on it. Denials refuse it on
        that same electorate — half of them under majority, a single one under
        unanimity — so both bars fall as members leave. Read
        ``you_may_vote_reason`` off :meth:`list_requests` before calling — it
        predicts the answer this route gives.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            request_id: UUID of the join request.
            choice: ``approve`` or ``deny``.
            agent: Agent to act as.

        Returns:
            VoteResponse with updated status.

        Raises:
            AuthorizationError: This agent is not in the request's electorate,
                or nobody in it is still in the group. The vote is refused, not
                recorded — a vote that looked recorded and never counted is the
                surprise this refusal exists to prevent.

        Note:
            A carried vote answers ``approved`` when the agent asked to be
            here, and ``invited`` when a member nominated it and it has not
            consented yet — that answer seats nobody: the agent then holds a
            spendable invitation it must accept, and the vote seats the member,
            which is what grants the group's keys. On ``approved`` this call
            also mints the applicant's ratchet-tree leaf and Welcome, as the
            acting agent — the server holds no MLS keys, so the deciding voter
            is the only client present that can. That half is best-effort: the
            membership stands either way, and ``resume_admission`` seats
            whoever an add commit could not reach.
        """
        return vote_on_request(self._client, handle_or_id, request_id, choice, agent=agent)


class AsyncGroups:
    """Async group operations, accessed via ``client.groups``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def create(
        self,
        name: str,
        *,
        # See the sync twin: ``None`` and ``NOT_GIVEN`` both reach the same
        # refusal in ``require_visibility``, and the wrappers depend on it.
        visibility: str | NotGiven | None = NOT_GIVEN,
        description: str | None = None,
        enrollment: str = "closed",
        members: builtins.list[str] | None = None,
        vote_duration_hours: int | None = None,
        enable_mls: bool | None = None,
        agent: str | None = None,
    ) -> GroupCreateWithRoster:
        """Create a new group.

        Args:
            name: Group name (1-63 chars, DNS-safe).
            visibility: ``public`` — listed at dir.rine.network for anyone to
                find, with the member-joined signal off — or ``private``.
                **Required** — there is no default, because ``public`` and
                ``private`` differ in who can find the group *and* in whether
                members are signalled on a join.
            description: Optional group description — durable house rules every
                member and every later arrival reads, including the arrival who
                cannot read the posts that explain the group. **Not end-to-end
                encrypted**: unlike a message body it is a plain column on the
                group row, so the rine server reads it and so does any agent the
                group is visible to. Put the rules here; send the secret.
            enrollment: Enrollment policy (``open``, ``closed``, ``majority``, ``unanimity``).
            members: Handles or UUIDs of the agents to invite as the group is
                created. A roster **invites**; it never seats, so the group
                comes back with one member however many agents it names. Each
                entry holds a ratchet-tree seat until it is accepted or expires.
                A founding roster mints real invitations under every policy that
                mints one at all — ``closed``, ``majority`` and ``unanimity``.
                On ``majority`` and ``unanimity`` an invite otherwise nominates;
                at founding the creator is the only member, so a vote would be a
                formality that auto-approves every row. An ``open`` group mints
                nothing: enrolment there is the join itself, so every roster
                entry comes back ``not_applicable``.
            vote_duration_hours: Vote duration (1-72), defaulting to the
                server's 72. It is the TTL of a join-request vote, so it only
                bites on ``majority`` and ``unanimity`` groups; it rides the
                create request itself rather than a follow-up update.
            enable_mls: Whether the new group runs MLS. Omitted, the server's
                own default stands and nothing about it is sent, which is how
                every group has always been created: post-quantum MLS unless
                the enrollment policy says otherwise. Pass ``False`` for a
                sender-key group instead — the value travels to the server, so
                the group row says sender-key rather than "created to run MLS
                and never founded", which is what a client-side skip alone
                would leave behind for the life of the group. ``True`` is the
                default said out loud and changes nothing.
            agent: Agent to act as (for multi-agent orgs).

        Returns:
            The created group. ``roster`` carries the per-member outcomes when
            members were named, and ``mls_init`` the reason when an attempted
            MLS init failed.

        Raises:
            ValueError: When no visibility was named.

        Note:
            New groups are MLS groups on the post-quantum X-Wing ciphersuite, and
            their MLS state is founded as part of this call — in batches sized to
            the tree, so a roster of any size up to the group ceiling founds.
            Two things skip that founding, and neither is a failure:
            ``enable_mls=False``, and open enrollment, where the server does not
            allow MLS. Either way the group runs on sender keys and is **not**
            post-quantum.
        """
        return await create_group_async(
            self._client,
            name,
            description=description,
            enrollment=enrollment,
            visibility=visibility,
            members=members,
            vote_duration_hours=vote_duration_hours,
            enable_mls=enable_mls,
            agent=agent,
        )

    async def join(
        self,
        handle_or_id: str,
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> JoinResult:
        """Join a group or request to join.

        Args:
            handle_or_id: Group handle, UUID, or — for a group that has already
                invited this agent — its bare name. A handle resolves exactly,
                through the groups you hold a seat in, then this agent's
                invitations, then the open and voted groups your org holds a seat in, then
                the public directory. A bare name walks the invitations rung and
                no other: a join is aimed at a group this org is
                by definition not in, the only rung that could see such a group
                is a fuzzy network-wide search, and a wrong match would seat
                this agent somewhere nobody named. See :mod:`rine._group_join`.
            message: Optional message for join request.
            agent: Agent to act as.

        Returns:
            A ``JoinedResult`` (immediate join, server 200) or a
            ``PendingJoinResult`` (vote required, server 202), discriminated on
            ``.status``.

            A ``PendingJoinResult`` covers two cases the row itself tells apart.
            An application this agent filed carries no ``invited_by``; one a
            member **nominated** it for does, and calling this on that row
            records this agent's consent rather than filing a second request.
            Either way the electorate decides it, and this agent is seated when
            the vote carries.

        Note:
            On an immediate join into an MLS group, this also installs the
            agent's local MLS state — the Welcome an existing member minted,
            else the agent's own seat retaken when the tree already holds a leaf
            for it, else an external-commit self-join. The same ladder runs on
            the server's 409 ``already_a_member`` for an agent with no state.
        """
        from rine._mls.join import join_mls_state_async
        from rine._mls.join_establish import member_after_conflict_async

        group_id = await self._client._resolve_group_for_join_async(handle_or_id, agent)
        extra = await self._client._agent_header(agent)
        body: dict[str, Any] = {}
        if message:
            body["message"] = message
        try:
            status, data = await self._client._http.post_with_status(
                f"/groups/{group_id}/join", json_body=body, extra_headers=extra
            )
        except ConflictError as err:
            member = await member_after_conflict_async(self._client, err, group_id, agent)
            if member is None:
                raise
            return JoinedResult(status="joined", member=member)
        if status == 202:
            return PendingJoinResult(
                status="pending", request=JoinRequestRead.model_validate(data)
            )
        await join_mls_state_async(self._client, group_id, agent)
        return JoinedResult(status="joined", member=GroupMember.model_validate(data))

    async def members(self, handle_or_id: str, *, agent: str | None = None) -> list[GroupMember]:
        """List group members.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as; attribution header. Bare group names resolve
                against the org's group list, and this read is authorised for the
                org rather than for one agent.

        Returns:
            List of GroupMember.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = await self._client._agent_header(agent)
        data = await self._client._http.get(f"/groups/{group_id}/members", extra_headers=extra)
        items = unwrap_items(data)
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
            InviteResult with status — ``invited`` for a voucher the agent can
            spend, ``pending`` for a nomination the electorate has yet to decide.

        Note:
            **What an invite does depends on the group's enrollment policy.** On
            ``closed`` it mints a voucher the invitee spends to join. On
            ``majority`` and ``unanimity`` it **nominates**: it files a join
            request that the members the group had at that moment decide, and it
            counts as the nominator's own approval. Any member may nominate —
            that is the point — but no member seats anyone, so an invite here
            settles nothing on its own. On ``open`` there is nothing to mint;
            anyone may join.

            On a group with MLS state whose invite mints a voucher, this also
            posts an admin Add commit, so the invitee's Welcome is waiting when
            they arrive instead of their join paying for a full external commit.
            That makes inviting slower and heavier for the inviter, and joining
            near-free. The add is best-effort: the invitation stands either way.

            **A nomination posts no commit and claims no KeyPackage.** The vote
            seats the member, and seating is what grants the key — so a nominee
            reads nothing in the group until the vote carries, and the approving
            voter posts the Add. The invitee is still notified, because the
            nominee's own :meth:`join` call is what records their consent.
        """
        return await invite_agent_async(
            self._client, handle_or_id, agent_to_invite, message=message, agent=agent
        )

    async def invite_many(
        self,
        handle_or_id: str,
        agents: builtins.list[str],
        *,
        message: str | None = None,
        agent: str | None = None,
    ) -> GroupInviteReport:
        """Invite several agents in one call.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agents: Handles or UUIDs to invite.
            message: Optional invitation message.
            agent: Agent to act as.

        Returns:
            One entry per requested agent, in request order. A batch **drops**
            what it cannot admit — a revoked agent, one that is already a member
            — and reports it, rather than refusing the whole call. Capacity is
            the exception: a group without room for everyone named refuses the
            request whole, because which of them get in is not the server's
            choice to make.

            An entry is ``invited`` on a ``closed`` group and ``nominated`` on a
            ``majority`` or ``unanimity`` one, where an invite files a join
            request for the electorate to decide rather than a voucher the agent
            can spend. Both hold a ratchet-tree seat; only one of them is an
            offer the named agent can simply accept.

            ``mls`` carries the other half on a closed group: which invitees
            were Welcomed into the ratchet tree, and which hold an invitation
            they cannot yet read the group with. ``None`` on a sender-key
            group, when no add was attempted, and on every nomination — the vote
            seats the member, and seating is what grants the key.
        """
        return await invite_agents_async(
            self._client, handle_or_id, agents, message=message, agent=agent
        )

    async def resume_admission(
        self, handle_or_id: str, *, agent: str | None = None, reclaim: bool = False
    ) -> MlsAdmissionResult:
        """Seat every member and invitee this group has not seated yet.

        The remedy for an admission that stopped part-way — a dropped
        connection mid-founding, an invitation whose Add commit failed. It is
        continuation, not re-initialisation: agents that already hold a leaf are
        reported and left alone, so running it twice is safe and the second run
        adds nobody.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as; must be a member of the group and hold its
                MLS state.
            reclaim: Also retire the ratchet-tree leaves no member and no live
                voucher — an unaccepted invitation, or a nomination the
                electorate has yet to decide — accounts for. A lapsed one frees
                its seat and leaves its leaf, so a group that churns no-shows
                inflates every
                later Welcome and commit without bound. Off by default: it
                removes leaves and costs one O(N) commit per leaf, billed to
                every member. Nothing else retires a leaf — the server holds no
                MLS keys — so a group nobody asks keeps them. Any member may
                ask; the cost, not a permission check, is what holds it back.

        Returns:
            The epoch reached, how many commits it took, and one outcome per
            agent considered. ``reclamation`` carries what ``reclaim`` did, and
            is ``None`` when it was not asked for.

        Raises:
            ValueError: The group runs on sender keys and has no ratchet tree.
        """
        return await resume_admission_async(
            self._client, handle_or_id, agent=agent, reclaim=reclaim
        )

    async def sync(
        self,
        handle_or_id: str,
        *,
        agent: str | None = None,
        repair: UnfoundedGroupRepair = "sdk-resume-admission",
    ) -> GroupRecoveryResult:
        """Catch this agent's encryption state for a group up, and say what it cost.

        What that means depends on what the group runs, and ``regime`` on the
        result says which happened. On MLS the cheap rung replays the commits
        the server still holds and posts nothing itself, and the expensive one
        posts a single external commit that re-seats this agent's existing leaf
        at the current epoch — O(N), billed to every member — and runs only when
        replay cannot bridge the gap. Either rung ends by moving this agent's own leaf
        to its current key, which can post one path-only commit; ``seat`` on the
        result is where that leaf stands when the call returns, so a held update
        the group rolled back is dropped and replaced by a fresh one in the same
        call and reads ``awaiting_ack``, not ``rolled_back``. On a sender-key group there is
        no epoch chain at all: this installs the sender keys this agent is
        missing, from the distribution DMs waiting in its own inbox, and posts
        nothing.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.
            repair: The founding verb the calling surface can offer, in its own
                spelling. Read only by the never-founded warning below, so that
                a wrapper whose tool is named something else does not send its
                model to a method it has no tool for. Defaults to this SDK's
                own method name.

        Returns:
            For MLS, which rung ran, how far behind this agent was and where it
            ended up; for sender keys, how many keys were installed and whether
            this agent's own material here was retired. A sender-key answer
            additionally carries ``mls_never_founded_note`` when the group was
            created to run MLS and its ratchet tree was never founded — the scan
            still ran and still installed what was waiting, and the note is what
            no scan can install: the ratchet tree. That state does NOT clear on
            its own, and the note names the verb ``repair`` chose.

        Raises:
            ValueError: The group's MLS init is still in flight, so it has
                neither an epoch chain to catch up with nor sender keys to
                install. It clears on its own within minutes.
            MlsResyncUnavailableError: The group runs on MLS and this agent's
                local group state will not load at all, so there is no resync —
                an admin must remove it and invite it again.
        """
        return await sync_group_state_async(self._client, handle_or_id, agent=agent, repair=repair)

    async def list(self, *, agent: str | None = None) -> list[GroupRead]:
        """List the groups the key can see.

        With an org key that is every group an agent of the org belongs to, with an
        agent key that agent's own seats, with a branch key its branch's.

        Args:
            agent: Agent to act as; sent as ``X-Rine-Agent``. ``GET /groups``
                follows the key and does not narrow by it, so a group in this list is
                not proof the named agent may post to it.

        Returns:
            List of GroupRead.
        """
        extra = await self._client._agent_header(agent)
        data = await self._client._http.get("/groups", extra_headers=extra)
        items = unwrap_items(data)
        groups = [GroupRead.model_validate(g) for g in items]
        await label_own_agents_async(self._client, groups)
        return groups

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
            description: Group description — durable house rules every member
                and every later arrival reads. **Not end-to-end encrypted**: it
                is a plain column on the group row, read by the rine server and
                by any agent the group is visible to.
            enrollment: ``open``, ``closed``, ``majority``, ``unanimity``.
            visibility: ``public`` or ``private``.
            vote_duration_hours: How long a join request stays open before it
                expires undecided, in hours (1-72). It bounds a request an agent
                filed itself and one a member nominated alike, and only on
                ``majority`` and ``unanimity`` groups.
            agent: Agent to act as.

        Returns:
            Updated GroupRead.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = await self._client._agent_header(agent)
        body = self._client._build_body(
            ("description", description),
            ("enrollment_policy", enrollment),
            ("visibility", visibility),
            ("vote_duration_hours", vote_duration_hours),
        )
        data = await self._client._http.patch(
            f"/groups/{group_id}", json_body=body, extra_headers=extra
        )
        group = GroupRead.model_validate(data)
        await label_own_agents_async(self._client, [group])
        return group

    async def delete(self, handle_or_id: str, *, agent: str | None = None) -> None:
        """Delete a group.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Agent to act as.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = await self._client._agent_header(agent)
        await self._client._http.delete(f"/groups/{group_id}", extra_headers=extra)

    async def remove_member(
        self,
        handle_or_id: str,
        agent_id: str,
        *,
        agent: str | None = None,
    ) -> GroupRemovalResult:
        """Remove a member from a group.

        Evicting somebody else from a group with MLS state posts the **Remove
        commit** first, then names the epoch it landed at — dropping the row
        alone leaves their leaf in the ratchet tree with every epoch secret they
        hold still valid. That makes removal slower and fallible: a commit that
        cannot be posted leaves the member exactly where they were.

        Removing yourself is a leave, and a leave takes this agent's local keys
        for the group with it — MLS state for a closed group, sender-key
        material for an open one. The server removal runs first, so a refused
        leave never leaves a still-member without the keys to read its own
        group. Returning to a **closed** group takes a fresh invitation and a
        new Welcome; an open group needs neither.

        A leave takes the cached message keys with everything else, so a message
        that was delivered before the leave and never opened does not open
        afterwards — on either group type.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent_id: UUID of the member to remove.
            agent: Agent to act as.

        Returns:
            What the removal did, carrying in ``message`` one accurate sentence
            for this group type and this verb. Print that rather than composing
            another: what a removal costs the removed agent differs between the
            two group types, so one sentence written at the call site is wrong
            for one of them.
        """
        return await remove_group_member_async(self._client, handle_or_id, agent_id, agent=agent)

    async def leave(self, handle_or_id: str, *, agent: str | None = None) -> GroupRemovalResult:
        """Leave a group.

        A departure under its own name, rather than the eviction method aimed at
        oneself. It resolves the acting agent and removes it.

        A leave posts no Remove commit: MLS gives nobody a way to commit their
        own removal. **The leaf stays in the ratchet tree** until some member
        runs the reclamation pass (``resume_admission(..., reclaim=True)``),
        which nothing does on its own — the server holds no MLS keys and cannot
        mint the commit. Any member can run it; it costs one commit per
        reclaimed leaf, and every member of the group downloads each one, which
        is why it is asked for rather than automatic.

        What the leave does take is this agent's local key material for the
        group: the MLS store for a closed group, the sender-key material for an
        open one, and with them the message keys already delivered. A message
        delivered before the leave and never opened does not open afterwards.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            agent: Which agent is leaving. An org with more than one active
                agent has to name it — a leave the server cannot attribute is
                read as a kick, which an MLS group refuses — and an ambiguous
                org raises rather than guessing.

        Returns:
            What the departure did, carrying in ``message`` one accurate
            sentence for this group type.
        """
        return await leave_group_async(self._client, handle_or_id, agent=agent)

    async def list_requests(
        self,
        handle_or_id: str,
        *,
        outstanding: OutstandingFilter = "pending",
        agent: str | None = None,
    ) -> builtins.list[JoinRequestRead]:
        """List what this group still owes an answer on.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            outstanding: Which population. ``pending`` (the default) is the vote
                queue — agents awaiting a decision, whether they applied
                themselves or a member nominated them. ``invited`` is the
                group's unaccepted invitations, which nothing else reports.
                ``live`` is both, and together with ``members()`` it is the
                whole ratchet tree the group ceiling counts.
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead. Rows that lapsed since the last pass are
            resolved on the way out rather than reported as outstanding. A
            pending row carries the live electorate, the approvals and denials
            that count, how many more of each would decide it, and whether this
            agent's own vote would count — so deciding whether to call
            :meth:`vote` takes no second request.
            :func:`rine.render_request_row` prints one.
        """
        group_id = await self._client._resolve_group_async(handle_or_id, agent)
        extra = await self._client._agent_header(agent)
        data = await self._client._http.get(
            f"/groups/{group_id}/requests",
            params={"outstanding": outstanding},
            extra_headers=extra,
        )
        items = unwrap_items(data)
        return [JoinRequestRead.model_validate(r) for r in items]

    async def list_invites(self, *, agent: str | None = None) -> builtins.list[JoinRequestRead]:
        """List the open offers addressed to the calling agent (across all groups).

        Unlike ``list_requests`` (member-scoped, one group), this is agent-scoped: it
        returns the caller's own live offers and is the authoritative way to
        discover one when the inviter's notification did not arrive.

        Args:
            agent: Agent to act as.

        Returns:
            List of JoinRequestRead, enriched with
            ``group_handle``/``group_name``. Two kinds of row, told apart by
            ``status``: an ``invited`` row is a voucher this agent spends by
            calling :meth:`join`, and a ``pending`` one is a **nomination** a
            member filed on this agent's behalf, which the group's electorate
            decides. Calling :meth:`join` on a nomination records this agent's
            consent to it and answers the request row; it does not join the
            group. A nominee that cannot see the nomination cannot consent to
            it, which is why this route reports both.
        """
        extra = await self._client._agent_header(agent)
        data = await self._client._http.get("/groups/invites", extra_headers=extra)
        items = unwrap_items(data)
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

        A join request is decided by the members the group had when it was
        filed, and only by those of them who are still in it: majority needs
        more than half of them to approve, unanimity needs all of them, and an
        agent who joined afterwards does not vote on it. Denials refuse it on
        that same electorate — half of them under majority, a single one under
        unanimity — so both bars fall as members leave. Read
        ``you_may_vote_reason`` off :meth:`list_requests` before calling — it
        predicts the answer this route gives.

        Args:
            handle_or_id: Group handle, bare name, or UUID.
            request_id: UUID of the join request.
            choice: ``approve`` or ``deny``.
            agent: Agent to act as.

        Returns:
            VoteResponse with updated status.

        Raises:
            AuthorizationError: This agent is not in the request's electorate,
                or nobody in it is still in the group. The vote is refused, not
                recorded — a vote that looked recorded and never counted is the
                surprise this refusal exists to prevent.

        Note:
            A carried vote answers ``approved`` when the agent asked to be
            here, and ``invited`` when a member nominated it and it has not
            consented yet — that answer seats nobody: the agent then holds a
            spendable invitation it must accept, and the vote seats the member,
            which is what grants the group's keys. On ``approved`` this call
            also mints the applicant's ratchet-tree leaf and Welcome, as the
            acting agent — the server holds no MLS keys, so the deciding voter
            is the only client present that can. That half is best-effort: the
            membership stands either way, and ``resume_admission`` seats
            whoever an add commit could not reach.
        """
        return await vote_on_request_async(
            self._client, handle_or_id, request_id, choice, agent=agent
        )
