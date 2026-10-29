"""SyncRineClient — synchronous client for the Rine messaging platform.

Uses ``httpx.Client`` directly (NOT ``asyncio.run()`` wrapping). Works in
Jupyter notebooks, scripts, and synchronous applications without event loop conflicts.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from uuid import UUID

    import httpx

    from rine._crypto.message import DecryptResult
    from rine._mls import MlsCutoverResult

from rine._actor import ResolvedActor, normalize_actor, refuse_if_not_addressee
from rine._agent_provision import create_agent as _create_agent
from rine._agent_rotate_seats import RotatedAgent, rotate_agent_with_seats
from rine._base_client import BaseRineClient
from rine._constants import NOT_GIVEN, EncryptionVersion, MessageType, NotGiven
from rine._crypto._agent_keys import fetch_recipient_keys_sync
from rine._crypto._sender_verify import refuse_if_sender_differs
from rine._crypto.message import (
    decrypt_group_message_sync,
    decrypt_message_sync,
    encrypt_message,
)
from rine._crypto.sender_keys_helpers import (
    lift_retirement_if_member,
    load_sender_key_states,
    save_sender_key_state,
    sender_keys_retired,
)
from rine._group_join import (
    DirectoryHandleScan,
    ambiguous_invitation_join_refusal,
    bare_name_join_refusal,
    is_exact_group_handle,
    is_invitation_of_that_name,
    unresolved_handle_join_refusal,
)
from rine._group_recovery import SenderKeyScan, unscanned_beyond_page
from rine._group_ref import (
    is_bare_reference,
    is_sigil_group_reference,
    sigiled_group_ref,
)
from rine._http import SyncHttpClient
from rine._logging import logger
from rine._mls.escrow_sweep import startup_escrow_sweep
from rine._recipient import (
    REF_CLASS_GROUP,
    REF_CLASS_ID,
    GroupTarget,
    RecipientTarget,
    classify_reference,
    group_target_by_id,
)
from rine._recipient_ladder import group_ladder, recipient_ladder
from rine._recipient_reads import (
    ReferenceReads,
    answered_group_id,
    group_read_refused,
    note_group_id_recipient,
    refuse_a_substituted_group,
    walk,
)
from rine._render_recovery import RenderRecovery
from rine._resolve import (
    is_uuid,
    normalize_handle,
    resolve_agent,
    resolve_to_uuid_sync,
    warn_if_handle_moved,
)
from rine._resources.group_ops import unwrap_items
from rine._resources.groups import SyncGroups
from rine._resources.webhooks import SyncWebhooks
from rine._thread import to_thread_entry
from rine._utils import apply_cleartext_fields
from rine._verify import verify_identity as _verify_identity
from rine._whoami import parse_whoami
from rine.a2a_cleartext import is_a2a_cleartext, read_a2a_cleartext
from rine.errors import (
    CryptoError,
    NoSenderKeyStateError,
    NotFoundError,
    RineApiError,
    UnsupportedTargetError,
)
from rine.sender_key_words import SenderKeyRefusal
from rine.thread_words import (
    blank_as_absent,
    conversation_transcript_path,
    group_transcript_path,
    named_conversation_uuid,
    refuse_if_two_transcript_references,
)
from rine.types import (
    AgentCardRead,
    AgentProfile,
    AgentRead,
    AgentSummary,
    ConversationParticipant,
    ConversationRead,
    CursorPage,
    DecryptedMessage,
    ErasureResult,
    Event,
    GroupSummary,
    MessageRead,
    OrgQuotas,
    OrgRead,
    PollTokenResponse,
    SendAndWaitResult,
    ThreadEntry,
    VerifyIdentityResult,
    WhoAmI,
)

# Inbox delivery-status filter values (server: messages_inbox.py ``list_messages``' ``status``).
InboxStatus = Literal["new", "delivered", "read"]


class SyncRineClient(BaseRineClient):
    """Synchronous client for the Rine messaging platform.

    Identical API surface to ``RineClient`` without ``async``/``await``.
    Uses ``httpx.Client`` directly — no event loop conflicts.

    Args:
        config_dir: Config directory path. Auto-resolved if not provided.
        api_url: API base URL. Auto-resolved if not provided.
        agent: Agent name, handle, or UUID for multi-agent orgs.
        timeout: HTTP request timeout in seconds.
        max_retries: Maximum retry attempts for rate limiting.
        http_client: Optional custom ``httpx.Client``.
        owner_dir: Owner directory holding ``root.key``; ``RINE_OWNER_DIR`` or
            ``~/.config/rine-owner`` when omitted.
        profile: Named profile to act as; the default profile when omitted.
        agent_only: Act only as an agent whose leaf keys are in ``config_dir``; the
            owner dir is never read, so ``root.key`` cannot make this client the org.

    Example::

        with SyncRineClient() as client:
            client.send("kofi@acme.rine.network", {"task": "hello"})
    """

    def __init__(
        self,
        *,
        config_dir: str | None = None,
        api_url: str | None = None,
        agent: str | NotGiven = NOT_GIVEN,
        timeout: float = 30.0,
        max_retries: int = 2,
        http_client: httpx.Client | None = None,
        owner_dir: str | None = None,
        profile: str | None = None,
        agent_only: bool = False,
    ) -> None:
        super().__init__(
            config_dir=config_dir,
            api_url=api_url,
            agent=agent,
            timeout=timeout,
            max_retries=max_retries,
            owner_dir=owner_dir,
            profile=profile,
            agent_only=agent_only,
        )
        self._http = SyncHttpClient(
            config_dir=self._config_dir,
            api_url=self._api_url,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
            owner_dir=self._owner_dir,
            profile=self._profile,
            agent_only=self._agent_only,
        )
        self.groups = SyncGroups(self)
        self.webhooks = SyncWebhooks(self)
        # Escrow files a previous process left behind (a leave or a recovery ends
        # the process that wrote them) are cleared now, not at the first MLS call.
        startup_escrow_sweep(self._http, self._config_dir, self._escrow_sweep_agent())

    def __enter__(self) -> SyncRineClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connections."""
        self._http.close()

    def with_options(
        self,
        *,
        timeout: float | NotGiven = NOT_GIVEN,
        agent: str | NotGiven = NOT_GIVEN,
        max_retries: int | NotGiven = NOT_GIVEN,
    ) -> SyncRineClient:
        """Return a new client with overridden options.

        Args:
            timeout: Override request timeout.
            agent: Override agent selection.
            max_retries: Override max retries.

        Returns:
            New SyncRineClient instance with overrides applied.
        """
        return SyncRineClient(
            config_dir=self._config_dir,
            api_url=self._api_url,
            agent=agent if not isinstance(agent, NotGiven) else self._agent,
            timeout=timeout if not isinstance(timeout, NotGiven) else self._timeout,
            max_retries=max_retries
            if not isinstance(max_retries, NotGiven)
            else self._max_retries,
        )

    # --- Agent resolution helpers ---

    def _agent_header(self, agent: str | None = None) -> dict[str, str] | None:
        """Build X-Rine-Agent header dict.

        Priority: the per-call ``agent`` override, then the constructor's agent —
        resolved once via :meth:`_resolve_agent_id` and memoised, so a client built
        with ``agent=`` names its actor on every request without re-resolving. Stays
        ``None`` when no agent was configured; the server then auto-selects.

        The header carries what the *wire* accepts, not what the caller typed: a
        bare name is resolved here too (see :meth:`_needs_actor_resolution`), and
        through the same :meth:`_resolve_agent_id` this client's other rung uses,
        so the two cannot disagree about which agent a name meant. Both share one
        memoised ``GET /agents``, so a call site that asks both spends one lookup.
        """
        aid = normalize_actor(agent) or self._get_agent_header()
        if self._needs_actor_resolution(aid):
            aid = self._resolve_agent_id(aid)
        return self._actor_header_dict(aid)

    def _resolve_agent_id(self, agent: str | None = None) -> str:
        """The acting agent's UUID — :meth:`resolve_actor` without the warning."""
        return self.resolve_actor(agent).agent_id

    def resolve_actor(self, agent: str | None = None) -> ResolvedActor:
        """Which agent this call acts as, and anything the caller should be told.

        The one **public, per-call** resolve step. A surface that wants to show
        the caller a one-agent fallback resolves here first and passes the
        resolved UUID down; every inner path short-circuits a UUID without a
        lookup, so nothing re-resolves and no second warning is minted.

        **Every spelling of the actor is answered from this org's own agents** —
        an acting agent must be an agent the caller owns — and never through
        :func:`rine._resolve.resolve_to_uuid_sync`: that function is also the
        **recipient / invitee / target** resolver, it holds only an API URL and
        an unauthenticated WebFinger client, and teaching it bare names would
        make ``invite(invitee="ops")`` silently resolve the *caller's* ``ops``
        against a peer org's roster.

        🔴 The other direction is the one that shipped. A handle-spelled *actor*
        sent to that resolver asked WebFinger who owns the handle — a question
        about somebody else's org — and, finding nobody, handed the handle back
        as though it were an id. Nothing refused it, so it surfaced two calls
        later from the key store as ``Invalid agent_id: 'x@org'. Expected a
        UUID.``: a filesystem path-safety guard, read by a caller who had merely
        named an agent this org does not have, while the same mistake spelled as
        a bare name was answered by :func:`rine._actor.unknown_actor_refusal`.
        There is no foreign-org fallback for this slot.
        """
        agent = normalize_actor(agent)
        if agent:
            # A UUID is the answer already, and spending a ``GET /agents`` on one
            # would fetch a list ``resolve_agent`` then never reads.
            if is_uuid(agent):
                return ResolvedActor(agent)
            return resolve_agent(self._fetch_agents(), explicit=agent)
        if self._resolved_actor:
            return self._resolved_actor
        agents = self._fetch_agents()
        named = None if isinstance(self._agent, NotGiven) else self._agent
        self._resolved_actor = resolve_agent(agents, explicit=named, origin=self._actor_origin)
        return self._resolved_actor

    def _fetch_agents(self) -> list[dict[str, Any]]:
        if self._agents_cache is not None:
            return self._agents_cache
        data = self._http.get("/agents")
        self._agents_cache = data.get("items", data) if isinstance(data, dict) else data
        return self._agents_cache

    def _fetch_own_groups(self, agent: str | None) -> list[dict[str, Any]]:
        """Every group the key can see, unfiltered — the one rung the server cannot take.

        ``GET /groups?handle=`` matches a FULL ``#name@org`` handle only, so both
        callers that start from a bare name have to list and decide locally. What
        is done with the list lives in :mod:`rine._group_ref`; this is the fetch
        and nothing else, which is the same seam ``fetchOwnGroups``
        (``rine-core/src/resolve-group.ts``) holds on the TypeScript side.

        ``agent`` becomes the ``X-Rine-Agent`` attribution header. It does not
        select whose list comes back: the route follows the key either way.
        """
        extra = self._agent_header(agent)
        return list(unwrap_items(self._http.get("/groups", extra_headers=extra)))

    def _seated_group_row_by_handle(self, handle_or_id: str) -> dict[str, Any] | None:
        """The group ``GET /groups?handle=`` answers with, or ``None``.

        🔴 **Seat-scoped, and that is the whole point of naming it so.** The route
        joins ``GroupMember`` to the caller's scope (its own seats for an agent,
        its branch's for a branch, the org's for the org), so it answers for a
        group the caller already holds a seat in and for no other. Every group
        verb but one wants exactly that. :meth:`_resolve_group_for_join_sync` is the one
        that does not, which is why it takes this as a rung rather than as the
        answer.

        The ROW rather than the id, for the reason its asynchronous twin
        (:meth:`rine.RineClient._seated_group_row_by_handle`) gives: the filter
        already returned a whole group, and the member ladder needs the group's
        own handle to address a send.

        The handle is sigiled but not otherwise normalised: the server
        normalises ``?handle=`` its own way, and doing it twice here would only
        add a second opinion.
        """
        data = self._http.get("/groups", params={"handle": sigiled_group_ref(handle_or_id)})
        items = data.get("items", []) if isinstance(data, dict) else data
        return dict(items[0]) if items else None

    def _seated_group_id_by_handle(self, handle_or_id: str) -> str | None:
        """The id that filter answered with — :meth:`_seated_group_row_by_handle`'s.

        The join ladder's first rung, which wants to know only WHETHER the caller
        is already seated. Kept as its own name because that is the question it
        asks; it is one line and holds no lookup of its own.
        """
        row = self._seated_group_row_by_handle(handle_or_id)
        return str(row["id"]) if row is not None else None

    def _org_joinable_group_id_by_handle(self, handle_or_id: str) -> str | None:
        """The id of the OPEN or VOTED group of that handle this org holds a seat in, or ``None``.

        The join ladder's third rung: ``GET /groups/org-joinable`` answers
        existence only, because an agent's own ``GET /groups`` is scoped to its
        own seats and cannot see an own-org open or voted group a sibling sits in. The
        id it returns is the ordinary join's.
        """
        data = self._http.get(
            "/groups/org-joinable", params={"handle": sigiled_group_ref(handle_or_id)}
        )
        return str(data["id"]) if data.get("id") else None

    def _readable_group_by_id(self, group_id: str, agent: str | None) -> dict[str, Any] | None:
        """The group one id names, or ``None`` when this caller may not read it.

        The synchronous twin of
        :meth:`rine.RineClient._readable_group_by_id`, which is where the
        single-row read and the check on what it answered are described. Both
        rules are shared rather than restated:
        :func:`rine._recipient_reads.group_read_refused` is the only place
        either client decides what a status means here, and
        :func:`rine._recipient_reads.refuse_a_substituted_group` the only place
        either decides what a substituted body means.

        Raises:
            GroupIdentityMismatchError: The body named a different group.
        """
        extra = self._agent_header(agent)
        try:
            found = self._http.get(f"/groups/{group_id}", extra_headers=extra)
        except RineApiError as error:
            if group_read_refused(error):
                return None
            raise
        row = dict(found)
        refuse_a_substituted_group(group_id, answered_group_id(row))
        return row

    def _reference_reads(self, agent: str | None) -> ReferenceReads:
        """The five reads a ladder may ask for, bound to this client and actor.

        The whole of what :mod:`rine._recipient_ladder` is allowed to do to the
        wire. ``agent`` is captured here rather than threaded through the rungs,
        because it is an attribution header and never changes what a rung means.
        """
        return ReferenceReads(
            own_groups=lambda: self._fetch_own_groups(agent),
            group_by_id=lambda group_id: self._readable_group_by_id(group_id, agent),
            seated_by_handle=self._seated_group_row_by_handle,
            own_agents=self._fetch_agents,
            agent_id_for=lambda reference: resolve_to_uuid_sync(self._api_url, reference),
        )

    def resolve_group(self, reference: str, agent: str | None = None) -> GroupTarget:
        """The group a reference names, with everything the resolve already knows.

        The synchronous twin of :meth:`rine.RineClient.resolve_group`, and
        literally the same rungs: both walk
        :func:`rine._recipient_ladder.group_ladder`, which is the only copy of
        them. What differs between the two clients is the driver and nothing
        else.

        Raises:
            NotFoundError: No group in the key's scope answers to the reference.
            ConfigError: More than one does.
        """
        return walk(group_ladder(reference), self._reference_reads(agent))

    def resolve_group_for_join(self, reference: str, agent: str | None = None) -> GroupTarget:
        """The group a JOIN reference names — the one ladder aimed outside the org.

        🔴 Answers with the id and nothing else, on every rung, for the reason
        :meth:`rine.RineClient.resolve_group_for_join` states: a join's target is
        a group this org holds no seat in, so ``GET /groups`` cannot describe it.
        """
        return group_target_by_id(self._resolve_group_for_join_sync(reference, agent), reference)

    def resolve_recipient(self, to: str, agent: str | None = None) -> RecipientTarget:
        """What a ``send()`` recipient names, and which namespace answered it.

        The synchronous twin of :meth:`rine.RineClient.resolve_recipient`, over
        the same :func:`rine._recipient_ladder.recipient_ladder`.

        Raises:
            NotFoundError: Nothing in the named namespace answers to it.
            ConfigError: More than one group does, or the bare name is an
                agent's.
        """
        return walk(recipient_ladder(normalize_handle(to), to), self._reference_reads(agent))

    def _resolve_group_sync(self, handle_or_id: str, agent: str | None = None) -> str:
        """Resolve a group UUID, full handle, or bare name to a group ID.

        :meth:`resolve_group`'s id, and the twin of
        :meth:`rine.RineClient._resolve_group_async` — which is where the rungs
        are described in full.

        The rungs, the local-part fallback included, are
        :func:`rine._recipient_ladder.group_ladder`'s.
        """
        return self.resolve_group(handle_or_id, agent).id

    def _scan_public_directory(self, handle: str) -> DirectoryHandleScan:
        """Walk the public directory for that handle, within one join's budget.

        The one rung that can see a group this caller has no relationship with.
        ``GET /directory/groups`` searches ``name`` and ``description`` and never
        ``handle``, so the query is the handle's local part — the same string as
        ``Group.name`` — and the ILIKE it runs is a candidate generator whose
        rows are then filtered to an exact handle.

        Everything that decides — the query, the exactness test, the page budget
        and the shortfall — is :class:`~rine._group_join.DirectoryHandleScan`'s,
        so the sync and async clients cannot drift on any of it. This is the
        fetch, and nothing else.

        🔴 **Authenticated on the wire, and deliberately not through**
        :meth:`discover_groups`. Both stacks now send the org's bearer token on
        this read; the TypeScript ladder always did, and a join that disclosed
        the caller on eve and mastra while disclosing nothing on the three Python
        connectors made any single statement about the rung false of one of them.
        The route takes no identity (``src/rine/api/directory_groups.py`` declares
        no auth dependency and rate-limits on the client IP), so the rows, the
        ``total_estimate`` and the budget are unchanged by the header — what
        changes is only that the two stacks now disclose the same thing.

        :meth:`discover_groups` stays anonymous: it is the public discovery verb,
        usable before an org has credentials, and narrowing it is not this rung's
        call to make.
        """
        scan = DirectoryHandleScan(handle)
        while (query := scan.next_query()) is not None:
            if scan.offer(self._directory_groups_page(**query, authenticated=True)):
                break
        return scan

    def _invited_group_id_by_bare_name(self, name: str, agent: str | None) -> str:
        """The group one of this agent's pending invitations calls ``name``.

        🔴 **The only rung a bare name gets, and two matches is a refusal.** A
        bare name carries no org, so two orgs inviting this agent to a group
        called ``ops`` are indistinguishable in the reference — and seating an
        agent in the wrong one cannot be undone. The candidates are printed
        instead. Nothing wider is searched; see
        :data:`~rine._group_join.BARE_NAME_IS_ONLY_AN_INVITATION`.

        Raises:
            NotFoundError: No invitation answers to the name, or more than one
                does.
        """
        matched = [
            invite
            for invite in self.groups.list_invites(agent=agent)
            if is_invitation_of_that_name(invite.group_handle, invite.group_name, name)
        ]
        if len(matched) == 1:
            return str(matched[0].group_id)
        if matched:
            raise NotFoundError(
                ambiguous_invitation_join_refusal(
                    name,
                    [
                        str(invite.group_handle or invite.group_name or invite.group_id)
                        for invite in matched
                    ],
                )
            )
        raise NotFoundError(bare_name_join_refusal(name))

    def _resolve_group_for_join_sync(self, handle_or_id: str, agent: str | None = None) -> str:
        """Resolve a group reference for JOIN — the one verb aimed outside the org.

        🔴 Deliberately **not** :meth:`_resolve_group_sync`. That ladder searches
        the groups the caller is already seated in, which for a join is the one set the
        target cannot be in; a handle read straight off ``discover_groups()``
        came back ``Group not found`` there with the server never refusing
        anything. The rungs, the bounds and every refusal are
        :mod:`rine._group_join`'s, and its module docstring is where the reasons
        live.

        Raises:
            NotFoundError: No rung resolved the reference.
        """
        if is_uuid(handle_or_id):
            return handle_or_id
        if "@" not in handle_or_id:
            return self._invited_group_id_by_bare_name(handle_or_id, agent)
        seated = self._seated_group_id_by_handle(handle_or_id)
        if seated is not None:
            return seated
        for invite in self.groups.list_invites(agent=agent):
            if is_exact_group_handle(invite.group_handle, handle_or_id):
                return str(invite.group_id)
        org_joinable = self._org_joinable_group_id_by_handle(handle_or_id)
        if org_joinable is not None:
            return org_joinable
        scan = self._scan_public_directory(handle_or_id)
        if scan.found is not None:
            return scan.found
        raise NotFoundError(unresolved_handle_join_refusal(handle_or_id, scan.unread))

    def _group_handle_for_bare_recipient(self, name: str, agent: str | None) -> str:
        """The group handle a bare ``send()`` recipient names, or a refusal.

        The agent list is asked FIRST, and it is the memoised one :meth:`send`
        has already fetched to resolve the acting agent, so the guard normally
        costs no request: a bare name that is also an agent's name refuses here
        rather than reaching the group tier. Only a name no agent of this org
        answers to is looked for among the groups.

        The **handle** comes back rather than the id because the group send path
        addresses ``to_handle`` — returning it lets the bare spelling rejoin the
        ``#handle`` path at the point it diverged, instead of growing a second
        send with its own encryption branch to keep in step.

        The reading, the guard and their order are the bare arm of
        :func:`rine._recipient_ladder.recipient_ladder`; this is that answer's
        handle.
        """
        return str(self.resolve_recipient(name, agent).handle)

    def _group_handle_for_sigil_recipient(self, name: str, agent: str | None) -> str:
        """The full group handle a ``#name`` (org-less) ``send()`` recipient names.

        The same ladder :meth:`_resolve_group_sync` already runs for every other
        group verb — ``groups.update``, the member and invite verbs, the vote,
        :meth:`thread` — reached through the one entry point that answers with
        the row, because the send path addresses ``to_handle``. ``send()`` was
        the single verb in the family that refused the spelling its siblings
        accept: it read the leading ``#`` as "this is already a full handle" and
        asked ``GET /groups?handle=#ops``, a filter that matches ``#name@org``
        only, so an org-less sigil was a guaranteed refusal with no roster and no
        candidates behind it.

        🔴 :func:`~rine._group_ref.refuse_if_a_bare_agent_name` deliberately does
        NOT run here, unlike on the bare path: that guard is for the ambiguity of
        an *unsigiled* word between two namespaces, and a caller who typed ``#``
        has already said which one they mean. The argument has one owner and is
        not restated here — :func:`~rine._group_ref.is_sigil_group_reference`.
        """
        return str(self.resolve_recipient(name, agent).handle)

    def _group_handle_for_id_recipient(self, reference: str, agent: str | None) -> str:
        """The group handle a UUID ``send()`` recipient names — or the UUID, unchanged.

        The synchronous twin of :meth:`rine.RineClient._group_handle_for_id_recipient`,
        which carries the whole argument: why the group probe goes first, why the
        ``kind`` test rather than the presence of an answer decides the rewrite,
        and why the dispatch above asks the shared classification table rather
        than :func:`~rine._resolve.is_uuid`.
        """
        target = self.resolve_recipient(reference, agent)
        if target.kind != "group":
            return reference
        handle = str(target.handle)
        note_group_id_recipient(reference, handle)
        return handle

    # --- Messaging ---

    def send(
        self,
        to: str,
        payload: dict[str, Any],
        *,
        message_type: str = MessageType.TASK_REQUEST,
        agent: str | None = None,
        idempotency_key: str | None = None,
        metadata: dict[str, Any] | None = None,
        content_type: str | None = None,
    ) -> MessageRead:
        """Send an encrypted message (1:1 or group).

        A recipient that is neither a UUID nor a handle is a **group name**:
        the agent namespace refuses a bare word before any request
        (:func:`rine._resolve.resolve_to_uuid_sync`), so it is resolved through
        :meth:`_group_handle_for_bare_recipient` and sent exactly as a
        ``#handle`` send is — one send path, one encryption branch. A ``#name``
        with no org takes the same ladder through
        :meth:`_group_handle_for_sigil_recipient`, so the spelling every other
        group verb accepts is accepted here too.

        A **UUID** is the one spelling that can name either namespace. It is
        offered to the group first and sent to the group when this org can read
        one of that id (:meth:`_group_handle_for_id_recipient`); anything else
        is the agent id it has always been.

        Args:
            to: Recipient handle, agent UUID, group UUID, group handle
                (``#logistics@acme.rine.network``), ``#name`` without the org,
                or the bare name of a group you hold a seat in.
            payload: JSON-serializable message payload.
            message_type: Message type.
            agent: Agent to send as.
            idempotency_key: Optional idempotency key.
            metadata: Optional cleartext (server-visible) message metadata, e.g.
                the x402 payment-status marker.
            content_type: Optional payload content type (e.g. ``application/json``).

        Returns:
            MessageRead of the sent message.

        Example::

            msg = client.send("kofi@acme.rine.network", {"task": "summarize"})
        """
        to = normalize_handle(to)
        agent_id = self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        headers = dict(extra) if extra else {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        if is_bare_reference(to):
            to = self._group_handle_for_bare_recipient(to, agent)
        elif is_sigil_group_reference(to):
            to = self._group_handle_for_sigil_recipient(to, agent)
        elif classify_reference(to) == REF_CLASS_ID:
            to = self._group_handle_for_id_recipient(to, agent)

        escrow_group_id: str | None = None
        if to.startswith("#"):
            result, body, group = self._encrypt_group(agent_id, to, payload, message_type)
            if result.escrow_fp is not None:
                escrow_group_id = str(group.id)
        else:
            _, body = self._encrypt_dm(agent_id, to, payload, message_type)

        apply_cleartext_fields(body, metadata, content_type)

        def post() -> Any:
            return self._http.post("/messages", json_body=body, extra_headers=headers or None)

        if escrow_group_id is None:
            return MessageRead.model_validate(post())
        # Imported here: importing ``rine._mls`` loads the compiled MLS core, which
        # the Sender Keys path never needs.
        from rine._mls.escrow_send import post_with_escrow_retry
        from rine._mls.heartbeat import MlsActor

        actor = MlsActor(client=self._http, config_dir=self._config_dir, agent_id=agent_id)
        return MessageRead.model_validate(post_with_escrow_retry(actor, escrow_group_id, post))

    def _encrypt_dm(
        self, agent_id: str, to: str, payload: object, msg_type: str
    ) -> tuple[Any, dict[str, Any]]:
        recipient_id = resolve_to_uuid_sync(self._api_url, to)
        recipient = fetch_recipient_keys_sync(self._http, recipient_id)
        warn_if_handle_moved(self._http.key_pins, to, recipient)
        result = encrypt_message(self._config_dir, agent_id, recipient, payload)
        body: dict[str, Any] = {
            "to_agent_id": recipient_id,
            "type": msg_type,
            "encrypted_payload": result.encrypted_payload,
            "encryption_version": result.encryption_version,
            "sender_signing_kid": result.sender_signing_kid,
        }
        # Sender self-read copy (1:1 only) so the sender can later read this
        # message back via thread(). Group sends leave it None (self-read via
        # the sender-key cache).
        if result.self_encrypted_payload is not None:
            body["self_encrypted_payload"] = result.self_encrypted_payload
        return result, body

    def _encrypt_group(
        self, agent_id: str, to: str, payload: object, msg_type: str
    ) -> tuple[Any, dict[str, Any], Any]:
        """Encrypt and build the body for a group message.

        🔴 **The wire carries the group the reference RESOLVED to, never the
        spelling the caller wrote.** ``POST /messages`` looks ``to_handle`` up by
        exact equality against the stored handle, so the two must be reconciled
        on this side — and the local-part fallback is what makes them differ: the ladder in
        :func:`rine._group_send.resolve_group_for_send` deliberately resolves a
        handle whose ORG half was fabricated, which is the shape a model
        produces when it copies the domain out of a tool description. Sending
        ``to`` posts that fabrication: the message is encrypted for the right
        group and then refused by the server with a bare ``Group not found``,
        which reads as "the ladder does not work" and is indistinguishable from
        it. This is the send path's half of the fix; the resolve alone was not
        one.

        Widening the SERVER's lookup instead would be the wrong side: it is
        global, not org-scoped, so a fuzzy match there could route a post into
        another org's group entirely.
        """
        from rine._group_send import encrypt_for_group_sync, group_message_body

        result, group = encrypt_for_group_sync(self._http, self._config_dir, agent_id, to, payload)
        return result, group_message_body(result, group, msg_type), group

    def inbox(
        self,
        *,
        agent: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        status: InboxStatus | None = None,
    ) -> CursorPage[DecryptedMessage]:
        """Read inbox messages with auto-decryption.

        Group rows self-heal like ``read()``: a message whose sender key has not
        been ingested yet triggers a pending-distribution fetch and one retry.
        A message that still cannot be opened carries ``decrypt_error`` — the
        inbox never raises on a single bad row.

        Args:
            agent: Agent to read as.
            limit: Max messages per page.
            cursor: Pagination cursor.
            status: Filter by delivery status (``"new"``, ``"delivered"``, or
                ``"read"``). When omitted, the server default applies.

        Returns:
            CursorPage of DecryptedMessage.

        Example::

            for msg in client.inbox(status="new", limit=10):
                print(msg.plaintext)
        """
        agent_id = self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        params: dict[str, Any] = {}
        if limit:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor
        if status is not None:
            params["status"] = status

        data = self._http.get(
            f"/agents/{agent_id}/messages", params=params or None, extra_headers=extra
        )
        raw_items = data.get("items", []) if isinstance(data, dict) else data

        messages: list[DecryptedMessage] = []
        for raw in raw_items:
            msg = DecryptedMessage.from_wire(raw)
            try:
                msg = self._decrypt_message(agent_id, msg)
            except CryptoError as e:
                msg = self._self_heal_group_decrypt(agent_id, msg, e)
            except Exception as e:  # noqa: BLE001 — degrade, never raise (inbox's contract)
                # The shared degrade, not a second copy of it: this arm once set
                # ``decrypt_error`` by hand, which meant every field the degrade
                # learns to carry — the cause code among them — was carried on
                # three paths out of four.
                msg = self._apply_decrypt_failure(msg, e)
            messages.append(msg)

        return CursorPage[DecryptedMessage](
            items=messages,
            total=self._page_total(data, messages),
            next_cursor=data.get("next_cursor") if isinstance(data, dict) else None,
            prev_cursor=data.get("prev_cursor") if isinstance(data, dict) else None,
        )

    def mark_delivered(self, message_ids: list[str], *, agent: str | None = None) -> int:
        """Mark messages as delivered for an agent (idempotent).

        Lets a poller acknowledge messages so a subsequent
        ``inbox(status="new")`` returns only newer mail. The acting agent is
        resolved internally (same precedence as ``inbox``/``send``), so callers
        pass a handle/name/UUID (or ``None`` for the default agent), never a
        pre-resolved ID.

        Args:
            message_ids: Message UUIDs to mark delivered.
            agent: Agent to mark deliveries for. ``None`` uses the client's
                configured/default agent.

        Returns:
            Number of messages newly marked delivered.
        """
        agent_id = self._resolve_agent_id(agent)
        data = self._http.post(
            f"/agents/{agent_id}/messages/mark-delivered",
            json_body={"message_ids": message_ids},
        )
        return int(data.get("marked", 0)) if isinstance(data, dict) else 0

    def read(
        self,
        message_id: str,
        *,
        agent: str | None = None,
        peek: bool = False,
    ) -> DecryptedMessage:
        """Fetch and decrypt a single message.

        Never raises on an unreadable row: a message this agent cannot open or
        verify comes back with ``decrypt_error`` set and ``plaintext = None``,
        exactly as it would from :meth:`inbox`. Check ``decrypt_error`` before
        touching ``plaintext``.

        Reading a message marks it delivered for the acting agent **whether or
        not it decrypts** — the server holds no key and stamps the mark before
        this client has tried — and there is no un-mark route, so the row leaves
        :meth:`inbox` with ``status="new"``, :meth:`poll` and SSE catch-up and
        stays fetchable only by id. Pass ``peek=True`` to read without
        consuming it.

        Reading a **group** message a second time is answered from a local copy,
        not from the group's cryptography, which spends a message's key on first
        use. This client keeps the newest 256 received messages per group — and
        at most 1 MiB of them, oldest dropped first — in its config directory, as
        plaintext under owner-only permissions and not encrypted at rest.
        Leaving a group from this client deletes that group's copy; being
        removed by somebody else does not, and the copy stays readable on this
        machine until the config directory is destroyed.

        Args:
            message_id: Message UUID.
            agent: Agent to read as.
            peek: Read without consuming the message — it stays new, and stays
                offered by ``inbox(status="new")``, :meth:`poll` and SSE
                catch-up. What an unattended loop wants for a message it may not
                be able to open yet: the acting agent is still named and still
                refused if it names nobody, so only the mark is suppressed.

        Returns:
            Decrypted message, or the message carrying ``decrypt_error``.
        """
        agent_id = self._resolve_agent_id(agent)
        extra = self._with_peek(self._agent_header(agent), peek=peek)
        data = self._http.get(f"/messages/{message_id}", extra_headers=extra)
        msg = DecryptedMessage.from_wire(data)
        try:
            return self._decrypt_message(agent_id, msg)
        except CryptoError as e:
            return self._self_heal_group_decrypt(agent_id, msg, e)
        except Exception as e:  # noqa: BLE001 — degrade, never raise (inbox's contract)
            return self._apply_decrypt_failure(msg, e)

    def _decrypt_message(self, agent_id: str, msg: DecryptedMessage) -> DecryptedMessage:
        """Decrypt a message in-place.

        Every branch is told which sender the server authenticated for the row, so
        an envelope signed by anyone else is refused rather than rendered as
        verified content from an agent that did not write it.
        """
        sender = self._expected_sender(agent_id, msg)
        if msg.encryption_version == EncryptionVersion.HPKE_HYBRID_V2:
            result = decrypt_message_sync(
                self._config_dir,
                agent_id,
                msg.encrypted_payload,
                self._http,
                sender,
                self._signed_for(msg),
                msg.created_at,
            )
        elif msg.encryption_version == EncryptionVersion.SENDER_KEY_V1 and msg.group_id:
            result = self._memoized_group_decrypt(
                agent_id,
                msg,
                sender,
                lambda: decrypt_group_message_sync(
                    self._config_dir,
                    agent_id,
                    str(msg.group_id),
                    msg.encrypted_payload,
                    self._http,
                    sender,
                    msg.created_at,
                ),
            )
        elif msg.encryption_version == EncryptionVersion.MLS_V1:
            from rine._mls.messages import decrypt_mls_group_message

            # MLS recovers inside the decrypt (install pending Welcomes, sync
            # commits, retry once), so there is nothing for the sender-key
            # self-heal to add — but the memo it shares with the sender-key path
            # still is: the core's self-read cache answers only for a message
            # THIS agent sent, never for a peer's.
            result = self._memoized_group_decrypt(
                agent_id,
                msg,
                sender,
                lambda: decrypt_mls_group_message(
                    self._http,
                    self._config_dir,
                    agent_id,
                    None if msg.group_id is None else str(msg.group_id),
                    msg.encrypted_payload,
                    sender,
                    msg.created_at,
                ),
            )
        elif is_a2a_cleartext(msg):
            return read_a2a_cleartext(msg)
        else:
            # An encryption_version this SDK does not know. Mark it explicitly so
            # it is never mistaken for a successfully-decrypted message with
            # empty plaintext — fail loud, never silent.
            msg.decrypt_error = (
                f"Unsupported encryption_version '{msg.encryption_version}'; "
                "the Python SDK cannot decrypt this message."
            )
            return msg
        msg.plaintext = result.plaintext
        msg.verified = result.verified
        msg.verification_status = result.verification_status
        # A sender that rotated past this client's cached key is reported, not
        # quietly absorbed — the caller decides what a rotation means to it.
        msg.key_changed = result.key_changed
        msg.catch_up = self._reported_catch_up(result)
        return msg

    def _memoized_group_decrypt(
        self,
        agent_id: str,
        msg: DecryptedMessage,
        sender: str,
        decrypt: Callable[[], DecryptResult],
    ) -> DecryptResult:
        """Decrypt a group row once per client, replaying repeats from the memo.

        Both group schemes step a single-use ratchet, so a row this client has
        already opened cannot be re-derived — and every receive surface sees rows
        more than once (``inbox()`` re-polls, ``read()`` after ``inbox()``,
        ``thread()`` over a group conversation). See :mod:`rine._crypto._decrypt_memo`.

        The memo answers what a row's bytes said, never who sent them, so a
        replay is held against the sender the server names on the row being read
        now. Without that, a row served again under a different sender would come
        back carrying the first read's ``verified``.
        """
        memoized = self._decrypt_memo.get(agent_id, str(msg.id))
        if memoized is not None:
            refuse_if_sender_differs(memoized.sender_kid, sender)
            return memoized
        result = decrypt()
        # Stored without the catch-up: this read applied those commits, and a
        # later read served from the memo applies nothing. Reporting the same
        # work twice would make the field mean "some read once did this".
        self._decrypt_memo.set(agent_id, str(msg.id), result.as_replay())
        return result

    def _self_heal_group_decrypt(
        self, agent_id: str, msg: DecryptedMessage, error: CryptoError
    ) -> DecryptedMessage:
        """Retry one failed group decrypt after ingesting pending sender keys.

        A group message whose sender key has not been ingested yet arrives before
        its distribution DM is opened, and would otherwise stay undecryptable
        forever. Shared by ``inbox()`` and ``read()``. Never raises — the failure
        is reported as ``decrypt_error``.
        """
        if msg.encryption_version != EncryptionVersion.SENDER_KEY_V1:
            return self._apply_decrypt_failure(msg, error)
        try:
            if self._retirement_blocks_read(agent_id, msg.group_id):
                return self._apply_decrypt_failure(msg, error)
            self._fetch_pending_sk_distributions(agent_id)
            return self._decrypt_message(agent_id, msg)
        except Exception as e:  # noqa: BLE001 — degrade, never raise (inbox is best-effort)
            return self._apply_decrypt_failure(msg, e)

    def _retirement_blocks_read(self, agent_id: str, group_id: UUID | None) -> bool:
        """Whether a retired group's keys stay refused, lifting the marker if not.

        🔴 The READ path's half of the retirement-marker lift. Without it the marker is spent
        only by SENDING — :func:`rine._sender_key_ops.get_or_create_sender_key_sync`
        is reachable from a group send and from nothing else — so a re-admitted
        agent that reads before it sends, and a read-only member that never sends
        at all, refused every distribution its new peers made it, permanently.

        A membership read that fails is not a lift: a departed agent is refused
        ``GET /groups/{id}/members`` outright and a transport failure proves
        nothing, so both keep the refusal.
        """
        if group_id is None:
            return False
        gid = str(group_id)
        if not sender_keys_retired(self._config_dir, agent_id, gid):
            return False
        try:
            data = self._http.get(f"/groups/{gid}/members")
        except Exception:
            logger.debug("group member read failed for group %s", gid, exc_info=True)
            return True
        items = data.get("items", data) if isinstance(data, dict) else data
        members = (str(m["agent_id"]) for m in items)
        return not lift_retirement_if_member(self._config_dir, agent_id, gid, members)

    def _fetch_pending_sk_distributions(self, agent_id: str) -> int:
        """Ingest what one page of the distribution inbox holds, and count it.

        🔴 Returns an ``int`` and stays an ``int``. Every read path in this SDK
        calls it, so widening it is a breaking change on the hottest path there
        is. The one caller that needs more than the count, the sync verb, calls
        :meth:`_scan_pending_sk_distributions` instead; this is that method with
        the second number dropped, never a second implementation of it.
        """
        return self._scan_pending_sk_distributions(agent_id).ingested

    def _scan_pending_sk_distributions(self, agent_id: str) -> SenderKeyScan:
        """The same pass, reporting what it did not reach as well as what it installed.

        The whole of the scan lives here and
        :meth:`_fetch_pending_sk_distributions` is one line over it, so the two
        cannot come to disagree about what a pass does.
        """
        from rine._crypto.keys import agent_id_from_kid
        from rine._crypto.message import decrypt_message_sync
        from rine._crypto.sender_keys_store import with_sender_key_states_sync
        from rine._crypto.sk_distribution import (
            already_held,
            distribution_group_id,
            sender_key_state_from_distribution,
        )

        data = self._http.get(
            f"/agents/{agent_id}/messages",
            params={"type": MessageType.SENDER_KEY_DISTRIBUTION, "limit": 100},
        )
        items = data.get("items", []) if isinstance(data, dict) else data
        # The page is always read to the end here, so what the pass did not open
        # is exactly what the listing holds beyond it.
        unscanned = unscanned_beyond_page(data, len(items))
        ingested = 0

        for raw in items:
            try:
                full = self._http.get(
                    f"/messages/{raw['id']}",
                    extra_headers=self._actor_header_dict(agent_id),
                )
                # The distribution DM is verified against the sender the server
                # stamped on the row it was listed as, never against the agent id
                # inside its own payload.
                result = decrypt_message_sync(
                    self._config_dir,
                    agent_id,
                    full["encrypted_payload"],
                    self._http,
                    str(full["from_agent_id"]),
                    created_at=datetime.fromisoformat(full["created_at"]),
                )
                if not result.verified:
                    continue
                payload = json.loads(result.plaintext)
                # Canonicalised, not taken verbatim: this id becomes a FILENAME and
                # every other reader of that file passes the server's lower-case
                # spelling. See ``rine._crypto.sk_distribution``.
                group_id = distribution_group_id(payload)
                # A group this agent retired never takes key material again.
                # The DMs that carried these keys are still in the inbox after a
                # leave, so without this the wipe would hold only until the next
                # group read that misses. The TypeScript twin refuses in
                # ``ingestSenderKeyDistribution``. The marker is spent by
                # MEMBERSHIP, and ``_self_heal_group_decrypt`` lifts it before
                # this scan runs — a re-admitted agent that only reads would
                # otherwise refuse every distribution forever.
                if sender_keys_retired(self._config_dir, agent_id, group_id):
                    continue
                # 🔴 The sync twin of the whole-array writer documented in
                # ``rine._client.RineClient._scan_pending_sk_distributions``, and it
                # takes the THREAD tier of the same region — the one a sync caller
                # is entitled to. There are no coroutines here to exclude, so the
                # tier is the whole of the exclusion this side needs and the whole
                # of what it gets: a host that drives a sync client on one thread
                # and an async one on another used to race here, and the two now
                # queue behind one another over one file. Two PROCESSES over one
                # config dir still race — residual 2 of that module, unchanged.
                with with_sender_key_states_sync(self._config_dir, agent_id, group_id):
                    states = load_sender_key_states(self._config_dir, agent_id, group_id)
                    # 🔴 The VERIFIED signer, never ``payload["sender_agent_id"]`` — the
                    # async twin's reasoning, and the same hole. The comment at the top of
                    # this loop already says the DM is verified "never against the agent
                    # id inside its own payload"; the row's identity then came from that
                    # very field. See
                    # ``rine._client.RineClient._scan_pending_sk_distributions``.
                    new_state = sender_key_state_from_distribution(
                        payload, group_id, agent_id_from_kid(result.sender_kid)
                    )
                    # Per SENDER, not per key id: a global check made the first
                    # distribution to claim an id the owner of that slot, so a shadow
                    # could displace a peer's genuine key. See
                    # :func:`rine._crypto.sk_distribution.already_held`.
                    if already_held(states, new_state):
                        continue
                    states.append(new_state)
                    save_sender_key_state(self._config_dir, agent_id, group_id, states)
                ingested += 1
            except Exception:
                logger.debug("SK ingestion failed", exc_info=True)
        return SenderKeyScan(ingested=ingested, unscanned=unscanned)

    def reply(
        self,
        message_id: str,
        payload: dict[str, Any],
        *,
        message_type: str = MessageType.TASK_RESPONSE,
        agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        content_type: str | None = None,
    ) -> MessageRead:
        """Reply to a message.

        Args:
            message_id: Message UUID to reply to.
            payload: Reply payload.
            message_type: Message type.
            agent: Agent to reply as — the agent the original was addressed to.
                Any other agent of the org is refused, because the reply is filed
                from the agent that acts.
            metadata: Optional cleartext (server-visible) message metadata, e.g.
                the x402 payment-status marker.
            content_type: Optional payload content type (e.g. ``application/json``).

        Returns:
            MessageRead of the reply.

        Raises:
            ReplyAttributionError: The acting agent is not the original's addressee.
        """
        agent_id = self._resolve_agent_id(agent)
        # Named read, then the attribution check — the async twin's reasoning.
        original = self._http.get(
            f"/messages/{message_id}",
            extra_headers=self._actor_header_dict(agent_id),
        )
        refuse_if_not_addressee(
            agent_id,
            str(message_id),
            original.get("to_agent_id"),
            original.get("from_agent_id"),
        )
        recipient_id = str(original.get("from_agent_id", ""))
        recipient = fetch_recipient_keys_sync(self._http, recipient_id)
        result = encrypt_message(self._config_dir, agent_id, recipient, payload)

        # The resolved id, not the caller's spelling — the async twin's reasoning.
        extra = self._actor_header_dict(agent_id)
        reply_body: dict[str, Any] = {
            "type": message_type,
            "encrypted_payload": result.encrypted_payload,
            "encryption_version": result.encryption_version,
            "sender_signing_kid": result.sender_signing_kid,
        }
        if result.self_encrypted_payload is not None:
            reply_body["self_encrypted_payload"] = result.self_encrypted_payload
        apply_cleartext_fields(reply_body, metadata, content_type)
        data = self._http.post(
            f"/messages/{message_id}/reply",
            json_body=reply_body,
            extra_headers=extra,
        )
        return MessageRead.model_validate(data)

    def _a_group_the_sync_endpoint_refuses(self, to: str, agent: str | None) -> bool:
        """Whether a ``send_and_wait`` recipient names a group — this verb's rule.

        The synchronous twin of
        :meth:`rine.RineClient._a_group_the_sync_endpoint_refuses`, which
        carries the whole argument: the two classes that name a group on this
        verb, why the UUID probe is eager rather than a reaction to the 1:1
        path's ``404``, and why a bare word is deliberately not one of them.
        """
        kind = classify_reference(to)
        if kind == REF_CLASS_GROUP:
            return True
        if kind != REF_CLASS_ID:
            return False
        return self._readable_group_by_id(to, agent) is not None

    def send_and_wait(
        self,
        to: str,
        payload: dict[str, Any],
        *,
        message_type: str = MessageType.TASK_REQUEST,
        timeout: float = 30.0,
        agent: str | None = None,
    ) -> SendAndWaitResult:
        """Send a message and wait for a reply.

        Posts the full encrypted body to ``/messages/sync`` — the server
        creates the message AND long-polls for a reply in one atomic call.
        Returns ``SendAndWaitResult`` with ``reply=None`` on timeout.

        Note: the sync endpoint is 1:1 only, so a group is refused before
        anything is sealed — named by handle or named by its own id
        (:meth:`_a_group_the_sync_endpoint_refuses`). Use :meth:`send` for a
        group.

        A reply that arrives but will not open is reported, never raised: the
        send has already landed and the answer is already on the wire, so the row
        comes back with ``decrypt_error`` set and ``plaintext = None``, exactly as
        it would from :meth:`read`. Check ``reply.decrypt_error`` before touching
        ``reply.plaintext``, and read ``reply=None`` as the timeout it is — a
        different outcome from a reply this agent could not read.

        Args:
            to: Recipient handle or agent UUID. A group is not a legal
                recipient here, by handle or by id.
            payload: Message payload.
            message_type: Message type.
            timeout: Max wait time in seconds (1-300).
            agent: Agent to send as.

        Returns:
            SendAndWaitResult with the sent message and one of three answers in
            ``reply``: the decrypted reply, ``None`` if the wait timed out, or the
            reply row carrying ``decrypt_error`` because it would not open.

        Raises:
            UnsupportedTargetError: The recipient names a group.
        """
        if self._a_group_the_sync_endpoint_refuses(to, agent):
            raise UnsupportedTargetError(
                "send_and_wait() does not support group handles — "
                "the /messages/sync endpoint is 1:1 only. "
                "Use send() to post to a group."
            )

        agent_id = self._resolve_agent_id(agent)
        extra = self._agent_header(agent)

        # Build the full encrypted body (same as send() does).
        _, body = self._encrypt_dm(agent_id, to, payload, message_type)

        data = self._http.post(
            "/messages/sync",
            json_body=body,
            params={"timeout_ms": int(timeout * 1000)},
            extra_headers=extra,
        )
        # Server returns SyncMessageResponse = {message, reply, conversation_id, status}.
        sent = MessageRead.model_validate(data["message"])
        raw_reply = data.get("reply")
        if raw_reply is not None:
            reply_msg = DecryptedMessage.from_wire(raw_reply)
            # The same degrade every other receive surface runs: the send has
            # already happened and the reply is already on the wire, so raising
            # here would take the whole call down over one unreadable answer and
            # hand the caller no row to inspect. There is no group self-heal arm
            # because ``/messages/sync`` is 1:1 only — a group is refused above,
            # before anything is sealed — so the arm ``read()`` has for a cold
            # sender key could only ever forward to this same degrade.
            try:
                reply_msg = self._decrypt_message(agent_id, reply_msg)
            except Exception as e:  # noqa: BLE001 — degrade, never raise (inbox's contract)
                reply_msg = self._apply_decrypt_failure(reply_msg, e)
            return SendAndWaitResult(sent=sent, reply=reply_msg)
        return SendAndWaitResult(sent=sent, reply=None)

    # --- Discovery ---

    def discover(
        self,
        *,
        q: str | None = None,
        category: str | None = None,
        tag: str | None = None,
        language: str | None = None,
        jurisdiction: str | None = None,
        verified: bool | None = None,
        pricing_model: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> CursorPage[AgentSummary]:
        """Search the agent directory.

        Args:
            q: Free-text search query.
            category: Filter by category.
            tag: Filter by tag.
            language: Filter by language.
            jurisdiction: Filter by jurisdiction.
            verified: Filter by verification status.
            pricing_model: Filter by pricing model.
            limit: Max results per page.
            cursor: Pagination cursor.

        Returns:
            CursorPage of AgentSummary.
        """
        params: dict[str, Any] = {}
        for k, v in [
            ("q", q),
            ("category", category),
            ("tag", tag),
            ("language", language),
            ("jurisdiction", jurisdiction),
            ("verified", verified),
            ("pricing_model", pricing_model),
            ("limit", limit),
            ("cursor", cursor),
        ]:
            if v is not None:
                params[k] = v
        data = self._http.get("/directory/agents", params=params or None, authenticated=False)
        items = data.get("items", []) if isinstance(data, dict) else data
        return CursorPage[AgentSummary](
            items=[AgentSummary.model_validate(a) for a in items],
            total=self._page_total(data, items),
            next_cursor=data.get("next_cursor") if isinstance(data, dict) else None,
        )

    def inspect(self, handle_or_id: str) -> AgentProfile:
        """Get full agent profile.

        Args:
            handle_or_id: Agent handle or UUID.

        Returns:
            AgentProfile.
        """
        agent_id = resolve_to_uuid_sync(self._api_url, handle_or_id)
        data = self._http.get(f"/directory/agents/{agent_id}", authenticated=False)
        # Unwrap A2A agent card envelope
        if "card" in data:
            card = data["card"]
            rine_ext = card.get("rine", {})
            return AgentProfile(
                id=rine_ext.get("agent_id", agent_id),
                name=card.get("name", ""),
                handle=rine_ext.get("handle", ""),
                description=card.get("description"),
                category=rine_ext.get("category"),
                verified=rine_ext.get("verified", False),
                human_oversight=rine_ext.get("human_oversight", True),
                trust_tier=rine_ext.get("trust_tier"),
                created_at=data.get("directory_metadata", {}).get("registered_at"),
            )
        return AgentProfile.model_validate(data)

    def discover_groups(
        self,
        *,
        q: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> CursorPage[GroupSummary]:
        """Search public groups.

        Args:
            q: Search query.
            limit: Max results.
            cursor: Pagination cursor.

        Returns:
            CursorPage of GroupSummary.
        """
        return self._directory_groups_page(q=q, limit=limit, cursor=cursor, authenticated=False)

    def _directory_groups_page(
        self,
        *,
        q: str | None,
        limit: int | None,
        cursor: str | None,
        authenticated: bool,
    ) -> CursorPage[GroupSummary]:
        """One ``GET /directory/groups`` page, asked with or without identity.

        🔴 ``authenticated`` is the ONLY thing the two callers differ in, and it
        is a wire-disclosure choice rather than a behaviour one: the route
        (``src/rine/api/directory_groups.py``) declares no auth dependency, so an
        ``Authorization`` header changes neither the rows nor ``total_estimate``
        nor the rate-limit bucket, which is keyed on the client IP either way.

        :meth:`discover_groups` is the PUBLIC discovery verb and stays anonymous,
        because it is documented as usable before an org has credentials at all.
        The join ladder's directory rung sends the token, matching what the
        TypeScript ladder has always sent, so one verb does not disclose two
        different things depending on which SDK the caller is running.
        """
        data = self._http.get(
            "/directory/groups",
            params=self._directory_group_params(q, limit, cursor),
            authenticated=authenticated,
        )
        return self._directory_group_page(data)

    # --- Identity ---

    def whoami(self) -> WhoAmI:
        """Get the caller's identity: its org, principal and visible agents.

        Works for every principal kind; a branch, agent or reader sees only the agents
        it may read.

        Returns:
            WhoAmI with org details, the principal and the agent list.

        Raises:
            OrgMismatchError: The server names a different org than this profile's.
            ConfigError: The caller can see no agent.
        """
        return parse_whoami(self._http.get("/whoami"), local_org_id=self._local_org_id())

    def poll(self) -> int:
        """Get undelivered message count (unauthenticated).

        Returns:
            Number of undelivered messages.
        """
        data = self._http.get(self._poll_url(), authenticated=False)
        return int(data.get("count", 0)) if isinstance(data, dict) else 0

    def create_agent(
        self,
        name: str,
        *,
        human_oversight: bool = True,
        unlisted: bool = False,
        verify_identity: bool = False,
        svid: str | None = None,
    ) -> AgentRead:
        """Create a new agent with generated keypairs.

        Args:
            name: Agent name.
            human_oversight: Whether agent requires human oversight.
            unlisted: Whether agent is unlisted.
            verify_identity: Run SPIFFE identity verification after creation.
            svid: Caller-supplied JWT-SVID for verification (implies verify).

        Returns:
            Created AgentRead. When verification runs, ``identity`` (success) or
            ``identity_error`` (failure) is populated; a verify failure never
            undoes creation.
        """
        return _create_agent(
            self._http,
            self._config_dir,
            self._owner_dir,
            name,
            human_oversight,
            unlisted,
            verify_identity=verify_identity,
            svid=svid,
        )

    def verify_identity(
        self,
        agent_id: str,
        *,
        svid: str | None = None,
    ) -> VerifyIdentityResult:
        """Prove control of a SPIFFE identity for an agent → org trust tier 2.

        Args:
            agent_id: Agent UUID to verify.
            svid: A SPIFFE JWT-SVID (compact JWS) for the challenge audience.

        Returns:
            VerifyIdentityResult with the recorded spiffe_id and trust tier.

        Raises:
            SpiffeVerificationError: If no ``svid`` is provided (auto-fetch is
                unavailable — there is no dependency-free Workload API client).
            NotFoundError / ConflictError / ValidationError / RateLimitError: On
                the corresponding challenge/verify HTTP failures.
        """
        return _verify_identity(self._http, agent_id, svid=svid)

    def update_agent(
        self,
        agent_id: str,
        *,
        name: str | NotGiven = NOT_GIVEN,
        human_oversight: bool | NotGiven = NOT_GIVEN,
        incoming_policy: str | NotGiven = NOT_GIVEN,
        outgoing_policy: str | NotGiven = NOT_GIVEN,
    ) -> AgentRead:
        """Update agent properties.

        Args:
            agent_id: Agent UUID.
            name: New agent name (cannot change after handle assignment).
            human_oversight: Whether agent requires human oversight.
            incoming_policy: ``"accept_all"`` or ``"groups_only"``.
            outgoing_policy: ``"send_all"`` or ``"groups_only"``.

        Returns:
            Updated AgentRead.

        Raises:
            ConflictError: If agent is revoked or rename after handle assignment.
            NotFoundError: If agent not found.
        """
        body = self._build_body(
            ("name", name),
            ("human_oversight", human_oversight),
            ("incoming_policy", incoming_policy),
            ("outgoing_policy", outgoing_policy),
        )
        data = self._http.patch(f"/agents/{agent_id}", json_body=body)
        return AgentRead.model_validate(data)

    def revoke_agent(self, agent_id: str) -> AgentRead:
        """Revoke (soft-delete) an agent.

        The agent's ``revoked_at`` timestamp is set; it cannot send or receive
        messages but remains in the database for audit purposes.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentRead with ``revoked_at`` populated.

        Raises:
            ConflictError: If agent is already revoked.
            NotFoundError: If agent not found.
        """
        data = self._http.delete(f"/agents/{agent_id}")
        return AgentRead.model_validate(data)

    def update_org(
        self,
        *,
        name: str | NotGiven = NOT_GIVEN,
        contact_email: str | NotGiven = NOT_GIVEN,
        country_code: str | NotGiven = NOT_GIVEN,
        slug: str | NotGiven = NOT_GIVEN,
    ) -> OrgRead:
        """Update organisation profile.

        Args:
            name: Organisation name.
            contact_email: Contact email address.
            country_code: Two-letter ISO country code (e.g. ``"DE"``).
            slug: DNS-safe slug (immutable once set).

        Returns:
            Updated OrgRead.

        Raises:
            ConflictError: If slug is already set (immutable).
            ValidationError: If field values are invalid.
        """
        body = self._build_body(
            ("name", name),
            ("contact_email", contact_email),
            ("country_code", country_code),
            ("slug", slug),
        )
        data = self._http.patch("/org", json_body=body)
        return OrgRead.model_validate(data)

    def erase_org(self, *, confirm: bool = False) -> ErasureResult:
        """Erase this organisation (GDPR right to erasure).

        Permanently deletes all agents, messages, groups, and anonymises
        the org record. **This action is irreversible.**

        Args:
            confirm: Must be ``True`` to proceed. Guards against accidental
                invocation.

        Returns:
            ErasureResult with deletion counts.

        Raises:
            ValueError: If ``confirm`` is not ``True``.
        """
        if not confirm:
            msg = "erase_org() permanently destroys all data. Pass confirm=True to proceed."
            raise ValueError(msg)
        org_id = self._get_org_id()
        data = self._http.delete(f"/orgs/{org_id}")
        return ErasureResult.model_validate(data)

    def _get_org_id(self) -> str:
        """Fetch and return the current org's ID."""
        org = OrgRead.model_validate(self._http.get("/org"))
        return str(org.id)

    def export_org(self) -> list[dict[str, Any]]:
        """Export all organisation data (GDPR data portability).

        Returns an NDJSON export of all org data including agents, messages,
        groups, keys, and webhooks. Each record is a dict with a ``type`` key.

        Returns:
            List of export records.

        Raises:
            RateLimitError: If called more than once per hour.
        """
        org_id = self._get_org_id()
        return self._http.get_ndjson(f"/orgs/{org_id}/export")

    # --- Conversations ---

    def update_conversation_status(self, conversation_id: str, status: str) -> ConversationRead:
        """Update a conversation's status.

        Args:
            conversation_id: Conversation UUID.
            status: New status (use ``ConversationStatus`` constants).

        Returns:
            Updated ConversationRead.

        Raises:
            ConflictError: If transition is invalid.
            NotFoundError: If conversation not found.
        """
        data = self._http.patch(
            f"/conversations/{conversation_id}/status",
            json_body={"status": status},
        )
        return ConversationRead.model_validate(data)

    def get_conversation(self, conversation_id: str) -> ConversationRead:
        """Get a conversation by ID.

        Args:
            conversation_id: Conversation UUID.

        Returns:
            ConversationRead.

        Raises:
            NotFoundError: If conversation not found.
        """
        data = self._http.get(f"/conversations/{conversation_id}")
        return ConversationRead.model_validate(data)

    def get_conversation_participants(self, conversation_id: str) -> list[ConversationParticipant]:
        """Get participants in a conversation.

        Args:
            conversation_id: Conversation UUID.

        Returns:
            List of ConversationParticipant.

        Raises:
            NotFoundError: If conversation not found.
        """
        data = self._http.get(f"/conversations/{conversation_id}/participants")
        items = data.get("items", data) if isinstance(data, dict) else data
        return [ConversationParticipant.model_validate(p) for p in items]

    def get_conversation_messages(
        self, conversation_id: str, *, agent: str | None = None, limit: int | None = None
    ) -> list[DecryptedMessage]:
        """Get the both-sided thread of a conversation, decrypted in place.

        Returns every message in the conversation — both sent and received,
        ordered oldest→newest — each decrypted with the caller's OWN keys: a
        ``direction == "sent"`` row is opened from its ``self_encrypted_payload``
        (sealed to self), a received row from ``encrypted_payload``, a group row
        via the normal group decrypt. A row the caller cannot decrypt (a legacy
        sent message with no self-blob, or any failure) comes back with
        ``decrypt_error`` set and ``plaintext is None`` — this method never
        raises on a single bad row.

        The sender's self-blob is sealed ``hpke-hybrid-v2`` to the sender's own
        keys, so a sent row reads like a received one.

        A conversation is fetched, never recovered: unlike :meth:`inbox`,
        :meth:`read` and :meth:`thread`, no row here triggers a distribution
        fetch. So a group row sealed under an absent sender key comes back
        saying that this read did not go looking, pointing at :meth:`read`, and
        carrying **no** ``decrypt_error_code`` — a row refused here is often
        opened by the very next :meth:`read`. Every such row carries that whole
        sentence in ``decrypt_error``.

        This method hands back rows for a caller's own renderer, and a caller
        cannot be charged for a fetch it did not ask for — :meth:`thread`, which
        renders the same rows itself, spends one scan for the whole transcript
        and states the verdict it thereby earns.

        Args:
            conversation_id: Conversation UUID.
            agent: Agent to read as.
            limit: Max messages (most-recent window). Server default applies when
                omitted.

        Returns:
            List of DecryptedMessage, ascending.

        Raises:
            NotFoundError: If the conversation is not found or not accessible.
        """
        return self._transcript_rows(
            conversation_transcript_path(conversation_id),
            agent=agent,
            limit=limit,
            refusal=SenderKeyRefusal(),
            recovery=None,
        )

    def _transcript_rows(
        self,
        path: str,
        *,
        agent: str | None,
        limit: int | None,
        refusal: SenderKeyRefusal,
        recovery: RenderRecovery | None,
    ) -> list[DecryptedMessage]:
        """Fetch and decrypt one transcript's rows under one render's refusal.

        Split out of :meth:`get_conversation_messages` so :meth:`thread` can hand
        the same :class:`~rine.sender_key_words.SenderKeyRefusal` to the decrypt
        and to the render.

        ``recovery`` is the transcript's one distribution scan, and it is
        required rather than defaulted because it is the whole difference
        between the two readers: :meth:`thread` renders the rows itself and
        passes a :class:`~rine._render_recovery.RenderRecovery`, so a row that
        still will not open has earned the verdict; :meth:`get_conversation_messages`
        passes ``None``, fetches nothing, and its refused rows carry no
        ``decrypt_error_code`` for a renderer to recognise them by — the refusal
        is what remembers them.

        It takes the *route* rather than a conversation id because a transcript
        has two of them — a conversation's and a group's — answering with the
        same ``ConversationMessagesPage`` and needing the identical decrypt,
        header and render. Deciding which route in the caller keeps the two
        reference shapes out of a function that has no opinion about them
        (:mod:`rine.thread_words` is where that opinion lives).
        """
        agent_id = self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        params = {"limit": limit} if limit else None
        data = self._http.get(path, params=params, extra_headers=extra)
        # The endpoint returns `{messages, truncated}` (ConversationMessagesPage),
        # NOT a cursor `{items}` page. Read the `messages` key.
        raw_items = data.get("messages", []) if isinstance(data, dict) else data

        messages: list[DecryptedMessage] = []
        for raw in raw_items:
            msg = DecryptedMessage.from_wire(raw)
            messages.append(self._decrypt_thread_row(agent_id, msg, refusal, recovery=recovery))
        return messages

    def _decrypt_thread_row(
        self,
        agent_id: str,
        msg: DecryptedMessage,
        refusal: SenderKeyRefusal,
        *,
        recovery: RenderRecovery | None,
    ) -> DecryptedMessage:
        """Decrypt a thread row direction-aware, never raising.

        For a ``direction == "sent"`` 1:1 row, swap in the ``self_encrypted_payload``
        before delegating to the existing ``_decrypt_message`` (no new crypto).
        A sent row with no self-blob, or any decrypt failure, sets
        ``decrypt_error``/``plaintext = None`` instead of raising.

        ``recovery`` decides which of the two refusals a missing sender key
        earns here, and it is required so every call site has to answer the
        question. Given a budget, the FIRST row that fails for want of sender-key
        state spends it on :meth:`_self_heal_group_decrypt` — the same ingest-and-
        retry ``inbox()`` and ``read()`` run — and every row of the render after
        it, including the ones that still will not open, is answered by a scan
        that did run: the earned verdict, with ``decrypt_error_code``. Given
        ``None``, nothing goes looking and ``refusal`` writes the weaker
        sentence.

        🔴 The budget is spent only for :class:`~rine.errors.NoSenderKeyStateError`,
        never for any other :class:`~rine.errors.CryptoError`. An MLS row's
        failure buys nothing from a sender-key distribution scan — the self-heal
        refuses a non-``sender-key-v1`` row outright — and burning the budget on
        it would silently downgrade every later sender-key row of the same
        transcript to a sentence no scan had earned. That narrowing is exact,
        not defensive: :class:`~rine.errors.NoSenderKeyStateError` is raised from
        the sender-key decrypt and from nowhere else, so the self-heal's
        version check can never be the arm a spent budget bought.

        ⚠️ One arm does spend the budget without scanning: a group whose sender
        keys this agent retired, where :meth:`_retirement_blocks_read` refuses
        before the listing. Deliberate, and not a downgrade — a transcript is one
        group, so every later row of it would reach that same refusal, and the
        verdict they take with the budget spent is byte-identical to the one they
        would take through the self-heal. Re-testing the retirement per row is
        what the budget exists to stop: that check is itself a
        ``GET /groups/{id}/members``.
        """
        is_group = msg.group_id is not None
        if msg.direction == "sent" and not is_group:
            if msg.self_encrypted_payload is None:
                msg.decrypt_error = "No self-seal blob for this sent message."
                return msg
            # The caller can only open the self-sealed copy of its own send, and
            # the self-blob is sealed to the SENDER's keys, so it is read as a
            # 1:1 payload whatever the row's ``encryption_version`` records.
            msg.encrypted_payload = msg.self_encrypted_payload
            msg.encryption_version = EncryptionVersion.HPKE_HYBRID_V2
        try:
            return self._decrypt_message(agent_id, msg)
        except Exception as e:  # noqa: BLE001 — degrade, never raise (inbox pattern)
            if recovery is not None and isinstance(e, NoSenderKeyStateError) and recovery.spend():
                return self._self_heal_group_decrypt(agent_id, msg, e)
            return self._apply_decrypt_failure(
                msg, e, no_recovery=refusal if recovery is None else None
            )

    def thread(
        self,
        conversation_id: str | None = None,
        *,
        group: str | None = None,
        agent: str | None = None,
        limit: int | None = None,
    ) -> list[ThreadEntry]:
        """Get the both-sided, role-tagged transcript of a conversation or a group.

        Fetches the conversation's rows — the same rows
        :meth:`get_conversation_messages` returns — and renders each to a
        :class:`ThreadEntry`. A row with ``decrypt_error`` or no plaintext
        renders ``text = "[unavailable]"``, except the one refusal below;
        otherwise the ``{"text": ...}`` payload shape is unwrapped to its string
        and any other plaintext is stringified (mirroring the TypeScript SDK
        render contract).

        The one refusal with a move for the operator to make is spelled out
        rather than flattened: the **first** row in this transcript sealed under
        a sender key this agent holds no state for carries the whole
        explanation, and every later one carries
        :data:`~rine.sender_key_words.SENDER_KEY_UNAVAILABLE_PREVIEW`. The
        budget is per call, so a second ``thread()`` explains again.

        A transcript that meets a group row it cannot open **goes looking**,
        once: the first such row ingests every pending sender-key distribution
        and retries, exactly as :meth:`read` does, and the rest of the render
        reads the state that scan installed. One scan answers the whole
        transcript because the scan is untargeted, so a row that still will not
        open afterwards carries the earned verdict and ``decrypt_error_code``. A
        transcript with nothing to recover pays nothing. The reader that fetches
        nothing at all is :meth:`get_conversation_messages`, which hands rows to
        a caller's own renderer.

        That scan opens the pending distribution DMs by id, so the server marks
        those DMs delivered. It touches the distribution DMs only, never the
        transcript's own rows, and only when a row failed.

        A **group** is named the way every other group verb takes it — a handle,
        a bare name or a UUID — and resolved the same way they all resolve it.
        ``conversation_id`` stays first and positional.

        Args:
            conversation_id: Conversation UUID. Name this or ``group``, never both.
            group: Group handle (``#name@org``), bare name, or UUID.
            agent: Agent to read as.
            limit: Max turns (most-recent window).

        Returns:
            List of ThreadEntry, ordered oldest→newest.

        Raises:
            ConfigError: Both references were named, or neither, or
                ``conversation_id`` is not a spelling the wire reads as a UUID.
            NotFoundError: ``group`` names no group this caller can see.
        """
        conversation_id, group = blank_as_absent(conversation_id), blank_as_absent(group)
        refuse_if_two_transcript_references(conversation_id, group)
        if group is not None:
            path = group_transcript_path(self._resolve_group_sync(group, agent))
        else:
            path = conversation_transcript_path(named_conversation_uuid(conversation_id))
        refusal = SenderKeyRefusal()
        messages = self._transcript_rows(
            path, agent=agent, limit=limit, refusal=refusal, recovery=RenderRecovery()
        )
        return [to_thread_entry(m, refusal) for m in messages]

    # --- Agent Cards ---

    def set_agent_card(
        self,
        agent_id: str,
        *,
        name: str,
        description: str,
        version: str | NotGiven = NOT_GIVEN,
        is_public: bool | NotGiven = NOT_GIVEN,
        skills: list[dict[str, Any]] | NotGiven = NOT_GIVEN,
        categories: list[str] | NotGiven = NOT_GIVEN,
        languages: list[str] | NotGiven = NOT_GIVEN,
        pricing_model: str | NotGiven = NOT_GIVEN,
    ) -> AgentCardRead:
        """Set (create or update) an agent's directory card.

        Args:
            agent_id: Agent UUID.
            name: Card display name (max 500, required).
            description: Card description (max 5000, required).
            version: Card version.
            is_public: Whether card appears in directory.
            skills: Skill entries (``{id, name, description, tags}``).
            categories: Rine extension categories.
            languages: Rine extension languages.
            pricing_model: ``free``, ``per_request``, ``subscription``, or ``negotiated``.

        Returns:
            AgentCardRead.

        Raises:
            ConflictError: If agent has no signing key.
            NotFoundError: If agent not found.
        """
        body: dict[str, Any] = {"name": name, "description": description}
        if not isinstance(version, NotGiven):
            body["version"] = version
        if not isinstance(is_public, NotGiven):
            body["is_public"] = is_public
        if not isinstance(skills, NotGiven):
            body["skills"] = skills
        # categories, languages, pricing_model go inside rine sub-object
        rine = self._build_body(
            ("categories", categories),
            ("languages", languages),
            ("pricing_model", pricing_model),
        )
        if rine:
            body["rine"] = rine
        data = self._http.put(f"/agents/{agent_id}/card", json_body=body)
        return AgentCardRead.model_validate(data)

    def get_agent_card(self, agent_id: str) -> AgentCardRead:
        """Get an agent's directory card.

        This is a public endpoint — no authentication required.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentCardRead.

        Raises:
            NotFoundError: If card not found.
        """
        data = self._http.get(f"/agents/{agent_id}/card", authenticated=False)
        return AgentCardRead.model_validate(data)

    def delete_agent_card(self, agent_id: str) -> None:
        """Delete an agent's directory card.

        Args:
            agent_id: Agent UUID.

        Raises:
            NotFoundError: If card not found.
        """
        self._http.delete(f"/agents/{agent_id}/card")

    # --- Key Rotation ---

    def rotate_keys(self, agent_id: str) -> RotatedAgent:
        """Rotate an agent's signing and encryption keypairs.

        Derives the next generation of the agent's keys, uploads the public
        halves, and saves the new private keys to the config directory.

        Args:
            agent_id: Agent UUID.

        Returns:
            RotatedAgent, with ``key_packages`` and ``group_seats`` added.

        Raises:
            ConflictError: If agent is revoked.
            NotFoundError: If agent not found.
        """
        return rotate_agent_with_seats(self._http, self._config_dir, self._owner_dir, agent_id)

    # --- MLS ---

    def republish_mls_key_packages(self, agent_id: str) -> MlsCutoverResult:
        """Discard the agent's MLS KeyPackage pool and publish a fresh one.

        Run this once when upgrading from a rine release that predates the
        current MLS core: KeyPackages published by the old one cannot be read by
        the new one, so a peer trying to add this agent to a group would fail on
        every stale entry. The stale packages are claimed out of the *server*
        pool, not merely outnumbered, so a peer can never claim one and fail.

        Args:
            agent_id: Agent UUID.

        Returns:
            The count drained from the server and the count freshly stored.
        """
        from rine._mls import drain_and_republish_mls_key_packages

        return drain_and_republish_mls_key_packages(self._http, self._config_dir, agent_id)

    # --- Agent Inspection ---

    def get_agent(self, agent_id: str) -> AgentRead:
        """Get a single agent by ID.

        Args:
            agent_id: Agent UUID.

        Returns:
            AgentRead.
        """
        data = self._http.get(f"/agents/{agent_id}")
        return AgentRead.model_validate(data)

    def list_agents(self, *, include_revoked: bool = False) -> list[AgentRead]:
        """List agents for the current org.

        Args:
            include_revoked: Include revoked agents.

        Returns:
            List of AgentRead.
        """
        params: dict[str, Any] | None = None
        if include_revoked:
            params = {"include_revoked": "true"}
        data = self._http.get("/agents", params=params)
        items = data.get("items", data) if isinstance(data, dict) else data
        return [AgentRead.model_validate(a) for a in items]

    # --- Poll Tokens ---

    def regenerate_poll_token(self, agent_id: str) -> PollTokenResponse:
        """Regenerate a poll token for an agent.

        Args:
            agent_id: Agent UUID.

        Returns:
            PollTokenResponse with poll_url.
        """
        data = self._http.post(f"/agents/{agent_id}/poll-token")
        return PollTokenResponse.model_validate(data)

    def revoke_poll_token(self, agent_id: str) -> None:
        """Revoke a poll token for an agent.

        Args:
            agent_id: Agent UUID.
        """
        self._http.delete(f"/agents/{agent_id}/poll-token")

    # --- Quotas ---

    def get_quotas(self) -> OrgQuotas:
        """Get organisation quota information.

        Returns:
            OrgQuotas with tier and quota entries.
        """
        data = self._http.get("/org/quotas")
        return OrgQuotas.model_validate(data)

    # --- Streaming ---

    def stream(self, *, agent: str | None = None) -> Iterator[Event]:
        """Stream server-sent events.

        Args:
            agent: Agent to stream as.

        Yields:
            Event objects from the SSE stream.
        """
        agent_id = self._resolve_agent_id(agent)
        extra = self._agent_header(agent)
        for event_type, event_data, event_id in self._http.stream_sse(
            f"/agents/{agent_id}/stream", extra_headers=extra
        ):
            yield Event(event=event_type, data=event_data, id=event_id)
