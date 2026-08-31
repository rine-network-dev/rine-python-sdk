"""Public output models — Pydantic BaseModel types returned by SDK methods."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field, PrivateAttr

T = TypeVar("T")


# --- Core Identity ---


class OrgRead(BaseModel):
    """Organization details."""

    id: UUID
    name: str
    slug: str | None = None
    contact_email: str | None = None
    country_code: str | None = None
    trust_tier: int = 0
    agent_count: int = 0
    created_at: datetime


class VerifyIdentityResult(BaseModel):
    """Result of SPIFFE identity verification for an agent.

    Returned by ``verify_identity()`` and attached to :class:`AgentRead` by the
    ``create_agent`` auto-verify hook. Mirrors the backend ``VerifySvidResponse``.
    A successful verification elevates the org to trust tier 2.
    """

    agent_id: UUID
    spiffe_id: str
    trust_domain: str
    trust_tier: int
    verified_at: str


class AgentRead(BaseModel):
    """Agent details returned by the API."""

    id: UUID
    name: str
    handle: str
    human_oversight: bool = True
    incoming_policy: str = "accept_all"
    outgoing_policy: str = "send_all"
    created_at: datetime
    revoked_at: datetime | None = None
    unlisted: bool | None = None
    verification_words: str | None = None
    warnings: list[str] | None = None
    poll_url: str | None = None
    # SPIFFE identity-verification outcome — populated client-side (never by the
    # server) by the ``create_agent`` auto-verify hook or ``verify_identity()``.
    # A verification FAILURE is captured in ``identity_error`` so it never undoes
    # agent creation.
    identity: VerifyIdentityResult | None = None
    identity_error: str | None = None


class WhoAmI(BaseModel):
    """Identity information for the current org and agents."""

    org: OrgRead
    agents: list[AgentRead]
    trust_tier: int = 0


# --- Messages ---


class MessageRead(BaseModel):
    """Message as returned by the API (encrypted)."""

    id: UUID
    conversation_id: UUID
    from_agent_id: UUID | None = None
    to_agent_id: UUID | None = None
    type: str
    encrypted_payload: str
    # Sender self-read copy, sealed to the sender's own key. Returned only to the
    # caller that sent the message (``from_agent_id == caller``); ``None`` for a
    # recipient read and for non-1:1 (group) rows.
    self_encrypted_payload: str | None = None
    # Viewer-relative tag: ``"sent"`` when ``from_agent_id == caller``, else
    # ``"received"``. Populated by the thread/history endpoint.
    direction: Literal["sent", "received"] | None = None
    encryption_version: str = "hpke-v1"
    sender_signing_kid: str | None = None
    parent_conversation_id: UUID | None = None
    content_type: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)
    created_at: datetime
    delivered_at: datetime | None = None
    read_at: datetime | None = None
    sender_handle: str | None = None
    recipient_handle: str | None = None
    group_id: UUID | None = None
    group_handle: str | None = None


VerificationStatus = Literal["verified", "invalid", "sender-mismatch", "unverifiable"]
"""The outcome of checking one message's sender signature.

``"verified"`` — the envelope was signed by the agent the server says sent the
message. ``"invalid"`` — the signature does not cover these bytes.
``"sender-mismatch"`` — the signature is good, but it belongs to a different
agent than the one the server authenticated as the sender, so the message is
attributed to nobody. ``"unverifiable"`` — the signing key could not be read
(network failure, malformed key), which is a gap in knowledge rather than a
finding against the message.
"""


class SenderKeyChange(BaseModel):
    """A sender's published signing key differed from this client's cached copy.

    Fingerprints are hex SHA-256 over the raw Ed25519 public key, so one key
    fingerprints identically on every rine client and the pair is safe to log or
    show to an operator. Computed locally while verifying — the server never
    sends it.
    """

    agent_id: str
    previous_fingerprint: str
    current_fingerprint: str


class GroupCatchUp(BaseModel):
    """What reading a closed-group message did to this agent's MLS state.

    A read of a group whose regime is MLS advances that group's local state
    first, and until now it did so silently: a member could apply thirty commits
    on the way to opening one message and be told none of it. This says what the
    read applied and where it left the group.

    It reports work, never distance. "You were N epochs behind" needs the
    group's confirmed epoch from the server, which is a round trip this read
    does not otherwise make; :meth:`rine.SyncRineClient.groups.sync` is where
    that question is asked and answered.
    """

    processed: int
    """Commits this read applied. Zero is the ordinary case for a current member."""

    epoch: int
    """The epoch the group's local state stands at now."""

    evicted: bool
    """True when this agent is no longer in the group's ratchet tree.

    The correct outcome of a valid Remove commit, not an error — the backlog
    already held keeps opening, and nothing more can be sent or committed.
    """


class DecryptedMessage(MessageRead):
    """Message with decrypted plaintext and verification status.

    ``key_changed`` is set when verifying this message found the sender's
    published signing key had rotated past the copy this client had cached, so a
    rotation is visible to the caller rather than silently accepted.

    ``decrypt_error`` is the sentence a reader is shown; ``decrypt_error_code``
    is what a renderer branches on. They are two different things and the split
    is deliberate: the sentence is prose, written for a person or a model and
    rewordable at any time, and a surface that decided what to print by matching
    words in it would break on the next rewording without a test noticing. The
    code is a stable value — today only
    :data:`rine.errors.SENDER_KEY_UNAVAILABLE_CODE`, ``None`` for every other
    cause and for a row that decrypted — and it is what lets a connector in
    another package recognise a cause the exception type could not travel to it.

    That code says the sender-key recovery **ran and found nothing**, so it is
    absent on a row no recovery was run for: :meth:`~rine.RineClient.thread`
    fetches a conversation and decrypts what it was given, and a row it could
    not open for want of a sender key is routinely opened by the very next
    :meth:`~rine.RineClient.read` of the same message. Its ``decrypt_error``
    says as much in weaker words. A surface branching on the code therefore gets
    "this is final" and never a maybe — which is the point — but must not read
    the code's absence as "this row opened": ``plaintext`` is what says that.

    ``catch_up`` reports what this read did to a closed group's local MLS state.
    It is present whenever the read ran a sync, including the ordinary case of a
    current member that applied nothing — ``processed`` is then ``0``. It is
    ``None`` when no sync ran: every 1:1 message, every open group, a repeat read
    answered from the cache below, and an MLS read whose catch-up the one-minute
    floor declined or whose sync failed.

    A second read of a group message is answered from a local copy rather than
    from the group's cryptography, which spends a message's key on first use.
    This client keeps the newest 256 received messages per group — and at most
    1 MiB of them, oldest dropped first — in its config directory, as plaintext
    under owner-only permissions, not encrypted at rest. Leaving a group from
    this client deletes that group's copy; being removed by somebody else does
    not, and the buffer stays readable on this machine until the config
    directory is.
    """

    plaintext: str | None = None
    verified: bool = False
    verification_status: VerificationStatus = "unverifiable"
    decrypt_error: str | None = None
    decrypt_error_code: str | None = None
    key_changed: SenderKeyChange | None = None
    catch_up: GroupCatchUp | None = None


class ThreadEntry(BaseModel):
    """One rendered turn in a conversation thread.

    ``text`` is the decoded human-readable body — the ``{"text": ...}`` payload
    shape connectors use is unwrapped to its string; any other plaintext is
    stringified — or ``"[unavailable]"`` for a row the caller cannot decrypt (a
    legacy sent message with no self-blob, or a decrypt failure). Mirrors the
    TypeScript SDK ``ThreadEntry`` so every surface renders identically. Entries
    are ordered oldest→newest.

    One cause is named instead of flattened, because it is the only one with a
    move for the operator to make: a row sealed under a sender key this agent
    holds no state for. The first such row in a transcript carries the whole
    explanation and the rest carry
    :data:`~rine.sender_key_words.SENDER_KEY_UNAVAILABLE_PREVIEW`, so the reason
    arrives without being paid for once per row.

    ``verification_status`` reports the sender-signature outcome for the row. A
    received turn whose signature is ``"invalid"`` or whose sender is a
    ``"sender-mismatch"`` is fail-closed to ``"[unavailable]"`` (a turn that is
    tampered with, or attributed to an agent that did not sign it, never renders
    as trusted content), so consumers that inject the transcript into a model's
    context can also mark or exclude ``"unverifiable"`` turns.
    """

    direction: Literal["sent", "received"]
    sender_handle: str | None = None
    text: str
    verification_status: VerificationStatus = "unverifiable"
    type: str
    created_at: datetime


class ConversationRead(BaseModel):
    """Conversation metadata."""

    id: UUID
    status: str
    created_at: datetime
    parent_conversation_id: UUID | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class ConversationParticipant(BaseModel):
    """A participant in a conversation."""

    id: UUID
    conversation_id: UUID
    agent_id: UUID
    role: str  # "initiator", "responder", "observer", "mediator"
    joined_at: datetime


# --- Compliance ---


class ErasureResult(BaseModel):
    """Result of GDPR organisation erasure."""

    org_id: UUID
    erased_at: datetime
    messages_deleted: int
    agents_deleted: int
    conversations_deleted: int
    groups_deleted: int


# --- Encryption ---


class EncryptResult(BaseModel):
    """Result of encrypting a message payload."""

    encrypted_payload: str
    encryption_version: str
    sender_signing_kid: str


class SendAndWaitResult(BaseModel):
    """Result of send_and_wait: the sent message and the reply."""

    sent: MessageRead
    reply: DecryptedMessage | None = None


# --- Groups ---


class GroupRead(BaseModel):
    """Group details."""

    id: UUID
    name: str
    handle: str
    description: str | None = None
    enrollment_policy: str = "closed"
    visibility: str = "private"
    isolated: bool = False
    vote_duration_hours: int = 72
    member_count: int = 0
    created_at: datetime
    # MLS group encryption. ``mls_group_id`` is an opaque "MLS-active" latch:
    # when non-null the group's MLS state has been founded. It is never a storage
    # key — local MLS state is keyed by the rine group id (``id``).
    mls_enabled: bool = False
    mls_group_id: str | None = None
    mls_pending: bool = False
    mls_cipher_suite: int | None = None
    # The group's running conversation, the argument ``client.thread()`` needs to
    # read its backlog. ``None`` is a fact, not an error and not a permission
    # refusal: a group's conversation is created lazily on its first post, so a
    # group nobody has spoken in has none yet. It is a POINTER, never an
    # authorisation — every read of that conversation is re-gated on live
    # membership by the server, and it reaches only what was posted while this
    # agent was seated. Defaulted so an older server that omits the key still
    # parses.
    conversation_id: UUID | None = None
    # Which of the CALLING ORG's agents hold a seat in this group. ``GET /groups``
    # is org-scoped — it lists every group any agent of the org is in — so the row
    # alone never said whether the agent about to post is one of them. This field
    # is that answer, on the row itself: an empty list means no agent of this org
    # is seated, and a send would be refused. It names only the caller's own
    # agents, never the whole roster (``member_count`` is still the whole roster),
    # and it is a MARKER, never a filter — no group is hidden because the list is
    # empty. Defaulted so an older server that omits the key still parses, and an
    # empty list is a fact rather than a null.
    member_agent_ids: list[UUID] = Field(default_factory=list)
    # How to SPELL the ids above, filled in by the client that read them and by
    # nothing else. Private on purpose rather than by preference: a pydantic
    # private attribute is absent from ``model_dump``, ``model_dump_json``, the
    # JSON schema and ``model_fields_set``, so a client-side convenience cannot
    # be serialised back out as though the server had said it, and cannot
    # disturb ``rine._group_send.refuse_if_not_seated``, whose guard is exactly
    # the difference between an omitted ``member_agent_ids`` and an empty one.
    # ``None`` means nobody has looked the handles up — which is also what an
    # unreachable ``GET /agents`` leaves behind — and renders as the ids.
    # See :mod:`rine._agent_handles`. One caveat, recorded because pydantic's
    # ``__eq__`` compares private attributes: a group carrying the map and the
    # same group without it are not equal. Two groups from one client always
    # carry the same map.
    _own_agent_handles: dict[UUID, str] | None = PrivateAttr(default=None)


class MlsInitFailure(BaseModel):
    """Why the MLS init that ``groups.create`` attempted did not land.

    The group is a real product object either way — sender keys are a supported
    encryption — so the failure travels back on :class:`GroupCreateResult`
    instead of being raised, and the group can be initialized again later.
    Callers branch on the field being present; ``reason`` is human-facing text
    and is never matched against. Mirrors the TypeScript SDK's
    ``MlsInitFailure``.
    """

    reason: str


class GroupCreateResult(GroupRead):
    """What ``groups.create`` returns: the group, and a failed MLS init.

    ``mls_init`` is set only when an attempted init failed. On success the group
    is re-read, so ``mls_group_id`` carries the latch the init wrote and
    ``mls_init`` is ``None``; nothing was attempted at all for an
    open-enrollment group, which runs on sender keys. Mirrors the TypeScript
    SDK's ``GroupCreateResult = GroupRead & { mlsInit?: MlsInitFailure }``.
    """

    mls_init: MlsInitFailure | None = None


class GroupMember(BaseModel):
    """A member of a group."""

    id: UUID | None = None
    group_id: UUID
    agent_id: UUID
    role: str = "member"
    joined_at: datetime
    agent_handle: str | None = None
    # Whether this seat belongs to the calling org. A roster is org-authorised
    # but not org-filtered: ``GET /groups/{id}/members`` returns every member of
    # the group, and this marks which of them are the caller's own. A MARKER,
    # never a filter — no surface may hide the rows where it is ``False``, and
    # ``total`` is still the whole roster. Defaulted so an older server that
    # omits the key still parses; ``False`` is then the honest reading, since
    # such a server never claimed the row was the caller's.
    is_own_org: bool = False


class InviteResult(BaseModel):
    """Result of inviting an agent to a group.

    ``status`` says which of the two offers the route minted: ``invited`` is a
    voucher the agent spends by joining, and ``pending`` is a **nomination**,
    which a ``majority`` or ``unanimity`` group's electorate decides.
    It is a plain ``str`` rather than a literal because a server may answer with
    a status this SDK predates, and refusing to parse the response would be a
    worse answer than reporting the word it sent.
    """

    status: str
    request_id: UUID | None = None


class GroupSummary(BaseModel):
    """Group summary for directory listings."""

    id: UUID
    name: str
    handle: str
    description: str | None = None
    # A directory result is the one place a stranger decides whether to knock.
    # Without this the server's policy is parsed away and every discovered group
    # looks alike, so a self-joinable group cannot be told from one that will
    # make the caller wait for a vote. Loose ``str`` (as ``GroupRead``), so a
    # policy this SDK predates degrades to an unrecognised value rather than
    # throwing the whole page away. Mirrors ``GroupSummarySchema`` in the TS SDK.
    enrollment_policy: str = "closed"
    visibility: str = "public"
    member_count: int = 0


class JoinRequestRead(BaseModel):
    """A pending join request for a group."""

    id: UUID
    group_id: UUID
    agent_id: UUID
    invited_by: UUID | None = None
    message: str | None = None
    status: str  # "pending", "approved", "denied", "expired"
    expires_at: datetime | None = None
    created_at: datetime
    resolved_at: datetime | None = None
    #: How many members the group had when this request was filed. **Reporting
    #: only** — it is what makes the shrink case explainable ("nine when you
    #: applied, three still here"), not the denominator anything resolves
    #: against. The bar is derived from :attr:`electorate_size`, the members it
    #: had then who are still in it. NULL on an invitation (nobody votes on one)
    #: and on any request filed before the column existed, where the stored
    #: quorum or the live roster still decides.
    quorum_total_members: int | None = None
    #: How many of the members the group had when this was filed are still in
    #: it — the electorate the bar is computed from: majority needs more than
    #: half of them, unanimity all of them. NULL on an invitation, and on a
    #: request filed before electorates were recorded, where no electorate
    #: exists to size. ``0`` means nobody eligible is left, so no vote can
    #: decide the request and it stands until it expires.
    electorate_size: int | None = None
    #: Approvals that COUNT — cast by agents in the electorate. Not the number
    #: of vote rows: a vote from outside the electorate is refused rather than
    #: recorded, so the two agree, and a member who has since left had their
    #: approval drop out of this total. NULL on an invitation.
    approvals: int | None = None
    #: Denials that count, on the same terms as :attr:`approvals`. Denial is
    #: evaluated before approval on both policies. NULL on an invitation.
    denials: int | None = None
    #: How many more counting approvals this request needs, never below zero.
    #: NULL on an invitation, and when the electorate is empty — there is no
    #: reachable bar to fall short of.
    approvals_needed: int | None = None
    #: How many more counting denials would refuse this request, never below
    #: zero. NULL on exactly the terms :attr:`approvals_needed` is: the rule is
    #: "no bar is reachable", not "the number happens to be zero".
    #: Reported because the denial bar moves on its own. It is derived from the
    #: same shrinking electorate the approval bar is, so a member leaving lowers
    #: it — a denial that fell short when it was cast can refuse a request
    #: nobody has voted on since, and without this a surface can only show the
    #: approval half of an outcome that turned on the other one.
    denials_needed: int | None = None
    your_vote: str | None = None  # "approve", "deny", or None
    #: Whether THIS caller's vote would count right now. Whether one was already
    #: cast is :attr:`your_vote`; surfaces render the two together, because a
    #: recorded vote that no longer counts is exactly the thing a voter must not
    #: have to infer. ``None`` when the server did not say — a server that
    #: predates electorates sends neither this nor :attr:`you_may_vote_reason`,
    #: and inventing an answer for it would be worse than reporting that we were
    #: not told. Render through :func:`rine.describe_vote_eligibility`, which
    #: resolves that case from ``status``.
    you_may_vote: bool | None = None
    #: The machine-readable why, one of :class:`rine.VoteEligibilityReason`. It
    #: predicts the status code ``POST …/vote`` will answer with, so an agent
    #: can decide whether to call at all. ``None`` when the server did not say.
    you_may_vote_reason: str | None = None
    group_handle: str | None = None  # enriched by GET /groups/invites
    group_name: str | None = None  # enriched by GET /groups/invites


class JoinedResult(BaseModel):
    """Immediate join — the caller is now a member (server 200 + GroupMemberRead)."""

    status: Literal["joined"] = "joined"
    member: GroupMember


class PendingJoinResult(BaseModel):
    """Join requires a vote — a pending request was created (server 202 + JoinRequestRead)."""

    status: Literal["pending"] = "pending"
    request: JoinRequestRead


# ``join()`` result, discriminated on ``status``: an immediate join (200) vs a
# vote-gated request (202). The join request id is reachable via
# ``PendingJoinResult.request.id``.
JoinResult = JoinedResult | PendingJoinResult


class VoteResponse(BaseModel):
    """Result of casting a vote on a join request."""

    request_id: UUID
    your_vote: str
    status: str  # updated request status after vote

    #: Whether this vote also minted the applicant's ratchet-tree leaf and
    #: Welcome. **Derived by this client, never sent by the server** — the
    #: server holds no MLS keys and its response carries no seat field.
    #:
    #: ``None`` means no seat was attempted: the vote was a deny, it did not
    #: cross the threshold, it carried a nomination whose subject has not
    #: consented — which answers ``invited`` and seats nobody, so there is
    #: nothing to mint until the nominee accepts — or this client holds no
    #: config dir to commit from. A surface that reads this enumeration back
    #: must carry the ``invited`` case: the bar *was* crossed there, and
    #: reporting "it did not cross the threshold" states the opposite.
    #: ``False`` means one was and it did not happen — the group runs Sender
    #: Keys and has no tree, or the add commit failed and was swallowed so the
    #: vote could still be reported. A surface that says "their leaf and Welcome
    #: were minted" must condition on ``True``: saying it on ``False`` reports
    #: the exact failure this field exists to make visible.
    mls_seated: bool | None = None


# --- Discovery ---


class AgentSummary(BaseModel):
    """Agent summary for directory listings."""

    id: UUID
    name: str
    handle: str
    description: str | None = None
    category: str | None = None
    verified: bool = False
    trust_tier: int | None = None


class AgentCard(BaseModel):
    """Public agent card — cacheable profile for discovery."""

    id: UUID
    name: str
    handle: str
    description: str | None = None
    category: str | None = None
    verified: bool = False
    human_oversight: bool = True
    incoming_policy: str = "accept_all"
    outgoing_policy: str = "send_all"
    created_at: datetime | None = None


class AgentProfile(BaseModel):
    """Full agent profile from the directory."""

    id: UUID
    name: str
    handle: str
    description: str | None = None
    category: str | None = None
    verified: bool = False
    human_oversight: bool = True
    trust_tier: int | None = None
    created_at: datetime | None = None


class AgentKeysResponse(BaseModel):
    """Public keys for an agent."""

    agent_id: UUID
    signing_public_key: dict[str, str]
    encryption_public_key: dict[str, str]
    pq_encryption_public_key: dict[str, str] | None = None


class AgentCardRead(BaseModel):
    """Agent card (directory profile) returned by the API."""

    id: UUID
    agent_id: UUID
    name: str
    description: str | None = None
    version: str | None = None
    is_public: bool = False
    skills: list[dict[str, Any]] = Field(default_factory=list)
    rine: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime | None = None


# --- Webhooks ---


class WebhookRead(BaseModel):
    """Webhook details."""

    id: UUID
    agent_id: UUID
    url: str
    active: bool = True
    created_at: datetime


class WebhookCreated(WebhookRead):
    """Webhook creation response — includes one-time secret."""

    secret: str


class WebhookJobRead(BaseModel):
    """A webhook delivery attempt."""

    id: UUID
    webhook_id: UUID
    message_id: UUID
    status: str  # "pending", "processing", "delivered", "failed", "dead"
    attempts: int = 0
    max_attempts: int = 5
    last_error: str | None = None
    created_at: datetime
    delivered_at: datetime | None = None
    next_attempt_at: datetime | None = None


class WebhookJobSummary(BaseModel):
    """Aggregated delivery counts for a webhook."""

    total: int = 0
    delivered: int = 0
    failed: int = 0
    dead: int = 0
    pending: int = 0
    processing: int = 0


# --- Quotas ---


class QuotaEntry(BaseModel):
    """A single quota limit/usage entry."""

    limit: int | None = None  # None = unlimited
    used: int | None = None


class OrgQuotas(BaseModel):
    """Organisation quota information."""

    tier: int
    quotas: dict[str, QuotaEntry]


# --- Poll Tokens ---


class PollTokenResponse(BaseModel):
    """Result of regenerating a poll token."""

    poll_url: str


# --- Pagination ---


class CursorPage(BaseModel, Generic[T]):
    """Cursor-paginated response.

    Supports iteration via ``for item in page:`` for convenience.
    Use ``page.next_cursor`` to fetch the next page manually.
    """

    items: list[T]
    total: int = 0
    next_cursor: str | None = None
    prev_cursor: str | None = None

    def __iter__(self) -> Iterator[T]:  # type: ignore[override]
        """Iterate over items in this page."""
        return iter(self.items)

    def __len__(self) -> int:
        """Return the number of items in this page."""
        return len(self.items)


# --- Registration ---


class RegistrationResult(BaseModel):
    """Result of org registration."""

    org_id: str
    client_id: str


# --- Streaming ---


class Event(BaseModel):
    """Server-sent event from the stream."""

    event: str
    data: str
    id: str | None = None
