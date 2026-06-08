"""Public output models — Pydantic BaseModel types returned by SDK methods."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Iterator, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

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
    encryption_version: str = "hpke-v1"
    sender_signing_kid: str | None = None
    content_type: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)
    created_at: datetime
    delivered_at: datetime | None = None
    read_at: datetime | None = None
    sender_handle: str | None = None
    recipient_handle: str | None = None
    group_id: UUID | None = None
    group_handle: str | None = None


class DecryptedMessage(MessageRead):
    """Message with decrypted plaintext and verification status."""

    plaintext: str | None = None
    verified: bool = False
    verification_status: Literal["verified", "invalid", "unverifiable"] = "unverifiable"
    decrypt_error: str | None = None


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


class DecryptResult(BaseModel):
    """Result of decrypting a message payload."""

    plaintext: str
    sender_kid: str
    verified: bool
    verification_status: Literal["verified", "invalid", "unverifiable"]


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
    # when non-null the group uses MLS (unsupported by the Python SDK), never
    # a storage key. See errors.MlsUnsupportedError.
    mls_enabled: bool = False
    mls_group_id: str | None = None
    mls_pending: bool = False
    mls_cipher_suite: int | None = None


class GroupMember(BaseModel):
    """A member of a group."""

    id: UUID | None = None
    group_id: UUID
    agent_id: UUID
    role: str = "member"
    joined_at: datetime
    agent_handle: str | None = None


class JoinResult(BaseModel):
    """Result of attempting to join a group."""

    status: str
    group: GroupRead | None = None
    request_id: UUID | None = None


class InviteResult(BaseModel):
    """Result of inviting an agent to a group."""

    status: str
    request_id: UUID | None = None


class GroupSummary(BaseModel):
    """Group summary for directory listings."""

    id: UUID
    name: str
    handle: str
    description: str | None = None
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
    your_vote: str | None = None  # "approve", "deny", or None


class VoteResponse(BaseModel):
    """Result of casting a vote on a join request."""

    request_id: UUID
    your_vote: str
    status: str  # updated request status after vote


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
