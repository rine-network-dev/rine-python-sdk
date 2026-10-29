"""Internal input types — TypedDict parameters and private data structures."""

from __future__ import annotations

from typing import Any, NotRequired, TypedDict


class SendParams(TypedDict):
    """Parameters for sending a message."""

    to: str
    payload: dict[str, Any]
    message_type: NotRequired[str]
    agent: NotRequired[str]
    idempotency_key: NotRequired[str]


class InboxParams(TypedDict):
    """Parameters for reading the inbox."""

    agent: NotRequired[str]
    limit: NotRequired[int]
    cursor: NotRequired[str]


class DiscoverParams(TypedDict):
    """Parameters for discovering agents."""

    q: NotRequired[str]
    category: NotRequired[str]
    tag: NotRequired[str]
    language: NotRequired[str]
    jurisdiction: NotRequired[str]
    verified: NotRequired[bool]
    pricing_model: NotRequired[str]
    limit: NotRequired[int]
    cursor: NotRequired[str]


class GroupCreateParams(TypedDict):
    """Parameters for creating a group."""

    name: str
    enrollment: NotRequired[str]
    visibility: NotRequired[str]
    agent: NotRequired[str]


class GroupJoinParams(TypedDict):
    """Parameters for joining a group."""

    handle_or_id: str
    message: NotRequired[str]
    agent: NotRequired[str]


class SenderKeyStateDict(TypedDict):
    """Serialized sender key state (JSON-compatible)."""

    senderKeyId: str
    groupId: str
    senderAgentId: str
    chainKey: str  # base64url
    messageIndex: int
    skippedKeys: NotRequired[dict[str, str]]  # index_str -> base64url
    distributedTo: NotRequired[list[str]]
    createdAt: NotRequired[int]


class Profile(TypedDict):
    """One principal's entry in ``profiles.json``. It holds no secret."""

    org_id: str
    principal: str
    branch: NotRequired[str]
    agent_id: NotRequired[str]
    poll_url: NotRequired[str]


class CachedToken(TypedDict):
    """A cached OAuth token."""

    access_token: str
    expires_at: float
