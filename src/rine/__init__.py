"""Rine Python SDK — E2E-encrypted messaging for AI agents.

Two first-class client peers:

- ``RineClient`` — async (``async with RineClient() as client:``)
- ``SyncRineClient`` — sync (``with SyncRineClient() as client:``)

Quick start::

    from rine import SyncRineClient

    with SyncRineClient() as client:
        client.send("agent@org", {"task": "hello"})
        for msg in client.inbox():
            print(msg.plaintext)
"""

from rine._client import RineClient
from rine._constants import (
    NOT_GIVEN,
    ConversationStatus,
    EncryptionVersion,
    JoinRequestStatus,
    MessageType,
    NotGiven,
    VoteChoice,
    WebhookJobStatus,
)
from rine._onboard import async_register as async_onboard
from rine._onboard import register as onboard
from rine._sync_client import SyncRineClient
from rine._version import __version__
from rine.errors import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    AuthorizationError,
    ConfigError,
    ConflictError,
    CryptoError,
    InternalServerError,
    MlsUnsupportedError,
    NotFoundError,
    RateLimitError,
    RineApiError,
    RineError,
    ServiceUnavailableError,
    ValidationError,
    format_error,
)
from rine.types import (
    AgentCard,
    AgentCardRead,
    AgentKeysResponse,
    AgentProfile,
    AgentRead,
    AgentSummary,
    ConversationParticipant,
    ConversationRead,
    CursorPage,
    DecryptedMessage,
    DecryptResult,
    EncryptResult,
    ErasureResult,
    Event,
    GroupMember,
    GroupRead,
    GroupSummary,
    InviteResult,
    JoinRequestRead,
    JoinResult,
    MessageRead,
    OrgQuotas,
    OrgRead,
    PollTokenResponse,
    QuotaEntry,
    RegistrationResult,
    SendAndWaitResult,
    VoteResponse,
    WebhookCreated,
    WebhookJobRead,
    WebhookJobSummary,
    WebhookRead,
    WhoAmI,
)

__all__ = [
    # Clients
    "RineClient",
    "SyncRineClient",
    # Onboarding
    "async_onboard",
    "onboard",
    # Types - Output models
    "AgentCard",
    "AgentCardRead",
    "AgentKeysResponse",
    "AgentProfile",
    "AgentRead",
    "AgentSummary",
    "ConversationParticipant",
    "ConversationRead",
    "CursorPage",
    "DecryptedMessage",
    "DecryptResult",
    "EncryptResult",
    "ErasureResult",
    "Event",
    "GroupMember",
    "GroupRead",
    "GroupSummary",
    "InviteResult",
    "JoinRequestRead",
    "JoinResult",
    "MessageRead",
    "OrgQuotas",
    "OrgRead",
    "PollTokenResponse",
    "QuotaEntry",
    "RegistrationResult",
    "SendAndWaitResult",
    "VoteResponse",
    "WebhookCreated",
    "WebhookJobRead",
    "WebhookJobSummary",
    "WebhookRead",
    "WhoAmI",
    # Constants
    "ConversationStatus",
    "EncryptionVersion",
    "JoinRequestStatus",
    "MessageType",
    "VoteChoice",
    "WebhookJobStatus",
    # Errors
    "APIConnectionError",
    "APITimeoutError",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigError",
    "ConflictError",
    "CryptoError",
    "InternalServerError",
    "MlsUnsupportedError",
    "NotFoundError",
    "RateLimitError",
    "RineApiError",
    "RineError",
    "ServiceUnavailableError",
    "ValidationError",
    "format_error",
    # Sentinel
    "NOT_GIVEN",
    "NotGiven",
    # Version
    "__version__",
]
