"""SDK constants and NOT_GIVEN sentinel."""

from __future__ import annotations

from typing import Any

DEFAULT_API_URL = "https://rine.network"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
TOKEN_REFRESH_MARGIN = 60  # base seconds before expiry to trigger refresh (jittered per client)
TOKEN_REFRESH_JITTER = 120  # max extra seconds added to the base margin, drawn once per client
TOKEN_RETRY_ATTEMPTS = 3  # max attempts for the OAuth token POST (D-3)
TOKEN_RETRY_TOTAL_CAP = 30.0  # max cumulative backoff sleep across token retries (seconds)
KEY_CACHE_TTL = 600.0  # seconds an agent's public keys stay cached client-side (D-5)
KEY_CACHE_MAX_ENTRIES = 256  # max distinct agents cached before LRU eviction
MAX_SKIP = 1000  # max skipped sender keys cached
ROTATION_MESSAGE_LIMIT = 100
ROTATION_AGE_MS = 7 * 24 * 60 * 60 * 1000  # 7 days


class _NotGiven:
    """Sentinel to distinguish 'not provided' from ``None``.

    Use ``NOT_GIVEN`` as default parameter value when ``None`` is a valid
    user-supplied value. Check with ``isinstance(val, NotGiven)`` or
    ``val is NOT_GIVEN``.
    """

    def __repr__(self) -> str:
        return "NOT_GIVEN"

    def __bool__(self) -> bool:
        return False


NOT_GIVEN: Any = _NotGiven()
"""Sentinel indicating a parameter was not provided."""

NotGiven = _NotGiven
"""Type alias for the NOT_GIVEN sentinel, for use in type annotations."""


# --- Wire format constants ---


class EncryptionVersion:
    """Encryption version identifiers used in the wire protocol."""

    HPKE_V1 = "hpke-v1"
    SENDER_KEY_V1 = "sender-key-v1"
    MLS_V1 = "mls-v1"


class MessageType:
    """Message type identifiers used in the wire protocol."""

    TASK_REQUEST = "rine.v1.task_request"
    TASK_RESPONSE = "rine.v1.task_response"
    TEXT = "rine.v1.text"
    SENDER_KEY_DISTRIBUTION = "rine.v1.sender_key_distribution"
    GROUP_INVITE = "rine.v1.group_invite"
    WEBHOOK = "rine.v1.webhook"
    # x402 payments (v1.0) — E2EE payload is the verbatim x402 V2 object.
    X402_PAYMENT_REQUIRED = "rine.v1.x402_payment_required"
    X402_PAYMENT = "rine.v1.x402_payment"
    X402_RECEIPT = "rine.v1.x402_receipt"


class ConversationStatus:
    """Conversation status values for the state machine."""

    SUBMITTED = "submitted"
    OPEN = "open"
    PAUSED = "paused"
    INPUT_REQUIRED = "input_required"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELED = "canceled"
    FAILED = "failed"


class JoinRequestStatus:
    """Status values for group join requests."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class VoteChoice:
    """Vote choices for group join requests."""

    APPROVE = "approve"
    DENY = "deny"


class WebhookJobStatus:
    """Status values for webhook delivery jobs."""

    PENDING = "pending"
    PROCESSING = "processing"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD = "dead"


RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504, 408})
