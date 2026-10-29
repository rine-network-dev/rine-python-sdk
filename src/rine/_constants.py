"""SDK constants and NOT_GIVEN sentinel."""

from __future__ import annotations

from typing import Any

DEFAULT_API_URL = "https://rine.network"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
TOKEN_REFRESH_MARGIN = 60  # base seconds before expiry to trigger refresh (jittered per client)
TOKEN_REFRESH_JITTER = 120  # max extra seconds added to the base margin, drawn once per client
TOKEN_RETRY_ATTEMPTS = 3  # max attempts for the OAuth token POST
TOKEN_RETRY_TOTAL_CAP = 30.0  # max cumulative backoff sleep across token retries (seconds)
KEY_CACHE_TTL = 600.0  # seconds an agent's public keys stay cached client-side
KEY_CACHE_MAX_ENTRIES = 256  # max distinct agents cached before LRU eviction
DECRYPT_MEMO_MAX_ENTRIES = 256  # max group messages memoized per client before LRU eviction
MLS_HEARTBEAT_MIN_INTERVAL_S = 60.0  # shortest gap between two gated MLS heartbeats and sweeps


# --- Limits restated from the server, and from the TypeScript stack ---
#
# The Python SDK **cannot import** ``src/rine/core/group_limits.py`` or
# ``src/rine/api/mls_schemas.py``: the backend and this SDK both own the
# top-level ``rine`` import package, so only one of them exists in any given
# interpreter. Every number below is therefore a restatement, and this block is
# the ONLY sanctioned place for one — ``tests/test_client-server-contract_group0.py``
# pins each against the definition it copies, the same way that gate
# already pins ``rine-core``'s copy of the Welcome rate. Never restate one of
# these anywhere else in the SDK; import it from here.
#
# The group-size ceiling itself (``MAX_GROUP_MEMBERS``) is deliberately NOT
# among them: nothing in this SDK enforces it. The server refuses a full group
# in rine's own vocabulary, naming both populations and the remedy, and a client
# copy of the rule could only ever be a second, worse version of that sentence.

#: Base64 bytes one MLS Welcome costs per seated member, MEASURED at N=1000 on
#: the post-quantum suite. ``rine.core.group_limits.MLS_WELCOME_B64_PER_MEMBER``,
#: and the same number ``rine-core/src/mls-founding.ts`` carries as
#: ``WELCOME_B64_PER_MEMBER``. It is what ``MLS_BLOB_MAX_B64`` is derived from,
#: so a batch sized against a drifted copy is sized against the wrong cap.
MLS_WELCOME_B64_PER_MEMBER = 1_868

#: Welcome entries one ``POST /groups/{id}/mls/commit`` accepts —
#: ``rine.api.mls_schemas.MLS_WELCOMES_PER_COMMIT_MAX``. The upper clamp on the
#: size-aware batch below, never the batch itself.
MLS_WELCOMES_PER_COMMIT_MAX = 32

#: Agent ids one ``POST /agents/mls/key-packages/claim`` accepts —
#: ``rine.api.mls_schemas.MLS_BATCH_CLAIM_AGENTS_MAX``, which matches the cap on
#: ``GET /agents/keys``. The client chunks to it rather than trusting the server
#: to take whatever it sends: an unchunked client against a server-side id cap
#: is the live defect this wave closes on the sender-key side.
MLS_CLAIM_AGENTS_MAX = 200

#: Base64 bytes one founding/add commit POST may weigh. A CLIENT budget, not a
#: server cap: mirrors ``MLS_FOUNDING_POST_BUDGET_B64`` in
#: ``rine-core/src/mls-founding.ts`` so the two stacks batch identically. Its
#: derivation — why 8 MiB is a floor as well as a ceiling — is stated there and
#: is not repeated here, because a second copy of the reasoning would drift too.
MLS_FOUNDING_POST_BUDGET_B64 = 8 * 1024 * 1024

#: Size-independent remainder of a Welcome, and the commit's UpdatePath plus the
#: republished GroupInfo priced in Welcomes. Both MEASURED and both mirrored
#: from ``rine-core/src/mls-founding.ts`` (``WELCOME_B64_BASE``,
#: ``COMMIT_AND_GROUP_INFO_IN_WELCOMES``). The intercept is what makes the
#: estimate an UPPER bound at every measured size: under-estimating is what
#: produces an oversized POST, so the model error is spent in the safe direction.
MLS_WELCOME_B64_BASE = 13_100
MLS_COMMIT_AND_GROUP_INFO_IN_WELCOMES = 2


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


#: The request header that reads a message without consuming it.
#:
#: The twin of ``rine.api.message_words.PEEK_HEADER``. Two constants bound by a
#: test rather than one import, for the reason ``rine._actor`` states: the
#: backend and this SDK both own the top-level ``rine`` import package, so no
#: interpreter holds both. Boolean-valued on the wire — see the server constant
#: for the accepted spellings; this stack sends ``"1"``.
#:
#: Deliberately not re-exported from ``rine/__init__``. ``AGENT_HEADER`` is
#: public because a caller building raw requests needs it; the peek surface is
#: ``read(peek=True)``, and publishing the header would invite a second,
#: hand-rolled copy of the one decision both clients must share.
PEEK_HEADER = "X-Rine-Peek"


class EncryptionVersion:
    """Encryption version identifiers used in the wire protocol."""

    HPKE_HYBRID_V2 = "hpke-hybrid-v2"
    SENDER_KEY_V1 = "sender-key-v1"
    MLS_V1 = "mls-v1"
    #: The A2A cleartext carve-out; no rine client ever sends it.
    NONE = "none"


class MessageType:
    """Message type identifiers used in the wire protocol."""

    TASK_REQUEST = "rine.v1.task_request"
    TASK_RESPONSE = "rine.v1.task_response"
    TEXT = "rine.v1.text"
    SENDER_KEY_DISTRIBUTION = "rine.v1.sender_key_distribution"
    GROUP_INVITE = "rine.v1.group_invite"
    WEBHOOK = "rine.v1.webhook"
    # Terminal types (PROTOCOL.md §4.1): they close an exchange rather than open one, so a
    # receiving agent records them instead of answering them.
    RECEIPT = "rine.v1.receipt"
    ERROR = "rine.v1.error"
    # x402 payments (v1.0) — E2EE payload is the verbatim x402 V2 object.
    X402_PAYMENT_REQUIRED = "rine.v1.x402_payment_required"
    X402_PAYMENT = "rine.v1.x402_payment"
    X402_RECEIPT = "rine.v1.x402_receipt"
    A2A_MESSAGE = "rine.v1.a2a_message"


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


class VoteEligibilityReason:
    """Why this caller's vote on a join request would, or would not, count.

    The server computes one of these per listed request and it predicts, one to
    one, what ``POST /groups/{id}/requests/{rid}/vote`` will answer: the first
    two are a 200, ``not_in_electorate``, ``electorate_empty`` and
    ``bar_unreachable`` are a 403 with the electorate code, ``is_applicant`` is
    a 403 — for want of membership, and carrying the ``is_applicant`` code
    itself once the group has seated the caller by another route while its own
    request still stands — ``already_voted`` is a 409 and ``not_pending``
    a 422. A surface that renders the reason therefore never has to guess
    whether voting is worth the call — which is why the one-to-one mapping is
    the invariant the whole read model rests on, and why an applicant reading
    its own request is told ``is_applicant`` rather than a token that predicts
    the wrong refusal.

    Declared in the order the published tables list them, and the server
    resolves them highest-precedence first: ``not_pending``, ``is_applicant``,
    ``electorate_empty``/``bar_unreachable``, ``not_in_electorate``,
    ``already_voted``, ``electorate_not_recorded``, ``in_electorate``. If the
    vote cannot count, that is the fact to report.
    """

    #: The caller was a member when the request was filed, and still is.
    IN_ELECTORATE = "in_electorate"
    #: Filed before the group recorded electorates, so any current member votes.
    ELECTORATE_NOT_RECORDED = "electorate_not_recorded"
    #: The caller joined after the request was filed.
    NOT_IN_ELECTORATE = "not_in_electorate"
    #: The caller already cast a vote on this request; it cannot be changed.
    ALREADY_VOTED = "already_voted"
    #: Nobody who was a member when this was filed is still in the group.
    ELECTORATE_EMPTY = "electorate_empty"
    #: No electorate was recorded for this request and the bar is zero, so no
    #: vote can carry it. Distinct from :attr:`ELECTORATE_EMPTY`, which asserts
    #: that a recorded electorate has entirely left — a claim about a set
    #: nobody wrote is not one to make.
    BAR_UNREACHABLE = "bar_unreachable"
    #: This is the caller's own request. An applicant does not decide it.
    IS_APPLICANT = "is_applicant"
    #: The row is not open for voting — an invitation, or already resolved.
    NOT_PENDING = "not_pending"


class WebhookJobStatus:
    """Status values for webhook delivery jobs."""

    PENDING = "pending"
    PROCESSING = "processing"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD = "dead"


RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504, 408})

#: The branch a first agent is minted under, and the one registration seeds.
MAIN_BRANCH = "main"
