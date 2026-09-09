"""Rine Python SDK — E2E-encrypted messaging for AI agents.

Two first-class client peers:

- ``RineClient`` — async (``async with RineClient() as client:``)
- ``SyncRineClient`` — sync (``with SyncRineClient() as client:``)

Quick start::

    from rine import SyncRineClient

    with SyncRineClient() as client:
        client.send("kofi@acme.rine.network", {"task": "hello"})
        for msg in client.inbox():
            print(msg.plaintext)
"""

from rine._actor import (
    AGENT_HEADER,
    ResolvedActor,
    normalize_actor,
    single_actor_value,
)
from rine._client import RineClient
from rine._config import resolve_api_url, resolve_config_dir
from rine._constants import (
    NOT_GIVEN,
    ConversationStatus,
    EncryptionVersion,
    JoinRequestStatus,
    MessageType,
    NotGiven,
    VoteChoice,
    VoteEligibilityReason,
    WebhookJobStatus,
)
from rine._crypto._sender_verify import is_authenticity_failure
from rine._group_join import JOIN_REFERENCE_RULE
from rine._group_recovery import SenderKeyRecoveryResult
from rine._group_ref import (
    GROUP_ROSTER_LEAD,
    NO_GROUPS_IN_ORG,
    is_bare_reference,
    is_sigil_group_reference,
)
from rine._onboard import async_register, register
from rine._onboard import async_register as async_onboard
from rine._onboard import register as onboard
from rine._recipient import (
    REF_CLASS_AGENT,
    REF_CLASS_BARE,
    REF_CLASS_EMPTY,
    REF_CLASS_GROUP,
    REF_CLASS_ID,
    GroupTarget,
    RecipientTarget,
    classify_reference,
)
from rine._resolve import is_uuid, normalize_handle
from rine._resources.group_ops import VISIBILITY_REQUIRED_MESSAGE
from rine._sync_client import SyncRineClient
from rine._version import __version__
from rine.admission_words import (
    admission_headline,
    admitted_agent_ids,
    describe_admission_entry,
    describe_mls_admission,
    describe_mls_outcome,
    describe_mls_reclamation,
    group_admission_skip_sentence,
    mls_admission_skip_sentence,
)
from rine.errors import (
    GROUP_EVICTED_CODE,
    MLS_RESYNC_UNAVAILABLE_CODE,
    SENDER_KEY_UNAVAILABLE_CODE,
    WELCOME_REFUSED_CODE,
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    AuthorizationError,
    ConfigError,
    ConflictError,
    CryptoError,
    GroupEvictedError,
    GroupIdentityMismatchError,
    InternalServerError,
    MlsError,
    MlsResyncUnavailableError,
    MlsWelcomeRefusedError,
    NoMlsGroupStateError,
    NoSenderKeyStateError,
    NotAGroupMemberError,
    NotFoundError,
    RateLimitError,
    ReplyAttributionError,
    RineApiError,
    RineError,
    SenderMismatchError,
    ServiceUnavailableError,
    SignatureVerificationError,
    SpiffeVerificationError,
    UnpersistedSenderKeyStateError,
    UnsupportedTargetError,
    ValidationError,
    WelcomeRefusalReason,
    format_error,
)
from rine.group_admission import (
    GroupAdmissionEntry,
    GroupAdmissionReport,
    GroupAdmissionSkipReason,
    GroupCreateWithRoster,
    GroupInviteReport,
    OutstandingFilter,
)
from rine.group_removal import GroupRemovalEncryption, GroupRemovalResult
from rine.group_words import (
    ACTING_AGENT_SPELLING,
    NO_OWN_AGENTS,
    NO_SEAT_TO_ACT_AS,
    NOT_A_MEMBER_CLAUSE,
    SEATED_SIBLING_CLAUSE,
    is_not_a_member,
    not_a_member_message,
    own_agents_clause,
)
from rine.sender_key_words import SENDER_KEY_UNAVAILABLE_PREVIEW, SenderKeyRefusal
from rine.thread_words import TRANSCRIPT_REFERENCE_REQUIRED, not_a_conversation_uuid
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
    EncryptResult,
    ErasureResult,
    Event,
    GroupCatchUp,
    GroupCreateResult,
    GroupMember,
    GroupRead,
    GroupSummary,
    InviteResult,
    JoinedResult,
    JoinRequestRead,
    JoinResult,
    MessageRead,
    MlsInitFailure,
    OrgQuotas,
    OrgRead,
    PendingJoinResult,
    PollTokenResponse,
    QuotaEntry,
    RegistrationResult,
    SendAndWaitResult,
    SenderKeyChange,
    ThreadEntry,
    VerificationStatus,
    VerifyIdentityResult,
    VoteResponse,
    WebhookCreated,
    WebhookJobRead,
    WebhookJobSummary,
    WebhookRead,
    WhoAmI,
)
from rine.verification_display import (
    compare_verification_words_for_agent,
    verification_words_lines,
)
from rine.verification_words import (
    VerificationWordsComparison,
    VerificationWordsStatus,
    compare_verification_words,
    verification_words_for_jwk,
    verification_words_for_key,
)
from rine.vote_words import (
    VOTE_DURATION_DEFAULT_HOURS,
    VOTE_DURATION_MAX_HOURS,
    VOTE_DURATION_MIN_HOURS,
    VOTE_DURATION_RULE,
    VOTE_ELECTORATE_RULE,
    describe_expiry,
    describe_vote_counts,
    describe_vote_eligibility,
    may_vote,
    render_request_row,
    vote_eligibility_reason,
)

__all__ = [
    # Clients
    "RineClient",
    "SyncRineClient",
    # Onboarding. ``register``/``async_register`` are the TypeScript SDK's and
    # the CLI's spelling of the same two functions, bound here to the very
    # objects ``onboard``/``async_onboard`` name — a reader who reaches for the
    # word the rest of the product uses finds it, and neither spelling is a
    # second implementation that can drift from the other.
    "async_onboard",
    "async_register",
    "onboard",
    "register",
    # Resolution & config helpers
    "is_uuid",
    "normalize_handle",
    # The acting-agent contract. Public because the framework wrappers are
    # separate packages that must not re-declare the wire header, re-invent
    # the trim rule, or hand-roll the "named twice" refusal — three things
    # that drifted apart on the TypeScript stack before one place held them.
    # ``ResolvedActor`` joins them for the same reason: it is what
    # ``RineClient.resolve_actor`` returns, and ``rine-hermes`` renders its
    # warning on a model-facing tool result.
    "AGENT_HEADER",
    "ResolvedActor",
    "normalize_actor",
    "single_actor_value",
    # Which of an org's agents hold a seat in a group, on both sides of the
    # gate: the clause a group row prints, and the refusal a turned-away agent
    # reads. Public for the same reason as the acting-agent contract above —
    # the three framework wrappers each render both and must not each re-type
    # the phrase the server opens its refusal with, nor each invent their own
    # sentence about a header none of them exposes — nor their own sentence for
    # the arm where the org holds no seat and there is no header value to name.
    "ACTING_AGENT_SPELLING",
    "NOT_A_MEMBER_CLAUSE",
    "NO_OWN_AGENTS",
    "NO_SEAT_TO_ACT_AS",
    "SEATED_SIBLING_CLAUSE",
    "is_not_a_member",
    "not_a_member_message",
    "own_agents_clause",
    # The two sentences a group refusal carries its ROSTER in. Public because
    # the three framework wrappers append a "go and find the group" verb to a
    # 404, and once the refusal lists the groups itself that advice tells a
    # model to fetch what it is already reading — the same defect as naming a
    # search for an agent the refusal has already listed. A wrapper decides by
    # looking for these, so they are imported and never retyped: a fourth copy
    # of a sentence is how the two TypeScript not-a-member texts drifted.
    "GROUP_ROSTER_LEAD",
    "NO_GROUPS_IN_ORG",
    # What a recipient spelling NAMES, and what a resolve answers with. Public
    # because a surface decides which slot a caller's string belongs in before
    # this SDK ever sees it: five of them re-derive "is this a group or an
    # agent" from their own reading of a ``#``, an ``@`` and a UUID, and a
    # surface that reads the string differently from the ladder it then calls is
    # how a reference comes to resolve for one verb and 404 for another. The
    # table is imported, never re-implemented — the predicates below are two
    # readings OF it, kept because they are what ``send()`` asks.
    #
    # ``GroupTarget``/``RecipientTarget`` are exported alongside so a caller that
    # needs the handle as well as the id resolves ONCE. They are what
    # ``resolve_group``, ``resolve_group_for_join`` and ``resolve_recipient``
    # answer with on both clients.
    "REF_CLASS_AGENT",
    "REF_CLASS_BARE",
    "REF_CLASS_EMPTY",
    "REF_CLASS_GROUP",
    "REF_CLASS_ID",
    "GroupTarget",
    "RecipientTarget",
    "classify_reference",
    "is_bare_reference",
    "is_sigil_group_reference",
    # What ``join`` accepts, which is not what every other group verb accepts.
    # Public because five surfaces advertise it in a tool description and the
    # ladder that enforces it is private: a connector restating the rule in its
    # own words is how a surface comes to advertise a spelling the ladder
    # refuses, and the model reads that refusal as a broken product.
    "JOIN_REFERENCE_RULE",
    # The refusal a caller sees when a group creation names no visibility.
    # Public so a wrapper can state it at its OWN entry point: every agent
    # framework validates its argument schema before the handler runs, so a
    # wrapper that waits for the SDK to raise hands the model a pydantic dump
    # instead of this sentence.
    "VISIBILITY_REQUIRED_MESSAGE",
    # The sender-key refusal on a render that carries many rows. Public because
    # the surfaces that render N messages are the framework wrappers, not this
    # SDK: hermes, crewai and langchain each loop over an inbox, and a wrapper
    # that had to decide for itself whether it had already explained this cause
    # would be the fourth copy of a two-state machine — and, without
    # ``decrypt_error_code``, would decide it by matching words in a paragraph.
    # Build one ``SenderKeyRefusal`` per render, ask it for each row's text.
    "SENDER_KEY_UNAVAILABLE_PREVIEW",
    "SenderKeyRefusal",
    # How a transcript names what it reads, for the three wrappers that each
    # expose ``rine_thread`` and would otherwise retype these two sentences —
    # which is exactly what happened to ``INVITE_TARGET_REQUIRED``. A wrapper
    # validating its own tool arguments raises with these; the SDK raises with
    # them too, so one mistake reads one way whichever surface made it.
    "TRANSCRIPT_REFERENCE_REQUIRED",
    "not_a_conversation_uuid",
    "resolve_api_url",
    "resolve_config_dir",
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
    "EncryptResult",
    "ErasureResult",
    "Event",
    # A plural admission's per-agent answer, and the filter that reads the
    # population it acts on. Public at the root because a caller branching on
    # a skip reason, or naming an `outstanding` filter, must be able to name
    # the type — the TypeScript SDK exports its equivalents from its own root.
    "GroupAdmissionEntry",
    "GroupAdmissionReport",
    "GroupAdmissionSkipReason",
    # What a read did to a closed group's local MLS state. Public because it
    # rides on `DecryptedMessage`, which every receive surface hands back.
    "GroupCatchUp",
    "GroupCreateResult",
    "GroupCreateWithRoster",
    "GroupInviteReport",
    "GroupMember",
    "GroupRead",
    # What a removal did and the one sentence to print about it. Public at the
    # root because a surface that prints its own sentence is how the shipped one
    # came to be false for every open group; the TypeScript SDK exports its twin
    # from its own root for the same reason.
    "GroupRemovalEncryption",
    "GroupRemovalResult",
    "GroupSummary",
    # One arm of what ``groups.sync()`` returns. A public method whose return
    # type a caller cannot name is a type they must retype by hand to annotate
    # or narrow, and the TypeScript twin is exported from its SDK root.
    #
    # ⚠️ Only this arm. ``MlsRecoveryResult`` lives in ``rine._mls.resync``, and
    # importing that module reaches the ``rine-mls`` wheel, which is not
    # installable on every platform this package supports — so naming it here
    # would make ``import rine`` itself fail where the SDK is meant to keep
    # working without MLS. The union is annotated lazily, which is all an
    # annotation ever needs.
    "SenderKeyRecoveryResult",
    "InviteResult",
    "JoinRequestRead",
    "OutstandingFilter",
    "JoinResult",
    "JoinedResult",
    "MessageRead",
    "MlsInitFailure",
    "OrgQuotas",
    "OrgRead",
    "PendingJoinResult",
    "PollTokenResponse",
    "QuotaEntry",
    "RegistrationResult",
    "SendAndWaitResult",
    "SenderKeyChange",
    "ThreadEntry",
    "VerifyIdentityResult",
    "VoteResponse",
    "WebhookCreated",
    "WebhookJobRead",
    "WebhookJobSummary",
    "WebhookRead",
    "WhoAmI",
    # Rendering
    # A skip reason and a per-agent outcome, in words rather than wire tokens.
    # ``not_applicable`` is why: an open group's roster comes back entirely
    # skipped while the same call notifies every one of those agents.
    "admission_headline",
    "admitted_agent_ids",
    "describe_admission_entry",
    "group_admission_skip_sentence",
    # The MLS half of admission: whether a leaf actually landed. A roster
    # invites; the Welcome is what decides whether an invitee can read a word,
    # and the voucher counts cannot say so.
    "describe_mls_admission",
    "describe_mls_outcome",
    "describe_mls_reclamation",
    "mls_admission_skip_sentence",
    # How a join request is decided, and whether this agent's vote counts. One
    # sentence and one row, shared by every surface that offers a vote: a
    # second wording of either is how a model comes to believe a rule the
    # server does not implement.
    "VOTE_DURATION_DEFAULT_HOURS",
    "VOTE_DURATION_MAX_HOURS",
    "VOTE_DURATION_MIN_HOURS",
    "VOTE_DURATION_RULE",
    "VOTE_ELECTORATE_RULE",
    "describe_expiry",
    "describe_vote_counts",
    "describe_vote_eligibility",
    "may_vote",
    "render_request_row",
    "vote_eligibility_reason",
    # Verification
    "VerificationStatus",
    "is_authenticity_failure",
    # Verification words, recomputed from the key this client holds rather than
    # read off an agent card. Public at the root because every surface that
    # displays an agent's words must derive them itself — printing the string
    # the server asserted compares the server against itself.
    "VerificationWordsComparison",
    "VerificationWordsStatus",
    "compare_verification_words",
    "compare_verification_words_for_agent",
    "verification_words_for_jwk",
    "verification_words_for_key",
    "verification_words_lines",
    # Constants
    "ConversationStatus",
    "EncryptionVersion",
    "JoinRequestStatus",
    "MessageType",
    "VoteChoice",
    "VoteEligibilityReason",
    "WebhookJobStatus",
    # Errors
    "APIConnectionError",
    "APITimeoutError",
    "AuthenticationError",
    "AuthorizationError",
    "ConfigError",
    "ConflictError",
    "CryptoError",
    "GroupIdentityMismatchError",
    # An eviction, said as a membership fact rather than as the MLS core's
    # ratchet-tree invariant. Branch on ``GROUP_EVICTED_CODE``, never on text.
    "GROUP_EVICTED_CODE",
    "GroupEvictedError",
    "InternalServerError",
    # A resync refused because the local group state will not load at all: the
    # remedy is an admin removing and re-inviting, not a retry.
    "MLS_RESYNC_UNAVAILABLE_CODE",
    "MlsError",
    "MlsResyncUnavailableError",
    # A Welcome this client refused to adopt, and why. Public at the root so a
    # caller recognises a refusal by TYPE rather than by matching its message —
    # the TypeScript twin is a `@rine-network/core` export, and an asymmetry
    # here is a defect a user only ever meets on the closed stack. Branch on
    # ``err.reason`` or on ``WELCOME_REFUSED_CODE``, never on the sentence.
    "WELCOME_REFUSED_CODE",
    "MlsWelcomeRefusedError",
    "WelcomeRefusalReason",
    "NoMlsGroupStateError",
    # A sender-key group message named a key this agent holds no state for —
    # never distributed, or retired by a leave. Nothing was consumed, which is
    # what tells it apart from the message-key refusals beside it. The code is
    # what a renderer branches on once the exception is gone: it is written onto
    # the row as ``decrypt_error_code`` and travels with it into a connector.
    "SENDER_KEY_UNAVAILABLE_CODE",
    "NoSenderKeyStateError",
    # A group send refused before the sender-key fan-out: the acting agent
    # holds no seat, so the key was never distributed and nothing was sent.
    "NotAGroupMemberError",
    "NotFoundError",
    "RateLimitError",
    "ReplyAttributionError",
    "RineApiError",
    "RineError",
    "SenderMismatchError",
    "ServiceUnavailableError",
    "SignatureVerificationError",
    "SpiffeVerificationError",
    # A group send handed a sender key that was never written to disk: the
    # message seals, and its ratchet advance and self-read key would be
    # discarded silently. Refused so a composing caller learns it at the seam.
    "UnpersistedSenderKeyStateError",
    "UnsupportedTargetError",
    "ValidationError",
    "format_error",
    # Sentinel
    "NOT_GIVEN",
    "NotGiven",
    # Version
    "__version__",
]
