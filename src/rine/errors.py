"""Structured error hierarchy with actionable messages for AI agent self-correction.

All errors include three components: what failed, why, and what to try.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Protocol

# Safe as a module-level import in the module every other one imports: ``format``
# is a leaf, with no runtime imports of its own at all.
from rine.format import _join_lines, key_package_top_up_line

if TYPE_CHECKING:
    from rine._group_recovery import KeyPackageTopUp


class RineError(Exception):
    """Base exception for all Rine SDK errors."""


class RineApiError(RineError):
    """HTTP API error with status code and detail.

    Args:
        status: HTTP status code.
        detail: Human-readable error description.
        raw: Optional raw response body.
    """

    def __init__(self, status: int, detail: str, raw: object = None) -> None:
        self.status = status
        self.detail = detail
        self.raw = raw
        super().__init__(f"{status}: {detail}")


class AuthenticationError(RineApiError):
    """401 — invalid or missing credentials.

    Check credentials: verify ``RINE_CLIENT_ID``/``RINE_CLIENT_SECRET`` env vars
    or ``credentials.json`` in your config directory.
    """

    def __init__(self, detail: str = "Authentication failed", raw: object = None) -> None:
        super().__init__(401, detail, raw)


class AuthorizationError(RineApiError):
    """403 — insufficient permissions for the requested operation."""

    def __init__(self, detail: str = "Permission denied", raw: object = None) -> None:
        super().__init__(403, detail, raw)


class NotFoundError(RineApiError):
    """404 — the requested resource was not found.

    Check the identifier format: ``name@org`` for handles,
    UUID for direct IDs. Search the directory: ``client.discover()``.
    """

    def __init__(self, detail: str = "Resource not found", raw: object = None) -> None:
        super().__init__(404, detail, raw)


class ConflictError(RineApiError):
    """409 — resource conflict (e.g., duplicate slug or agent name)."""

    def __init__(self, detail: str = "Conflict", raw: object = None) -> None:
        super().__init__(409, detail, raw)


class RateLimitError(RineApiError):
    """429 — rate limit exceeded.

    Attributes:
        retry_after: Seconds to wait before retrying, if provided by server.
    """

    def __init__(
        self,
        detail: str = "Rate limit exceeded",
        retry_after: float | None = None,
        raw: object = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(429, detail, raw)


class ValidationError(RineApiError):
    """422 — request validation failed."""

    def __init__(self, detail: str = "Validation error", raw: object = None) -> None:
        super().__init__(422, detail, raw)


class InternalServerError(RineApiError):
    """500 — unexpected server error."""

    def __init__(self, detail: str = "Internal server error", raw: object = None) -> None:
        super().__init__(500, detail, raw)


class ServiceUnavailableError(RineApiError):
    """503 — service temporarily unavailable."""

    def __init__(self, detail: str = "Service unavailable", raw: object = None) -> None:
        super().__init__(503, detail, raw)


class APITimeoutError(RineError):
    """Request timed out — the server did not respond in time."""


class APIConnectionError(RineError):
    """Network-level failure — could not reach the server."""


class CryptoError(RineError):
    """Encryption or decryption failure.

    Messages include recovery suggestions (e.g., fetch sender keys, regenerate keys).
    """


#: The stable code a sender-key-unavailable refusal carries, shared
#: byte-for-byte with ``rine-core``'s ``SENDER_KEY_UNAVAILABLE_CODE``
#: (``rine-core/src/sender-key-words.ts``), where it is the ``code`` field on
#: ``SenderKeyUnavailableError``.
#:
#: A renderer that has to tell this cause apart from every other decrypt
#: failure reads it off :attr:`rine.types.DecryptedMessage.decrypt_error_code`
#: — never by matching words in ``decrypt_error``, which is a paragraph written
#: for a reader and rewordable at any time. The exception type is the classifier
#: on this stack; the code is what survives being written onto a message and
#: handed to a connector in another package.
SENDER_KEY_UNAVAILABLE_CODE = "sender_key_unavailable"


class NoSenderKeyStateError(CryptoError):
    """A sender-key group message names a key this agent holds no state for.

    A :class:`CryptoError` subclass, and that is load-bearing rather than
    cosmetic: the read paths retry a failed sender-key decrypt by ingesting
    pending distributions and trying once more, and they select that retry on
    ``CryptoError``. Raising anything else here would silently delete the
    self-heal.

    Distinct from the message-key refusals around it because the cause is
    different in the one way that decides what an operator should do: **no key
    was consumed**. Either the state was never installed, or a leave deleted it
    and the retirement marker is correctly refusing to put it back.

    The refusal names the key it was asked for, both ways the state can be
    absent, the two real ways back, and that nothing was spent trying. Its words
    are :mod:`rine.sender_key_words`.

    Carries :data:`SENDER_KEY_UNAVAILABLE_CODE` so a receive surface can record
    *which* cause degraded a row without keeping the exception: a rendered
    message travels to a connector as data, and the type does not travel with
    it.

    It carries the ``sender_key_id`` beside the sentence for the same reason
    ``rine-core``'s ``SenderKeyUnavailableError`` does: a receive path that
    refuses without running the recovery has to say so in its own words
    (:func:`rine.sender_key_words.sender_key_not_recovered_detail`), and that
    sentence names the key. Parsing the id back out of the message would make
    the wording load-bearing, which is what this module exists to stop.
    """

    code = SENDER_KEY_UNAVAILABLE_CODE

    def __init__(self, message: str, sender_key_id: str) -> None:
        """Refuse a read for want of sender-key state, naming the key.

        Args:
            message: The refusal an operator reads.
            sender_key_id: The key the message named, for a caller that has to
                re-say the refusal its own way.
        """
        super().__init__(message)
        self.sender_key_id = sender_key_id


class SignatureVerificationError(CryptoError):
    """The sender's signature failed verification (``verification_status == "invalid"``).

    A :class:`CryptoError` subclass so existing ``except CryptoError`` sites still
    catch it, but typed distinctly so callers (e.g. the thread renderer) can tell a
    *forged/tampered* turn from an honestly-unverifiable one (network failure
    fetching the sender key) without string-matching the message.
    """


class SenderMismatchError(SignatureVerificationError):
    """The envelope's signer is not the agent the server authenticated as sender.

    The signature itself is good — it simply belongs to somebody else, so the
    message cannot be attributed to the agent it arrived from. A
    :class:`SignatureVerificationError` subclass, so every path that already
    refuses a bad signature refuses this too, while a caller that wants to tell
    "these bytes were tampered with" from "this is attributed to the wrong
    agent" can, and the receive surfaces map it to
    ``verification_status == "sender-mismatch"``.
    """


class ConfigError(RineError):
    """Missing or invalid SDK configuration.

    Messages include setup instructions (e.g., run ``rine onboard``).
    """


class GroupIdentityMismatchError(RineError):
    """A group read answered about a different group than the one it asked for.

    A :class:`RineError` rather than a :class:`RineApiError`: no status code
    said this, and the response may well have been a well-formed 200. What is
    wrong with it is that it is not an answer to the question that was asked.

    It fails closed because of what reads the result.
    :func:`rine._mls.api.read_group` is the one read every MLS flow starting
    from a bare group id comes through, and
    :func:`rine._mls.join.install_mls_state` scopes its Welcome pass by the id
    on what that read returned. An id the caller never named matches no
    refusal, so a Welcome this client refuses would be withheld rather than
    raised, and the join would report success holding no MLS state.

    There is ONE class of this name across both stacks: the TypeScript twin is
    declared in ``rine-core`` and re-exported by ``rine-ts-sdk``. A consumer
    narrowing to a single class therefore catches every throw, on either stack.

    ``answered_group_id`` is ``None`` for a body that named no group at all, and
    the sentence SAYS so rather than printing an empty slot. The message is
    byte-symmetric with TypeScript's, and a blank before a full stop reads as a
    rendering bug in a log rather than as a server fault. What decides that a
    body named no group is :func:`rine._recipient_reads.answered_group_id`,
    stated once, because ``str(x)`` and JavaScript's ``String(x)`` agree on
    strings and on nothing else.

    Args:
        requested_group_id: The group the caller asked about.
        answered_group_id: The group the server's body named, or ``None`` when
            it named none.
    """

    def __init__(self, requested_group_id: str, answered_group_id: str | None) -> None:
        self.requested_group_id = requested_group_id
        self.answered_group_id = answered_group_id
        named = (
            "the server's answer carried no group id"
            if answered_group_id is None
            else f"the server answered with group {answered_group_id}"
        )
        super().__init__(
            f"Refusing the group read for {requested_group_id}: {named}. A read that "
            "is not about the group it named cannot be used to establish that "
            "group's MLS state."
        )


class UnsupportedTargetError(RineError):
    """The target argument is not valid for this operation.

    Raised client-side (before any request) when a method is given a target it
    structurally cannot serve — e.g. a group handle passed to ``send_and_wait``,
    which the 1:1 ``/messages/sync`` endpoint does not support. The message
    states the constraint and the alternative to use.
    """


class NotAGroupMemberError(RineError):
    """A group send would be made by an agent that holds no seat in the group.

    Raised client-side, before anything is encrypted, distributed or posted. A
    :class:`RineError` rather than a :class:`RineApiError`: no status code said
    this — the group read that carried the seats was a well-formed ``200``, and
    the ``403`` this call was heading for has not been asked for yet.

    Refusing here rather than letting the server refuse is the whole point. On
    the Sender Keys path the client fans its key out to every member the server
    lists, as ordinary 1:1 messages, *before* the post. An unseated agent that
    reached the fan-out would therefore write real message and delivery rows
    into the inbox of every member, including members in other orgs, and only
    then be refused — and nothing undoes those rows. The Sender Keys fan-out is
    the reachable path; MLS sends carry no fan-out and are not refused here.

    The refusal names the group, the agent that was acting, which of the
    caller's own agents *are* seated, and — because the fan-out is what this
    exists to prevent — that nothing was sent.
    """


class ReplyAttributionError(RineError):
    """A reply would be filed from an agent the original was not addressed to.

    Raised client-side, before anything is encrypted or sent. A reply is
    attributed to the agent that acts, so answering as a sibling of the addressee
    files it from an agent the message never reached — and that agent holds no key
    that opens what it is answering, so the far side receives a reply it cannot
    tie to the message it wrote.

    ``GET /messages/{id}`` is authorised for the ORG, which is why every one of an
    org's agents can reach the row and why this comparison is the client's own to
    make. The refusal names the addressee because that is the one value that fixes
    the call — except for the one caller it cannot fix, see ``acting_is_sender``.

    Args:
        message_id: The message being replied to.
        acting_agent_id: The agent this call resolved as its actor.
        addressee_agent_id: The agent the original was addressed to.
        acting_is_sender: The acting agent SENT the original. It is still not the
            addressee, so the refusal stands, but the addressee is the far side's
            agent and this caller can never act as it. Telling it to reply as that
            agent would be advice it cannot take, so the remedy sentence changes.
    """

    def __init__(
        self,
        message_id: str,
        acting_agent_id: str,
        addressee_agent_id: str,
        *,
        acting_is_sender: bool = False,
    ) -> None:
        self.message_id = message_id
        self.acting_agent_id = acting_agent_id
        self.addressee_agent_id = addressee_agent_id
        remedy = (
            f"You sent {message_id}, so there is nothing here to answer as "
            f"{addressee_agent_id} — reply to the answer it gets, or send another message."
            if acting_is_sender
            else f"Reply as {addressee_agent_id}."
        )
        super().__init__(
            f"Refusing to reply to {message_id} as {acting_agent_id}: it was addressed to "
            f"{addressee_agent_id}. A reply is filed from the agent that acts, so this one "
            f"would arrive from an agent the message never reached. " + remedy
        )


class NoMlsGroupStateError(CryptoError):
    """This agent holds no local MLS state for the group it was asked about.

    The three causes a caller answers the same way — never added to the MLS
    group, a Welcome not installed yet, or state that was retired — so sending
    and reading both respond by installing state and retrying once. Reaching a
    caller means that recovery has already run and failed.
    """

    def __init__(self, group_id: str) -> None:
        super().__init__(
            f"No MLS state for group {group_id}. This agent is not in the group's "
            "MLS state yet; joining the group, or receiving a Welcome from a "
            "member, establishes it."
        )


#: The stable code the downgrade refusal carries, shared byte-for-byte with
#: ``rine-core``'s ``crypto/downgrade-error.ts``. Deliberately outside the
#: ``RINE_MLS_`` namespace: that prefix is the MLS core's own vocabulary, and in
#: the TypeScript stack a code inside it is classified as a recoverable MLS read
#: and swallowed by the retry a downgrade refusal must survive.
DOWNGRADE_REFUSED_CODE = "RINE_DOWNGRADE_REFUSED"


class MlsDowngradeError(CryptoError):
    """The server presented a group as sender-key while this agent holds MLS state.

    Only the contradiction raises this. Holding no local state is never evidence
    of a downgrade — a billboard group, a member whose Welcome has not been
    processed and a fresh install all hold none, and all keep working.

    A :class:`CryptoError` subclass so every path that already refuses
    unreadable content refuses this too. It is deliberately **not** an
    :class:`MlsError`: the MLS core did not raise it, and
    :func:`rine._mls.failures.is_recoverable_mls_failure` must answer ``False``
    for it, or the refusal would be retried away instead of surfaced.
    """

    code = DOWNGRADE_REFUSED_CODE

    def __init__(self, group_id: str) -> None:
        self.group_id = group_id
        super().__init__(
            f"Refusing group {group_id}: this client holds MLS state for it, and "
            "the server presented it as a sender-key group. Sending or reading "
            "under sender keys here would hand a server-chosen recipient list a "
            "key the MLS group never granted it. Resolve the contradiction "
            "before retrying."
        )


class MlsError(CryptoError):
    """A failure raised by the MLS core, carried into this SDK's hierarchy.

    The core exposes twenty exception classes under a ``#[non_exhaustive]`` code
    enum, half of which have no name in this SDK, so an ``except`` list over them
    is structurally incomplete — a code added upstream lands on the core's base
    class and would escape as something no ``except RineError`` catches.
    Normalizing at the MLS package boundary is what keeps that from happening.

    Args:
        code: The core's stable code for this failure — a value to branch on,
            never a message to parse. ``None`` only for a core error raised
            without one, which the core itself never does.
        detail: The core's message.
    """

    def __init__(self, code: str | None, detail: str) -> None:
        self.code = code
        super().__init__(detail)


#: The stable code an eviction carries, shared byte-for-byte with the
#: TypeScript SDK's ``GROUP_EVICTED_CODE``
#: (``rine-ts-sdk/src/resources/groups-mls-context.ts``). Deliberately outside
#: the ``RINE_MLS_`` namespace: that prefix is the MLS core's own vocabulary,
#: and this is rine restating one of its invariants as a membership fact.
GROUP_EVICTED_CODE = "group_membership_removed"


class GroupEvictedError(MlsError):
    """This agent was removed from the group by an admin's Remove commit.

    The MLS core answers every later operation on an evicted handle with
    ``RINE_MLS_GROUP_INACTIVE`` and the message *"this member was removed from
    the group at epoch 47"* — a correct statement about a ratchet tree, and an
    unusable one for an agent working out what happened to it: it names no
    group and offers no remedy. Eviction is a membership fact, so rine states it
    as one.

    An :class:`MlsError` subclass on purpose: every ``except MlsError`` site
    catches an eviction too, and only the sentence differs. Branch on
    :data:`GROUP_EVICTED_CODE`, never on the message.

    Args:
        group_id: The group this agent was evicted from.
    """

    def __init__(self, group_id: str) -> None:
        """Build the eviction refusal for one group."""
        self.group_id = group_id
        super().__init__(
            GROUP_EVICTED_CODE,
            f"You were removed from group {group_id}. Your ratchet-tree leaf is gone, "
            f"so nothing committed to this group after the Remove will open, and "
            f"messages that already arrived still do. Ask an admin to invite you "
            f"again — re-admission mints a new leaf and a fresh Welcome.",
        )


#: The stable code the resync refusal carries, shared byte-for-byte with
#: ``rine-core``'s ``MLS_RESYNC_UNAVAILABLE_CODE``
#: (``rine-core/src/mls-ops-resync.ts``). Outside the ``RINE_MLS_`` namespace on
#: purpose: that prefix is the MLS core's own vocabulary, and this is rine
#: refusing a recovery the core was never asked about.
MLS_RESYNC_UNAVAILABLE_CODE = "mls_resync_unavailable"


class MlsResyncUnavailableError(CryptoError):
    """This agent holds no loadable MLS state, so the group cannot be resynced.

    A resync replaces the agent's **own** ratchet-tree leaf, and the leaf index
    naming it can only come from the stale local state — the server does not
    know MLS leaf indices and must never appear to. Absent state therefore has
    no recovery at this end: the remedy is an admin removing this agent from the
    group and inviting it again, which mints a new leaf and a fresh Welcome.

    Deliberately not a fallback to a plain external join. MLS refuses that for
    an agent its tree already holds, so the fallback would replace an actionable
    refusal with a protocol error about a leaf the operator never asked about.

    🔴 It carries the recovery's key-package top-up, and that is not decoration.
    This refusal IS the answer an agent gets when a carried vote seated it with
    no Welcome — the exact population whose published pool has run out — so the
    one thing that unblocks the re-admission it asks for is the pool the top-up
    just refilled. Reporting the top-up only on a returned result would report it
    everywhere except the case it was built for.

    Args:
        group_id: The group that cannot be resynced.
        key_packages: What the top-up that ran ahead of this refusal did, when
            one ran.
    """

    code = MLS_RESYNC_UNAVAILABLE_CODE

    def __init__(self, group_id: str, key_packages: KeyPackageTopUp | None = None) -> None:
        """Build the refusal for one group."""
        self.group_id = group_id
        self.key_packages = key_packages
        super().__init__(
            _join_lines(
                f"Cannot resync MLS group {group_id}: this agent's local group state will not "
                f"load, and a resync needs it — the leaf a resync replaces is named by the "
                f"stale state itself and by nothing the server knows. Ask an admin to remove "
                f"this agent from the group and invite it again; re-admission mints a new leaf "
                f"and a fresh Welcome.",
                key_package_top_up_line(key_packages),
            )
        )


#: The stable code a Welcome refusal carries, shared byte-for-byte with
#: ``rine-core``'s ``WELCOME_REFUSED_CODE``
#: (``rine-core/src/mls-welcome-guard.ts``). Deliberately outside the
#: ``RINE_MLS_`` namespace: that prefix is the MLS core's own vocabulary, and a
#: code inside it is classified as a recoverable MLS failure and retried away —
#: which is exactly the path a refusal has to survive.
WELCOME_REFUSED_CODE = "RINE_WELCOME_REFUSED"

#: Why a Welcome was not adopted. A value to branch on, never a message to parse.
#:
#: * ``group_id_mismatch`` — the joined group's own id is not the one the
#:   delivery was filed under.
#: * ``roster_uncorroborated`` — the roster was read and named nobody holding a
#:   leaf in the joined tree.
#: * ``state_would_be_overwritten`` — this agent holds local state for that group
#:   id and the roster could not be read, so nothing corroborates spending it.
WelcomeRefusalReason = Literal[
    "group_id_mismatch",
    "roster_uncorroborated",
    "state_would_be_overwritten",
]


class MlsWelcomeRefusedError(CryptoError):
    """A Welcome this client refuses to adopt as state for the group it names.

    A :class:`CryptoError` subclass so every path that already refuses
    unreadable content refuses this too, and deliberately not an
    :class:`MlsError`: the MLS core did not raise it, and
    :func:`rine._mls.failures.is_recoverable_mls_failure` must answer ``False``
    or the refusal would be retried away instead of surfaced.

    It **raises** rather than logging, and both stacks owe that: a refusal that
    is loud on one stack and a warning on the other is a defect a user only ever
    meets on the quiet one.

    It lives in this hierarchy alongside :class:`MlsDowngradeError` and
    :class:`MlsResyncUnavailableError` because a refusal rine mints itself is
    one of its own errors, not one of the MLS core's. Being catchable by name is
    the whole point of the class; a caller reduced to matching the message text
    has not got it, and that is what the reason codes exist to prevent.

    Args:
        group_id: The group whose Welcome was refused.
        reason: Which check refused it — see :data:`WelcomeRefusalReason`.
        detail: The sentence the operator reads, remedy included.
    """

    code = WELCOME_REFUSED_CODE

    def __init__(self, group_id: str, reason: WelcomeRefusalReason, detail: str) -> None:
        """Build the refusal for one Welcome."""
        self.group_id = group_id
        self.reason: WelcomeRefusalReason = reason
        super().__init__(detail)


class SpiffeVerificationError(RineError):
    """SPIFFE identity verification could not obtain a JWT-SVID.

    Raised client-side (before the verify request) when no SVID is available —
    never a silent no-op. ``reason`` is machine-readable so callers branch
    without string-matching:

    - ``"no-svid"`` — no ``svid`` given and no SPIFFE Workload API endpoint.
    - ``"autofetch-unavailable"`` — a ``SPIFFE_ENDPOINT_SOCKET`` is present but
      automatic fetch is not supported in this build; supply ``svid`` explicitly.
    """

    def __init__(self, detail: str, reason: Literal["no-svid", "autofetch-unavailable"]) -> None:
        self.reason = reason
        super().__init__(detail)


class _StatusErrorFactory(Protocol):
    """What every ``_STATUS_MAP`` entry must be: constructible from detail + raw alone.

    ``type[RineApiError]`` is the obvious annotation and the wrong one. Each subclass
    pins its own status (``AuthenticationError`` passes 401 up), so none of them takes
    the ``status`` argument the base class requires — under ``type[RineApiError]`` mypy
    applies the *base* signature and rejects the call below. This states the property
    the map actually holds, so a new entry that demanded a status would be caught here
    rather than at the one call site.
    """

    def __call__(self, *, detail: str = ..., raw: object = ...) -> RineApiError: ...


_STATUS_MAP: dict[int, _StatusErrorFactory] = {
    401: AuthenticationError,
    403: AuthorizationError,
    404: NotFoundError,
    409: ConflictError,
    422: ValidationError,
    429: RateLimitError,
    500: InternalServerError,
    503: ServiceUnavailableError,
}


def raise_for_status(status: int, detail: str, raw: object = None) -> None:
    """Raise the appropriate error class for an HTTP status code.

    Args:
        status: HTTP status code.
        detail: Error detail string.
        raw: Optional raw response body.

    Raises:
        RineApiError: Subclass matching the status code.
    """
    cls = _STATUS_MAP.get(status)
    if cls:
        raise cls(detail=detail, raw=raw)
    raise RineApiError(status, detail, raw)


def format_error(err: BaseException) -> str:
    """Format an error for display.

    Args:
        err: Any exception.

    Returns:
        Human-readable error string.
    """
    if isinstance(err, RineApiError):
        return err.detail
    if isinstance(err, Exception):
        return str(err)
    return str(err)
