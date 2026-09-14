"""BaseRineClient — shared config resolution, crypto, and agent resolution.

Contains no I/O — delegates to the HTTP layer. Both RineClient (async) and
SyncRineClient (sync) inherit from this base.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._actor import (
    AGENT_HEADER,
    ActorOrigin,
    ResolvedActor,
    actor_from_env,
    normalize_actor,
)
from rine._config import get_credential_entry, resolve_api_url, resolve_config_dir
from rine._constants import (
    DECRYPT_MEMO_MAX_ENTRIES,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    NOT_GIVEN,
    PEEK_HEADER,
    NotGiven,
)
from rine._crypto._decrypt_memo import DecryptMemo
from rine._logging import logger
from rine._resolve import is_wire_agent_id
from rine.errors import (
    ConfigError,
    CryptoError,
    MlsError,
    NoMlsGroupStateError,
    NoSenderKeyStateError,
    SenderMismatchError,
    SignatureVerificationError,
)
from rine.mls_read_words import mls_read_refusal, sdk_sync_remedy
from rine.types import CursorPage, GroupSummary

if TYPE_CHECKING:
    from rine._crypto.message import DecryptResult
    from rine.sender_key_words import SenderKeyRefusal
    from rine.types import DecryptedMessage, GroupCatchUp, MessageRead


class BaseRineClient:
    """Shared base for async and sync Rine clients.

    Handles configuration resolution, credential validation, and
    agent selection. Does not perform any I/O.

    Args:
        config_dir: Config directory path. Auto-resolved if not provided.
        api_url: API base URL. Auto-resolved if not provided.
        agent: Agent name, handle, or UUID for multi-agent orgs. Omitted, the
            ``RINE_AGENT`` environment variable names it; with neither, the
            server auto-selects when the org has exactly one active agent.
        timeout: HTTP request timeout in seconds.
        max_retries: Maximum retry attempts for rate limiting.
    """

    def __init__(
        self,
        *,
        config_dir: str | None = None,
        api_url: str | None = None,
        agent: str | NotGiven = NOT_GIVEN,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        self._config_dir = config_dir or resolve_config_dir()
        self._api_url = api_url or resolve_api_url()
        # Rungs 2 and 3 of the ladder, settled once, here: the constructor's
        # agent, then ``RINE_AGENT``. An agent that is empty after trimming is
        # *absent*, so it falls through to the environment rather than refusing.
        # Rung 4 — the org's only active agent — stays the server's job.
        #
        # 🔴 Rung 4 is why a single-agent org that sets *neither* sees no change
        # from any of this, and an org that exports ``RINE_AGENT``
        # now sees very little either: the header is sent and the server resolves
        # it, but a value naming no live agent of a ONE-agent org is no longer
        # refused — that agent acts and ``ignored_actor_warning`` says so. On a
        # multi-agent org the refusal stands. So a stale export is a *warning*
        # for the single-agent case and a *refusal* for every other, and the
        # difference must not be written down as if it were one rule.
        #
        # 🔴 Which rung answered is remembered, not just the value: the two are
        # collapsed into one attribute here, and the warning downstream has to
        # name the lever the reader can actually move (``ActorOrigin``).
        named = normalize_actor(None if isinstance(agent, NotGiven) else agent)
        self._actor_origin: ActorOrigin = "argument"
        if named is None:
            named = actor_from_env()
            self._actor_origin = "environment"
        self._agent: str | NotGiven = named if named is not None else NOT_GIVEN
        self._timeout = timeout
        self._max_retries = max_retries
        self._agents_cache: list[dict[str, Any]] | None = None
        # The whole verdict, not just the id: a one-agent org that was handed a
        # value naming nobody resolves to its sole agent and carries a warning,
        # and memoising the id alone would drop that warning after the first
        # call — so the second send would report nothing while doing exactly
        # the same substitution.
        self._resolved_actor: ResolvedActor | None = None
        # Shared by the sync and async receive paths: makes a repeat decrypt of
        # an already-opened group message return the same plaintext instead of
        # hitting the consumed sender-key ratchet.
        self._decrypt_memo = DecryptMemo(DECRYPT_MEMO_MAX_ENTRIES)

        # Validate credentials exist
        entry = get_credential_entry(self._config_dir)
        if not entry:
            logger.debug("No credentials found at %s", self._config_dir)

    @property
    def config_dir(self) -> str:
        """Config directory path."""
        return self._config_dir

    @property
    def api_url(self) -> str:
        """API base URL."""
        return self._api_url

    def _get_agent_header(self) -> str | None:
        """Get the agent ID for X-Rine-Agent header, or None for auto."""
        return self._resolved_actor.agent_id if self._resolved_actor else None

    def _needs_actor_resolution(self, agent_id: str | None) -> bool:
        """Whether the value headed for ``X-Rine-Agent`` still has to be resolved.

        The non-awaiting half of the decision both ``_agent_header`` twins make;
        each keeps only its own ``await``. Two cases reach ``_resolve_agent_id``:

        - **Nothing yet**, with an actor configured on the constructor: the
          memoised id has not been computed.
        - **A bare name or a handle.** The per-call rung accepts both — the name
          is the spelling the ambiguity refusal asks for — and both name an
          agent the caller must *own*, so both are answered from this org's own
          agent list and the resolved UUID is what goes out. The wire refuses a
          bare name outright (``422``, ``src/rine/api/agent_identity.py``) and
          would resolve a handle itself; letting it do so left the two spellings
          of one mistake with two different answers, one of them a ``422`` about
          a header that names no agent.

        Only an id skips the lookup — it is the answer already — and "an id"
        here means every spelling the **wire** parses, not only the canonical
        dashed one, which is why this asks
        :func:`rine._resolve.is_wire_agent_id` rather than asking whether the
        value is a bare name. A dashless or ``urn:uuid:`` actor has always
        reached the server and been accepted there; resolving it as a name
        instead would refuse it here, for an agent nobody named.
        """
        if agent_id is None:
            return not isinstance(self._agent, NotGiven)
        return not is_wire_agent_id(agent_id)

    def _actor_header_dict(self, agent_id: str | None) -> dict[str, str] | None:
        """The ``X-Rine-Agent`` header for a resolved actor, or None to let the server pick."""
        return {AGENT_HEADER: agent_id} if agent_id else None

    def _with_peek(self, headers: dict[str, str] | None, *, peek: bool) -> dict[str, str] | None:
        """``headers`` plus the peek header, when the caller asked not to consume the row.

        The sync and async ``read()`` are independent copies of each other, so
        the one thing they must not each own is the decision — a header spelled
        two ways, or added on one client only, is this package's most-paid-for
        defect class. This is the non-awaiting half of it, on the base class for
        the reason :meth:`_needs_actor_resolution` gives.

        Takes and returns the same ``extra_headers`` shape
        :meth:`_actor_header_dict` produces, ``None`` included: a one-agent org
        that configured no actor sends no ``X-Rine-Agent`` at all, and a peek
        from that client is the peek header alone.

        ``"1"`` because the server parses this slot as a boolean and takes every
        spelling of true; the shortest one is the one that never needs quoting.
        """
        if not peek:
            return headers
        return {**(headers or {}), PEEK_HEADER: "1"}

    @staticmethod
    def _build_body(*pairs: tuple[str, Any]) -> dict[str, Any]:
        """Build a JSON body from key-value pairs, excluding ``NotGiven`` values."""
        return {k: v for k, v in pairs if not isinstance(v, NotGiven)}

    @staticmethod
    def _page_total(data: Any, items: list[Any]) -> int:
        """How many rows the server says match, for a page that carries only some.

        🔴 **The directory routes send ``total_estimate``, not ``total``.** Both
        ``DirectorySearchResponse`` and ``DirectoryGroupSearchResponse`` name the
        field that way, so reading ``total`` alone fell through to the fallback
        every time and a page of 50 out of 900 reported a total of 50 — a number
        that is indistinguishable from an exhaustive answer. ``GET /messages``
        does send ``total`` (and omits the key entirely under
        ``include_total=false``), so all three shapes are read here in one place.

        The TypeScript twin is ``parseCursorPage`` in
        ``rine-ts-sdk/src/api/adapters.ts``, which has read
        ``total_estimate ?? total ?? items.length`` all along.

        Args:
            data: The decoded response body, or a bare list.
            items: The rows already extracted from it.

        Returns:
            The server's count where it stated one, else this page's length.
        """
        if not isinstance(data, dict):
            return len(items)
        total = data.get("total_estimate", data.get("total"))
        return total if isinstance(total, int) else len(items)

    @staticmethod
    def _directory_group_params(
        q: str | None, limit: int | None, cursor: str | None
    ) -> dict[str, Any] | None:
        """The query string for one ``GET /directory/groups`` page, or ``None``.

        Four call sites — ``discover_groups`` and the join ladder's directory
        rung, on each of the two hand-kept clients — so the falsy-drop rule lives
        once. ``None`` rather than ``{}`` because the HTTP layer takes that as
        "no query string at all".
        """
        params: dict[str, Any] = {}
        if q:
            params["q"] = q
        if limit:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor
        return params or None

    @classmethod
    def _directory_group_page(cls, data: Any) -> CursorPage[GroupSummary]:
        """One ``GET /directory/groups`` body, read into a page.

        Shared by the same four call sites as :meth:`_directory_group_params`,
        and it is :meth:`_page_total` that makes sharing it matter: the field is
        ``total_estimate``, and a copy that read ``total`` reported a page of 50
        out of 900 as a total of 50 — the number the join ladder's shortfall
        sentence is subtracted from.
        """
        items = data.get("items", []) if isinstance(data, dict) else data
        return CursorPage[GroupSummary](
            items=[GroupSummary.model_validate(g) for g in items],
            total=cls._page_total(data, items),
            next_cursor=data.get("next_cursor") if isinstance(data, dict) else None,
        )

    @staticmethod
    def _expected_sender(agent_id: str, msg: MessageRead) -> str:
        """The sender every decrypt of this row must find in the envelope.

        Only the server's own ``from_agent_id`` counts: the envelope, the key id
        and the plaintext are all chosen by whoever posted the message, so
        checking one of them against another proves nothing. A row the caller
        sent carries the caller as that sender, which is why a self-read verifies
        like any other message.

        Args:
            agent_id: The reading agent's UUID.
            msg: The row as the server returned it.

        Returns:
            The agent UUID the envelope's key id must name.

        Raises:
            CryptoError: The row names no sender, so nothing can be attributed
                to anyone — a refusal, never a guess.
        """
        if msg.from_agent_id is not None:
            return str(msg.from_agent_id)
        if msg.direction == "sent":
            return agent_id
        raise CryptoError(
            "This message names no sender, so its signature cannot be attributed "
            "to an agent. Refusing to treat it as verified."
        )

    @staticmethod
    def _reported_catch_up(result: DecryptResult) -> GroupCatchUp | None:
        """What this read did to the group's MLS state, in the public shape.

        The internal :class:`~rine._mls.sync.MlsSyncResult` is under ``_mls`` and
        stays there; a caller reading an inbox gets a declared public type or
        nothing. ``None`` all the way through means no sync ran — a 1:1 message,
        an open group, a repeat read served from the memo, or a catch-up the
        one-minute floor swallowed or that failed. A current member with nothing
        to apply DID run one and reports it, with ``processed`` at zero: the
        absence says nothing was done, never that this agent is current.
        """
        from rine.types import GroupCatchUp as _GroupCatchUp

        if result.catch_up is None:
            return None
        return _GroupCatchUp(
            processed=result.catch_up.processed,
            epoch=result.catch_up.epoch,
            evicted=result.catch_up.evicted,
        )

    @staticmethod
    def _apply_decrypt_failure(
        msg: DecryptedMessage,
        error: Exception,
        *,
        no_recovery: SenderKeyRefusal | None = None,
    ) -> DecryptedMessage:
        """Report a decrypt failure on the message rather than raising.

        The degrade contract every receive surface shares: ``plaintext`` stays
        ``None`` and ``decrypt_error`` carries the reason. A refused signature
        keeps its status — ``"sender-mismatch"`` for an envelope signed by an
        agent other than the row's sender, ``"invalid"`` for one that does not
        cover the bytes — so consumers can still tell either from an
        honestly-unverifiable row.

        The one choke point every receive surface degrades through, which is why
        the cause is classified here rather than at any of them: this is the last
        place that still holds the exception. Past it the row is data, and a
        renderer that wanted to know why it failed would have to read the
        sentence — so ``decrypt_error_code`` is written here, off the type, and
        is never inferred from the words downstream.

        ``no_recovery`` is the one fact the choke point cannot see and the caller
        cannot avoid knowing: whether the path that got here ever gave the
        sender-key recovery its turn. ``inbox()``, ``read()`` and ``thread()``
        do — they ingest every pending distribution and retry — so they leave it
        unset and their refusal is the earned verdict, with the code that says
        so. ``thread()`` spends **one** scan for the whole render rather than one
        per row, which is enough: the scan is untargeted, so every row after it
        is answered by a recovery that ran.

        ``send_and_wait()`` leaves it unset for a different reason, and the
        difference is worth writing down: not that the recovery ran, but that
        there is no recovery to run. ``/messages/sync`` is 1:1 only — a group
        recipient is refused before anything is sealed — so a reply arriving
        there is a DM, and a DM that will not open never failed on a cold sender
        key. The weaker sentence ``no_recovery`` exists to write is a claim about
        a group render, and there is no group render here to make it about.

        ``stream()`` yields raw events and
        decrypts nothing, so a further decrypting receive path arriving here has
        to answer this question for itself rather than inherit an answer.

        ``get_conversation_messages()`` does not — it hands rows back for a
        caller's own renderer and fetches nothing — so it passes that read's
        :class:`~rine.sender_key_words.SenderKeyRefusal` and the row gets the
        weaker sentence and **no** code: the code means the recovery ran and
        lost, and a row this one refused is opened by the very next ``read()``.
        The refusal is passed rather than a boolean because the render, not the
        row, decides whether this is its first such row — and it is the only
        thing that can afterwards tell the render which rows were refused this
        way, since there is no code to recognise them by.

        Args:
            msg: The row that would not open.
            error: The failure, still typed.
            no_recovery: This render's refusal state, when — and only when — the
                calling path never ran the sender-key recovery.
        """
        if no_recovery is not None and isinstance(error, NoSenderKeyStateError):
            msg.decrypt_error = no_recovery.not_recovered(msg, error.sender_key_id)
        else:
            msg.decrypt_error = _refusal_text(msg, error)
            if isinstance(error, NoSenderKeyStateError):
                msg.decrypt_error_code = error.code
        if isinstance(error, SenderMismatchError):
            msg.verification_status = "sender-mismatch"
        elif isinstance(error, SignatureVerificationError):
            msg.verification_status = "invalid"
        logger.debug("Decrypt failed for %s", msg.id, exc_info=error)
        return msg

    def _require_credentials(self) -> None:
        """Raise ConfigError if no credentials are available."""
        entry = get_credential_entry(self._config_dir)
        if not entry:
            raise ConfigError(
                "No credentials found. Run: rine onboard\n"
                "Or set RINE_CLIENT_ID and RINE_CLIENT_SECRET environment variables."
            )


#: The MLS core's code for a message no key this agent holds will open.
#:
#: Matched as a value, never as a message. It is the ONE code translated here,
#: and the narrowness is the point: a store failure, a panic and this agent's
#: own message aged out of the self-read cache all carry different codes and are
#: all things :func:`~rine._resources.groups.GroupsResource.sync` cannot mend,
#: so they keep the words they arrived with rather than being handed a remedy
#: that would not work. An eviction is an :class:`~rine.errors.MlsError` too and
#: is excluded by the same test — it carries ``group_membership_removed``,
#: because rine already restates that one as a membership fact.
_MLS_PROTOCOL_CODE = "RINE_MLS_PROTOCOL"


def _refusal_text(msg: DecryptedMessage, error: Exception) -> str:
    """The sentence for a row that would not open, in rine's words where it has any.

    What this replaced was ``str(error)`` for every cause alike, which on an MLS
    group row printed mls-rs's own *"the provided length of the key 0 is shorter
    than the minimum length 32"* — the KDF refusing to derive from an epoch
    secret this agent never held, stated in a vocabulary that belongs to a Rust
    crate and names neither the group nor a move. The CLI leaked the same string
    from its own renderer; both now say the same thing.
    """
    if msg.group_id and _is_unopenable_group_read(error):
        group_id = str(msg.group_id)
        return mls_read_refusal(group_id, sdk_sync_remedy(group_id))
    return str(error)


def _is_unopenable_group_read(error: Exception) -> bool:
    """The two failures this sentence answers, and no others.

    🔴 Both arms, because the two are one failure to the agent this phase was
    opened for. A vote seated it on the roster with no Welcome, so it holds no
    leaf: the epoch secret it never had surfaces as the core's protocol refusal,
    and the state it never established surfaces as
    :class:`~rine.errors.NoMlsGroupStateError` — same agent, same move, and
    before this only the first got told what the move was. The TypeScript twin
    is ``isRecoverableMlsRead`` (``rine-core/src/crypto/mls.ts``), which unions
    the same two.

    The coded arm stays a single value rather than "any code that is not a local
    failure". Inside :mod:`rine._mls` the twin predicate
    :func:`~rine._mls.failures.is_recoverable_mls_failure` branches on the core's
    exception CLASSES, and it cannot be used here: ``mls_boundary`` has already
    replaced them with :class:`~rine.errors.MlsError`, deliberately, so nothing
    outside that package holds a type from the compiled wheel. Restating the
    core's local-failure codes here would be a second copy of its vocabulary in
    the one place that exists to not have one — and a store failure handed this
    remedy would send an operator to sync a group whose disk is unwritable.
    """
    if isinstance(error, NoMlsGroupStateError):
        return True
    return isinstance(error, MlsError) and error.code == _MLS_PROTOCOL_CODE
