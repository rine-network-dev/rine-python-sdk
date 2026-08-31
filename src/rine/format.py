"""The group predicates every Python surface shares.

A rine group runs one of two encryptions, and both are supported products.
Closed, majority and unanimity groups run on **MLS over the post-quantum X-Wing
ciphersuite**, which is the default for every new group. Open-enrollment groups
run on **sender keys**: MLS's Add semantics would hand an unattested joiner a
cryptographic seat, so the server keeps open enrollment on the sender-key path
by design. These predicates are how a surface tells the two apart.

The first two answer different questions and must never be swapped:

* :func:`group_is_mls` — the **render/state** question: does this group have MLS
  state a client can hold? Only a latched ``mls_group_id`` answers yes.
* :func:`group_accepts_mls_send_only` — the **send** question: will the server
  accept anything but an MLS message here?

The third, :func:`group_mls_init_in_flight`, is the gap between them, and is
written as that gap rather than as a third reading of the fields. The fourth,
:func:`group_mls_never_founded`, is the one none of the MLS columns can answer:
a group created to run MLS whose tree was never founded is field for field an
open group there, so it reads what the group was created FOR instead.

:func:`group_encryption` folds all of it — plus the case none of the predicates
covers, an MLS init this client watched **fail** — into the one answer a surface
actually renders, and :func:`describe_group_encryption` puts it in words. Both
exist because every wrapper was rendering a group whose MLS never landed as a
plain sender-key one: the group had no MLS state, so "is it MLS?" said no, and
nothing read the failure the create call had already returned.

:func:`describe_mls_recovery` is here for the same reason, one question further
on: once a surface can say what a group is encrypted with, it also has to say
what catching that encryption up cost. It answers for both regimes, selecting on
``result.regime`` — for MLS, which rung ran, how far behind the agent was, and
whether the expensive rung billed every member an O(N) commit; for sender keys,
how many of the keys this agent was missing were installed.

They live in their own module because :mod:`rine.types` is already far over the
file-size rule, and they live in the SDK rather than in each integration because
five copies drifted into five different answers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from rine._group_recovery import GroupRecoveryResult, SenderKeyRecoveryResult
    from rine.types import GroupRead


#: What a surface should say a group is encrypted with.
#:
#: ``mls-failed`` is what this client knows and a later read cannot: an init this
#: SDK attempted and could not land. It appears only on the object
#: ``groups.create`` returned. 🔴 It is NOT a synonym for the next word — an init
#: that reached the server before it failed leaves the group frozen to non-MLS
#: sends for up to 900 s, and this word covers that group too.
#:
#: ``mls-never-founded`` is the same group seen from any later read, once that
#: knowledge is gone and the freeze with it. It runs **sender keys**, which is
#: the half four words could not express: ``"sender-key"`` was true of this group
#: and stopped short, and the two stacks then disagreed about it in one
#: operator's terminal — ``rine group show`` calling it post-quantum MLS while
#: ``rine group sync`` called it sender-key.
GroupEncryption = Literal[
    "mls",
    "mls-pending",
    "mls-failed",
    "mls-never-founded",
    "sender-key",
]

#: A group created to run MLS, whose ratchet tree was never founded.
#:
#: 🔴 **The one place this fact is worded, on this stack**, and byte for byte its
#: TypeScript twin ``MLS_NEVER_FOUNDED_NOTE`` (``rine-core``). Two surfaces state
#: it and they must state it identically: :func:`describe_group_encryption`
#: renders it when a caller asks what a group is encrypted with, and the sync
#: verb appends it to whatever the recovery it just ran produced.
#:
#: What it says, and why every clause of it is load-bearing:
#:
#: * **"was created to run MLS"** — the group's four MLS columns are field for
#:   field an open group's, so nothing but the intent the server kept from create
#:   time (:func:`group_mls_never_founded`) can tell the two apart.
#: * **"never founded"**, never "founding failed". A founding that died and one
#:   that was never attempted leave identical rows, and the column that recorded
#:   the attempt is nulled by the server's own self-heal.
#: * **"its messages are sealed with sender keys"** — the group is not broken,
#:   not frozen, and holds keys: the server accepts a sender-key send into it,
#:   the send path mints and fans out sender keys for it, and it carries
#:   messages. What it has not got is the MLS it was created for.
#:
#: It names no verb and no group. No verb, because six agent surfaces have none
#: that founds a group — :data:`UnfoundedGroupRepair` is where a surface that HAS
#: one says so. No group, because it is appended to a sentence that already
#: named one — the shape the eviction sentence already uses: a second identifier
#: in the same answer is what makes two stacks' output differ.
MLS_NEVER_FOUNDED_NOTE = (
    "This group was created to run MLS, but its ratchet tree was never founded, "
    "so its messages are sealed with sender keys rather than the MLS it was "
    "created for."
)

#: The head BOTH sender-key answers open on — the ordinary one in
#: :data:`_ENCRYPTION_WORDS`, and the never-founded one composed in
#: :func:`describe_group_encryption`.
#:
#: 🔴 Its TypeScript twin is ``SENDER_KEY_HEAD`` (``rine-core/src/group-format.ts``)
#: and the two are byte for byte identical, because both stacks build the
#: never-founded summary as this head plus :func:`unfounded_group_note`: a
#: rewording on one stack alone is two products describing one group in two
#: different first sentences. It had already drifted —
#: ``Sender Keys, which are NOT post-quantum.`` here against ``Sender Keys — NOT
#: post-quantum.`` there, on the one string the two stacks share — and nothing
#: looked, because the twin suite bound the note and not the head it is appended
#: to. It is bound now, by ``rine-core/test/mls-recovery-twin.test.ts``.
_SENDER_KEYS_HEAD = "Sender Keys — NOT post-quantum."

_ENCRYPTION_WORDS: dict[GroupEncryption, str] = {
    "mls": (
        "MLS over the post-quantum X-Wing ciphersuite. Every member holds a leaf "
        "in the group's ratchet tree."
    ),
    "mls-pending": (
        "MLS, being founded right now. Sends already take the MLS path; the "
        "group's state latches when the founding commit lands."
    ),
    # 🔴 It says neither "holds no keys and cannot carry a message" nor "carries
    # sender-key traffic". Both are claims this vantage point cannot make, and
    # each was shipped in turn. ``mls_init`` is set for an attempt that never
    # reached the server AND for one whose init POST landed before a later step
    # failed; the second leaves ``mls_pending`` set server-side
    # (``api/mls.py::init_mls_group``), which is ``is_mls_frozen``
    # (``api/group_helpers.py``), and ``POST /messages`` then refuses every
    # non-``mls-v1`` send with a 409 (``api/messages.py``) until the server's own
    # 900 s self-heal clears it (``api/mls_confirmation.py``). The object this is
    # rendered from is the create response, minted BEFORE the init, so its
    # ``mls_pending`` is false on both and cannot tell them apart — the sentence
    # names the fork instead of guessing which side of it the caller is on.
    #
    # It does not reuse ``MLS_NEVER_FOUNDED_NOTE``: that note states the group's
    # messages ARE sealed with sender keys, which is exactly the half this state
    # cannot promise yet. Nothing here restates it.
    #
    # It names no verb, for the reason the note names none: this sentence is
    # rendered by ``rine-crewai``, ``rine-langchain`` and ``rine-hermes``, none of
    # which has a ``resume_admission`` — naming it sent a model looking for a
    # tool that is not there. :data:`UnfoundedGroupRepair` is where a surface
    # that has the verb names it, in its own spelling.
    "mls-failed": (
        "MLS was asked for and did not land. This client tried to found the "
        "group's ratchet tree and the attempt failed, so the group has not got "
        "the MLS it was created for and is NOT post-quantum. If the attempt "
        "reached the server before it failed, the server refuses every non-MLS "
        "send here until it clears the half-started init, within 15 minutes; "
        "after that the group runs sender keys, like any group with no ratchet "
        "tree."
    ),
    # 🔴 ``mls-never-founded`` has NO row here, and that is the point: its
    # sentence is the only one of the five that carries a remedy, and the remedy
    # is spelled differently on every surface. It is composed in
    # :func:`describe_group_encryption` from this same head plus
    # :func:`unfounded_group_note`, so there is one wording and not a table row
    # that quietly disagrees with it.
    # 🔴 It does not say "this group is open-enrollment". A group runs sender
    # keys whenever it has no ratchet tree, and open enrollment is only the
    # commonest way to be in that position: a closed group created without MLS
    # lands on this same word, and telling its operator their private group is
    # open-enrollment is a misstatement about who can join it. A group created
    # to run MLS and never founded lands on ``mls-never-founded`` instead —
    # this word is true of it, but only half the answer.
    "sender-key": (
        f"{_SENDER_KEYS_HEAD} A group runs them whenever it "
        "has no ratchet tree. Open-enrollment groups are that way by design — "
        "MLS would hand an unattested joiner a cryptographic seat, so the server "
        "keeps open enrollment off the MLS path — and a closed group created "
        "without MLS runs them too. Removal here is enforced by rine's delivery "
        "filter, not by cryptography."
    ),
}


def group_encryption(g: GroupRead) -> GroupEncryption:
    """What this group is encrypted with, as a surface should render it.

    Five answers, not two. A group with an MLS latch is MLS; one whose init is
    in flight is on its way there and is emphatically not sender-key; one whose
    init this client watched fail was meant to run MLS and did not get it; one
    whose tree was never founded was meant to run MLS, did not get it, and runs
    sender keys; and everything else simply runs Sender Keys.

    ``"mls-failed"`` and ``"mls-never-founded"`` are the same group from two
    vantage points, which is why they sit next to each other. 🔴 They do not say
    the same thing: an init that reached the server before it failed leaves
    ``mls_pending`` set, and until the server's own 900 s self-heal clears it
    every non-MLS send into that group is refused — so the failed word states
    the fork and the never-founded one, past the freeze, states the traffic. The
    first is read off ``mls_init`` on the object
    ``groups.create`` returned, and nowhere else — so it is available for
    exactly as long as the caller holds that object. 🔴 It is NOT recoverable
    from a re-read: the server nulls ``mls_pending`` on its own 15 minutes after
    an init that never committed, so a ``GroupRead`` fetched later carries no
    trace of the attempt. That row is what :func:`group_mls_never_founded`
    answers for, and it used to fall to ``"sender-key"`` — true, and half the
    answer: the operator was never told the group had not got the encryption it
    was created for.

    Args:
        g: The group. A ``GroupCreateResult`` additionally carries a failed init.

    Returns:
        The regime to name.
    """
    if group_is_mls(g):
        return "mls"
    # Asked before the predicate below, which is true of this same row: an init
    # this client watched fail is strictly more than the row can say, and it is
    # the only vantage point that can name what the caller just did.
    if getattr(g, "mls_init", None) is not None:
        return "mls-failed"
    # The founding LANDED and only the re-read after it was refused, so the row
    # this is asked about is the PRE-init one: no latch, no pending, and every
    # predicate below reads it as a group whose tree was never founded. The
    # admission is what the founding returned and exists nowhere else — it is
    # carried across the failure at ``_resources/group_ops.py:177`` (sync) and
    # ``:222`` (async) for this reason.
    if getattr(g, "mls_admission", None) is not None:
        return "mls"
    if group_mls_init_in_flight(g):
        return "mls-pending"
    if group_mls_never_founded(g):
        return "mls-never-founded"
    return "sender-key"


def describe_group_encryption(
    g: GroupRead, repair: UnfoundedGroupRepair = "sdk-resume-admission"
) -> str:
    """One sentence naming the group's encryption, for an operator.

    Stated where the operator sees the group rather than left to the docs: which
    regime a group runs, and whether it is post-quantum, is not something anyone
    should have to look up — and until now nothing in any Python surface said it
    at all.

    Args:
        g: The group, read fresh enough to carry its current MLS latch.
        repair: How THIS surface spells the verb that founds a group's MLS
            state. It reaches exactly one word — ``mls-never-founded``, the only
            state with a remedy — and the clause never mentions a sync, because
            the caller here is describing a group and not reporting one.

            🔴 It defaults to this SDK's own method name, the same default
            :meth:`rine._resources.groups.GroupsResource.sync` carries, and
            NOT to ``"none"``. ``"none"`` renders "No verb on this surface founds
            it", and there is no Python caller of whom that is true: this
            function ships inside ``rine``, so anything that can import it can
            call ``client.groups.resume_admission()``. Every surface whose
            nearest verb refuses — ``rine-ts-sdk``, ``rine-mastra``,
            ``rine-eve``, ``rine-mcp``, ``rine-openclaw`` — is TypeScript and
            reads ``groupEncryption`` instead, which is why the default on THAT
            stack is ``"none"``. A connector rendering for a model that holds a
            differently spelled tool passes its own word: ``rine-crewai``,
            ``rine-langchain`` and ``rine-hermes`` pass ``"tool-group-reclaim"``.

    Returns:
        The sentence, in the words a surface prints as-is.
    """
    word = group_encryption(g)
    if word == "mls-never-founded":
        return f"{_SENDER_KEYS_HEAD} {unfounded_group_note(repair)}"
    return _ENCRYPTION_WORDS[word]


def group_is_mls(g: GroupRead) -> bool:
    """Whether a group runs on MLS.

    ``mls_group_id`` is the server's MLS latch: non-null means the group's MLS
    state has been founded and every member holds (or can install) local MLS
    state. It is the only field that says so.

    ``mls_enabled`` is an *intent* flag — a closed group carries it from birth,
    before any MLS state exists, and an open-enrollment group carries it while
    running on sender keys, because the server refuses MLS there. ``mls_pending``
    marks an init in flight, which is not state either. Neither belongs in this
    answer; a surface that reads them labels a sender-key group "MLS".

    Args:
        g: The group, read fresh enough to carry its current MLS latch.

    Returns:
        True when the group has MLS state.
    """
    return g.mls_group_id is not None


def group_accepts_mls_send_only(g: GroupRead) -> bool:
    """Whether a group will accept only MLS messages.

    The client-side mirror of the server's ``is_mls_frozen``
    (``src/rine/api/group_helpers.py``): once a group is MLS-latched **or** an
    init is in flight, the server refuses a sender-key send with a 409. A send
    path that asks :func:`group_is_mls` instead walks into that 409 during the
    init window, which the server self-clears after 15 minutes.

    Args:
        g: The group, read fresh enough to carry its current MLS latch.

    Returns:
        True when a sender-key send into this group would be refused.
    """
    return group_is_mls(g) or g.mls_pending


def group_mls_init_in_flight(g: GroupRead) -> bool:
    """Whether a group's MLS initialisation is still in flight.

    The window between the server accepting a group's MLS init and its
    ``mls_group_id`` latching. It is written as the gap between the other two
    answers — no MLS state to render yet (:func:`group_is_mls` is false) while
    the server already refuses everything but MLS
    (:func:`group_accepts_mls_send_only` is true) — and never as a third reading
    of the fields, so it cannot drift away from the pair it sits between.

    This is a normal transient state of a healthy group, not a failure: a send
    made during the window already takes the MLS branch, because the send path
    asks :func:`group_accepts_mls_send_only`
    (``rine._group_send.encrypt_for_group_sync``). A surface that renders a
    group therefore has three cases, not two, and rendering this one
    "sender-key" says the opposite of what the group is doing.

    Args:
        g: The group, read fresh enough to carry its current MLS latch.

    Returns:
        True while the group's MLS init is in flight.
    """
    return not group_is_mls(g) and group_accepts_mls_send_only(g)


def group_mls_never_founded(g: GroupRead) -> bool:
    """Whether a group created to run MLS still has no ratchet tree.

    The fourth case, and the one the other three collapse into "sender key". A
    closed group whose founding never landed carries a null latch and — once the
    server has cleared the init window it self-heals after 15 minutes — a false
    ``mls_pending``, which is field for field what an open group looks like.
    Nothing in the group's MLS columns survives to say a founding was ever
    attempted, so the only durable record is the intent pair set at create time,
    and this reads it.

    🔴 It says **never founded**, not "founding failed". A group whose init died
    and one whose client never ran an init are the same four values on the wire,
    so no client can tell them apart and no sentence built on this may claim to.

    The group is not broken: the server does not freeze it, so sends take the
    sender-key branch and are accepted. That is the point — a group created to
    run MLS is carrying sender-key traffic, and nothing said so.

    ``mls_enabled`` is read here, and only here, because it is the one field
    that can say a closed group was deliberately NOT given MLS — legal on the
    wire and settable while the group is unlatched. Both stacks read it for the
    same reason — an absent or unset field means a projection rather than an
    answer, and must never be what manufactures a refusal — but they do not read
    it with the same test: the TypeScript twin is ``=== true`` and this is a
    truthiness check. They agree on every row this SDK can produce, because
    :class:`rine.types.GroupRead` declares the field ``bool`` and pydantic has
    already coerced it by the time this runs; ``rine-core``'s ``GroupRead`` is an
    unvalidated cast of raw JSON, so a server or proxy emitting a truthy
    non-boolean would divide the two. No such emitter exists, and the strict
    test is the safe side of that divide.

    Args:
        g: The group, read fresh enough to carry its current MLS latch.

    Returns:
        True when the group was created to run MLS and has no ratchet tree.
    """
    # ``not group_accepts_mls_send_only`` is exactly "no latch and no init in
    # flight" — the server would accept a sender-key send into this group now.
    return (
        g.enrollment_policy != "open"
        and bool(g.mls_enabled)
        and not group_accepts_mls_send_only(g)
    )


#: What a sync refuses on a group between its MLS init and the latch, in one
#: sentence a surface prints as-is. It takes ``{handle}`` and lives here rather
#: than beside the verb because every Python surface that offers ``sync`` needs
#: the same refusal.
#:
#: Its own answer, because it is the one case both arms of the sync would get
#: wrong: ``mls_group_id`` has not latched, so a two-way branch reads the group
#: as sender-key and runs an ingest against a group that is really MLS — a wrong
#: action rather than a wrong sentence. Raised as a ``ValueError``, with no new
#: error class and no new code: the state clears itself within minutes. The
#: TypeScript twin is ``mlsInitInFlightSync`` (``rine-core``).
MLS_INIT_IN_FLIGHT_SYNC = (
    "Group {handle} is still founding its MLS state, so there is no epoch chain to "
    "catch up with yet and no sender keys to install. This clears on its own within "
    "minutes — run the sync again then."
)

#: The repair a surface can actually offer for a group with no ratchet tree.
#:
#: The remedy is one operation — found the group's MLS state — and it is spelled
#: differently on every kind of caller, so it is the caller that names it. The
#: set is closed and every spelling in it reaches the founding path:
#:
#: * ``cli-resume-admission`` — ``rine group resume-admission``, which branches
#:   to the init on an unlatched group.
#: * ``sdk-resume-admission`` — this SDK's :meth:`GroupsResource.resume_admission`,
#:   whose ``_resume`` does the same branch. The default here, because a caller
#:   holding this client is exactly the caller who has that method.
#: * ``tool-group-reclaim`` — ``rine_group_reclaim``, which wraps that method on
#:   ``rine-crewai``, ``rine-langchain`` and ``rine-hermes``.
#: * ``none`` — a surface whose nearest verb refuses instead of founding.
#:
#: A value rather than a caller-supplied string, so the clauses live beside the
#: sentence they are part of instead of drifting across the surfaces that print
#: them. The TypeScript twin is ``UnfoundedGroupRepair`` (``rine-core``).
UnfoundedGroupRepair = Literal[
    "cli-resume-admission",
    "sdk-resume-admission",
    "tool-group-reclaim",
    "none",
]

#: How each surface spells the founding verb, and nothing else.
#:
#: 🔴 One map, two clause tables DERIVED from it. The remedy is read in two
#: contexts and the sentence cannot be the same in both — a sync ends "then run
#: the sync again", and a renderer describing the group cannot say that because
#: nobody ran a sync — but the load-bearing token is identical in both: how this
#: surface spells the verb. A second table written by hand would drift on exactly
#: that token, which is what the two stacks had already done to each other on a
#: sentence nothing bound. The TypeScript twin is ``REPAIR_VERBS``
#: (``rine-core/src/mls-recovery-format.ts``).
#:
#: ``None`` is a surface whose nearest verb refuses instead of founding.
_REPAIR_VERBS: dict[UnfoundedGroupRepair, str | None] = {
    "cli-resume-admission": "rine group resume-admission",
    "sdk-resume-admission": "resume_admission()",
    "tool-group-reclaim": "rine_group_reclaim",
    "none": None,
}

#: The half both no-verb clauses share; only what follows it is context.
_NO_VERB_HERE = " No verb on this surface founds it: a member has to found the group's MLS state"

#: What a sync says: the remedy, and the sync that has to follow it.
_SYNC_VERB_CLAUSE = " Run {verb} on it to found its MLS state, then run the sync again."
_SYNC_NO_VERB_CLAUSE = f"{_NO_VERB_HERE} before this sync has anything to catch up."

#: What a surface describing the GROUP says: the remedy, and no sync. Every
#: clause above ends on a sync, which is false in a renderer where nobody ran
#: one — that is the whole reason this second shape exists.
_STATE_VERB_CLAUSE = " Run {verb} on it to found its MLS state."
_STATE_NO_VERB_CLAUSE = f"{_NO_VERB_HERE}."


def _repair_clauses(with_verb: str, without_verb: str) -> dict[UnfoundedGroupRepair, str]:
    """Both tables, from one spelling each: the verb arm, and the arm with no verb."""
    return {
        repair: without_verb if verb is None else with_verb.format(verb=verb)
        for repair, verb in _REPAIR_VERBS.items()
    }


_UNFOUNDED_REPAIR_CLAUSES = _repair_clauses(_SYNC_VERB_CLAUSE, _SYNC_NO_VERB_CLAUSE)
_UNFOUNDED_REPAIR_STATE_CLAUSES = _repair_clauses(_STATE_VERB_CLAUSE, _STATE_NO_VERB_CLAUSE)


def _note_with_repair(table: dict[UnfoundedGroupRepair, str], repair: UnfoundedGroupRepair) -> str:
    """The note, plus this surface's clause — or a refusal naming the closed set.

    🔴 An unmapped word is refused rather than rendered, on both tables, and both
    stacks refuse it: the TypeScript twin used to concatenate ``undefined`` into
    the operator's warning instead, so one event had two behaviours and the
    silent one was the one that reached a user. The set is named from
    :data:`_REPAIR_VERBS`, so the refusal cannot list a set neither table has.
    """
    clause = table.get(repair)
    if clause is None:
        expected = ", ".join(_REPAIR_VERBS)
        raise ValueError(f"Unknown repair verb {repair!r} — expected one of: {expected}.")
    return MLS_NEVER_FOUNDED_NOTE + clause


def unfounded_group_note(repair: UnfoundedGroupRepair = "none") -> str:
    """The same fact, said by a surface describing the group rather than a sync.

    🔴 Its own function rather than an argument on
    :func:`mls_never_founded_sync`, because the two differ in what they may claim
    happened, not in tone: every clause the sync renders ends on a sync — "then
    run the sync again", "before this sync has anything to catch up" — and a
    group renderer telling a caller to repeat an operation they never performed
    is a straight falsehood about their own session. Both tables name the verb
    from one map, so the half that drifts unwatched cannot.

    The TypeScript twin is ``unfoundedGroupNote`` (``rine-core``), bound to this
    one by ``rine-core/test/mls-recovery-twin.test.ts``.

    Args:
        repair: The founding verb this surface can offer, in its own spelling.

    Returns:
        The note, in the words a surface prints as-is.

    Raises:
        ValueError: If *repair* is not one of :data:`UnfoundedGroupRepair`.
    """
    return _note_with_repair(_UNFOUNDED_REPAIR_STATE_CLAUSES, repair)


def mls_never_founded_sync(repair: UnfoundedGroupRepair = "none") -> str:
    """What a sync says about a group whose ratchet tree was never founded.

    🔴 **A warning appended to the recovery, not a refusal instead of one.** The
    sync's sender-key arm really is part of this group's recovery: the group
    carries sender-key traffic, so the distribution scan can and does install
    keys for it. What no scan installs is a ratchet tree, so the work happens
    and then this says what the work did not reach. Refusing ahead of the scan
    bought an operator nothing and cost them the keys.

    The repair clause is the whole of what differs between surfaces, and it
    defaults to naming no verb: a warning that names a verb the caller cannot
    run is the failure :data:`UnfoundedGroupRepair` exists to prevent. The
    TypeScript twin is ``mlsNeverFoundedSync`` (``rine-core``) and the two are
    sentence for sentence identical.

    Args:
        repair: The founding verb this surface can offer, in its own spelling.

    Returns:
        The warning, in the words a surface prints as-is.

    Raises:
        ValueError: If *repair* is not one of :data:`UnfoundedGroupRepair` — see
            :func:`_note_with_repair`.
    """
    return _note_with_repair(_UNFOUNDED_REPAIR_CLAUSES, repair)


_RECOVERY_EVICTED = (
    "This agent was removed from the group by a commit it just replayed: messages that "
    "already arrived still open, and nothing committed after the Remove ever will."
)

_SCAN_DONE = (
    "This sync is finished; nothing here is a message from the group, so read the "
    "group's own messages next."
)
"""What to do once the sync is over, on every arm where the scan actually ran.

🔴 The answer used to end on a description of state, and a model reading it
handed the product's own status sentence to its user AS IF IT WERE WHAT THE
GROUP SAID, then never read the group (``e2e-group-qol.sh``'s g4, measured at
0.00 twice). So this says both halves out loud: that our own text is not a
message from the group, and that the group's messages are the thing to read
next. It names no verb, because "read a group" is spelled differently on every
surface and a sentence naming somebody else's spelling is the failure
:data:`UnfoundedGroupRepair` exists to prevent one level down.

Not on the retired arm: nothing was installed there and nothing could be, so
sending its reader to the group's messages would send them to the same refusal.
That arm already ends on its own next action.

The TypeScript twin is ``SCAN_DONE`` (``rine-core/src/mls-recovery-format.ts``),
bound by ``rine-core/test/mls-recovery-twin.test.ts``.
"""


def _unscanned_clause(unscanned: int | None) -> str:
    """The part of the distribution inbox this pass never opened, if there is one.

    The scan reads one page of a hundred and follows no cursor, so an agent with
    a longer distribution inbox gets a partial pass — and until this, the answer
    reported that partial pass as a whole one. The number is the server's own
    ``total`` minus the page that was read, so it costs no extra request.

    🔴 What it may say is bounded by what the number is, and the first version of
    this sentence said more. It counted rows this pass did not LOOK at and called
    them DMs that "stayed unopened, so a key this agent needs may be among them"
    — but the listing it counts is every distribution this agent has EVER been
    sent, read-state and installed-state alike, so the rows behind the page are
    mostly keys installed long ago. "stayed unopened" was false of them, and an
    agent past a hundred lifetime distributions read that hint on every healthy
    sync it ever ran, with no verb offered for it — a wider page and a cursor
    were both declined. So the sentence now states what the number is, states
    what it is NOT, and names nothing to do about it.

    The TypeScript twin is ``unscannedClause``.

    Args:
        unscanned: What the scan did not reach, or ``None``/``0`` when the one
            page it reads covered the whole distribution inbox.

    Returns:
        The clause with its own leading space, or ``""`` — the
        ``_NO_VERB_HERE`` shape, so the two arms compose one way and not two.
    """
    if not unscanned:
        return ""
    return (
        f" {unscanned} older sender-key distribution(s) in this agent's inbox sat past "
        "the end of this scan's one page. That is a count of rows this pass did not "
        "read, on a listing that holds every distribution this agent has ever been "
        "sent — not a count of keys it is missing."
    )


def _describe_sender_key_recovery(group_ref: str, result: SenderKeyRecoveryResult) -> str:
    """What recovering a sender-key group did, in the words the operator gets.

    Three facts and no more: what was installed, that nothing was committed, and
    what is still out of reach. The last clause is the one that has to be exact
    — an ingested distribution carries the sender's chain key at the index it
    was distributed at, and a chain key only ratchets forward, so this repairs
    reads from each key's own index onward and never behind it. It is not "read
    the backlog", and it is emphatically not a re-key, a rotation or anything
    that changes what an old key could open: recovery here installs the sender
    keys this agent is missing, and touches nobody else's material.

    Each arm ends on a forward half, and that is a rule rather than a habit: the
    retired arm names the next step, the installed arm says what is readable now,
    and the empty arm says that this agent's state did not move — so an operator
    who ran the sync because something would not open learns from the answer
    itself whether the sync was the lever.

    Both arms where the scan actually ran then close on the same two clauses:
    :func:`_unscanned_clause`, when the one page the scan reads did not cover the
    distribution inbox, and :data:`_SCAN_DONE`, which names the next action. The
    retired arm takes neither — no scan ran there to fall short, and its reader
    has its own next step.

    🔴 Two matrix drivers decide whether the surface answered at all by
    ``^``-anchored regexes on these heads
    (``scripts/mls-matrix/driver_framework_ts_admin.mjs``,
    ``scripts/mls-matrix/container_admin.py``), and a miss there is reported as
    the refusal — a successful recovery graded as a broken surface. So a head may
    be reworded, but only together with both of those regexes and its TypeScript
    twin, in one commit. The empty-scan head has been reworded twice for the same
    reason — it kept claiming more than the number it reads can say. First the
    success verb went (``Recovered group X:`` on a scan that recovered nothing),
    then the inbox inventory that had survived it. The never-founded warning
    rides on its own line, the eviction-sentence shape.
    """

    def with_note(head: str) -> str:
        note = result.mls_never_founded_note
        return f"{head}\n{note}" if note else head

    # Both arms where the scan ran end the same way: what it could not reach, if
    # anything, and then the next action. Composed once so the two cannot drift.
    scan_tail = f"{_unscanned_clause(result.unscanned)} {_SCAN_DONE}"
    if result.retired:
        # 🔴 It does not say "the server does not name this agent a member". The
        # retirement gate fails closed, so ``retired`` is also what a membership
        # read that never got an answer produces — and a sentence that stated the
        # server's verdict as fact sent an operator to an admin for a
        # re-invitation they already had, while ruling out the one thing that
        # would have worked. Cheapest remedy first, escalation second.
        return with_note(
            f"Group {group_ref} refused its own key material to this agent: its sender "
            "keys were retired here, and nothing lifted that retirement, so nothing was "
            "installed. A retirement lifts when the server names this agent a member "
            "again: run the sync again, and if it still refuses, this agent needs an "
            "invitation before it can take the group's keys."
        )
    if result.ingested == 0:
        # 🔴 "nothing new was installed", never "none were waiting". The number
        # this arm reads counts distributions the scan INSTALLED, and the scan
        # reaches zero with distribution DMs sitting in the inbox — one already
        # installed, one whose envelope refused, one past the un-paginated
        # hundred-row fetch. So the sentence states what the zero observes and
        # stops: an inventory of the inbox is a claim this vantage point cannot
        # make, and the version that made it went on to rule out the one thing
        # that would have explained the miss.
        return with_note(
            f"Scanned group {group_ref} for sender keys: nothing new was installed, so "
            "this agent's local state is unchanged. A sender-key group has no epoch "
            "chain, so nothing was committed and this cost reads only. Whatever opened "
            "here before opens now, and a member's key this agent has not got yet "
            f"reaches it on that member's next post to the group.{scan_tail}"
        )
    return with_note(
        f"Recovered group {group_ref}: installed {result.ingested} sender key(s) that "
        "were waiting in this agent's inbox. A sender-key group has no epoch chain, so "
        "nothing was committed and this cost reads only. The messages those keys cover "
        "open now; anything a member sent before its key was minted stays unreadable."
        f"{scan_tail}"
    )


def describe_mls_recovery(group_ref: str, result: GroupRecoveryResult) -> str:
    """What the operator paid for a recovery, and what they got for it.

    Selects on ``result.regime`` first and on nothing else — never on which
    fields a result happens to carry. A sender-key recovery has no epoch, no
    commit, no ratchet tree and no leaf, so falling into either MLS rung would
    describe events that did not happen, and appending the eviction sentence to
    one would report an MLS Remove for a group whose removals are the server's
    delivery filter.

    Both MLS rungs report how far behind the agent was, because that is the
    number that says whether the recovery was routine; and the resync rung says
    out loud that a commit was posted and who is billed for it, because an O(N)
    commit charged to every member of the group is not something to discover
    later.

    ``group_ref`` is whatever the caller named the group — a handle as often as a
    UUID — so the sentence talks about the group the operator asked about.

    The name keeps its ``mls`` in it although it now answers for both regimes:
    renaming a published export across the packages that call it buys one word.

    The TypeScript twin is ``describeMlsRecovery`` (``rine-core``), and the two
    print the same sentences: two stacks describing one event differently is the
    defect this pair exists to stop.
    """
    if result.regime == "sender-key":
        return _describe_sender_key_recovery(group_ref, result)
    distance = (
        "by an unknown distance (the group has published no confirmed epoch)"
        if result.behind is None
        else f"by {result.behind} epoch(s)"
    )
    if result.rung == "replay":
        head = (
            f"Replayed {result.processed} commit(s) for group {group_ref}: it was behind "
            f"{distance}, and is now at epoch {result.epoch}. Nothing was committed."
        )
    else:
        head = (
            f"Resynced group {group_ref}: it was behind {distance} and no stored commit "
            f"could bridge that gap, so one external commit re-seated this agent's "
            f"existing leaf at epoch {result.epoch}. That commit is O(N) — every member "
            f"of the group downloads and processes it."
        )
    if not result.evicted:
        return head
    return f"{head}\n{_RECOVERY_EVICTED}"


__all__ = [
    "MLS_INIT_IN_FLIGHT_SYNC",
    "MLS_NEVER_FOUNDED_NOTE",
    "GroupEncryption",
    "UnfoundedGroupRepair",
    "describe_group_encryption",
    "describe_mls_recovery",
    "group_accepts_mls_send_only",
    "group_encryption",
    "group_is_mls",
    "group_mls_init_in_flight",
    "group_mls_never_founded",
    "mls_never_founded_sync",
    "unfounded_group_note",
]
