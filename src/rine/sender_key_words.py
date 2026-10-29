"""The words a sender-key refusal is made of.

One cause lives here — a group message sealed under a sender key this client
holds no state for — and it is said **two** ways, because two different things
are known about it:

- **Earned.** ``inbox()``, ``read()`` and ``thread()`` ingest every pending
  distribution and try again before they give up, so when they refuse, no
  distribution is waiting: :func:`no_sender_key_state_detail` states the verdict
  and the row carries :data:`rine.errors.SENDER_KEY_UNAVAILABLE_CODE`.
  ``thread()`` renders N rows and pays for **one** scan across all of them, not
  one per row (the bound is about the cost, not about looking): the scan is
  untargeted, so a single one is everything N of them could have found.
- **Un-earned.** ``get_conversation_messages()`` hands its rows back for a
  caller's own renderer and fetches nothing on their behalf, so it never goes
  looking: :func:`sender_key_not_recovered_detail` says exactly that, names the
  read that does go looking, and the row carries **no** code — the code means the
  verdict already ran and lost, and this one never ran.

The earned sentence used to be printed on both paths. It reads ``Ask the sender
to post to the group again … no later distribution reopens this message`` — a
final answer, on rows the very next ``read()`` opens. That is the same defect
the original wording had, one rung up: a remedy a reader cannot use, stated with
a confidence nobody earned.

The clauses are constants rather than literals at the throw site for the same
reason :mod:`rine.group_words`' are: the sentence is read by people and by
tests, and a wording change that lands in one of those and not the other is how
a refusal quietly stops meaning what its test says it means.

**The TypeScript stack carries its own copy** of both refusals, in ``rine-core``
(``sender-key-words.ts``), and nothing binds the two — there is no server half
to pin them against, unlike :data:`rine.group_words.NOT_A_MEMBER_CLAUSE`, which
``tests/test_client-server-contract_group0.py`` holds to the server's. Treat the
two stacks as deliberately parallel prose: re-read the other one when you change
this one. ``tests/test_sender_key_refusal.py`` reads that file and pins the
un-earned sentence and both markers against it; the earned sentence is the one
pair that was written independently on the two stacks and stays that way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine.errors import SENDER_KEY_UNAVAILABLE_CODE

if TYPE_CHECKING:
    from uuid import UUID

    from rine.types import DecryptedMessage

#: Why the message cannot be opened. Never "the key expired" and never "already
#: consumed": no key was spent here, and saying so sends a reader looking for a
#: read that never happened. State for this sender key was absent, and there are
#: exactly two ways for that to be true.
NO_SENDER_KEY_STATE_CLAUSE = (
    "this agent holds no sender key state for it. Either that key was never "
    "distributed to this agent — a sender distributes its key to the members "
    "seated at the moment it posts — or this agent left the group, which "
    "deletes the group's keys and refuses to take them back"
)

#: What to do instead. Both arms are real actions an operator can take; neither
#: is "fetch the pending distributions", which the read path already did.
SENDER_KEY_REMEDY_CLAUSE = (
    "Ask the sender to post to the group again so its key is distributed to the "
    "current roster, or — if this agent left the group — rejoin it: the refusal "
    "holds for as long as this agent's retirement of that group's keys does."
)

#: What did and did not happen to the world. The clause the seat-403 refusal
#: carries, and the one this sentence most obviously lacked: a reader who has
#: just been told a key is unknown assumes a one-shot key was burnt on a read
#: that failed. Nothing was.
#:
#: 🔴 It must not promise that THIS message opens later. A distribution carries
#: the sender key's *current* position and no earlier one
#: (``_crypto/sender_keys.py`` refuses an index below the state's, and ingest
#: stores no skipped keys), so a key that arrives afterwards opens what the
#: sender writes from then on and never this row. The TypeScript twin has always
#: said so; this clause once said the opposite, which is the "remedy that cannot
#: work" this module exists to delete.
NOTHING_CONSUMED_CLAUSE = (
    "Nothing was decrypted and no message key was consumed — the state needed to "
    "open it was absent, not spent. A distribution carries the sender key's "
    "current position and nothing earlier, so no later distribution reopens this "
    "message: what a fresh post recovers is everything the sender writes from "
    "then on."
)


def no_sender_key_state_detail(sender_key_id: str) -> str:
    """The whole refusal, in its fixed clause order.

    What was refused and under which key → the fact → what to do instead → what
    did and did not happen to the world. Composed in one place so the throw site
    cannot reorder it and the tests can assert the clauses rather than a
    paragraph.

    🔴 A **verdict**, and only a path that has already ingested every pending
    distribution and retried may print it — on this stack, ``inbox()``,
    ``read()`` and ``thread()`` and nothing else (``stream()`` yields raw events
    and decrypts nothing). A read that never went looking says
    :func:`sender_key_not_recovered_detail` instead.
    """
    return (
        f"Refusing to open a group message encrypted under sender key "
        f"{sender_key_id}: {NO_SENDER_KEY_STATE_CLAUSE}. "
        f"{SENDER_KEY_REMEDY_CLAUSE} {NOTHING_CONSUMED_CLAUSE}"
    )


#: The move back, for a surface with no recovery switch to offer.
#:
#: 🔴 Byte-identical to ``rine-core``'s ``SINGLE_MESSAGE_READ_REMEDY``. The
#: TypeScript twin picks between this and ``RECOVERY_LEFT_ON_REMEDY``
#: ("read the message again with the sender-key recovery left on"), which has no
#: Python spelling on purpose: it names ``retrySenderKey``, a switch only the
#: TypeScript SDK's ``decrypt`` exposes. Minting it here would hand a Python
#: reader a control this stack does not have — the exact defect this sentence
#: exists to stop. So the remedy is not a parameter here: there is one true
#: answer on this stack, and :func:`sender_key_not_recovered_detail` states it.
SINGLE_MESSAGE_READ_REMEDY = (
    "read this one message on its own, which does go looking before it answers."
)


def sender_key_not_recovered_detail(sender_key_id: str) -> str:
    """What a read is told when it never went looking for the key.

    The one thing :func:`no_sender_key_state_detail` may not say here: that no
    distribution is coming. ``get_conversation_messages()`` runs no recovery —
    it hands rows back for a caller's own renderer, and a caller cannot be
    charged for a fetch it did not ask for — so it has not ruled the remedy out
    and has no verdict to state. This names the cause, says plainly that nothing
    went looking, and names the read that does: ``read()`` ingests pending
    distributions and retries before it answers, and so does ``thread()``, once
    per transcript.

    🔴 Byte-identical to ``rine-core``'s ``senderKeyNotRecoveredMessage``
    composed with :data:`SINGLE_MESSAGE_READ_REMEDY`, and pinned against that
    source by ``tests/test_sender_key_refusal.py``.
    """
    return (
        "rine cannot open this group message: it is sealed under sender key "
        f"{sender_key_id}, and this agent holds no key by that id. This read did "
        "not go looking for the distribution that carries it, so whether one is "
        "waiting for this agent is unknown and this is not a final answer — "
        f"{SINGLE_MESSAGE_READ_REMEDY}"
    )


#: The same refusal, cut to one row of a render that carries many.
#:
#: A thread, an inbox or a stream renders N rows and cannot spend a paragraph on
#: each one: eight unopenable rows is ~4.8 KB of identical prose, and on the
#: surfaces that feed a model it is 4.8 KB of context bought for one fact. But
#: ``[unavailable]`` is the sentence-shaped nothing this module exists to
#: delete — it names no cause and offers no move. This names both in the width
#: available, and the full sentence stays one ``read`` of that single message
#: away.
#:
#: 🔴 Byte-identical to ``rine-core``'s ``SENDER_KEY_UNAVAILABLE_PREVIEW``
#: (``rine-core/src/sender-key-words.ts``). An operator reading one surface in
#: Python and the next in TypeScript must not meet two spellings of the same
#: refusal, and no gate binds the two files — ``tests/test_sender_key_refusal.py``
#: reads the TypeScript source and pins it.
#:
#: 🔴 It carries no sender key id, no group id and no agent: it is printed once
#: per row and must stay byte-identical across rows, so a reader cannot count
#: distinct keys off a render. The id rides on the
#: once-per-render sentence, which is composed by
#: :func:`no_sender_key_state_detail` and parsed out of the caller's own
#: ciphertext.
SENDER_KEY_UNAVAILABLE_PREVIEW = "[no sender key: ask the sender to post to the group again]"

#: The marker for a render that never let the recovery run.
#:
#: The repeat arm of :func:`sender_key_not_recovered_detail`, and it exists
#: because one marker cannot serve both sentences: a render whose first row says
#: "nothing went looking, so this is not a final answer" may not mark its
#: remaining rows with a remedy only a *final* answer has earned. Marked with
#: :data:`SENDER_KEY_UNAVAILABLE_PREVIEW` they did exactly that. This names the
#: move that IS available here, and it is the same move on every such surface.
#:
#: 🔴 Byte-identical to ``rine-core``'s ``SENDER_KEY_NOT_RECOVERED_PREVIEW``, and
#: cause-free for the same reason the other marker is.
#:
#: ⚠️ On THIS stack nothing renders it any more. The sentence it repeats is
#: written only by ``get_conversation_messages()``, and tiering that list needs
#: the very refusal that decrypted it — which no reader in this package holds
#: after ``thread()`` started recovering. The one surface that still prints this
#: marker is ``rine-mcp``'s inbox page (``rine-mcp/src/tools/messaging-inbox.ts``,
#: re-exported verbatim by OpenClaw), which opens each row with the plain
#: ``decryptGroupMessage`` because a round trip per row does not pay on a page.
#: ``rine-ts-sdk`` does NOT: both of its many-row group reads set
#: ``retrySenderKey``, so they earn the verdict and print the other marker.
#: The constant stays because it is the only thing binding that surface's
#: spelling to ours — ``tests/test_sender_key_refusal.py`` reads ``rine-core``'s
#: file and pins it. Deleting the Python copy would delete that binder, not a
#: duplicate.
SENDER_KEY_NOT_RECOVERED_PREVIEW = (
    "[no sender key: read this message on its own to find out whether one is coming]"
)


class SenderKeyRefusal:
    """One render's worth of "explain the sender-key refusal once, then mark".

    A render that carries N rows explains the cause on the **first** row that
    has it and marks every later one. The agent still learns the cause in-band,
    with no extra call, and pays for it once instead of once per row. The marker
    belongs to the sentence the row would otherwise have printed —
    :data:`SENDER_KEY_UNAVAILABLE_PREVIEW` for the earned verdict,
    :data:`SENDER_KEY_NOT_RECOVERED_PREVIEW` for a row nothing went looking for —
    so no row asserts a remedy its own sentence disclaims.

    🔴 The state is an instance, not a module flag, and it is passed
    explicitly. A module-level "have I explained this yet" boolean leaks across
    calls, across groups and across agents: the second thread an operator reads
    would explain nothing, and the output of any one render would depend on what
    ran before it — untestable, and wrong in exactly the case (a long-lived
    client) the SDK is built for. One instance per render, discarded with it.
    Constructing one per row is the other way to get this wrong, and it is what
    a single-message read wants: one row, one full sentence.

    Scoped to this cause alone. A row that failed for any other reason is not
    this class's business and gets ``None`` back, so the caller keeps whatever
    it already renders for it — the pool of "explained" is per cause, never
    per render-with-any-failure.

    Usage, per render::

        refusal = SenderKeyRefusal()
        for msg in messages:
            body = refusal.text_for(msg) or my_own_rendering(msg)

    A render that also *produces* the refusals it will show — the SDK's own
    ``thread()``, which decrypts and then renders — hands the same instance to
    both halves. Its rows earn the verdict (it spends one distribution scan per
    transcript), so :meth:`text_for` recognises them by the code and
    :meth:`not_recovered` never fires there; the method is reached from
    ``get_conversation_messages()``, the one reader that fetches nothing.

    🔴 That recipe reads a row's :data:`~rine.errors.SENDER_KEY_UNAVAILABLE_CODE`,
    so it recognises rows from a path that earns the verdict — ``inbox()``,
    ``read()`` and ``thread()``. Rows from ``get_conversation_messages()`` carry
    **no** code, and a refusal this render did not itself produce has no record
    of them, so :meth:`text_for` answers ``None`` for every one of them. Those
    rows need no help: each already carries its whole sentence in
    ``decrypt_error``, and a renderer of that list prints it rather than
    ``[unavailable]``. To tier them, render through ``thread()``, which hands its
    own refusal both halves.

    The TypeScript twin lives in ``rine-core/src/sender-key-explain.ts`` beside
    the constants it chooses between.
    """

    def __init__(self) -> None:
        """Start a render with the explanation still owed."""
        self._explained = False
        self._not_recovered: set[UUID] = set()

    def not_recovered(self, msg: DecryptedMessage, sender_key_id: str) -> str:
        """Record this row as one this render refused without going looking.

        Returns the sentence to put on it, because recording and composing are
        one act: the caller has nothing to write without the sentence, and the
        render cannot recognise a row nobody recorded.

        🔴 The earned refusal is recognised by
        :data:`~rine.errors.SENDER_KEY_UNAVAILABLE_CODE` on the row, and this
        one must not stamp it — the code is a claim about the world ("the
        recovery ran and lost") that this path has not earned. What a render
        keys off instead is a claim about *itself*: which rows this render's own
        decrypt refused this way. Nothing on the wire, nothing to leak, and no
        renderer matching words in a paragraph.

        ⚠️ The record has no reader in this package today. Both paths that reach
        here — ``get_conversation_messages()`` and the x402 quote reopen — build
        a :class:`SenderKeyRefusal` inline and drop it, and the one renderer that
        would read the record, ``thread()``, now earns the verdict instead. The
        sentence this returns is still load-bearing; the recording is answered by
        nobody, and collapsing it (with :meth:`text_for`'s first branch and the
        choke point's ``no_recovery`` parameter, which then becomes a flag) is a
        refactor of its own, not a docstring's to make.

        Args:
            msg: The row that would not open.
            sender_key_id: The key it is sealed under, read from the caller's
                own ciphertext.

        Returns:
            The un-earned sentence for this row.
        """
        self._not_recovered.add(msg.id)
        return sender_key_not_recovered_detail(sender_key_id)

    def text_for(self, msg: DecryptedMessage) -> str | None:
        """The refusal text this row should show, or ``None`` for any other cause.

        Returns the full sentence the decrypt already composed for the first
        no-sender-key row of this render, and the bounded marker for every one
        after it. The sentence is read off the message rather than re-composed
        because the sender key id it names is the row's own, and only the row
        carries it.

        Args:
            msg: The rendered row, carrying ``decrypt_error_code`` — or recorded
                by :meth:`not_recovered` on this same render.

        Returns:
            The sentence, the marker belonging to it, or ``None`` if this row
            did not fail for want of a sender key.
        """
        if msg.id in self._not_recovered:
            return self._tier(msg.decrypt_error, SENDER_KEY_NOT_RECOVERED_PREVIEW)
        if msg.decrypt_error_code != SENDER_KEY_UNAVAILABLE_CODE:
            return None
        return self._tier(msg.decrypt_error, SENDER_KEY_UNAVAILABLE_PREVIEW)

    def _tier(self, explanation: str | None, marker: str) -> str:
        """Spend the render's one explanation, or mark the row.

        A row carrying the cause but no sentence takes the marker without
        spending the explanation: there is nothing to explain with, and burning
        the budget on it would mute the next row that does have one.
        """
        if self._explained or explanation is None:
            return marker
        self._explained = True
        return explanation


__all__ = [
    "NOTHING_CONSUMED_CLAUSE",
    "NO_SENDER_KEY_STATE_CLAUSE",
    "SENDER_KEY_NOT_RECOVERED_PREVIEW",
    "SENDER_KEY_REMEDY_CLAUSE",
    "SENDER_KEY_UNAVAILABLE_PREVIEW",
    "SINGLE_MESSAGE_READ_REMEDY",
    "SenderKeyRefusal",
    "no_sender_key_state_detail",
    "sender_key_not_recovered_detail",
]
