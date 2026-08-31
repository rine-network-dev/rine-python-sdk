"""What recovering a group produced, whichever encryption that group runs.

A rine group runs one of two encryptions and both are supported products, so
"catch this group up" has two meanings that share no field. MLS recovery walks
an epoch ladder and reports a rung, a distance and a leaf
(:class:`~rine._mls.resync.MlsRecoveryResult`). Sender-key recovery has none of
those: there is no epoch chain, so what a member can be missing is other
members' keys, and the whole of the repair is ingesting the distribution DMs
already sitting in this agent's own inbox.

The two are told apart by ``regime`` and by nothing else. It is a real field
rather than a TypeScript-only intersection because these shapes are twins across
the two stacks and Python has no intersections — and because the discriminant
has to survive into JSON, which is what the CLI prints and what an MCP tool
returns. A discriminant that exists only in the type system is absent from
exactly the place a consumer needs it.

The TypeScript twin is ``rine-core/src/group-recovery.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from typing import TypeAlias

    from rine._mls.resync import MlsRecoveryResult


@dataclass(frozen=True)
class SenderKeyScan:
    """One pass over the distribution inbox: what it installed, what it skipped.

    The second number is the whole reason this shape exists. The scan reads ONE
    page of ``limit=100`` and follows no cursor, so on an agent whose
    distribution inbox is longer than that page the pass is a partial one — and
    the count of what it installed cannot say so. Carrying the two together is
    what lets the sync answer state the shortfall instead of reporting a partial
    pass as a whole one.

    It lives here rather than beside either client because both clients are
    hand-mirrored copies of the same pass and a shape declared in one of them is
    a shape the other can drift from. The TypeScript twin is ``SenderKeyScan``
    (``rine-core/src/sender-key-recovery.ts``).
    """

    ingested: int
    """Sender keys newly installed by this pass. What every read path reads, and
    the number ``_fetch_pending_sk_distributions`` hands back."""

    unscanned: int
    """How many distribution DMs the server counts for this agent BEYOND the page
    this pass read — ``0`` when the page covered them all, and ``0`` again when
    the server sent no total to compare against.

    🔴 It is a count of what this pass did not LOOK at, and says nothing about
    what those DMs hold: the inbox listing is every distribution this agent has
    ever been sent, so most of the ones behind that page are keys it installed
    long ago. A renderer may state the number and may not conclude a missing key
    from it.

    The TypeScript twin carries one more term this stack has no way to produce:
    it takes an optional target key id and stops the pass the moment it installs
    that key, so the rows of its own page after that break are unopened too and
    are counted here as well. No scan on this stack takes a target, so the page
    is always read to the end and the two definitions agree."""


def unscanned_beyond_page(listing: object, opened: int) -> int:
    """How much of a distribution listing the pass that just read it did not open.

    ``total`` counts every row the server matched, the page holds at most the
    hundred asked for, and the difference is the part of the inbox this pass
    never opened. The list route computes the total by default
    (``include_total``, ``src/rine/api/messages.py``) but a server that omitted
    it leaves nothing to subtract — and a shortfall invented out of a missing
    field is worse than none, so an absent total is no shortfall.

    It lives beside :class:`SenderKeyScan` for the reason the shape does: the
    sync and async scans are hand-mirrored copies of one pass, and arithmetic
    written twice is arithmetic that gets corrected once. The TypeScript twin is
    inline in ``scanPendingSKDistributions``
    (``rine-core/src/sender-key-recovery.ts``), which has a single copy of it.

    Args:
        listing: The list response, in whatever shape it came back.
        opened: How many of its rows this pass actually read.

    Returns:
        The rows it did not read, or ``0`` when the server sent no total.
    """
    total = listing.get("total") if isinstance(listing, dict) else None
    return max(0, total - opened) if isinstance(total, int) else 0


@dataclass(frozen=True)
class SenderKeyRecoveryResult:
    """What recovering a sender-key group installed, and what it could not."""

    regime: Literal["sender-key"]
    """Which recovery ran. Every consumer branches on this, never on which
    fields a result happens to carry."""

    ingested: int
    """Sender keys newly installed. The scan is this agent's whole distribution
    inbox rather than one group's share of it — the group a distribution belongs
    to is only known after its DM is decrypted — so a recovery run for one group
    also installs any key waiting for another."""

    retired: bool
    """True when this agent retired its keys for this group and nothing lifted
    that retirement, so nothing was installed and nothing could be.

    🔴 NOT "the server said this agent is not a member". The gate fails closed —
    a membership read that errors keeps the refusal, because a transport failure
    proves nothing — so this covers both "the server does not name this agent a
    member" and "the server could not be asked". Anything rendering it must
    leave a retry open."""

    unscanned: int | None = None
    """How many distribution DMs the server counts for this agent beyond the
    single page the scan read — the exact shortfall, straight out of the
    ``total`` the list response already carries, at no extra request.

    ``None``, never ``0``, when the page covered everything, and ``None`` again
    when the scan never ran (the retired arm): the renderer's shortfall sentence
    is the only reader, so ``None`` and ``0`` mean the same thing to it while a
    surface projecting this into JSON would print a number reporting that
    nothing happened.

    🔴 It counts what the pass did not LOOK at, and it is not a count of keys
    this agent is missing. The inbox listing is every distribution this agent has
    ever been sent, so most of what sits behind that page is material it
    installed long ago — the sentence built from it may state the number and may
    not conclude a missing key from it. The TypeScript twin is ``unscanned``
    (``rine-core/src/group-recovery.ts``)."""

    mls_never_founded_note: str | None = None
    """Set when the group was created to run MLS and its ratchet tree was never
    founded: what this recovery could not reach, in the words every surface
    prints (:func:`rine.format.mls_never_founded_sync`, already carrying the
    calling surface's own spelling of the founding verb).

    A fact about the GROUP and not about the scan, so it rides on all three
    sender-key answers alike. ``None`` when there is nothing to say, and a
    surface projecting this into JSON must then omit the key rather than emit a
    null — the ``actor note`` rule both stacks already follow.

    🔴 It is deliberately not called ``warning``. The hermes tool passes an
    actor note to ``tool_result`` as ``**note``, whose own key is ``warning``,
    so a second ``warning`` here would raise ``TypeError: got multiple values
    for keyword argument 'warning'``; ``rine-mcp`` spreads its note over the
    same result object and would silently overwrite instead. The TypeScript twin
    is ``mlsNeverFoundedNote`` (``rine-core``)."""


if TYPE_CHECKING:
    #: What a recovery produced, whichever encryption the group runs.
    #:
    #: Declared for type checkers only, deliberately. Naming the MLS arm at run
    #: time would mean importing :mod:`rine._mls.resync`, which raises when the
    #: ``rine-mls`` wheel is not installable for the platform — and
    #: :mod:`rine.format`, which every framework wrapper imports, must stay
    #: importable there. Annotations in this SDK are lazy, so an annotation is
    #: all any caller needs.
    GroupRecoveryResult: TypeAlias = MlsRecoveryResult | SenderKeyRecoveryResult


__all__ = ["SenderKeyRecoveryResult", "SenderKeyScan", "unscanned_beyond_page"]
