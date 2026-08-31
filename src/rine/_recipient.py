"""What a caller's recipient spelling names, before anything is fetched.

The Python twin of ``rine-core/src/recipient-resolution.ts``. Three things live
here and nothing else: the classification table, the two records a resolve
answers with, and the constructors that build them. The rungs that WALK a reference are
:mod:`rine._recipient_ladder`, which imports this module.

That split is not cosmetic. :mod:`rine._group_ref` re-expresses its two
predicates over :func:`classify_reference`, so this module must be reachable
from there — and it holds the ladder's own matchers, so a single module holding
both the table and the rungs would import itself.

🔴 **Classification never crosses namespaces.** It answers what a string IS, as
written. Which ladder the string is then walked down is decided by the SLOT the
caller chose — a verb, or ``send``'s recipient — and never inferred from the
string. The asymmetry that makes that a safety rule rather than a preference:
the server refuses a post to a group the acting agent holds no seat in, so a
wrong group resolution is caught on the wire, and a wrong AGENT resolution
delivers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from rine._resolve import is_uuid

#: The five answers :func:`classify_reference` gives, one constant each.
#:
#: Plain assignments, deliberately. The source-parse registries in
#: ``tests/test_client-server-contract_group0.py`` read module-level
#: ``ast.Assign`` only, so an annotated ``REF_CLASS_EMPTY: str = "empty"`` is
#: invisible to them and reports as a rename rather than as a value.
#:
#: The five literals are written again in :func:`classify_reference`'s arms:
#: a bare assignment types as ``str``, the function answers the ``Literal``
#: union below, and threading one through the other would need a cast at every
#: arm. ``tests/test_recipient.py`` pins the constants against the function so
#: the two spellings of one table cannot drift apart.
REF_CLASS_EMPTY = "empty"
REF_CLASS_GROUP = "group"
REF_CLASS_ID = "id"
REF_CLASS_AGENT = "agent"
REF_CLASS_BARE = "bare"

RefClass = Literal["empty", "group", "id", "agent", "bare"]
"""Which namespace a reference names, as written."""


def classify_reference(value: str) -> RefClass:
    """Read a recipient spelling — the one table, tested in one order.

    Empty after trimming, then a leading ``#``, then a UUID, then an ``@``, then
    everything else. The order is the contract, not an implementation detail:
    the twin (``classifyReference``, ``rine-core``) tests the same five in the
    same sequence, and the server's own discriminator is the same first
    question (``to_handle.startswith("#")``, ``src/rine/api/messages.py``,
    before any DB access).

    🔴 ``id`` is tested BEFORE ``@`` and after ``#``. A UUID carries no ``@``,
    so the order between those two is unobservable today — it is pinned so the
    stacks cannot drift apart the day a UUID pattern widens. Python already has
    a looser reading of a UUID than the TypeScript stack does
    (:func:`rine._resolve.parses_as_uuid`); it is deliberately NOT wired in here
    — an open follow-up.
    """
    if not value.strip():
        return "empty"
    if value.startswith("#"):
        return "group"
    if is_uuid(value):
        return "id"
    if "@" in value:
        return "agent"
    return "bare"


@dataclass(frozen=True, slots=True)
class GroupTarget:
    """The group a reference named, and everything the resolve already knows.

    ``row`` exists so a caller never re-reads what the resolve fetched, and
    ``handle`` because the send path addresses ``to_handle``: a UUID-only answer
    is what forced the local-name match to be a second, parallel change
    (:func:`rine._group_ref.match_group_by_local_name`).

    🔴 **On the member ladder both are set on every rung**, the UUID included:
    it used to ask the server nothing and answer with an id alone, and that was
    closed onto the TypeScript twin's shape — it fetches the roster and refuses
    an unknown id locally, so both stacks are whole on all three rungs.
    That is asserted, rung by rung, in
    ``tests/contract/test_recipient_parity.py``.

    The JOIN ladder is why the fields are nullable at all — it answers with an
    id on every rung, its target being a group ``GET /groups`` cannot see. The
    member ladder's roster refusal must never be applied there.

    ``spelling`` is the caller's own argument, unchanged — never the local part
    a fallback matched on, never a normalised form. It is the only string a
    refusal may quote back.
    """

    id: str
    handle: str | None
    spelling: str
    row: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class RecipientTarget:
    """What ``send``'s ``to`` named, and which namespace answered it.

    ``kind`` is decided by :func:`classify_reference` and the slot, never by
    trying one namespace and then the other: there is no "try agent, then try
    group" on either stack.
    """

    kind: Literal["agent", "group"]
    id: str
    handle: str | None
    spelling: str
    row: dict[str, Any] | None


def group_target(row: dict[str, Any], spelling: str) -> GroupTarget:
    """The record a rung that has the ROW in hand answers with."""
    return GroupTarget(
        id=str(row["id"]),
        handle=str(row["handle"]) if row.get("handle") else None,
        spelling=spelling,
        row=row,
    )


def group_target_by_id(group_id: str, spelling: str) -> GroupTarget:
    """The record a rung that has only an id answers with.

    🔴 **One caller: the JOIN ladder**, every rung of it, whose target is by
    definition a group this org holds no seat in and that ``GET /groups``
    therefore cannot describe. The member ladder's UUID rung was the second
    caller once — it asked the server nothing and handed back an
    unvalidated id — and it now fetches the roster and answers with
    :func:`group_target` like every other member rung. Do not route a member
    rung back through here to save the read; that read IS the refusal.

    🔴 Not a shortcut for a rung that DID read. The exact ``?handle=`` filter
    used to come through here, throwing away a row it had been handed; it
    answers with :func:`group_target` now.
    """
    return GroupTarget(id=group_id, handle=None, spelling=spelling, row=None)


def group_recipient(target: GroupTarget, spelling: str) -> RecipientTarget:
    """A group the recipient slot resolved to, in the recipient slot's record.

    Takes the :class:`GroupTarget` rather than the row so the recipient slot and
    every group verb answer the same group with the same fields — including on
    the rungs where those fields are ``None``.
    """
    return RecipientTarget(
        kind="group",
        id=target.id,
        handle=target.handle,
        spelling=spelling,
        row=target.row,
    )


def agent_recipient(agent_id: str, reference: str, spelling: str) -> RecipientTarget:
    """An agent the recipient slot resolved to.

    ⚠️ ``agent_id`` is whatever :func:`rine._resolve.resolve_to_uuid_async`
    returned, and that function does **not** validate WebFinger's answer: a
    handle nobody could resolve comes back as the handle and travels on as
    though it were an id. The TypeScript twin validates and throws. This stack
    preserves the divergence rather than closing it here, because closing it
    turns a shipped soft failure into a refusal on a slot whose wrong answers
    DELIVER — a decision, not a cleanup.
    """
    return RecipientTarget(
        kind="agent",
        id=agent_id,
        handle=reference if "@" in reference else None,
        spelling=spelling,
        row=None,
    )


__all__ = [
    "REF_CLASS_AGENT",
    "REF_CLASS_BARE",
    "REF_CLASS_EMPTY",
    "REF_CLASS_GROUP",
    "REF_CLASS_ID",
    "GroupTarget",
    "RecipientTarget",
    "RefClass",
    "agent_recipient",
    "classify_reference",
    "group_recipient",
    "group_target",
    "group_target_by_id",
]
