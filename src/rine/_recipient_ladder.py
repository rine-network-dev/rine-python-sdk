"""The rungs — what is asked, in what order, before a reference is answered.

Both ladders, written once for both clients. Each is a generator over
:data:`rine._recipient_reads.LookupRequest`; :func:`rine._recipient_reads.walk`
and :func:`~rine._recipient_reads.walk_async` are what run one. Nothing here
touches the wire, so this module is where the whole cost and the whole order of
a resolution can be read.

The rung logic used to live in ``_client.py`` and again in ``_sync_client.py``.
It is here now, and the client methods are the reads plus a return type.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._group_ref import (
    group_local_part,
    group_row_by_local_name,
    recipient_group_for_bare_name,
    refuse_if_a_bare_agent_name,
    unknown_group_refusal,
)
from rine._recipient import (
    REF_CLASS_BARE,
    REF_CLASS_GROUP,
    REF_CLASS_ID,
    GroupTarget,
    RecipientTarget,
    agent_recipient,
    classify_reference,
    group_recipient,
    group_target,
)
from rine._recipient_reads import AgentIdFor, GroupById, OwnAgents, OwnGroups, SeatedByHandle
from rine.errors import NotFoundError

if TYPE_CHECKING:
    from collections.abc import Generator

    from rine._recipient_reads import LookupRequest


def group_ladder(
    reference: str, spelling: str | None = None
) -> Generator[LookupRequest, Any, GroupTarget]:
    """The group a reference names, for a caller who already holds a seat.

    Three rungs. A UUID is read from the group's own route. A reference
    carrying an org half goes to the server's exact ``?handle=`` filter, and if
    that answers nothing, its LOCAL PART goes down the same four-tier ladder a
    bare name gets, because an ``@`` the server does not recognise is the one
    spelling that used to fail worse than saying less would have. A
    reference with no org half skips straight to that ladder, since ``?handle=``
    matches a full ``#name@org`` and nothing shorter. The twin is
    ``resolveGroupByHandle`` (``rine-core/src/resolve-group.ts``).

    ⚠️ Only the first rung is read off :func:`~rine._recipient.classify_reference`.
    The second asks a different question — does this reference carry an org half
    — and ``#ops@acme.rine.network`` answers ``group`` to the first and *yes* to
    the second. The table says which NAMESPACE a reference names; it does not
    say which rung of that namespace's ladder answers it.

    🔴 **Every rung answers with the handle and the row, and the UUID rung is no
    longer the exception.** That is the guarantee that
    ``tests/contract/test_recipient_parity.py`` asserts, on every rung and on
    both clients: a rung that has paid for a listing does not hand back an id
    and make its caller pay again. The ``?handle=`` filter returns a whole group
    row, so that rung reads the handle out of the row rather than echoing the
    spelling.

    🔴 **The UUID rung reads too.** It used to pass an id straight through,
    unvalidated: an unknown one travelled to the wire and came back a bare
    server ``404``, whose measured recovery rate is 0/6, while the
    TypeScript twin refused the same id locally with the caller's own roster.
    One reference had two answers depending on which stack a caller stood on.
    Both stacks take the roster refusal now.

    🔴 **What it reads is ONE row.** That refusal first shipped as a match
    against the unpaginated roster, which cost that listing on the RESOLVED path
    as well as the refused one — and made a group this org owns but has vacated
    unaddressable by its own id, because such a group is invisible to ``GET
    /groups`` while the server serves it by id (``has_read_access`` grants on
    ``group.org_id`` before it looks at any seat). So the rung asks
    :class:`~rine._recipient_reads.GroupById` first, and the roster below is
    bought only to say which groups there were instead. A 403 falls into the
    same arm as a 404 by construction, so a stranger's id is never confirmed:
    see :func:`~rine._recipient_reads.group_read_refused`.

    ⚠️ The caller's own spelling goes on the wire, upper case and all. That is
    what preserves the local case fold this rung once carried and no longer
    needs: every group route types its path parameter ``group_id: uuid.UUID``,
    which parses either spelling to the same value, so the WIRE
    folds an id the client no longer compares — which is stricter than the local
    comparison was, since that one could only fold ids the roster contained.

    🔴 **What comes BACK is compared — but not here.** A rung that could be
    passed through could not be substituted; a rung that reads a row can be, and
    every group verb then acts on whatever group that row named.
    The comparison therefore lives inside the READ, in
    :meth:`rine.RineClient._readable_group_by_id` and its synchronous twin,
    where no caller of the id route can skip it; the alternative — checking here
    — would leave that read a seam the next rung to yield
    :class:`~rine._recipient_reads.GroupById` could forget, on this stack only,
    since TypeScript's ``readableGroupById`` makes the same mistake impossible.
    It raises rather than falling through to the roster refusal below: a server
    fault surfaces as a server fault, never as a missing group.

    🔴 The JOIN ladder is deliberately not this one and must stay so. A join
    targets a group this org is neither owner of nor seated in *by definition*,
    so neither of those two reads can describe it and a roster refusal there
    would refuse every legitimate join-by-UUID.
    :func:`~rine._recipient.group_target_by_id` — the record with no row — is
    the join ladder's alone now.

    Args:
        reference: The group reference, as the caller wrote it.
        spelling: What a refusal should quote, when that is not ``reference`` —
            see :func:`rine._group_ref.group_row_by_local_name`.

    Raises:
        NotFoundError: No group of this org answers to the reference.
        ConfigError: More than one does.
        GroupIdentityMismatchError: The id read's body named another group —
            raised by the read itself, and named here because it reaches every
            caller of this ladder.
    """
    said = reference if spelling is None else spelling
    if classify_reference(reference) == REF_CLASS_ID:
        readable = yield GroupById(reference)
        if readable is not None:
            return group_target(readable, said)
        groups = yield OwnGroups()
        raise NotFoundError(unknown_group_refusal(groups, said))
    if "@" not in reference:
        groups = yield OwnGroups()
        return group_target(group_row_by_local_name(groups, reference, said), said)
    seated = yield SeatedByHandle(reference)
    if seated is not None:
        return group_target(seated, said)
    groups = yield OwnGroups()
    return group_target(group_row_by_local_name(groups, group_local_part(reference), said), said)


def recipient_ladder(
    reference: str, spelling: str | None = None
) -> Generator[LookupRequest, Any, RecipientTarget]:
    """What a ``send()`` recipient names — one namespace, decided before any read.

    A bare word is a group: the agent namespace refuses it *syntactically,
    before any request* (:func:`rine._resolve.resolve_to_uuid_async`), so the
    group reading can only turn a certain refusal into a send or into a better
    refusal. :func:`~rine._group_ref.refuse_if_a_bare_agent_name` is what makes
    that safe, and it runs FIRST, against a list the caller has usually already
    fetched. Anything carrying the group sigil is a group as written. A handle
    and the empty string go to the agent namespace, whose refusal for a
    reference that names nothing is the clearest sentence either namespace has.

    🔴 An ID is the one reference that reaches BOTH namespaces, and it does so
    on a founder decision rather than on
    the argument the other classes rest on: a UUID has always been a legitimate
    agent id, so widening it was not free the way widening a spelling the agent
    namespace refused on syntax was. What makes it safe is the ORDER, which is
    the two routes' SCOPES. ``GET /groups/{id}`` answers only for a group this
    caller's org owns or is seated in (``has_read_access``), while
    ``GET /agents/{id}/keys`` is unauthenticated and global — so asking the
    agent side first would prefer a stranger's namespace over the caller's own
    org's. The group read goes first and a miss falls through to the agent rung
    below, which still costs nothing for a UUID.

    🔴 Only the READ is shared with :func:`group_ladder`, never the ladder. That
    one spends :class:`~rine._recipient_reads.OwnGroups` and RAISES on a miss,
    which here would refuse every agent id in the product. The JOIN ladder's
    UUID rung is a third question again — it passes an id through unread,
    because a joiner holds no seat this org-scoped route would answer for — and
    the three must not be unified.

    🔴 There is no ambiguity arm and none may be added. Both id spaces are
    minted server-side and no route accepts a caller-supplied primary key, so a
    UUID naming an agent AND a group is not constructible; a refusal for it
    would document a state the product cannot reach.

    Args:
        reference: The recipient, normalised the way ``send()`` normalises it.
        spelling: What the caller actually wrote, when normalisation changed it.
    """
    said = reference if spelling is None else spelling
    kind = classify_reference(reference)
    if kind == REF_CLASS_BARE:
        agents = yield OwnAgents()
        refuse_if_a_bare_agent_name(agents, reference)
        groups = yield OwnGroups()
        row = recipient_group_for_bare_name(groups, reference)
        return group_recipient(group_target(row, said), said)
    if kind == REF_CLASS_GROUP:
        return group_recipient((yield from group_ladder(reference, said)), said)
    if kind == REF_CLASS_ID:
        readable = yield GroupById(reference)
        if readable is not None:
            return group_recipient(group_target(readable, said), said)
    agent_id = yield AgentIdFor(reference)
    return agent_recipient(agent_id, reference, said)


__all__ = ["group_ladder", "recipient_ladder"]
