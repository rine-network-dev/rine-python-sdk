"""An admission, in words an operator or a model can act on.

**One rendering module per language**, holding both halves: the server's
vocabulary answers "was an invitation minted", the MLS one answers "did a
ratchet-tree leaf land". An agent can be ``invited`` in the first and
``no_key_package`` in the second — it may join, and it cannot read a word until
a leaf exists for it. The TypeScript twin is
``rine-core/src/group-admission.ts``, which holds exactly the same two maps.

**Both maps are byte-identical to their TypeScript counterparts**, and a lane
that adds a reason adds it in both languages in the same commit — the same rule
the enums carry. A reason one language can render and the other cannot is how a
surface comes to print a raw wire token, which is the whole defect this module
exists to close: every surface used to print ``skipped (not_applicable)`` for
agents the same code path had just DM'd an invitation notice.

:mod:`rine.group_admission` holds the shapes these render.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rine._mls.admission import (
        MlsAdmissionOutcome,
        MlsAdmissionResult,
        MlsAdmissionSkipReason,
        MlsReclamation,
    )
    from rine.group_admission import (
        GroupAdmissionEntry,
        GroupAdmissionReport,
        GroupAdmissionSkipReason,
    )

#: Why one requested agent was not invited, as a clause rather than a token.
#:
#: **Byte-identical to rine-core's ``GROUP_ADMISSION_SENTENCES``**
#: (``rine-core/src/group-admission.ts``). Two stacks that answer the same wire
#: token with two different sentences is the drift these contracts exist to
#: prevent, so a wording change lands in both files in the same commit.
#:
#: ``not_applicable`` is why any of this exists: an open group's roster comes
#: back entirely ``skipped/not_applicable`` while the very same call DMs every
#: one of those agents an invitation notice
#: (:func:`admitted_agent_ids`), so the surface that
#: knew they were reached printed "skipped". The server's own note is the
#: authority — ``not_applicable`` means "this group needs no voucher", not "we
#: did not look" (``src/rine/api/group_admission.py``).
_GROUP_ADMISSION_SENTENCES: dict[GroupAdmissionSkipReason, str] = {
    "agent_not_found": "no agent with that id exists here",
    "agent_revoked": "that agent's identity is revoked, so it can join nothing",
    "already_a_member": "already a member of this group",
    "already_invited": (
        "already holds an unaccepted invitation to this group, and that one still stands"
    ),
    "isolation_conflict": (
        "refused by the isolation rule — an isolated group takes only agents that are "
        "in no other group, and an agent that is in an isolated group joins nothing else"
    ),
    "not_applicable": (
        "this group takes open enrollment, so it mints no invitation because none is "
        "needed — the agent may join whenever it likes"
    ),
}


def group_admission_skip_sentence(reason: GroupAdmissionSkipReason | None) -> str:
    """Why an agent named in a roster or a plural invite was not invited.

    Reads as a clause, so a caller puts it wherever it renders the id:
    ``f"{entry.agent_id}: {group_admission_skip_sentence(entry.reason)}"``.
    :func:`describe_admission_entry` is that composition, kept in one place.

    The twin is ``groupAdmissionSkipSentence`` in
    ``rine-core/src/group-admission.ts``, over the same tokens with the same
    words. It differs in one respect, and only because the languages do: the
    TypeScript one takes a bare ``string`` and quotes an unrecognised token
    back, because a client that does not validate the wire must not throw while
    rendering. Python validates first — an unknown reason fails
    :class:`GroupAdmissionReport` at ``model_validate``, long before anything is
    rendered — so this one takes the literal and cannot be handed a surprise.

    Args:
        reason: The reason an entry carries, or ``None`` for an entry that
            names none.

    Returns:
        A lower-case clause, ready to follow a colon.
    """
    if reason is None:
        return "no reason given"
    return _GROUP_ADMISSION_SENTENCES[reason]


def describe_admission_entry(entry: GroupAdmissionEntry) -> str:
    """One line for one requested agent: what happened to it, and why.

    Surfaces print this rather than ``skipped (<token>)``, which on an open
    group labels every agent the same call just notified as skipped. The word
    "skipped" is deliberately absent: the server's ``status`` field is the
    machine's vocabulary, and what the reader needs is the fact.

    Args:
        entry: One entry of a :class:`GroupAdmissionReport`.

    Returns:
        A single line naming the agent and its outcome.
    """
    if entry.status == "invited":
        return f"{entry.agent_id}: invited"
    if entry.status == "nominated":
        return f"{entry.agent_id}: nominated, awaiting a vote"
    return f"{entry.agent_id}: {group_admission_skip_sentence(entry.reason)}"


def admitted_agent_ids(report: GroupAdmissionReport) -> list[str]:
    """The agents a report says are now welcome in the group.

    The invited entries **plus** the nominated ones **plus** the
    ``not_applicable`` ones, which is the same arithmetic the server charges
    seats by. An open group mints no voucher because it needs none, so every
    entry comes back ``not_applicable``: reading ``"invited"`` alone therefore
    produced an empty set and a whole plural invite into an open group went
    unannounced. A nomination is counted for the same reason from the other
    side — it reserves a ratchet-tree seat exactly as an invitation does, and
    the agent it names has to be told it is waiting on a vote.

    🔴 "Reached" is not "seated". These are the agents an invitation notice is
    owed to; whether a ratchet-tree leaf is minted for any of them is a
    different question, and on a nominating policy the answer is no until the
    vote carries (``rine._resources.group_invite_effects``).

    The twin is ``admittedAgentIds`` in ``rine-core/src/group-admission.ts``.

    Args:
        report: What the admission answered.

    Returns:
        The agent ids owed a notice, in request order.
    """
    return [
        str(e.agent_id)
        for e in report.entries
        if e.status in ("invited", "nominated") or e.reason == "not_applicable"
    ]


def admission_headline(report: GroupAdmissionReport) -> str:
    """The one line above the per-agent lines.

    🔴 Composed from the **entries**, not from ``invited``/``skipped``. The
    server answers ``not_applicable`` for every valid agent on an open group, so
    those two counters read "0 invited, N skipped" there — always — while the
    same call DMs all N an invitation notice. Six surfaces printed that headline
    directly above per-agent lines that had just been made truthful, so the
    summary contradicted the detail beneath it.

    An invitation and a nomination earn different clauses because they are
    different offers: one is accepted by the agent named, the other is decided
    by the electorate and may be denied. Calling a nomination an "invitation to
    accept" tells the operator the admission is finished when it has not begun.

    Args:
        report: What the admission answered.

    Returns:
        One sentence: how many agents were reached, how many hold a new
        invitation to accept, and how many nominations are waiting on a vote.
    """
    reached = len(admitted_agent_ids(report))
    nominated = sum(1 for e in report.entries if e.status == "nominated")
    invited = sum(1 for e in report.entries if e.status == "invited")
    clauses = []
    if invited or not nominated:
        clauses.append(f"{invited} new {_plural(invited, 'invitation')} to accept")
    if nominated:
        clauses.append(f"{nominated} new {_plural(nominated, 'nomination')} awaiting a vote")
    return f"{reached} of {len(report.entries)} reached; {'; '.join(clauses)}."


def _plural(count: int, noun: str) -> str:
    """``noun`` as ``count`` of them are. Both nouns take a plain ``s``."""
    return noun if count == 1 else f"{noun}s"


#: Why one requested agent got no ratchet-tree leaf, as a clause.
#:
#: ``no_key_package`` is the one an operator has to act on: the agent's
#: published pool was empty at claim time, so nothing could seat it and it can
#: read nothing until somebody refills the pool and resumes the admission — and
#: no count in the roster report says so.
#:
#: 🔴 It says nothing about WHICH entitlement the agent holds, and it must not:
#: the reason is recorded over members and live invitees flattened into one
#: list, so an invitee and an agent a carried vote already seated arrive
#: indistinguishable. This clause used to assert an invitation, which is false
#: of every member seated by a vote.
#:
#: The remedy names the MOVES and no verb's spelling: nine surfaces render these
#: clauses, and one surface's command line is a sentence only its own reader can
#: follow.
#:
#: 🔴 And it names TWO moves because the reason covers two populations that
#: cannot make the same one. Syncing a group opens with ``GET /groups/{id}``,
#: which ``has_read_access`` grants to the owning org or to an org holding a
#: MEMBER row (``src/rine/api/group_scope.py``) — so an agent from another org
#: that has not joined yet cannot read the group at all, and telling it to sync
#: would be a remedy the product refuses. Joining is that agent's move: a closed
#: group's joiner takes its own leaf by external commit and needs no Welcome from
#: anybody.
_MLS_ADMISSION_SENTENCES: dict[MlsAdmissionSkipReason, str] = {
    "no_key_package": (
        "published no key package to claim, so no Welcome could be minted — the "
        "group still holds their place, and they cannot read this group until a "
        "leaf exists for them. An agent that is already in the group republishes "
        "its key packages by syncing it; one that has not joined yet takes its "
        "own leaf on joining, and needs no Welcome from anybody. Resume the "
        "admission afterwards to seat whoever is left"
    ),
    "already_in_group": "already holds a ratchet-tree leaf, so there was nothing to do",
    "key_package_not_current": (
        "offered only a key package minted under an earlier key generation, which no "
        "Welcome may be sealed to — the package is spent, the agent publishes current "
        "ones on its next MLS operation, and resuming the admission afterwards seats them"
    ),
    "rejected_by_server": (
        "the server refused them as a Welcome recipient — revoked, gone, or not "
        "enrolled in this group — and the batch was retried without them"
    ),
    "revoked_seat_unreclaimed": (
        "was held back, because the group's tree still holds the leaf of a revoked member "
        "and a Welcome minted over it could never be opened — a member reclaims that leaf "
        "first, and resuming the admission afterwards seats them"
    ),
}


def mls_admission_skip_sentence(reason: MlsAdmissionSkipReason | None) -> str:
    """Why a named agent got no leaf in this admission.

    Reads as a clause, so a caller puts it wherever it renders the id:
    ``f"{outcome.agent_id}: {mls_admission_skip_sentence(outcome.reason)}"``.
    :func:`describe_mls_outcome` is that composition, kept in one place.

    Takes the literal rather than a bare ``str``, unlike its TypeScript twin,
    for the reason :func:`rine.group_admission.group_admission_skip_sentence`
    gives: these outcomes are built locally by
    :mod:`rine._mls.admission_state`, not read off the wire, so this one cannot
    be handed a surprise.

    Args:
        reason: The reason an outcome carries, or ``None`` for one that names
            none.

    Returns:
        A lower-case clause, ready to follow a colon.
    """
    if reason is None:
        return "no reason given"
    return _MLS_ADMISSION_SENTENCES[reason]


def describe_mls_outcome(outcome: MlsAdmissionOutcome) -> str:
    """One line for one requested agent: whether it got a leaf, and why not.

    The word "skipped" is deliberately absent, for the reason
    :func:`rine.group_admission.describe_admission_entry` gives: ``status`` is
    the machine's vocabulary and what the reader needs is the fact.

    Args:
        outcome: One outcome of an :class:`~rine._mls.admission.MlsAdmissionResult`.

    Returns:
        A single line naming the agent and what happened to it.
    """
    if outcome.status == "added":
        return f"{outcome.agent_id}: seated in the ratchet tree"
    return f"{outcome.agent_id}: {mls_admission_skip_sentence(outcome.reason)}"


def describe_mls_admission(result: MlsAdmissionResult) -> str:
    """The whole admission: what it seated, and everyone it did not.

    ``already_in_group`` is left out of the unseated lines: an agent that
    already holds a leaf is what a **resumed** admission looks like when it has
    nothing left to do, not a failure to report.

    Args:
        result: What the admission achieved.

    Returns:
        A head line, then one line per agent still without a leaf.
    """
    head = (
        f"MLS: {result.added} seated across {result.commits} commit(s), "
        f"now at epoch {result.epoch}."
    )
    unseated = [
        o for o in result.outcomes if o.status == "skipped" and o.reason != "already_in_group"
    ]
    tail = describe_mls_reclamation(result.reclamation)
    if not unseated:
        return f"{head}{tail}"
    lines = [f"  {describe_mls_outcome(o)}" for o in unseated]
    return "\n".join([f"{head} No ratchet-tree leaf yet:", *lines]) + tail


def describe_mls_reclamation(reclamation: MlsReclamation | None) -> str:
    """What a leaf-reclamation pass did, as a sentence to append to a headline.

    Empty when no pass ran. A pass that ran and found nothing still says so:
    "nobody asked" and "there was nothing there" are different facts, and only
    one of them means the tree is clean.
    """
    if reclamation is None:
        return ""
    if reclamation.declined is not None:
        return f" {reclamation.declined.detail}"
    if reclamation.found == 0:
        return " Every leaf belongs to a member or to an unanswered invitation."
    return (
        f" Reclaimed {reclamation.reclaimed} of {reclamation.found} orphaned leaves in "
        f"{reclamation.commits} commit(s), now at epoch {reclamation.epoch}; each Remove "
        "commit is O(N) and is billed to every member."
    )


__all__ = [
    "admission_headline",
    "admitted_agent_ids",
    "describe_admission_entry",
    "describe_mls_admission",
    "describe_mls_outcome",
    "describe_mls_reclamation",
    "group_admission_skip_sentence",
    "mls_admission_skip_sentence",
]
