"""What a plural admission did, per agent — the public shapes.

A roster on ``groups.create`` and a batched ``groups.invite_many`` are the same
operation at two entry points, so they answer with the same report. It is
per-member because a batch **drops** what it cannot admit and reports it: one
revoked agent refusing all 32 would be a regression from the singular
behaviour at 32× the blast radius. Capacity is the one exception and is
refused whole — which 30 of your 32 get in is not a choice the server makes on
anyone's behalf.

These mirror the server's ``GroupAdmissionReport``
(``src/rine/api/group_schemas.py``) and the TypeScript SDK's equivalents. They
live in their own module rather than in :mod:`rine.types`, which is already far
over the file-size rule, for the same reason :mod:`rine.format` does.

An admission report says which offer was minted for each named agent — an
**invitation** it can spend, or a **nomination** the group's electorate decides.
Whether a ratchet-tree **leaf** landed is a different question with a different
answer — ``rine._mls.admission.MlsAdmissionResult`` — because an agent can be
invited and unseated, or seated and not yet a member. A nomination is never
seated at all: the vote seats the member, and seating is what grants the key.

These are the **shapes**. Turning one into words an operator can act on is
:mod:`rine.admission_words`, which holds both halves' sentence maps in one file,
as ``rine-core/src/group-admission.ts`` does for TypeScript.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel

# Imported at RUNTIME, not behind TYPE_CHECKING: pydantic resolves these
# annotations when it builds the model, so the name has to be in module
# globals however the annotation is spelled.
from rine._mls.admission import MlsAdmissionResult  # noqa: TC001
from rine.types import GroupCreateResult

#: Why one requested agent was not invited.
#:
#: ``not_applicable`` is an open-enrollment group, where there is nothing to
#: mint — anyone may join — so naming agents there is a no-op rather than an
#: error. ``already_invited`` covers an unresolved request of either kind: a
#: second live voucher is what let a removed member readmit itself.
GroupAdmissionSkipReason = Literal[
    "agent_not_found",
    "agent_revoked",
    "already_a_member",
    "already_invited",
    "isolation_conflict",
    "not_applicable",
]

#: Which outstanding population ``groups.list_requests`` asks the server for.
#:
#: Mirrors the server's ``OutstandingFilter`` (``src/rine/api/group_schemas.py``)
#: and the TypeScript SDK's, so a typo fails at the call site instead of
#: reaching the server as a 422. ``live`` is ``pending`` plus ``invited``, and
#: it is the population the group ceiling counts — a caller sizing a ratchet
#: tree wants it, not the vote queue.
OutstandingFilter = Literal["pending", "invited", "live"]


class GroupAdmissionEntry(BaseModel):
    """What happened to one requested agent id.

    ``nominated`` is what an invite to a ``majority`` or ``unanimity`` group
    does: it files a join request the electorate decides, rather than a voucher
    the agent can spend. It is a third value rather than a reuse of
    ``invited`` because the two are different offers — one is accepted, the
    other is voted on and may be denied — and a renderer that cannot tell them
    apart states a falsehood about the row in front of it.
    """

    agent_id: UUID
    status: Literal["invited", "nominated", "skipped"]
    reason: GroupAdmissionSkipReason | None = None
    """Present iff ``status == "skipped"``."""


class GroupAdmissionReport(BaseModel):
    """Per-member outcomes for a plural admission."""

    invited: int
    skipped: int
    entries: list[GroupAdmissionEntry]
    """One per requested id, in request order."""


class GroupCreateWithRoster(GroupCreateResult):
    """A created group, and what its roster achieved.

    ``roster`` is ``None`` when no members were named — which is every call that
    ever worked before, and the response the server still returns byte for byte.
    A roster **invites**; it never seats, so a brand-new group has exactly one
    member however many agents it named. It mints real invitations on
    every policy, including the two where an invite otherwise nominates: at
    founding the creator is the only member, so a vote would be a formality that
    auto-approves every row.

    ``mls_admission`` is the other half of that answer and the reason both are
    here: on a closed group the same call also claims a KeyPackage per invitee
    and Welcomes them into the ratchet tree, and an invitee whose pool was empty
    holds a good invitation and can read nothing. The roster counts cannot say
    so — they are about vouchers — so a stack that reported only ``roster``
    answered "40 invited, 0 skipped" to a founding that left three agents
    unable to read a word. ``None`` when the group runs sender keys, or when no
    MLS admission was attempted.
    """

    roster: GroupAdmissionReport | None = None
    mls_admission: MlsAdmissionResult | None = None


class GroupInviteReport(GroupAdmissionReport):
    """A plural invitation's outcome, both halves of it.

    A subclass rather than a new shape: every caller that treats this as a
    :class:`GroupAdmissionReport` keeps working, and ``mls`` is additive. It is
    the invite path's twin of ``GroupCreateWithRoster.mls_admission``, and it is
    ``None`` for exactly the same reasons.
    """

    mls: MlsAdmissionResult | None = None


__all__ = [
    "GroupAdmissionEntry",
    "GroupAdmissionReport",
    "GroupAdmissionSkipReason",
    "GroupCreateWithRoster",
    "GroupInviteReport",
    "OutstandingFilter",
]
