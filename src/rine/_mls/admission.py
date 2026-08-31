"""What a batched MLS admission did, per requested agent.

One shape for founding a group and for adding to one later, because they are
the same loop: ``init_mls_group`` is its ``seated = 1`` entry point and
``add_mls_group_members`` is the other. Two shapes for one answer is what this
contract exists to prevent.

The TypeScript twin is ``MlsAdmissionResult`` in ``rine-core/src/mls-ops.ts``,
with the same field names in camelCase and the same reason strings. **The two
enums must hold the same members** — a lane that adds one adds it in both
languages in the same commit, or a surface reports a reason its sibling surface
cannot render.

This is the MLS half of admission and is deliberately not the server's
``GroupAdmissionReport`` (:mod:`rine.group_admission`): that one answers "was a
voucher minted", this one answers "did a leaf land in the ratchet tree". An
agent can be invited and unseated, or seated and not yet a member.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: Why a requested agent did not get a leaf in this admission.
#:
#: * ``no_key_package`` — the agent's KeyPackage pool was empty at claim time.
#:   Not an error: founding has always skipped such a member rather than
#:   failing, and the agent joins later once it republishes.
#: * ``already_in_group`` — its leaf already resolves in the ratchet tree. This
#:   is what makes the loop a **resume** rather than a re-run: an admission over
#:   a partly-founded group re-admits nobody.
#: * ``rejected_by_server`` — the server refused this recipient (422
#:   ``welcome_recipient_rejected``), and the batch was retried once without
#:   them.
MlsAdmissionSkipReason = Literal[
    "no_key_package",
    "already_in_group",
    "rejected_by_server",
]


@dataclass(frozen=True)
class MlsAdmissionOutcome:
    """What happened to one requested agent id."""

    agent_id: str
    status: Literal["added", "skipped"]
    reason: MlsAdmissionSkipReason | None = None
    """Present iff ``status == "skipped"``."""


#: Why leaf reclamation declined to act on the orphan set it could see.
#:
#: * ``identity_unknown`` — an agent the group entitles to a seat publishes no
#:   readable signing key, so its leaf cannot be told apart from an orphan's.
#:   ``GET /agents/keys`` omits revoked agents, and an invitation outlives the
#:   revocation of the agent it names: dropping that agent's leaf while its
#:   voucher stands would evict somebody the group still holds a seat for.
#: * ``identity_unseated`` — an agent the server calls a **member** publishes a
#:   signing key that occupies no leaf in the tree. Membership and the ratchet
#:   tree have come apart — a key rotation is the ordinary cause — and while
#:   they are apart no leaf can be attributed, so a set difference would evict a
#:   seated member whose leaf still carries the key they published before.
#: * ``outstanding_unknown`` — the group's live invitations could not be read,
#:   so every agent invited and not yet accepted would look like an orphan.
#:
#: The TypeScript twin holds the same three members
#: (``rine-core/src/mls-admission.ts``). Its pass raises rather than declining
#: on an unreadable outstanding read, because ``fetchGroupTree`` does not
#: degrade the way :func:`rine._mls.tree.read_group_tree` does.
MlsReclamationDeclineReason = Literal[
    "identity_unknown", "identity_unseated", "outstanding_unknown"
]


@dataclass(frozen=True)
class MlsReclamationDecline:
    """A stated refusal to reclaim, with the sentence a surface renders."""

    reason: MlsReclamationDeclineReason
    detail: str


@dataclass(frozen=True)
class MlsReclamation:
    """What one leaf-reclamation pass did to a group's ratchet tree.

    ``found`` is 0 whenever ``declined`` is set: the orphan set was not computed
    at all, rather than computed and left alone.

    The TypeScript twin is ``MlsReclamationResult`` in
    ``rine-core/src/mls-admission.ts``, with the same field names in camelCase
    and the same decline reasons.
    """

    found: int
    """Leaves entitled to nobody, as the pass found them."""

    reclaimed: int
    """How many of those a Remove commit actually retired."""

    commits: int
    """Remove commits posted — one per reclaimed leaf, each O(N)."""

    epoch: int
    """The group's epoch after the last Remove commit."""

    declined: MlsReclamationDecline | None = None
    """Set when nothing was reclaimed because the set could not be trusted."""


@dataclass(frozen=True)
class MlsAdmissionResult:
    """What a whole admission achieved.

    ``epoch`` is the group's epoch after the last accepted commit, so an
    admission that added nobody still reports where the group stands — which is
    what a removal path needs to name ``mls_removal_epoch``.
    """

    epoch: int
    commits: int
    """How many commits it took. One per batch, plus any retried batch."""

    added: int
    outcomes: tuple[MlsAdmissionOutcome, ...]
    """One per requested id, in request order."""

    reclamation: MlsReclamation | None = None
    """What leaf reclamation did, when the caller asked for it.

    ``None`` when it was not asked for — never a zeroed report, so "nobody ran
    it" and "it ran and found nothing" stay distinguishable.
    """


__all__ = [
    "MlsAdmissionOutcome",
    "MlsAdmissionResult",
    "MlsAdmissionSkipReason",
    "MlsReclamation",
    "MlsReclamationDecline",
    "MlsReclamationDeclineReason",
]
