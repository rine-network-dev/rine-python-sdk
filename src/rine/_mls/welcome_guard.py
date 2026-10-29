"""What a client checks before it adopts a Welcome as local group state.

``create_group_with_members`` takes a caller-chosen group id and the server holds
every KeyPackage every agent has published, so a compromised or compelled server
can found its OWN MLS group whose id bytes are a rine group UUID the victim
belongs to, seal a real Welcome to the victim's own published KeyPackage, and
serve it from ``GET /agents/{id}/mls/welcomes``. The only check the join path had
was comparing the joined group's id against the one the delivery was filed under
— and the server chose both sides of that comparison, so it catches a mis-filed
row and not an adversary. ``save()`` then truncates whatever real state sat under
that id, and epoch secrets are the only copy of themselves.

Two checks answer that here, and neither is the same kind of thing:

* The group id comparison is **local and exact**, and catches a mis-filed row.
* :func:`_corroborate_roster` asks whether anybody else in the tree this Welcome
  seats us in is an agent the group's roster names. That is a check on
  server-supplied data with server-supplied data, so it raises the bar from no
  check at all to two coordinated lies — a fabricated tree AND a matching
  fabricated roster, both of which ``GET /agents/keys`` and ``GET
  /groups/{id}/members`` are free to tell. It does not close the attack, and no
  surface may say it does; the residual is the key-transparency gap, which is
  a known and accepted limit.

🔴 **A corroborated Welcome is adopted even over local state this agent already
holds, and that is deliberate.** Holding state raises the bar; it is not a veto.
There is no local fact that tells "my leaf is gone and this is the way back in"
from "this is a substitution": ``is_active()`` is in-session only — the native
core does not persist eviction — so a reloaded handle reports ``True`` again for
every one-shot invocation and every restarted daemon. A guard that refused on
held state therefore refused every removed-then-re-invited member, permanently,
and re-invitation is a first-class rine flow. So this module does **not** close
the state-destruction half of the attack: a server that can fabricate a matching
roster can still get a Welcome adopted over live state, and no surface may say
otherwise.

🔴 **A check that refuses an honest Welcome is worse than the attack.** The
asymmetry is what sets the bar in each direction. With local state held, a wrong
refusal costs a retry and the agent keeps reading the group, while a wrong
adoption costs the only copy of the epoch secrets — so corroboration must be
**positive**, and ``unreadable`` refuses along with ``uncorroborated``. With no
local state held there is nothing to destroy and a wrong refusal is the
unrecoverable error, so the weakest predicate stands: ``unreadable`` accepts.

Corroboration itself is deliberately the weakest predicate that still catches a
group the roster knows nothing about: ONE identity in common with members or live
invitees is enough. The tree of an honest group routinely holds leaves no roster
read accounts for — an orphan from a self-leave or a lapsed invitation, a revoked
agent ``GET /agents/keys`` no longer publishes — so requiring every leaf to be on
the roster would refuse ordinary joins into ordinary groups. Those populations
are the same ones leaf reclamation declines on (:mod:`rine._mls.orphans`), for
the same reason.

A refusal is not a verdict for all time. Every reason a later attempt could clear
keeps the Welcome bytes on the spool — see :func:`refusal_is_retryable` and
:mod:`rine._mls.welcome_spool` — because ``GET /agents/{id}/mls/welcomes``
consumes what it serves and a dropped Welcome can never be re-minted.

The TypeScript twin is ``rine-core/src/mls-welcome-guard.ts``, check for check.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Literal

from rine._actor import AGENT_HEADER
from rine._mls.group_access import load_mls_group
from rine._mls.tree import fetch_agent_identities, read_group_tree
from rine.errors import (
    WELCOME_REFUSED_CODE,
    MlsWelcomeRefusedError,
    WelcomeRefusalReason,
)

if TYPE_CHECKING:
    from rine._mls.api import MlsWelcomeDelivery
    from rine._mls.binding import MlsClient, MlsGroup


def refusal_is_retryable(reason: WelcomeRefusalReason) -> bool:
    """Whether the Welcome bytes are kept for a later attempt, or dropped.

    ``group_id_mismatch`` and ``peer_not_admitted`` are deterministic — the Welcome
    joins one group and was filed under another, or its tree never verifies — so those
    two discard, and a join after a reclaim needs no copy of the bytes. The other two
    turn on facts that move: a roster read can fail transiently, an invitation can be
    accepted, a stale leaf can be re-seated. ``GET /agents/{id}/mls/welcomes`` consumes
    what it serves and no peer can mint a replacement without noticing the first went
    unused, so a refusal that dropped those bytes would be permanent by accident.
    """
    return reason not in ("group_id_mismatch", "peer_not_admitted")


def _corroborate_roster(
    client: Any, group_id: str, joined: MlsGroup, headers: dict[str, str]
) -> Literal["corroborated", "uncorroborated", "unreadable"]:
    """Whether anyone else in ``joined``'s tree is an agent the roster names.

    The populations are the ones leaf reclamation calls entitled — members plus
    every live voucher — because the wider set can only ever accept a Welcome it
    should have questioned, never refuse an honest one.

    ``unreadable`` is a real and ordinary answer, not a failure: a Welcome can be
    installed by an agent that has been invited and has not accepted yet, and
    ``GET /groups/{id}/members`` answers 403 to an org holding no member row.
    Every shipped join verb accepts the invitation first, so that is the
    exception rather than the rule — but it is honest, and it is why an
    unreadable roster accepts for an agent holding no state to lose.
    """
    try:
        tree = read_group_tree(client, group_id, headers)
        identities = fetch_agent_identities(client, [*tree.member_ids, *tree.outstanding_ids])
    except Exception:
        return "unreadable"
    # This agent's own leaf is excluded structurally rather than by trusting the
    # roster read: it is in the tree by construction and on the roster whenever
    # the invitation was accepted, so counting it would corroborate every
    # Welcome including a fabricated one.
    own = joined.current_member_index()
    others = {bytes(leaf.identity) for leaf in joined.member_identities() if leaf.index != own}
    return "corroborated" if others & set(identities.values()) else "uncorroborated"


def welcome_refusal(
    client: Any,
    mls: MlsClient,
    joined: MlsGroup,
    delivery: MlsWelcomeDelivery,
    agent_id: str,
) -> MlsWelcomeRefusedError | None:
    """The refusal one Welcome earns, or ``None`` when it may be adopted.

    The local id comparison is first because it is exact and free. Everything
    after it turns on the roster read, whose weight depends on what this agent
    stands to lose:

    =========== ================== ===================================
    local state roster             verdict
    =========== ================== ===================================
    either      ``corroborated``   adopt
    either      ``uncorroborated`` refuse ``roster_uncorroborated``
    none        ``unreadable``     adopt
    held        ``unreadable``     refuse ``state_would_be_overwritten``
    =========== ================== ===================================

    The last two rows are the whole design: with nothing to destroy, a wrong
    refusal is the unrecoverable error; with state held, a wrong adoption is.
    Note what is NOT in the table — ``is_active()``. It is in-session only, so it
    cannot mean "am I still in this group" across a process boundary and may not
    be a discriminator here.

    ``joined`` is a handle the caller has NOT saved. Nothing here writes, so a
    refused Welcome leaves the store exactly as it was.
    """
    group_id = delivery.group_id
    joined_id = str(uuid.UUID(bytes=joined.group_id()))
    if joined_id != group_id.lower():
        return MlsWelcomeRefusedError(
            group_id,
            "group_id_mismatch",
            f"Refusing the MLS welcome delivered for group {group_id}: it joins group "
            f"{joined_id} instead, so the state key and the group a user sees would "
            "disagree from here on. The welcome is discarded — no later attempt changes "
            "which group it joins.",
        )
    headers = {AGENT_HEADER: agent_id}
    corroboration = _corroborate_roster(client, group_id, joined, headers)
    if corroboration == "corroborated":
        return None
    if corroboration == "uncorroborated":
        return MlsWelcomeRefusedError(
            group_id,
            "roster_uncorroborated",
            f"Refusing the MLS welcome for group {group_id}: the group's roster names no "
            "member and no outstanding invitation holding a leaf in the ratchet tree this "
            "welcome seats the agent in, so the group it joins is not the group it names. "
            "The welcome is kept and retried.",
        )
    if load_mls_group(mls, group_id) is None:
        return None
    return MlsWelcomeRefusedError(
        group_id,
        "state_would_be_overwritten",
        f"Refusing the MLS welcome for group {group_id}: this agent already holds local "
        "state for it and the group's roster could not be read, so nothing corroborates "
        "the welcome — and adopting it would destroy the epoch secrets that are the only "
        "copy of themselves. The welcome is kept and retried. If this agent was invited "
        "to the group again, accept the invitation first: `GET /groups/{id}/members` "
        "answers 403 to an org holding no member row, and a roster that cannot be read "
        "corroborates nothing.",
    )


__all__ = [
    "WELCOME_REFUSED_CODE",
    "MlsWelcomeRefusedError",
    "WelcomeRefusalReason",
    "refusal_is_retryable",
    "welcome_refusal",
]
