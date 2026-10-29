"""The key-package heartbeat: one call that every MLS operation routes through.

Peers claim a key package each time they add this agent to a group, so a pool
that is never topped up runs out — and at zero the agent is **un-addable**. No
member can mint it a Welcome, every further admission degrades to a self-join,
and a self-join processes no Welcome, so zero is an absorbing state: the agent
that most needs a top-up is the one that never gets one. It is then seated on a
roster by a carried vote with no leaf in the ratchet tree, listed as a full
member, and reads nothing the group says.

So the beat is structural rather than per-verb. It rides inside
:func:`rine._mls.commit.post_mls_commit` and :func:`rine._mls.sync.sync_mls_group`
— which between them cover every MLS verb this SDK has — and a verb added later
inherits it instead of having to remember it. Nine near-identical call sites is
the duplication that let this defect ship in the first place.

The TypeScript twin is ``mlsHeartbeat`` (``rine-core/src/mls-heartbeat.ts``).
"""

from __future__ import annotations

import time
from typing import Literal

from rine._constants import MLS_HEARTBEAT_MIN_INTERVAL_S
from rine._logging import logger
from rine._mls.actor import MlsActor
from rine._mls.escrow_sweep import sweep_pending_escrow
from rine._mls.key_packages import ensure_mls_key_packages
from rine._mls.topup import _rescued_this_process

#: How a heartbeat treats the per-process floor.
#:
#: ``gated`` is the structural beat: every commit and every sync carries one, so
#: it must be cheap when it has nothing to do. ``forced`` is for the paths that
#: have just SPENT a key package — founding, adding members, resuming an
#: admission, processing a Welcome — where the pool provably moved and waiting
#: out a floor would leave the agent short in exactly the window a peer is most
#: likely to add it. Spelled at every call site rather than defaulted: a verb
#: added later has to answer the question rather than inherit an answer.
MlsHeartbeatPace = Literal["gated", "forced"]

# ``MLS_HEARTBEAT_MIN_INTERVAL_S`` (``rine._constants``) is the shortest gap between
# two gated heartbeats for one (config dir, agent) in one process. Keyed on the
# agent and not on the group because the pool is per-agent: ten groups draw down
# one inventory. The escrow retry schedule uses the same interval as its base.

_last_heartbeat: dict[tuple[str, str], float] = {}


def mls_heartbeat(actor: MlsActor, pace: MlsHeartbeatPace) -> None:
    """Top this agent's key-package pool back up as a side effect of MLS work.

    **Why the floor.** Founding a 500-member group posts one commit per batch of
    thirteen joiners, so an ungated beat inside the commit seam would open the
    store, sweep it twice and derive three asymmetric public keys thirty-nine
    times for one founding. The first (forced) beat of that founding stamps the
    gate, so the thirty-nine that follow cost nothing. Per process and
    deliberately not persisted: a one-shot CLI or script invocation beats
    exactly once, which is what is wanted there, and only a long-lived client
    can spin.

    🔴 **The floor is lifted again by a beat that failed.** The stamp is a claim
    that the maintenance has been done, and a top-up that hit a 429 or a 5xx did
    not do it. Leaving the stamp standing would hold an agent at inventory zero
    for the rest of the minute with nothing said, because the failure is
    swallowed here by design. Stamped BEFORE the call and cleared after, so a
    batch of commits issued back to back still does not each start a top-up
    while the first is in flight.

    The same beat uploads the pending escrow files of groups this agent no
    longer holds (:func:`rine._mls.escrow_sweep.sweep_pending_escrow`), so a
    process's first MLS operation is also its startup sweep. A failed sweep leaves
    its files for the next beat and does not lift the floor, which guards the
    key-package top-up.

    Best-effort by contract: it runs behind work that has already succeeded, so
    it never raises.

    Args:
        actor: Who is acting, and through which client.
        pace: Whether the per-process floor applies.
    """
    key = (actor.config_dir, actor.agent_id)
    previous = _last_heartbeat.get(key)
    now = time.monotonic()
    if pace == "gated" and previous is not None and now - previous < MLS_HEARTBEAT_MIN_INTERVAL_S:
        return
    _last_heartbeat[key] = now
    _settle_rotation_best_effort(actor)
    try:
        ensure_mls_key_packages(actor.client, actor.config_dir, actor.agent_id)
    except Exception:
        _last_heartbeat.pop(key, None)
        logger.debug("MLS KeyPackage heartbeat deferred", exc_info=True)
    try:
        sweep_pending_escrow(actor)
    except Exception:
        logger.debug("MLS escrow sweep deferred", exc_info=True)


def _settle_rotation_best_effort(actor: MlsActor) -> None:
    """Bring KeyPackages and seats up to the key on disk before the top-up counts them.

    A rotation that this host has not settled replaces the whole pool, so the
    top-up that follows never trusts a local count that still includes private
    halves of the previous generation. Imported here because the settlement opens
    groups, and opening a group runs this heartbeat.
    """
    from rine._mls.seat_sweep import settle_rotation

    try:
        settle_rotation(actor, background=True)
    except Exception:
        logger.debug("MLS rotation settlement deferred", exc_info=True)


def reset_mls_heartbeat_gate() -> None:
    """Forget the heartbeat floor, the key-package rescue mark and the catch-up floor.

    Test-only: a process boundary is what clears them in life. Like its TypeScript
    twin it is the one seam that forgets the MLS rate gates, so no gate has a reset
    of its own. The catch-up is imported here because it runs a sync, and a sync
    runs this heartbeat.
    """
    from rine._mls.catchup import _last_attempt

    _last_heartbeat.clear()
    _rescued_this_process.clear()
    _last_attempt.clear()


__all__ = [
    "MLS_HEARTBEAT_MIN_INTERVAL_S",
    "MlsActor",
    "MlsHeartbeatPace",
    "mls_heartbeat",
    "reset_mls_heartbeat_gate",
]
