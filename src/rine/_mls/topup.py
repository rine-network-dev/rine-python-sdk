"""Publishing an agent's own key packages as part of recovering a group.

Distinct from the heartbeat in :mod:`rine._mls.heartbeat`, and deliberately so.
The heartbeat is maintenance: it fires behind work that has already succeeded,
it tops up only what the LOCAL private-half count says is short, and it says
nothing. This is a recovery: the operator asked for it, so it reports what it
did, and it does not believe the local count.

🔴 **Why it cannot trust the local count.** The only inventory a client holds is
its own mirror of the private halves, and that mirror over-counts. A peer claims
a package to mint a Welcome that is never delivered and the half stays on disk
forever: the agent reads ten locally while the server holds none. That agent is
exactly the one this exists for — voted into a group, seated on the roster,
unable to read a word of it because no member could mint it a Welcome — and a
top-up that asked the local count would mint nothing for it.

**So it asks the server instead.** ``GET /agents/{id}/mls/key-packages/count``
is the one read of a published pool that consumes nothing (the ``GET`` beside it
is a destructive claim), and the rescue mints the difference between the target
and what the server says it holds. That is what makes a loop of one-shot
processes cost nothing after the first: the answer is a fact about the server,
so it survives the process boundary a client-side floor cannot.

A server old enough not to answer that route gets what this did before — one
full batch, additively, once per agent per process — and never a count invented
from the absence. See :func:`_server_key_package_count`.

The TypeScript twin is ``topUpKeyPackages``
(``rine-core/src/mls-keypackage-topup.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._group_recovery import KeyPackageTopUp
from rine._mls.binding import KEY_PACKAGE_TARGET
from rine._mls.key_packages import (
    ensure_mls_key_packages,
    is_inventory_full,
    publish_mls_key_packages,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._mls.heartbeat import MlsActor


_rescued_this_process: set[tuple[str, str]] = set()
"""Agents whose additive rescue has already run in this process — the floor for
a server that will not say what it holds, and for no other case.

When :func:`_server_key_package_count` answers, nothing here is read: the rescue
mints ``TARGET - available``, so the second sync of a pool already at target
mints zero whether or not it is a new process.

🔴 **The brake the server's inventory cap is not.** The cap is enforced over a
whole batch (``available + len(blobs) > MLS_KP_INVENTORY_CAP`` → one 422), and
the native core writes every private half to disk BEFORE the blobs are uploaded
— so a refused batch un-mints nothing, and the cap brakes the server's rows
rather than this client's minting. Without a floor here, a script looping
``groups.sync()`` against an un-upgraded server writes ten more ML-KEM-768
private halves per call into a directory whose only removal path is a Welcome
consuming one. Nothing prunes it, and the sweep that reads it runs on every MLS
operation.

Keyed and scoped exactly like the heartbeat's floor: one recovery episode is one
process. It is a weak floor by construction and always was — a LOOP of one-shot
processes gets one batch each, which is the leak the server count closes and
this cannot. A ceiling on the LOCAL mirror is not the missing strength: the
mirror says nothing about what the server holds, so it would refuse the second
genuine rescue of an agent that got wedged twice.
"""


def _server_key_package_count(actor: MlsActor) -> int | None:
    """How many unconsumed key packages the server holds, or None if it will not say.

    🔴 ``None`` is *no answer*, never a number. Read as *nothing to mint* the
    rescue becomes a no-op against the whole installed base, so the agent it
    exists for stays un-addable; read as *the pool is empty* it mints a full
    batch with no floor in front of it, which is the unbounded loop this route
    was added to close. So the recovery rescue routes the absence to
    :data:`_rescued_this_process`, and a maintenance caller publishes nothing.

    Any other failure is ``None`` too: whatever refused this read refuses the
    upload behind it. The shape is checked rather than trusted, and ``bool`` is
    excluded because Python would otherwise let ``True`` through as 1.
    """
    try:
        body: Any = actor.client.get(f"/agents/{actor.agent_id}/mls/key-packages/count")
    except Exception:
        return None
    available = body.get("available") if isinstance(body, dict) else None
    if isinstance(available, bool) or not isinstance(available, int) or available < 0:
        return None
    return available


def top_up_key_packages(actor: MlsActor) -> KeyPackageTopUp:
    """Publish key packages for this agent, as part of recovering one of its groups.

    Two steps, and the second only when the first found nothing to do:

    1. :func:`rine._mls.key_packages.ensure_mls_key_packages` — the same call
       the heartbeat makes. When it publishes, the pool was genuinely below its
       low-water mark and is now back at target; there is nothing left to add.
    2. When it publishes nothing, the local mirror claims the pool is healthy —
       which is what the un-addable agent's mirror also claims. So the server is
       asked what it holds, and the shortfall against ``KEY_PACKAGE_TARGET`` is
       what gets minted: nothing at all for a pool that really was healthy, and
       exactly the gap for one that was not. A server that will not answer gets
       the old behaviour — one full additive batch, once per agent per process
       (:data:`_rescued_this_process`) — and the server refusing that as over
       its per-agent cap is the answer that the pool really was healthy.

    Never the cutover (``drain_and_republish_mls_key_packages``): that claims the
    whole server pool out destructively and deletes the local private halves, so
    reaching for it here would take a wedged agent's remaining Welcomes with it.

    Raises nothing. A recovery reports a failed top-up rather than failing on it:
    the operator ran this to catch a group up, and losing that to a maintenance
    error would trade one broken group for two.

    Args:
        actor: Who is acting, and through which client.

    Returns:
        Which arm this was, and how many packages the server stored.
    """

    def step(key: tuple[str, str]) -> KeyPackageTopUp:
        status = ensure_mls_key_packages(actor.client, actor.config_dir, actor.agent_id)
        if status.cap_reached:
            return KeyPackageTopUp(outcome="cap-reached")
        if status.published > 0:
            return KeyPackageTopUp(outcome="topped-up", published=status.published)
        return _mint_server_shortfall(actor, key)

    return _guard_top_up(actor, step)


def top_up_from_server_count(actor: MlsActor) -> KeyPackageTopUp:
    """Step 2 of :func:`top_up_key_packages` alone, for a caller that ran step 1 itself.

    The welcome pass is that caller. A Welcome it sets aside unopened keeps the
    private half it was sealed to, so the local mirror reads full while the server
    pool may be empty — the one state the local count cannot see. A count the
    server will not give is no known shortfall, so unlike the recovery top-up this
    publishes nothing and leaves the additive rescue to
    :func:`top_up_key_packages`. Same cap and failure arms as the full top-up;
    raises nothing.

    Args:
        actor: Who is acting, and through which client.

    Returns:
        Which arm this was, and how many packages the server stored.
    """

    def step(_key: tuple[str, str]) -> KeyPackageTopUp:
        held = _server_key_package_count(actor)
        if held is None:
            return KeyPackageTopUp(outcome="healthy")
        return _publish_batch(actor, KEY_PACKAGE_TARGET - held)

    return _guard_top_up(actor, step)


def _mint_server_shortfall(actor: MlsActor, key: tuple[str, str]) -> KeyPackageTopUp:
    """Ask the server what it holds and publish the shortfall against the target."""
    held = _server_key_package_count(actor)
    if held is None:
        if key in _rescued_this_process:
            return KeyPackageTopUp(outcome="healthy")
        _rescued_this_process.add(key)
        return _publish_batch(actor, KEY_PACKAGE_TARGET)
    return _publish_batch(actor, KEY_PACKAGE_TARGET - held)


def _publish_batch(actor: MlsActor, count: int) -> KeyPackageTopUp:
    """Publish ``count`` key packages, or report the pool healthy when there is no gap."""
    # At or above target the pool really was healthy, and this is the arm
    # that makes a looped ``group sync`` cost nothing: no mint, no upload,
    # and no process boundary to reset.
    if count <= 0:
        return KeyPackageTopUp(outcome="healthy")
    stored = publish_mls_key_packages(actor.client, actor.config_dir, actor.agent_id, count)
    # ``stored`` and not the batch size: an upload the server answered by
    # storing none of it is not a top-up, and a sentence that says it topped
    # the pool up by zero is an affirmative claim beside its own refutation.
    if stored == 0:
        return KeyPackageTopUp(outcome="healthy")
    return KeyPackageTopUp(outcome="topped-up", published=stored)


def _guard_top_up(
    actor: MlsActor, step: Callable[[tuple[str, str]], KeyPackageTopUp]
) -> KeyPackageTopUp:
    """Run one top-up step under the shared cap, failure and rescue-floor handling."""
    key = (actor.config_dir, actor.agent_id)
    try:
        return step(key)
    except Exception as err:
        # The cap keeps its stamp: the server has answered, definitively, that
        # it will not hold more for this agent, and another batch would be ten
        # more private halves minted to hear the same 422.
        if is_inventory_full(err):
            return KeyPackageTopUp(outcome="cap-reached")
        # Anything else has not spent the rescue's one turn — the server never
        # answered — so the next recovery in this process may try again.
        _rescued_this_process.discard(key)
        return KeyPackageTopUp(outcome="failed", detail=str(err))


__all__ = [
    "top_up_from_server_count",
    "top_up_key_packages",
]
