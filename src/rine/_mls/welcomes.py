"""Installing the Welcomes an agent has been sent — one of the two ways in.

A member added by an existing member gets a Welcome: the founder's commit sealed
this agent's group secrets to the KeyPackage it published. Processing it is what
turns a rine group membership into an MLS membership.

Ordering is the whole design here. The Welcome is fetched destructively (see
:mod:`rine._mls.welcome_spool`), so it is persisted before it is used, and the
spooled copy is dropped only once the join has a final outcome — installed,
provably unusable, or refused for a reason no later attempt can clear.

🔴 **Which refusal is raised is :func:`_pick_refusal`'s decision, and a caller
that knows the group it is establishing must say so via ``for_group``.** It then
hears about that group and no other, in both directions. Without it the pass
answers about the whole queue under the arrival rule — loud once, then quiet, so
a single unusable Welcome cannot fail every future join, send and read on this
agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._logging import logger
from rine._mls.api import MlsWelcomeDelivery, fetch_welcomes
from rine._mls.binding import (
    CipherSuiteMismatchError,
    MlsClient,
    MlsProtocolError,
    open_mls_client,
)
from rine._mls.group_access import load_mls_group, note_mls_state_changed
from rine._mls.key_packages import replenish_mls_key_packages
from rine._mls.welcome_guard import (
    MlsWelcomeRefusedError,
    refusal_is_retryable,
    welcome_refusal,
)
from rine._mls.welcome_spool import WelcomeSpool, is_spoolable_id


@dataclass(frozen=True)
class MlsWelcomeOutcome:
    """What installing this agent's pending Welcomes achieved."""

    group_ids: tuple[str, ...]
    """Groups this agent now holds MLS state for."""

    discarded: int
    """Welcomes this pass dropped rather than installed.

    Three ways in: unusable by this MLS core, un-filable because the server
    named it something that is not a file name, or aged out of the retention
    bound. The TypeScript twin's ``MlsWelcomeOutcome.discarded`` counts the same
    three.
    """


@dataclass(frozen=True)
class _PassRefusal:
    """One refusal a pass earned, and whether its bytes arrived in that pass."""

    refusal: MlsWelcomeRefusedError
    is_new: bool


def _pick_refusal(
    refusals: list[_PassRefusal], for_group: str | None
) -> MlsWelcomeRefusedError | None:
    """Which refusal a pass raises, out of the ones it earned.

    🔴 Never ``refusals[0]``. The queue used to be ordered by file name, which is
    the server-chosen delivery id, so a server that wanted a refusal suppressed
    minted a decoy that sorted first and the caller's own group's refusal became
    a log line — measured, not hypothetical.

    ``for_group`` answers about exactly that group and nothing else, in both
    directions. Its refusal is raised whether or not the bytes arrived in this
    pass — the caller asked about that group, and a refusal is the answer to the
    question. Every other group's refusal is withheld from this caller, because
    a substituted Welcome for one group must not fail a legitimate install, send
    or read of another. Both halves live here rather than at the caller: leaving
    the second one to the caller is precisely how the TypeScript read path ended
    up aborting unrelated decrypts while this one did not.

    With no ``for_group`` the pass answers about the whole queue and the arrival
    rule decides: reported once, when its bytes arrive, then quiet, because a
    retained refusal that raised on every later pass would let one unusable
    Welcome fail every future join, send and read.

    Nothing withheld here is lost. A withheld refusal keeps its Welcome on the
    spool (:func:`~rine._mls.welcome_guard.refusal_is_retryable`) and is raised
    by the first call scoped to its own group — which is the call that needed to
    hear it. On this stack it is also logged once, on the pass its bytes arrive
    in; the TypeScript twin cannot, because rine-core has no logging facility.
    """
    if for_group is not None:
        wanted = for_group.lower()
        return next((e.refusal for e in refusals if e.refusal.group_id.lower() == wanted), None)
    return next((e.refusal for e in refusals if e.is_new), None)


def process_mls_welcomes(
    client: Any, config_dir: str, agent_id: str, *, for_group: str | None = None
) -> MlsWelcomeOutcome:
    """Install every Welcome waiting for this agent.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: Agent UUID whose Welcomes are being installed.
        for_group: The group this call is establishing state for, when there is
            exactly one. It decides which refusal is raised (:func:`_pick_refusal`).

    Returns:
        The groups now joined, and how many Welcomes were dropped.

    Raises:
        MlsWelcomeRefusedError: A Welcome was refused — see :func:`_pick_refusal`
            for which one, when more than one was.
    """
    spool = WelcomeSpool(config_dir, agent_id)
    # Bound the carried-over set BEFORE this pass's arrivals land. The count
    # bound reaches refused entries only, so neither this pass's batch nor one
    # an aborted pass carried over is evicted by its own size — spooling is not
    # the same event as having had a chance.
    discarded = spool.prune()
    # The fetch is one-shot, so an id it returns has never been spooled before:
    # this set is exactly "arrived in this pass".
    arrived: set[str] = set()
    for delivery in fetch_welcomes(client, agent_id):
        if not is_spoolable_id(delivery.id):
            # The id becomes the file name, so a server free to answer with a
            # path fragment is free to place the file (MEASURED: it lands outside
            # the spool dir and ``_write_atomic`` creates the directories on the
            # way). Asked here rather than caught out of ``store``, so a genuine
            # write failure still fails the pass instead of being mistaken for a
            # poisoned name — and so one poisoned name costs its own Welcome and
            # not the rest of the batch.
            logger.warning(
                "Dropping an MLS welcome the server named %r: a delivery id has to be a "
                "plain file name, and this one is not.",
                delivery.id,
            )
            discarded += 1
            continue
        spool.store(delivery)
        arrived.add(delivery.id)

    pending = spool.pending()
    if not pending:
        return MlsWelcomeOutcome(group_ids=(), discarded=discarded)

    mls = open_mls_client(config_dir, agent_id)
    joined: list[str] = []
    refusals: list[_PassRefusal] = []
    for path, delivery in pending:
        try:
            group_id = _install(client, mls, delivery, agent_id)
        except MlsWelcomeRefusedError as refusal:
            refusals.append(_PassRefusal(refusal=refusal, is_new=delivery.id in arrived))
            # A refusal a later attempt could clear keeps its bytes: the fetch is
            # destructive and no peer can mint a replacement without noticing the
            # first went unused, so discarding here would make a transient
            # refusal permanent. Marked as it is kept, because :meth:`prune`'s
            # count bound is over exactly this population — an entry that has
            # earned a retryable refusal is the only kind it may evict.
            if refusal_is_retryable(refusal.reason):
                spool.mark_refused(path)
            else:
                spool.discard(path)
            continue
        if group_id is None:
            discarded += 1
        else:
            # A processed Welcome is an establishment: invalidate here, at the
            # mutation, so a "this agent holds no MLS state" answer taken before
            # it cannot survive the join that made it false.
            note_mls_state_changed(config_dir, agent_id, group_id)
            joined.append(group_id)
        spool.discard(path)

    # Every processed Welcome consumed one of this agent's published KeyPackages.
    # This is the only path on which an agent's own pool shrinks, so it is where
    # topping it back up matters most: without it the agent silently becomes
    # un-addable once its onboarding batch runs out. Before the refusal, so a
    # substituted Welcome cannot cost this agent its pool as well.
    replenish_mls_key_packages(client, config_dir, agent_id)
    refused = _pick_refusal(refusals, for_group)
    for entry in refusals:
        # Everything this pass refused and did not raise, said once — on the pass
        # its bytes arrived, never again, so a retained refusal is not a warning
        # on every later send. The TypeScript twin has no logging facility and
        # relies on the scoped raise alone.
        if entry.is_new and entry.refusal is not refused:
            logger.warning("%s", entry.refusal)
    if refused is not None:
        raise refused
    return MlsWelcomeOutcome(group_ids=tuple(joined), discarded=discarded)


def _install(
    client: Any, mls: MlsClient, delivery: MlsWelcomeDelivery, agent_id: str
) -> str | None:
    """Join the group one Welcome invites this agent to.

    Returns:
        The group id now held locally, or ``None`` when the Welcome is unusable
        and there is nothing to retry.

    Raises:
        MlsWelcomeRefusedError: The Welcome joined a group this client refuses to
            adopt under that id — see :mod:`rine._mls.welcome_guard`.
    """
    try:
        group = mls.join_from_welcome(delivery.welcome)
    except (MlsProtocolError, CipherSuiteMismatchError) as exc:
        # Replaying a Welcome that already joined is one of these: `save()`
        # consumed the private KeyPackage half, so the second attempt cannot
        # find it. Local state settles which it was.
        if load_mls_group(mls, delivery.group_id) is not None:
            return delivery.group_id
        logger.warning(
            "Discarding an unusable MLS welcome for group %s: %s. It was minted by a "
            "different MLS core or for a different ciphersuite — ask an existing member "
            "to invite this agent again once everyone is on the current rine release.",
            delivery.group_id,
            exc,
        )
        return None

    refusal = welcome_refusal(client, mls, group, delivery, agent_id)
    if refusal is not None:
        raise refusal

    group.save()
    return delivery.group_id
