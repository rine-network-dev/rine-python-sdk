"""Installing the Welcomes an agent has been sent — one of the two ways in.

A member added by an existing member gets a Welcome: the founder's commit sealed
this agent's group secrets to the KeyPackage it published. Processing it is what
turns a rine group membership into an MLS membership.

Ordering is the whole design here. The Welcome is fetched destructively (see
:mod:`rine._mls.welcome_spool`), so it is persisted before it is used, and the
spooled copy is dropped only once the join has a final outcome — installed,
provably unusable, or refused for a reason no later attempt can clear.

🔴 **Which refusal is raised is :func:`~rine._mls.welcome_pick.pick_refusal`'s
decision, and a caller that knows the group it is establishing must say so via
``for_group``.** It then hears about that group and no other, in both directions.
Without it the pass answers about the whole queue under the arrival rule — loud
once, then quiet, so a single unusable Welcome cannot fail every future join,
send and read on this agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from typing import Any, assert_never

from rine._logging import logger
from rine._mls.allowed import admit_welcome_peers
from rine._mls.api import fetch_welcomes
from rine._mls.binding import open_mls_client
from rine._mls.escrow_report import EscrowReport
from rine._mls.heartbeat import MlsActor, mls_heartbeat
from rine._mls.topup import top_up_from_server_count
from rine._mls.welcome_guard import MlsWelcomeRefusedError, refusal_is_retryable
from rine._mls.welcome_install import WelcomeKept, install_welcome
from rine._mls.welcome_pick import PassRefusal, pick_refusal
from rine._mls.welcome_release import welcome_releaser
from rine._mls.welcome_spool import WelcomeSpool, is_spoolable_id


@dataclass(frozen=True)
class MlsWelcomeOutcome:
    """What installing this agent's pending Welcomes achieved."""

    group_ids: tuple[str, ...]
    """Groups this agent now holds MLS state for."""

    discarded: int
    """Welcomes this pass dropped rather than installed.

    Four ways in: unusable by this MLS core, un-filable because the server
    named it something that is not a file name, aged out of the retention
    bound, or for a group that no longer exists.
    """

    escrow: EscrowReport = field(default_factory=EscrowReport)
    """What settling each replaced state and draining each new one could not do,
    folded into one report."""


def process_mls_welcomes(
    client: Any, config_dir: str, agent_id: str, *, for_group: str | None = None
) -> MlsWelcomeOutcome:
    """Install every Welcome waiting for this agent.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: Agent UUID whose Welcomes are being installed.
        for_group: The group this call is establishing state for, when there is
            exactly one. It decides which refusal is raised
            (:func:`~rine._mls.welcome_pick.pick_refusal`).

    Returns:
        The groups now joined, and how many Welcomes were dropped.

    Raises:
        MlsWelcomeRefusedError: A Welcome was refused — see
            :func:`~rine._mls.welcome_pick.pick_refusal` for which one, when more than one was.
    """
    spool = WelcomeSpool(config_dir, agent_id)
    # Bound the carried-over set BEFORE this pass's arrivals land. The count
    # bound reaches refused entries only, so neither this pass's batch nor one
    # an aborted pass carried over is evicted by its own size — spooling is not
    # the same event as having had a chance.
    actor = MlsActor(client=client, config_dir=config_dir, agent_id=agent_id)
    mls_client = cache(lambda: open_mls_client(config_dir, agent_id))
    release = welcome_releaser(mls_client)
    discarded = spool.prune(release)
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

    mls = mls_client()
    joined: list[str] = []
    escrow = EscrowReport()
    refusals: list[PassRefusal] = []
    # Welcomes this pass set aside without opening because the roster answered
    # definitively. Each still holds the private half it was sealed to, so the
    # local mirror cannot see that the server pool spent it.
    set_aside = 0
    for path, delivery in pending:
        # The native core refuses a leaf whose (agent id, leaf key) is not in the
        # allowed set, so the group's chain-verified peers are admitted before the
        # Welcome is opened — and what the roster read answered decides whether it
        # is opened at all.
        admission = admit_welcome_peers(actor, delivery.group_id)
        match admission:
            case "admitted":
                pass
            case "unreachable":
                # A read that failed transiently could succeed next pass, so the
                # Welcome stays spooled; opening it now could install a group whose
                # roster this agent cannot read.
                continue
            case "not-seated":
                # An invitation this agent has not accepted yet: accepting later needs
                # these exact bytes, so they are kept unopened — under the refused-entry
                # bound, so an invitation never accepted ages out with the invitation.
                spool.mark_refused(path)
                set_aside += 1
                continue
            case "group-gone":
                # The group no longer exists, so no later pass can use this Welcome.
                spool.drop(path, release)
                discarded += 1
                set_aside += 1
                continue
            case _ as unhandled:
                assert_never(unhandled)
        try:
            installed = install_welcome(actor, mls, delivery)
        except WelcomeKept:
            continue
        except MlsWelcomeRefusedError as refusal:
            refusals.append(PassRefusal(refusal=refusal, is_new=delivery.id in arrived))
            # A refusal a later attempt could clear keeps its bytes: the fetch is
            # destructive and no peer can mint a replacement without noticing the
            # first went unused, so discarding here would make a transient
            # refusal permanent. Marked as it is kept, because :meth:`prune`'s
            # count bound is over exactly this population — an entry that has
            # earned a retryable refusal is the only kind it may evict.
            if refusal_is_retryable(refusal.reason):
                spool.mark_refused(path)
            else:
                spool.drop(path, release)
                # A final peer refusal is counted as the drop it was before it was raised.
                if refusal.reason == "peer_not_admitted":
                    discarded += 1
            continue
        if installed is None:
            discarded += 1
            spool.drop(path, release)
            continue
        group_id, report = installed
        joined.append(group_id)
        escrow = escrow.merge(report)
        spool.discard(path)

    # Every processed Welcome consumed one of this agent's published KeyPackages,
    # and this is the only path on which an agent's own pool shrinks — so the beat
    # here is forced, never gated: waiting out a floor would leave the agent short
    # in exactly the window a peer is most likely to add it. Unconditional within
    # the pass, because a pass whose Welcomes were all refused is a pass where the
    # pool matters more, not less. Before the refusal, so a substituted Welcome
    # cannot cost this agent its pool as well.
    mls_heartbeat(actor, "forced")
    # A Welcome set aside unopened still holds its private half, so the beat above
    # — which counts the local mirror — reads a full pool while the server may hold
    # none. Only the server's own count can see that, and only a pass that set
    # something aside pays for asking: a healthy pass makes no extra request.
    if set_aside:
        top_up_from_server_count(actor)
    refused = pick_refusal(refusals, for_group)
    for entry in refusals:
        # Everything this pass refused and did not raise, said once — on the pass
        # its bytes arrived, never again, so a retained refusal is not a warning
        # on every later send. The TypeScript twin has no logging facility and
        # relies on the scoped raise alone.
        if entry.is_new and entry.refusal is not refused:
            logger.warning("%s", entry.refusal)
    if refused is not None:
        raise refused
    return MlsWelcomeOutcome(group_ids=tuple(joined), discarded=discarded, escrow=escrow)
