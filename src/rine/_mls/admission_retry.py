"""Publishing one batch, and the two refusals it answers itself.

Split from :mod:`rine._mls.admission_loop` so the loop reads as the loop — what
each batch does, in order — with the recovery arms beside each other here, where
the one thing that matters about them is legible: **they are two separate
budgets, spent once each.** A lost epoch race is answered by catching up, a
refused recipient by dropping them, and a batch may need both in that order. What
neither may do is loop.

The TypeScript twin is ``commitBatch`` in ``rine-core/src/mls-admission-batch.ts``,
which spends the same two budgets in the same order.
"""

from __future__ import annotations

from rine._logging import logger
from rine._mls.admission import MlsAdmissionOutcome
from rine._mls.admission_recheck import drop_seated_joiners
from rine._mls.admission_state import Admission, commit_batch, discard_uncommitted
from rine._mls.failures import is_epoch_conflict
from rine._mls.sync import sync_mls_group
from rine._mls.wire import rejected_welcome_recipients


def commit_once(
    admission: Admission,
    joiners: list[str],
    key_packages: list[bytes],
    *,
    catch_up: bool,
) -> None:
    """Publish one batch, recovering once from each failure it can answer.

    ``catch_up`` is the epoch budget rather than a fact about the group: the
    retry calls back in with it spent, so a lost race is answered once and a
    batch that loses twice belongs to the caller — an unbounded retry against an
    advancing epoch is a self-DoS. The recipient budget in :func:`_retry_without`
    is separate and survives a catch-up, because the two refusals are about
    different things.
    """
    try:
        commit_batch(admission, joiners, key_packages)
    except Exception as err:
        if catch_up and is_epoch_conflict(err):
            _catch_up_and_retry(admission, joiners, key_packages)
            return
        rejected = rejected_welcome_recipients(err)
        if rejected is None:
            # Not a recipient refusal and not a race this batch may re-run — a
            # network failure, a 500. Dropping members cannot address it, so it
            # belongs to the caller.
            raise
        _retry_without(admission, joiners, key_packages, rejected)
        return

    admission.outcomes.extend(MlsAdmissionOutcome(agent_id=a, status="added") for a in joiners)


def _catch_up_and_retry(
    admission: Admission, joiners: list[str], key_packages: list[bytes]
) -> None:
    """Adopt the commit that won the race, then rebuild this batch over it.

    The same single sync-then-retry a removal, a reclamation and a self-join
    already answer a lost CAS with. Its absence is what made admission the one
    MLS commit verb that reported an epoch conflict to the operator instead of
    resolving it — and ``group resume-admission`` is precisely the verb an
    operator reaches for while other members are committing.

    Two things make the rebuild sound. The refused commit advanced a handle that
    was never saved, so reopening after the sync builds over the state the server
    agrees with; and the KeyPackages this batch claimed outlive the conflict,
    being one-time keys bound to their owner and not to an epoch.

    🔴 What is NOT sound is assuming the winning commit seated nobody from this
    batch — see :func:`rine._mls.admission_recheck.drop_seated_joiners`, which is
    what keeps a duplicate-identity refusal from escaping the whole admission.
    """
    sync_mls_group(
        admission.client,
        admission.config_dir,
        admission.agent_id,
        admission.group_id,
        cipher_suite=admission.cipher_suite,
    )
    # Reopened only now, so the handle holds what the sync just adopted.
    discard_uncommitted(admission)
    kept = drop_seated_joiners(admission, joiners, key_packages)
    if not kept:
        # The winning commit seated everybody in this batch, each recorded as
        # such. Nothing landed from this client, and the batches after it still
        # run.
        return
    commit_once(
        admission,
        [a for a, _ in kept],
        [kp for _, kp in kept],
        catch_up=False,
    )


def _retry_without(
    admission: Admission,
    joiners: list[str],
    key_packages: list[bytes],
    rejected: tuple[str, ...],
) -> None:
    """Drop the recipients the server named and commit the batch once more.

    One retry, never a loop: the ``rejected`` array names every offender, so a
    batch that fails a second time is failing for a reason dropping members
    cannot fix — and the KeyPackages this batch claimed are spent either way.

    A batch that cannot be salvaged is **recorded and left behind, never
    raised**. The admission carries on to the next batch, because the batches
    after this one are a different set of agents whose admission this one's
    failure says nothing about — and because ``mls_group_id`` is latched by the
    first commit that landed, so abandoning the loop here would strand every
    remaining member with no way forward but a resume nobody knows to run. An
    admission never fails whole.
    """
    discard_uncommitted(admission)

    def is_rejected(agent_id: str) -> bool:
        # A refusal naming nobody this client can read is, as far as it can
        # tell, about the whole batch: retrying it unchanged would fail
        # identically, so every recipient is dropped and none is retried.
        return not rejected or agent_id.lower() in rejected

    kept = [(a, kp) for a, kp in zip(joiners, key_packages, strict=True) if not is_rejected(a)]
    for agent_id in joiners:
        if is_rejected(agent_id):
            admission.skip(agent_id, "rejected_by_server")
    if not kept:
        return
    try:
        commit_batch(admission, [a for a, _ in kept], [kp for _, kp in kept])
    except Exception:
        # The retry is spent. Whatever refused this batch a second time is not
        # something a third attempt would tell us more about.
        logger.warning(
            "MLS batch refused twice — recording %d recipient(s) as rejected and "
            "continuing with the remaining batches",
            len(kept),
        )
        discard_uncommitted(admission)
        for agent_id, _ in kept:
            admission.skip(agent_id, "rejected_by_server")
        return
    admission.outcomes.extend(MlsAdmissionOutcome(agent_id=a, status="added") for a, _ in kept)


__all__ = ["commit_once"]
