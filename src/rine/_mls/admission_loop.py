"""The one loop that admits members to a group's ratchet tree.

Founding and adding are the same operation at different points in a group's
life, so they are one loop with two entry points:
:func:`rine._mls.group_init.init_mls_group` drives it with ``seated = 1`` and no
group yet, and :func:`rine._mls.add_members.add_mls_group_members` drives it
with the group's real occupancy and its established state. One loop, two entry
points, one audit surface.

Three properties it owes its callers, each of which is a defect it closes:

* **It resumes.** An agent whose leaf already resolves is skipped by the caller,
  so running an admission twice over the same group admits nobody the second
  time. ``mls_group_id`` is a one-way latch and ``/mls/init`` refuses once it is
  set, so before this the only way past a founding that stopped at commit 5 of
  39 was a new group.
* **It claims per batch.** A KeyPackage claim is destructive, so a founding
  refused at its fifth commit used to burn one for every member of the group,
  and a burned pool does not heal on its own.
* **It never fails whole.** A recipient the server refuses is dropped, the batch
  is retried **once**, and the outcome is reported per member.
"""

from __future__ import annotations

from rine._logging import logger
from rine._mls.admission import MlsAdmissionOutcome, MlsAdmissionResult
from rine._mls.admission_state import Admission, commit_batch, discard_uncommitted
from rine._mls.founding import claim_founding_key_packages, mls_founding_batch_sizes
from rine._mls.wire import rejected_welcome_recipients


def run_admission(admission: Admission, candidates: list[str], seated: int) -> MlsAdmissionResult:
    """Admit ``candidates`` in size-aware batches, reporting each one.

    Args:
        admission: The loop's state; carries the group once it exists.
        candidates: Ids that are not seated yet. The caller has already dropped
            its own id and anyone whose leaf already resolves.
        seated: The tree's occupancy before this admission, which is what sizes
            each commit — a Welcome carries the whole ratchet tree, so the cost
            of a batch is the batch times the size of the group it joins.
    """
    batches = _split(candidates, seated)
    if admission.group is None and not batches:
        # A group with no eligible member still founds — one commit admitting
        # nobody — so the caller always has a group to add to later.
        batches = [[]]
    for batch in batches:
        _admit_batch(admission, batch)
    return admission.result()


def _split(candidates: list[str], seated: int) -> list[list[str]]:
    batches: list[list[str]] = []
    taken = 0
    for size in mls_founding_batch_sizes(len(candidates), seated):
        batches.append(candidates[taken : taken + size])
        taken += size
    return batches


def _admit_batch(admission: Admission, batch: list[str]) -> None:
    """Claim, commit and record one batch, retrying once past a bad recipient."""
    claimed = (
        claim_founding_key_packages(admission.client, batch, admission.extra_headers)
        if batch
        else {}
    )
    joiners = [a for a in batch if a.lower() in claimed]
    for agent_id in batch:
        if agent_id.lower() not in claimed:
            # The pool emptied between the readiness report and the claim. That
            # member is admitted later; the admission must not block on it.
            logger.warning(
                "No MLS KeyPackage available for %s — admitting the rest without them",
                agent_id,
            )
            admission.skip(agent_id, "no_key_package")

    if not joiners and admission.group is not None:
        return

    key_packages = [claimed[a.lower()] for a in joiners]
    try:
        commit_batch(admission, joiners, key_packages)
    except Exception as err:
        rejected = rejected_welcome_recipients(err)
        if rejected is None:
            # Not a recipient refusal — a network failure, a lost epoch CAS, a
            # 500. Dropping members cannot address it, so it belongs to the
            # caller.
            raise
        _retry_without(admission, joiners, key_packages, rejected)
        return

    admission.outcomes.extend(MlsAdmissionOutcome(agent_id=a, status="added") for a in joiners)


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


__all__ = ["run_admission"]
