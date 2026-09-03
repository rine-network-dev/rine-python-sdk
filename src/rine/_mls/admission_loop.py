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
* **It never fails whole.** A recipient the server refuses is dropped and a lost
  epoch race is caught up on, each batch is retried **once** per refusal, and the
  outcome is reported per member. The recovery arms live in
  :mod:`rine._mls.admission_retry`.
"""

from __future__ import annotations

from rine._logging import logger
from rine._mls.admission import MlsAdmissionResult
from rine._mls.admission_retry import commit_once
from rine._mls.admission_state import Admission
from rine._mls.founding import claim_founding_key_packages, mls_founding_batch_sizes


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
    """Claim, commit and record one batch."""
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
    # Founding is the one batch with nothing to catch up to: no group means this
    # commit creates it, so there is no local state to sync and a conflict says
    # somebody else founded the group, which no retry mends.
    commit_once(admission, joiners, key_packages, catch_up=admission.group is not None)


__all__ = ["run_admission"]
