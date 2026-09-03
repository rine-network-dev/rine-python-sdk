"""The joiners a batch may still add, re-read after a lost epoch race.

🔴 **The commit that won the race may have seated some of them itself.** A
KeyPackage claim is exclusive per PACKAGE, not per agent: a healthy agent
publishes ten, so a second admin claiming a different one admits that agent just
as validly. Rebuilding the Add over a leaf the tree now holds is a duplicate
identity, which RFC 9420 forbids and the native core refuses out of the commit
BUILDER — before the post, and so out of the whole admission: no outcome is
recorded for the batch, the report loses every agent in it, and the batches after
it never run. The loop's own contract is that an admission never fails whole.

Reported ``already_in_group`` and not ``added``, which is what happened: this
client did not seat them, it lost to the client that did. Their claimed
KeyPackages are spent either way — a claim is consumed by the claiming, not by
the commit — and that is the ordinary cost of the race, not something to recover.

The TypeScript twin is ``dropSeatedJoiners``
(``rine-core/src/mls-admission-recheck.ts``), with the same reason string and the
same treatment of an agent the server names no key for.
"""

from __future__ import annotations

from rine._mls.admission_state import Admission
from rine._mls.tree import fetch_agent_identities, leaf_index


def drop_seated_joiners(
    admission: Admission, joiners: list[str], key_packages: list[bytes]
) -> list[tuple[str, bytes]]:
    """Which of ``joiners`` still hold no leaf, recording the ones that do.

    The group is read off the admission rather than passed in, because the
    caller has just reopened it from the state the catch-up adopted, and the
    tree before the catch-up is the tree that made this recheck necessary.

    An agent the server publishes no key for stays in the batch: it is revoked
    or gone, and both answers arrive properly named a step later, from the
    commit.
    """
    paired = list(zip(joiners, key_packages, strict=True))
    group = admission.group
    if not paired or group is None:
        return paired
    identities = fetch_agent_identities(admission.client, joiners)
    kept: list[tuple[str, bytes]] = []
    for agent_id, key_package in paired:
        identity = identities.get(agent_id.lower())
        if identity is not None and leaf_index(group, identity) is not None:
            admission.skip(agent_id, "already_in_group")
            continue
        kept.append((agent_id, key_package))
    return kept


__all__ = ["drop_seated_joiners"]
