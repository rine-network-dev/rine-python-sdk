"""Evicting a member — the half that is actual cryptography.

Deleting a ``GroupMember`` row evicts nobody: the leaf stays in the ratchet
tree, every epoch secret the evicted agent holds stays valid, and the only thing
locking them out is the server declining to hand them ciphertext. That is why
the crypto half exists.

So removal is two steps in a fixed order, and the server enforces the order:
post the Remove commit **while the target is still a member** — which is what
puts the commit in their delivery queue, so their client observes the eviction
instead of going quiet — then name the epoch it landed at on the DELETE. A
commit that ultimately fails leaves the member row exactly where it is.

The commit also **declares** who it removes, and the server spends
that declaration once per named agent: a commit posted without ``removes``
authorises no removal at all. 🔴 The declaration is client-asserted. A
passthrough server never opens the commit blob, so nothing there confirms that
the commit really carries a Remove for the agent it names; what declaring buys
is that the claim was made in advance, before the admin knew which ``DELETE``
would land, and is spendable exactly once.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._actor import AGENT_HEADER
from rine._logging import logger
from rine._mls.api import MlsCommit, mls_commit, read_group
from rine._mls.failures import group_failures, is_epoch_conflict
from rine._mls.group_access import note_mls_state_changed, open_mls_group
from rine._mls.sync import sync_mls_group
from rine._mls.tree import fetch_agent_identities, leaf_index


@dataclass(frozen=True)
class MlsRemovalCommit:
    """What one Remove commit did, and what it was able to do."""

    epoch: int
    """The epoch it landed at — what ``mls_removal_epoch`` must name, and only
    while it is still the group's current epoch."""

    removed_leaf: bool
    """Whether a leaf actually left the ratchet tree.

    ``False`` when no leaf carried the target's **currently published** signing
    key and the commit only **declared** the removal. Every surface that
    describes a removal must branch on this: saying a leaf was evicted when none
    was is the class of false report the removal sentences exist to prevent.

    🔴 ``False`` is not the same fact as "they hold no leaf". It is "no leaf
    matches the key they publish now", and the two come apart when the target
    rotated its signing key — see :func:`_post_removal`. Surfaces say the
    narrower thing.
    """


def remove_mls_group_member(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    member_agent_id: str,
    extra_headers: dict[str, str] | None = None,
) -> MlsRemovalCommit:
    """Commit the removal of one member, and report the epoch it landed at.

    The target is named by its **agent id**, which is both what the commit
    declares and what the ratchet-tree leaf is resolved from — the agent's MLS
    basic-credential identity is read here, so the leaf that is taken and the
    name that is declared can never be two different members.

    Retries **once** past a lost epoch CAS: an admin's Remove commit races every
    other commit in the group, and losing that race is ordinary rather than
    exceptional. The retry re-syncs first, so it builds on the epoch that won.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The acting admin's UUID; it must hold the group's MLS state.
        group_id: The rine group UUID.
        member_agent_id: The member to evict.
        extra_headers: Acting-agent headers for the group requests.

    Returns:
        The epoch the commit landed at and whether it took a leaf.

    Raises:
        NoMlsGroupStateError: This agent holds no local state for the group.
        GroupEvictedError: This agent's own leaf is gone from the group, so it
            can neither read the tree nor commit to it.
        RineApiError: The server refused the commit. The member row is untouched.
    """
    headers = dict(extra_headers or {AGENT_HEADER: agent_id})
    identity = fetch_agent_identities(client, [member_agent_id]).get(member_agent_id.lower())
    if identity is None:
        # No published signing key means no basic-credential identity, so no
        # leaf can be resolved for them — a revoked or erased agent. There is
        # nothing to evict, but there is still something to declare, so the
        # rescue below applies and such an agent stops being unremovable.
        logger.warning("No published signing key for %s — no MLS leaf to remove", member_agent_id)

    # An admin whose own leaf is gone is told that, rather than being handed the
    # core's ratchet-tree invariant or — worse — the "nothing to remove here"
    # answer a swallowed eviction would look like.
    with group_failures(group_id):
        try:
            return _post_removal(
                client, config_dir, agent_id, group_id, member_agent_id, identity, headers
            )
        except Exception as err:
            if not is_epoch_conflict(err):
                raise
        # One retry, after catching up on the commit that won the race. The leaf
        # is re-resolved from the identity inside ``_post_removal``: the winning
        # commit may have blanked it, and a later add may have refilled it with
        # somebody else.
        sync_mls_group(client, config_dir, agent_id, group_id)
        return _post_removal(
            client, config_dir, agent_id, group_id, member_agent_id, identity, headers
        )


def _post_removal(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    member_agent_id: str,
    identity: bytes | None,
    headers: dict[str, str],
) -> MlsRemovalCommit:
    """Build and publish one commit declaring ``member_agent_id``.

    Built from freshly reloaded local state.

    The group is reopened here rather than passed in, because the retry path
    must not rebuild from the handle whose commit was refused — and a leaf index
    read before another commit landed is not the leaf index after it.

    🔴 **A target holding no leaf gets a path-only commit, and that is the
    point.** ``add_members([])`` is a commit with no proposals and a
    fresh UpdatePath. It is what rescues a removal whose commit landed and whose
    DELETE then failed: the leaf is already out of the tree, so no second Remove
    can be built for it, so the client could produce no epoch, so the server's
    gate refused every retry and the member row survived its own eviction
    forever. The path-only commit claims no eviction — ``removed_leaf`` says so
    — and proves exactly what the gate asks for: this caller is still committing
    to this group at this epoch, and named this target before it knew which
    DELETE would land. Do not "simplify" it back to returning ``None``.

    🔴 **What "no leaf" means here is narrower than it reads.** The leaf is
    resolved from the signing key the target publishes *now*, so three states
    arrive as one:

    1. The server publishes no key for them — revoked, or gone. No leaf this
       group can name, and the path-only commit is right.
    2. Their leaf is already out: the stranded-removal rescue above. Right too.
    3. They rotated their signing key. ``POST /agents/{id}/keys`` has no MLS
       guard, so the tree still carries a leaf under the credential they
       published before, and this removal completes as a delivery-filter
       removal with that leaf's epoch secrets still valid.

    (2) and (3) cannot be told apart from here — there is no identity → agent
    lookup — so the removal proceeds, because refusing would break the rescue
    this path exists for, and every surface says the narrow, true thing: no leaf
    carries the key they publish now. Closing (3) needs key rotation to commit a
    self-update into every MLS group the agent is in; until it does,
    :func:`rine._mls.orphans.reclaim_orphan_leaves` declines to run on a group
    in this state and names the member.
    """
    # The group's own ciphersuite, never the default: a group created on the
    # classical suite is unreadable through a client opened on the current one.
    suite = read_group(client, agent_id, group_id).mls_cipher_suite
    group = open_mls_group(config_dir, agent_id, group_id, cipher_suite=suite)
    leaf = None if identity is None else leaf_index(group, identity)
    bundle = group.add_members([]) if leaf is None else group.remove_member(leaf)
    epoch = mls_commit(
        client,
        group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=group.cipher_suite(),
            removes=(member_agent_id,),
        ),
        headers,
    )
    # Only after the server accepted it, so a refused commit leaves no forked
    # local state for the retry to build on.
    group.save()
    note_mls_state_changed(config_dir, agent_id, group_id)
    return MlsRemovalCommit(epoch=epoch, removed_leaf=leaf is not None)


__all__ = ["MlsRemovalCommit", "remove_mls_group_member"]
