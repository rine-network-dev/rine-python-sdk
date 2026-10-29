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

from dataclasses import dataclass, field
from typing import Any

from rine._actor import AGENT_HEADER
from rine._mls.allowed import admit_group_peers
from rine._mls.api import MlsCommit
from rine._mls.binding import DEFAULT_CIPHER_SUITE, credential_identity
from rine._mls.commit import post_mls_commit
from rine._mls.commit_admission import admit_refused_peers
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
from rine._mls.failures import group_failures, is_epoch_conflict
from rine._mls.group_access import note_mls_state_changed, open_mls_group
from rine._mls.heartbeat import MlsActor
from rine._mls.sync import sync_mls_group
from rine._mls.tree import leaf_index


@dataclass(frozen=True)
class MlsRemovalCommit:
    """What one Remove commit did, and what it was able to do."""

    epoch: int
    """The epoch it landed at — what ``mls_removal_epoch`` must name, and only
    while it is still the group's current epoch."""

    removed_leaf: bool
    """Whether a leaf actually left the ratchet tree.

    ``False`` when no leaf carried the target's agent id and the commit only
    **declared** the removal: the leaf was already gone, or was never seated.
    Every surface that describes a removal must branch on this: saying a leaf was
    evicted when none was is the class of false report the removal sentences
    exist to prevent.
    """

    escrow: EscrowReport = field(default_factory=EscrowReport)
    """What the escrow drain of this commit could not do: epochs with no escrow, a
    deferral, and what waits queued."""


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
    basic-credential identity is that id, so the leaf that is taken and the name
    that is declared can never be two different members. No key read stands
    between the id and the leaf, so an agent the server publishes no key for (a
    revoked agent, or one on a revoked branch) and an agent that rotated its key
    are removed like any other member.

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
    identity = credential_identity(member_agent_id.lower())
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
    identity: bytes,
    headers: dict[str, str],
) -> MlsRemovalCommit:
    """Build and publish one commit declaring ``member_agent_id``.

    Built from freshly reloaded local state.

    The group is reopened here rather than passed in, because the retry path
    must not rebuild from the handle whose commit was refused — and a leaf index
    read before another commit landed is not the leaf index after it.

    🔴 **A target no leaf names gets a path-only commit, and that is the
    point.** ``add_members([])`` is a commit with no proposals and a
    fresh UpdatePath. It is what rescues a removal whose commit landed and whose
    DELETE then failed: the leaf is already out of the tree, so no second Remove
    can be built for it, so the client could produce no epoch, so the server's
    gate refused every retry and the member row survived its own eviction
    forever. The path-only commit claims no eviction — ``removed_leaf`` says so
    — and proves exactly what the gate asks for: this caller is still committing
    to this group at this epoch, and named this target before it knew which
    DELETE would land. Do not "simplify" it back to returning ``None``.

    A leaf names the target when its credential identity is the target's agent
    id. Two cases leave no such leaf: the removal's own commit already landed (the
    stranded-removal rescue above), or the agent was never seated. A revoked agent,
    an agent on a revoked branch and an agent that rotated its key all still hold
    the leaf their id names, so they get a real Remove.
    """
    actor = MlsActor(client=client, config_dir=config_dir, agent_id=agent_id)
    admit_group_peers(actor, group_id)
    group = open_mls_group(config_dir, agent_id, group_id)
    leaf = leaf_index(group, identity)
    bundle = admit_refused_peers(
        actor,
        group,
        lambda: group.add_members([]) if leaf is None else group.remove_member(leaf),
    )
    epoch = post_mls_commit(
        actor,
        group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=DEFAULT_CIPHER_SUITE,
            removes=(member_agent_id,),
        ),
        headers,
    )
    # Only after the server accepted it, so a refused commit leaves no forked
    # local state for the retry to build on.
    drained = drain_escrow(actor, group_id, group, carry_unreported=True)
    note_mls_state_changed(config_dir, agent_id, group_id)
    return MlsRemovalCommit(epoch=epoch, removed_leaf=leaf is not None, escrow=drained.report())


__all__ = ["MlsRemovalCommit", "remove_mls_group_member"]
