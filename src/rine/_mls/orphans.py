"""Leaves the ratchet tree still carries for agents the group no longer entitles.

An invitation takes a ratchet-tree leaf the moment its Welcome is minted, but
the server's voucher reaper only frees the **seat** when the invitation lapses.
The leaf stays. So a group that churns no-show invitations inflates every later
Welcome and every later commit without bound — composed at the 500-member
ceiling, 100 no-shows make every later commit ~19 % heavier for all 400 real
members, forever. A self-leave leaves the same residue: MLS gives nobody a way
to commit their own removal, so the leaver's row goes and their leaf does not.

🔴 **Reclamation is never automatic, and it is not admin-gated.** The server
holds no MLS keys, so it cannot mint the Remove commit; a group nobody runs the
resume verb on with ``reclaim=True`` keeps accumulating leaves. Posting the
Remove commit takes membership and no role beyond it (``mls.py:174-175``: "A
non-init epoch-advancing commit only requires membership, NOT admin"), so ANY
member can run it and post one O(N) Remove per orphan, billed to all. The
deterrent is that cost, not a permission check — do not write
"admin-initiated". 🔴 Do NOT restate this as "every route this pass calls is
member-gated": the pass reads ``GET /groups/{id}/members``, which is ORG-gated
(``has_read_access`` admits any org holding a member agent), and ``GET
/agents/keys``, which is unauthenticated; the epoch-conflict retry also reads
``GET /groups/{id}/mls/handshakes``, whose ``require_handshake_reader`` grant is
looser than membership. The conclusion is right and that reason is not. Write
"reclamation bounds the tree", never "expiry bounds the tree" — expiry frees the
seat only. A reclaimed leaf is genuinely re-occupiable (MEASURED,
``rine-mls-core/tests/leaf_reuse.rs``), which is what makes the bound real.

The set is ``{tree identities} \\ {members ∪ live vouchers}``, and the second
half is read from ``GET /groups/{id}/requests?outstanding=live`` and nowhere
else. Computing it from members alone classifies every agent who was
legitimately invited and has not accepted yet as an orphan, and evicts all of
them. ``live`` is ``pending`` plus ``invited``, so a **nomination** is entitled
by the same read that entitles an invitation, and is never reclaimed while the
electorate still owes it an answer.

🔴 **The subtraction is keyed by the signing key each entitled agent publishes
right now, and that is a narrower instrument than it looks.** Two populations
break it, and only one of them is detectable from here:

* An entitled agent whose published key occupies no leaf — a key rotation is the
  ordinary cause. Detectable, and :func:`reclaim_orphan_leaves` declines the
  whole pass and names them rather than reclaiming a seated member's leaf.
* A **revoked** member. ``DELETE /agents/{id}`` sets ``revoked_at`` and leaves
  both the group-membership row and the ratchet-tree leaf where they are, and
  the row is then invisible to every read this pass has: ``GET
  /groups/{id}/members`` filters revoked agents out, and so does ``GET
  /agents/keys``. So a revoked member enters neither the entitled set nor the
  unreadable set, and its leaf is reclaimed as an orphan. That leaves a member
  row with no leaf — recoverable, because the path-only rescue can still
  declare and remove it, but it costs an O(N) commit nobody asked for. Closing
  it needs a server view of membership that includes revoked agents; no
  client-side read distinguishes the two today, and no surface may claim this
  pass covers the revoked case.

The TypeScript twin is ``rine-core/src/mls-orphans.ts``, function for function.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rine._actor import AGENT_HEADER
from rine._mls.admission import MlsReclamation, MlsReclamationDecline
from rine._mls.api import MlsCommit, mls_commit, read_group
from rine._mls.failures import is_epoch_conflict
from rine._mls.group_access import open_mls_group
from rine._mls.sync import sync_mls_group
from rine._mls.tree import fetch_agent_identities, leaf_index, read_group_tree

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rine._mls.binding import MlsGroup


@dataclass(frozen=True)
class OrphanLeaf:
    """A ratchet-tree leaf no membership and no live voucher entitles."""

    index: int
    """The leaf's index at the epoch it was enumerated at."""

    identity: bytes
    """Its occupant's MLS basic-credential identity — a raw Ed25519 key."""


def orphan_leaves(group: MlsGroup, entitled: Iterable[bytes]) -> list[OrphanLeaf]:
    """The leaves in ``group``'s tree that none of ``entitled`` occupies.

    Local and exact: ``member_identities()`` enumerates every occupied leaf and
    no blanked one, and each index it reports round-trips through
    ``member_index`` (measured on both suites). Before that enumeration existed
    the whole tree-query surface was identity → index, so this set could not be
    constructed by any client at all.

    This agent's own leaf is excluded unconditionally rather than by trusting
    the membership read. An agent that self-evicts can neither commit nor
    recover, and a reclamation pass is exactly where a mis-read member list
    would do it.
    """
    keys = {bytes(identity) for identity in entitled}
    own = group.current_member_index()
    return [
        OrphanLeaf(index=leaf.index, identity=bytes(leaf.identity))
        for leaf in group.member_identities()
        if leaf.index != own and bytes(leaf.identity) not in keys
    ]


def _named_few(agent_ids: list[str]) -> str:
    """The first three of a named set, plus a count for the rest."""
    named = ", ".join(agent_ids[:3])
    return f"{named}, and {len(agent_ids) - 3} more" if len(agent_ids) > 3 else named


def _unreadable_detail(unreadable: list[str]) -> str:
    """The sentence an unreadable entitled agent earns, naming who it was.

    Deliberately does NOT claim to cover a revoked member: ``GET
    /groups/{id}/members`` filters revoked agents out, so one never reaches this
    set at all (see this module's header). What does reach it is an agent holding
    a live voucher whose key the server no longer publishes — an invitation
    outlives the revocation of the agent it names.
    """
    return (
        f"Reclaimed nothing: {len(unreadable)} agent(s) this group entitles to a seat "
        f"publish no readable signing key ({_named_few(unreadable)}), so their leaves "
        "cannot be told apart from an orphan's. An agent the group still holds a seat "
        "for is entitled to it, and dropping its leaf would leave an entitlement with "
        "no leaf behind it."
    )


def _unseated_detail(unseated: list[str]) -> str:
    """The sentence a member whose published key occupies no leaf earns.

    A member always holds a leaf — that is what admission committed. So a member
    whose published signing key matches none of them means the two have come
    apart, and the ordinary cause is a key rotation: ``POST /agents/{id}/keys``
    has no MLS guard, so a rotation changes what this pass subtracts while the
    leaf keeps carrying the credential the group was founded on. Reclaiming then
    evicts a seated member — the epoch advances, the group stops opening for
    them, their member row is untouched, and the pass reports only a count.

    So the pass declines and names them, exactly as :func:`_unreadable_detail`
    does, and for the same reason: an ambiguity between a member's leaf and an
    orphan's is not a licence to remove either.
    """
    return (
        f"Reclaimed nothing: {len(unseated)} member(s) of this group publish a signing "
        f"key that occupies no leaf in its ratchet tree ({_named_few(unseated)}), so "
        "this group's membership and its tree have come apart and no leaf can be "
        "attributed. A member that rotated its signing key looks exactly like this; "
        "its leaf still carries the key it published before, and removing that leaf "
        "would evict a seated member. Have them rejoin the group, or remove them and "
        "invite them again, and run this pass afterwards."
    )


def _commit_orphan_removal(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    identity: bytes,
    suite: int | None,
    headers: dict[str, str],
) -> int | None:
    """Post one Remove commit for the leaf ``identity`` holds right now.

    ``None`` when that identity holds no leaf any more. State and leaf index are
    both re-read here rather than carried in: a leaf index is only true of the
    epoch it was read at, and each removal in a pass moves the epoch.

    Deliberately declares nothing. ``removes`` names **agent ids**, and an
    orphan's leaf is precisely the one no server route can name — it holds no
    member row and no live voucher, and there is no identity → agent lookup. A
    commit that declares nothing can authorise no ``DELETE``, which is the
    correct answer here: an orphan has no member row to delete.
    """
    group = open_mls_group(config_dir, agent_id, group_id, cipher_suite=suite)
    leaf = leaf_index(group, identity)
    if leaf is None:
        return None
    bundle = group.remove_member(leaf)
    epoch = mls_commit(
        client,
        group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=group.cipher_suite(),
        ),
        headers,
    )
    # Adopted only after the server accepted it, so a refused commit leaves no
    # forked local state for the next leaf in the pass to build on.
    group.save()
    return epoch


def reclaim_orphan_leaves(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    extra_headers: dict[str, str] | None = None,
) -> MlsReclamation:
    """Retire every leaf this group's members and live vouchers do not account for.

    One Remove commit per leaf, each O(N) and billed to every member — the
    native core removes one leaf at a time, so a group carrying 100 orphans pays
    100 commits to reclaim them. That is a one-off against a weight every future
    commit would otherwise carry.

    A lost epoch CAS is ordinary rather than exceptional here: the pass is a
    sequence of commits against a group that is free to move underneath it. The
    first conflict syncs and retries that leaf once; a second ends the pass and
    reports what landed, because an unbounded retry against an advancing epoch
    is a self-DoS.

    🔴 It refuses to act at all on either ambiguity between a member's leaf and
    an orphan's — an entitled agent whose signing key is unreadable, and a member
    whose published key occupies no leaf — and when the outstanding invitations
    could not be read, which is what stops it evicting every agent who has not
    accepted yet. The one ambiguity it CANNOT see is a revoked member; see this
    module's header.

    One race it cannot close, and does not pretend to: an agent whose invitation
    lapsed and who is re-invited between the tree read and the Remove commit
    loses the fresh leaf too. Their membership is untouched, and the next resume
    seats them again.

    Args:
        client: Sync HTTP client.
        config_dir: Config directory path.
        agent_id: The acting agent's UUID; it must be a member of the group and
            hold its MLS state.
        group_id: The rine group UUID.
        extra_headers: Acting-agent headers for the group requests.

    Returns:
        What the pass found, what it retired, and what it cost.
    """
    headers = dict(extra_headers or {AGENT_HEADER: agent_id})
    suite = read_group(client, agent_id, group_id).mls_cipher_suite
    tree = read_group_tree(client, group_id, headers)
    group = open_mls_group(config_dir, agent_id, group_id, cipher_suite=suite)
    if not tree.outstanding_known:
        return MlsReclamation(
            found=0,
            reclaimed=0,
            commits=0,
            epoch=group.epoch(),
            declined=MlsReclamationDecline(
                reason="outstanding_unknown",
                detail=(
                    "Reclaimed nothing: this group's outstanding invitations could not "
                    "be read, so every agent who was invited and has not accepted yet "
                    "would look like an orphan. Retry as a member of the group — this "
                    "read requires membership, and it is the only thing that can tell "
                    "an unaccepted invitation from an orphan."
                ),
            ),
        )

    # The WIDER of the two voucher populations. A ``pending`` row — a
    # self-application or a member's nomination of one — holds no leaf today,
    # so counting them can only ever decline to reclaim a leaf, never wrongly
    # evict one, which is the safe direction for a destructive pass.
    entitled_ids = [*tree.member_ids, *tree.outstanding_ids]
    identities = fetch_agent_identities(client, entitled_ids)
    unreadable = [a for a in entitled_ids if a.lower() not in identities]
    if unreadable:
        return MlsReclamation(
            found=0,
            reclaimed=0,
            commits=0,
            epoch=group.epoch(),
            declined=MlsReclamationDecline(
                reason="identity_unknown", detail=_unreadable_detail(unreadable)
            ),
        )

    # Members only. An outstanding invitee legitimately holds no leaf yet — its
    # Welcome may not have been minted — so requiring one of them would decline
    # every pass on a group with an unaccepted invitation.
    unseated = [
        a
        for a in tree.member_ids
        if a.lower() in identities and leaf_index(group, identities[a.lower()]) is None
    ]
    if unseated:
        return MlsReclamation(
            found=0,
            reclaimed=0,
            commits=0,
            epoch=group.epoch(),
            declined=MlsReclamationDecline(
                reason="identity_unseated", detail=_unseated_detail(unseated)
            ),
        )

    orphans = orphan_leaves(group, identities.values())
    epoch = group.epoch()
    commits = 0
    reclaimed = 0
    for orphan in orphans:
        try:
            landed = _commit_orphan_removal(
                client, config_dir, agent_id, group_id, orphan.identity, suite, headers
            )
        except Exception as err:
            if not is_epoch_conflict(err):
                raise
            sync_mls_group(client, config_dir, agent_id, group_id)
            try:
                landed = _commit_orphan_removal(
                    client, config_dir, agent_id, group_id, orphan.identity, suite, headers
                )
            except Exception as retry_err:
                if not is_epoch_conflict(retry_err):
                    raise
                break
        # None means somebody else's commit already took this leaf — an answer,
        # not a failure, and the pass simply owes one fewer commit.
        if landed is None:
            continue
        epoch = landed
        commits += 1
        reclaimed += 1
    return MlsReclamation(found=len(orphans), reclaimed=reclaimed, commits=commits, epoch=epoch)


__all__ = ["OrphanLeaf", "orphan_leaves", "reclaim_orphan_leaves"]
