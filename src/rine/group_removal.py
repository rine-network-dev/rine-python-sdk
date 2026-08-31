"""What a removal did, and the one sentence that tells an operator about it.

It lives in its own module because the true sentence differs between the two
group types and between the two verbs, and every surface that composes its own
is a chance for one of them to be wrong. Nothing cryptographic ever kept a
departed member out of an open group, and no rejoin is needed to get back in,
so a sentence that says otherwise is false there. The TypeScript twin is
``rine-ts-sdk/src/resources/groups-removal-message.ts``, whose branches these
mirror.

**How the group's crypto is known here, without reading the group.** The
TypeScript SDK re-reads the group and asks ``groupIsMls``. This SDK does not,
deliberately: which removals need a Remove commit is the *server's* answer
(:mod:`rine._resources.group_members`), so a **kick** learns the regime from
whether the server asked for one — which is precisely
:func:`rine.format.group_is_mls`, ``mls_group_id is not None``, at no round
trip. A group whose MLS founding has not latched yet answers ``sender-key``
here, and :func:`rine.format.group_is_mls` answers the same for that group.

A **leave** is told instead by what this agent actually held, which is the more
precise answer for a sentence about a wipe: a member of an MLS group that never
installed its Welcome held no epoch secrets, and telling it "your MLS state is
gone" would report something that did not happen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: The crypto a removal acted on. ``None`` is a third answer rather than a
#: missing one — this client could not tell which regime the group ran, and
#: says only what it knows instead of picking one and hoping.
GroupRemovalEncryption = Literal["mls", "sender-key"]


@dataclass(frozen=True)
class GroupRemovalResult:
    """What a removal did, and what to tell the operator about it."""

    left: bool
    """True when the acting agent removed itself — a leave, not a kick."""

    encryption: GroupRemovalEncryption | None
    """The crypto this removal acted on, or ``None`` when it could not be told."""

    mls_removal_epoch: int | None
    """The epoch the Remove commit landed at. ``None`` when none was posted."""

    mls_removed_leaf: bool | None
    """Whether that commit actually took a ratchet-tree leaf.

    ``None`` when no commit was posted; ``False`` when one was, but the target
    held no leaf to take — the rescue path, which declares the removal so the
    ``DELETE`` can land without claiming an eviction that did not happen.
    """

    local_state_retired: bool
    """True when this call removed local key material this agent was holding.

    A leave that found nothing to retire — an MLS member whose Welcome was never
    installed, or a group this agent had never sent to — reports ``False``, so
    the flag is a report of what happened rather than of what was attempted.
    """

    message: str
    """One accurate sentence for this removal and this group type.

    Surfaces print it rather than composing their own: the true sentence differs
    between the two group types and between the two verbs, and nine surfaces
    guessing is how the shipped one came to be false for every open group.
    """


def removal_message(
    group_name: str,
    agent_id: str,
    *,
    left: bool,
    encryption: GroupRemovalEncryption | None,
    epoch: int | None,
    removed_leaf: bool = True,
) -> str:
    """The one true sentence for this removal.

    Args:
        group_name: The group as the caller named it — a handle when they used
            one, its UUID otherwise. This SDK does not read the group back, so
            there is no canonical handle to prefer over the caller's own word.
        agent_id: The member the caller asked to remove.
        left: Whether that member is the acting agent.
        encryption: The crypto the removal acted on, or ``None``.
        epoch: The epoch a Remove commit landed at, or ``None`` when none was.
        removed_leaf: Whether that commit took a ratchet-tree leaf. Ignored
            when ``epoch`` is ``None``. 🔴 A commit that landed no
            longer implies a leaf that went — the rescue path posts a path-only
            commit for a target holding none — so the two facts are separate
            arguments. It defaults to the historical answer so a caller with
            only an epoch keeps the sentence it always got.

    Returns:
        One sentence, safe to print as-is.
    """
    if left and encryption is None:
        return (
            f"You left group {group_name}. This client held no local key material for "
            f"it — neither MLS state nor sender-key material — so there was nothing "
            f"to retire."
        )
    if left and encryption == "mls":
        return (
            f"You left group {group_name}. Its local MLS state is gone — the current "
            f"epoch secrets, every retained epoch secret and the plaintext the "
            f"self-read cache held — so this group's messages no longer open on this "
            f"machine, including the ones that arrived before you left. Rejoining the "
            f"group is the only way back in."
        )
    if left:
        return (
            f"You left group {group_name}. Local sender-key material for it is gone — "
            f"the key you were sending under, every key you had from other members, "
            f"and the cached message keys — so this group's messages no longer open "
            f"on this machine, including the ones that arrived before you left and "
            f"were never read. An open group has no cryptographic eviction: what "
            f"bounds your reach into its later traffic is each remaining member "
            f"rotating their sender key on their next send, not this wipe."
        )
    if epoch is not None and removed_leaf:
        return (
            f"Removed {agent_id} from group {group_name}. A Remove commit at epoch "
            f"{epoch} took their ratchet-tree leaf with it, so nothing committed to "
            f"the group from that epoch on will open for them."
        )
    if epoch is not None:
        return (
            f"Removed {agent_id} from group {group_name}. The commit at epoch {epoch} "
            f"declared the removal, but no leaf in the ratchet tree carries the signing "
            f"key they publish now — nothing was removed from the tree, so what keeps "
            f"them out is the server declining to hand them the group's traffic. If "
            f"they rotated their signing key, their old leaf is still there: have them "
            f"rejoin, or re-invite them, so a Remove commit can name it."
        )
    if encryption is None:
        # A kick this client could not attribute: it never learned which agent
        # was acting, so it neither posted a commit nor retired anything, and
        # the server's own answer is all there is to report. Naming a regime
        # here would be a guess, and the open-group sentence would be a claim
        # about crypto this call never saw.
        return f"Removed {agent_id} from group {group_name}."
    if encryption == "mls":
        # A kick from an MLS group with no epoch: the target held no leaf, so
        # the server did not ask for a commit. Unreachable through
        # :func:`group_removal_result` today — ``encryption`` is derived from
        # ``epoch`` there — but this function is public and total over its own
        # signature, and without this branch it fell past every test and
        # answered the OPEN-group sentence for a closed MLS group.
        return (
            f"Removed {agent_id} from group {group_name}, without a Remove commit — "
            f"they held no ratchet-tree leaf to remove, so the eviction rests on the "
            f"server declining to hand them the group's traffic."
        )
    return (
        f"Removed {agent_id} from group {group_name}. An open group has no "
        f"cryptographic eviction: they stop receiving this group's traffic from the "
        f"server, and what bounds their reach into its later traffic is each remaining "
        f"member rotating their sender key on their next send."
    )


def group_removal_result(
    group_name: str,
    agent_id: str,
    *,
    left: bool,
    encryption: GroupRemovalEncryption | None,
    epoch: int | None,
    local_state_retired: bool,
    removed_leaf: bool | None = None,
) -> GroupRemovalResult:
    """Compose the result and its sentence, so sync and async cannot diverge.

    Args:
        group_name: The group as the caller named it.
        agent_id: The member the caller asked to remove.
        left: Whether that member is the acting agent.
        encryption: The crypto the removal acted on, or ``None``.
        epoch: The epoch a Remove commit landed at, or ``None`` when none was.
        local_state_retired: Whether local key material was actually removed.
        removed_leaf: Whether that commit took a ratchet-tree leaf, or ``None``
            when no commit was posted.

    Returns:
        The removal's outcome, carrying the sentence to print.
    """
    return GroupRemovalResult(
        left=left,
        encryption=encryption,
        mls_removal_epoch=epoch,
        mls_removed_leaf=removed_leaf,
        local_state_retired=local_state_retired,
        message=removal_message(
            group_name,
            agent_id,
            left=left,
            encryption=encryption,
            epoch=epoch,
            removed_leaf=removed_leaf is not False,
        ),
    )


__all__ = [
    "GroupRemovalEncryption",
    "GroupRemovalResult",
    "group_removal_result",
    "removal_message",
]
