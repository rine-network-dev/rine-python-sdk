"""Catching a group's encryption state up, as a verb a caller can reach.

A rine group runs one of two encryptions and both are supported products, so
this verb has two answers. The MLS ladder lives in :mod:`rine._mls.resync`,
which is private. Sender-key recovery is the client's own distribution scan:
there is no epoch chain to walk, and what a member can be missing is other
members' keys, sitting as DMs in this agent's own inbox. What is here is the
part a public method needs and neither recovery must know about: resolving a
handle to a group id, deciding which recovery the group even has, and running
the MLS ladder off the event loop for the async client.

🔴 The decision is made from the group row's ``mls_group_id`` latch, and never
from whether local state loads. Absent state is a symptom shared by an MLS
member whose store was deleted and by every member of an open group; branching
on it tells the second to ask an admin to remove and re-invite them, which is
advice about a ratchet tree their group has not got.

The TypeScript twin is ``recoverGroup`` (``rine-core/src/group-recovery.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from rine._group_recovery import SenderKeyRecoveryResult
from rine._mls.resync import recover_mls_group
from rine.format import (
    MLS_INIT_IN_FLIGHT_SYNC,
    group_is_mls,
    group_mls_init_in_flight,
    group_mls_never_founded,
    mls_never_founded_sync,
)
from rine.types import GroupRead

if TYPE_CHECKING:
    from rine._group_recovery import GroupRecoveryResult
    from rine.format import UnfoundedGroupRepair


def _regime(group: GroupRead) -> Literal["mls", "sender-key"]:
    """Which recovery this group takes.

    Stated once even though the two arms below are hand-mirrored, so the sync
    and async clients cannot come to disagree about what a group is — and so
    the refusal cannot be added to one client and forgotten on the other.

    Args:
        group: The group row the caller just read from the server.

    Raises:
        ValueError: **The MLS init is still in flight**, so the group has
            neither an epoch chain to catch up with nor sender keys to install.
            It is its own answer because it is the case a two-way branch reads
            as sender-key and then runs an ingest against a group that is really
            MLS — a wrong action rather than a wrong sentence. The sentence
            lives beside :func:`rine.format.describe_mls_recovery`, with the
            rest of what a surface says about a group's encryption; a second
            copy here is how the two stacks came to print different words for
            one event.
    """
    if group_mls_init_in_flight(group):
        raise ValueError(MLS_INIT_IN_FLIGHT_SYNC.format(handle=group.handle))
    return "mls" if group_is_mls(group) else "sender-key"


def _never_founded_note(group: GroupRead, repair: UnfoundedGroupRepair) -> str | None:
    """What a sync could not reach on this group, or ``None`` if it reached it all.

    🔴 A warning, not a refusal. A group created to run MLS whose tree was never
    founded is field for field an open group in the MLS columns, so the latch
    alone sent it to the distribution scan and reported "Recovered group …" for
    a group that never got the encryption it was created for. But that scan is
    real work — the server accepts sender-key sends into this group, so keys for
    it really are waiting — and refusing ahead of it cost an operator those keys
    to buy a sentence. So the scan runs and this rides on its answer.

    Composed here, where ``repair`` is in scope, rather than at each render: the
    surface that knows which founding verb its caller can run is the one that
    called this.

    Args:
        group: The group row the caller just read from the server.
        repair: The founding verb the calling surface can offer, in its own
            spelling.

    Returns:
        The warning, or ``None`` when this group has the encryption it was
        created for.
    """
    if not group_mls_never_founded(group):
        return None
    return mls_never_founded_sync(repair)


def _read_group(client: Any, group_id: str, extra: dict[str, str] | None) -> GroupRead:
    return GroupRead.model_validate(client._http.get(f"/groups/{group_id}", extra_headers=extra))


def sync_group_state(
    client: Any,
    handle_or_id: str,
    *,
    agent: str | None,
    repair: UnfoundedGroupRepair = "sdk-resume-admission",
) -> GroupRecoveryResult:
    """Catch one group's local encryption state up with the group (sync)."""
    group_id = client._resolve_group_sync(handle_or_id, agent)
    group = _read_group(client, group_id, client._agent_header(agent))
    regime = _regime(group)
    acting = client._resolve_agent_id(agent)
    if regime == "mls":
        return recover_mls_group(
            client._http,
            client._config_dir,
            acting,
            group_id,
            cipher_suite=group.mls_cipher_suite,
        )
    note = _never_founded_note(group, repair)
    # ⚠️ Not optional, and not what the TypeScript stack does. There the gate
    # rides inside the scan; here ``_scan_pending_sk_distributions`` takes no
    # group id, refuses per distribution on the marker and never lifts one. This
    # call is what makes the two stacks agree about a re-admitted member, and it
    # is the order ``_self_heal_group_decrypt`` already uses.
    if client._retirement_blocks_read(acting, group.id):
        return SenderKeyRecoveryResult(
            regime="sender-key", ingested=0, retired=True, mls_never_founded_note=note
        )
    # The scan, not the count-only wrapper every read path calls: this is the one
    # caller that reports what the pass could not reach as well as what it
    # installed, and the wrapper is this method with that second number dropped.
    scan = client._scan_pending_sk_distributions(acting)
    return SenderKeyRecoveryResult(
        regime="sender-key",
        ingested=scan.ingested,
        # ``None`` rather than ``0``, the ``mls_never_founded_note`` rule: a page
        # that covered everything says nothing, and a ``0`` projected into JSON is
        # a number reporting that nothing happened.
        unscanned=scan.unscanned or None,
        retired=False,
        mls_never_founded_note=note,
    )


async def sync_group_state_async(
    client: Any,
    handle_or_id: str,
    *,
    agent: str | None,
    repair: UnfoundedGroupRepair = "sdk-resume-admission",
) -> GroupRecoveryResult:
    """Async counterpart of :func:`sync_group_state`."""
    from rine._mls.bridge import with_sync_http

    group_id = await client._resolve_group_async(handle_or_id, agent)
    extra = await client._agent_header(agent)
    group = GroupRead.model_validate(
        await client._http.get(f"/groups/{group_id}", extra_headers=extra)
    )
    regime = _regime(group)
    acting = await client._resolve_agent_id(agent)
    if regime == "mls":
        return await with_sync_http(
            client,
            lambda http: recover_mls_group(
                http,
                client._config_dir,
                acting,
                group_id,
                cipher_suite=group.mls_cipher_suite,
            ),
        )
    note = _never_founded_note(group, repair)
    if await client._retirement_blocks_read(acting, group.id):
        return SenderKeyRecoveryResult(
            regime="sender-key", ingested=0, retired=True, mls_never_founded_note=note
        )
    scan = await client._scan_pending_sk_distributions(acting)
    return SenderKeyRecoveryResult(
        regime="sender-key",
        ingested=scan.ingested,
        unscanned=scan.unscanned or None,
        retired=False,
        mls_never_founded_note=note,
    )


__all__ = ["sync_group_state", "sync_group_state_async"]
