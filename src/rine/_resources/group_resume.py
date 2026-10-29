"""Finishing an admission that stopped part-way.

``mls_group_id`` is a one-way latch, set by the first commit that lands and
cleared nowhere, and ``POST /mls/init`` refuses once it is set. So a founding
that stopped at commit 5 of 39 — a dropped connection, a refused recipient, a
process that died — had **no way forward at all**: the group was latched,
half its roster held vouchers and no leaf, and the only Python remedy was a new
group. Two shipped docstrings already promised this was recoverable.

Resume is continuation, not re-initialisation. It is the add path run over the
group's whole known population, which seats exactly the members and invitees
that are not seated yet and reports every one it skipped.

🔴 It reads the group's **outstanding invitations**, not just its members and
its vote queue. An agent that was legitimately invited and has not accepted yet
holds a ratchet-tree seat and is entitled to a leaf; a resume computed from
members alone concludes that every one of them holds nothing, which is the
premise under which leaf reclamation would evict all of them.

``reclaim`` adds the other half: once everyone entitled to a leaf has one,
retire the leaves nobody is entitled to. It is off unless asked for, because it
removes leaves and costs one O(N) commit per leaf — and it is the only thing
that retires one. The server holds no MLS keys, so nothing does this
automatically; a group nobody asks keeps accumulating them. Any member may ask.
"""

from __future__ import annotations

from typing import Any

from rine._actor import AGENT_HEADER
from rine._mls.admission import MlsAdmissionResult
from rine.format import group_is_mls
from rine.types import GroupRead

NOT_AN_MLS_GROUP = (
    "Group {handle} runs on sender keys, not MLS, so it has no ratchet tree to "
    "seat anyone in. Open-enrollment groups are sender-key groups by design: MLS "
    "would hand an unattested joiner a cryptographic seat, so the server keeps "
    "open enrollment off the MLS path. There is nothing to resume here."
)


def _resume(
    client_http: Any, config_dir: str, acting: str, group: GroupRead, reclaim: bool
) -> MlsAdmissionResult:
    """Seat everyone this group knows about who is not seated yet.

    Founding and continuing are the same loop at different points, so which one
    this is comes down to whether the group is latched: an unlatched group has
    no state to continue from and is founded, a latched one is continued. Either
    way the answer is the same shape.

    Reclamation runs **after** admission, never before, so every entitled agent is
    seated before the leaves nobody entitles are dropped. A group being founded
    here has no orphans to reclaim: every leaf in it was minted by the founding
    commits themselves.
    """
    from dataclasses import replace

    from rine._mls.add_members import add_mls_group_members
    from rine._mls.group_init import init_mls_group
    from rine._mls.orphans import reclaim_orphan_leaves
    from rine._mls.tree import read_group_tree

    group_id = str(group.id)
    headers = {AGENT_HEADER: acting}
    if not group_is_mls(group):
        # Never founded, or a founding whose very first commit was refused. The
        # server's own init window (and its stale-`mls_pending` self-heal) is
        # what decides whether this is allowed yet, and it says so if not.
        return init_mls_group(client_http, config_dir, acting, group_id, headers)
    tree = read_group_tree(client_http, group_id, headers)
    result = add_mls_group_members(
        client_http,
        config_dir,
        acting,
        group_id,
        [*tree.member_ids, *tree.invited_ids],
        headers,
    )
    if not reclaim:
        return result
    reclamation = reclaim_orphan_leaves(client_http, config_dir, acting, group_id, headers)
    return replace(result, epoch=reclamation.epoch, reclamation=reclamation)


def _refuse_sender_key_group(group: GroupRead) -> None:
    if group.enrollment_policy == "open":
        raise ValueError(NOT_AN_MLS_GROUP.format(handle=group.handle))


def resume_admission(
    client: Any, handle_or_id: str, *, agent: str | None, reclaim: bool = False
) -> MlsAdmissionResult:
    """Seat every member and invitee this group has not seated yet (sync)."""
    group_id = client._resolve_group_sync(handle_or_id, agent)
    extra = client._agent_header(agent)
    group = GroupRead.model_validate(client._http.get(f"/groups/{group_id}", extra_headers=extra))
    _refuse_sender_key_group(group)
    acting = client._resolve_agent_id(agent)
    return _resume(client._http, client._config_dir, acting, group, reclaim)


async def resume_admission_async(
    client: Any, handle_or_id: str, *, agent: str | None, reclaim: bool = False
) -> MlsAdmissionResult:
    """Async counterpart of :func:`resume_admission`."""
    from rine._mls.bridge import with_sync_http

    group_id = await client._resolve_group_async(handle_or_id, agent)
    extra = await client._agent_header(agent)
    group = GroupRead.model_validate(
        await client._http.get(f"/groups/{group_id}", extra_headers=extra)
    )
    _refuse_sender_key_group(group)
    acting = await client._resolve_agent_id(agent)
    return await with_sync_http(
        client, lambda http: _resume(http, client._config_dir, acting, group, reclaim)
    )


__all__ = ["resume_admission", "resume_admission_async"]
