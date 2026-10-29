"""Removing a member — the order the two halves have to happen in.

Dropping the membership row evicts nobody on its own: the leaf stays in the
ratchet tree and every epoch secret the evicted agent holds stays valid, so the
removal would be enforced by the server's delivery filter and nothing else. So
an eviction from a group with MLS state posts the Remove commit **first**, while
the target is still a member — which is what queues the commit for them, so
their client learns it was evicted instead of going quiet — and then names the
epoch it landed at.

Which removals need one is the **server's** answer, not a guess made here: the
DELETE is attempted, and a group that needs a commit refuses it by name. That
costs a sender-key group nothing, cannot act on a stale reading of the group,
and means this client never has to keep its own copy of the rule.

``mls_removal_epoch`` is a **query parameter**, and that is not a style choice:
sent as a JSON body — the shape every other rine mutation uses — it binds
``None`` server-side, and every cross-org removal is then refused for not
posting a commit the client did post.

Leaving is the one carve-out. MLS gives nobody a way to commit their own
removal, so a self-leave is never asked for one and its leaf is reclaimed later
by an admin. The server tells a leave from a kick by the acting-agent header and
fails closed; this path resolves the same agent for the same reason.

The commit **declares** the member it removes and the server spends
that declaration once, so a commit naming nobody authorises no removal; and
a target that holds no leaf still earns a path-only commit, which
is what completes a removal whose commit landed and whose DELETE did not. Both
live in :mod:`rine._mls.removal`; what this module owes them is to report the
difference rather than to claim an eviction that did not happen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._logging import logger
from rine._mls.wire import api_error_code
from rine.errors import ConflictError
from rine.group_removal import GroupRemovalEncryption, GroupRemovalResult, group_removal_result

if TYPE_CHECKING:
    from rine._mls.leave import RetiredGroupState
    from rine._mls.removal import MlsRemovalCommit

REMOVAL_COMMIT_REQUIRED = "mls_removal_commit_required"


def _warn_unresolved_actor() -> None:
    logger.warning("Cannot resolve the acting agent; leaving local MLS state in place")


def _result(
    group_name: str,
    agent_id: str,
    acting_agent_id: str | None,
    removal: MlsRemovalCommit | None,
    retired: RetiredGroupState,
) -> GroupRemovalResult:
    """What this removal did, in the one shape both peers answer with.

    The group's regime is read off what the call already learned, never off a
    fresh group read (:mod:`rine.group_removal` says why). A **kick** is told by
    the server: it refuses one on a group with MLS state until a Remove commit
    names an epoch, so an epoch means MLS and its absence means the server
    holds no MLS state for the group. A **leave** is told by what was actually
    retired, which is the fact the sentence is about.
    """
    if acting_agent_id is None:
        # Neither verb can be attributed and nothing was retired, so the only
        # honest report is that the server removed the member.
        return group_removal_result(
            group_name,
            agent_id,
            left=False,
            encryption=None,
            epoch=None,
            local_state_retired=False,
        )
    left = agent_id.lower() == acting_agent_id.lower()
    encryption: GroupRemovalEncryption | None
    if not left:
        encryption = "mls" if removal is not None else "sender-key"
    elif retired.mls:
        encryption = "mls"
    elif retired.sender_key:
        encryption = "sender-key"
    else:
        encryption = None
    return group_removal_result(
        group_name,
        agent_id,
        left=left,
        encryption=encryption,
        epoch=None if removal is None else removal.epoch,
        removed_leaf=None if removal is None else removal.removed_leaf,
        local_state_retired=retired.mls or retired.sender_key,
    )


def _needs_removal_commit(err: BaseException) -> bool:
    """Whether the server refused this DELETE for want of a Remove commit."""
    return isinstance(err, ConflictError) and api_error_code(err) == REMOVAL_COMMIT_REQUIRED


def _actor_for_removal(client: Any, agent: str | None) -> tuple[dict[str, str] | None, str | None]:
    """The acting-agent header and id for a removal — tolerating only an *ambient* actor.

    Resolved before the removal: an org whose acting agent is ambiguous must
    still be able to remove a member, it just cannot be told a leave from a
    kick, and an unresolved agent never wipes anything.

    🔴 **The tolerance is for the actor nobody named on this call, and only
    that.** ``agent is None`` means the actor came from the constructor, from
    ``RINE_AGENT`` or from the server's one-active-agent shortcut, and the org
    that never names one has always been able to kick header-less. A value the
    **caller passed to this call** is different: since the header resolves bare
    names too, a typo'd or ambiguous ``agent=`` now fails while building the
    header, which used to be sent verbatim for the server to refuse. Swallowing
    that would strip the header the caller asked for and send an unattributed
    DELETE — and ``get_optional_acting_agent`` swallows the server's refusal in
    turn, so a same-org member is removed under no named identity, reported as
    neither a leave nor a kick. A refusal became a silent destructive removal,
    so a named actor that cannot be resolved raises here.

    It also puts this verb back in step with its own neighbour: a *bare group
    name* already raises out of ``_resolve_group_sync`` one line above, on
    exactly the same input.
    """
    try:
        return client._agent_header(agent), client._resolve_agent_id(agent)
    except Exception:
        if agent is not None:
            raise
        _warn_unresolved_actor()
        return None, None


async def _actor_for_removal_async(
    client: Any, agent: str | None
) -> tuple[dict[str, str] | None, str | None]:
    """Async twin of :func:`_actor_for_removal`; the rule is stated there."""
    try:
        return await client._agent_header(agent), await client._resolve_agent_id(agent)
    except Exception:
        if agent is not None:
            raise
        _warn_unresolved_actor()
        return None, None


def _evict(
    http: Any, config_dir: str, acting: str, group_id: str, agent_id: str
) -> MlsRemovalCommit:
    """Commit the removal and return the epoch the retry must name."""
    from rine._mls.removal import remove_mls_group_member

    return remove_mls_group_member(http, config_dir, acting, group_id, agent_id)


def remove_group_member(
    client: Any, handle_or_id: str, agent_id: str, *, agent: str | None
) -> GroupRemovalResult:
    """Remove a member, evicting the leaf if asked and retiring local keys (sync)."""
    from rine._mls.leave import (
        RetiredGroupState,
        retire_local_group_state,
        settle_escrow_before_leave,
    )

    group_id = client._resolve_group_sync(handle_or_id, agent)
    extra, acting_agent_id = _actor_for_removal(client, agent)
    if acting_agent_id is not None:
        settle_escrow_before_leave(
            client._http, client._config_dir, group_id, agent_id, acting_agent_id
        )

    path = f"/groups/{group_id}/members/{agent_id}"
    removal: MlsRemovalCommit | None = None
    try:
        client._http.delete(path, extra_headers=extra)
    except Exception as err:
        if not _needs_removal_commit(err) or acting_agent_id is None:
            raise
        removal = _evict(client._http, client._config_dir, acting_agent_id, group_id, agent_id)
        client._http.delete(path, params={"mls_removal_epoch": removal.epoch}, extra_headers=extra)

    retired = (
        retire_local_group_state(client._config_dir, group_id, agent_id, acting_agent_id)
        if acting_agent_id is not None
        else RetiredGroupState(mls=False, sender_key=False)
    )
    return _result(handle_or_id, agent_id, acting_agent_id, removal, retired)


async def remove_group_member_async(
    client: Any, handle_or_id: str, agent_id: str, *, agent: str | None
) -> GroupRemovalResult:
    """Async counterpart of :func:`remove_group_member`.

    The Remove commit is the same synchronous function, run on a worker thread:
    the MLS core and its store are compiled and synchronous, and a second async
    copy of the flow would be a second chance to diverge on epoch handling.
    """
    from rine._mls.bridge import with_sync_http
    from rine._mls.leave import (
        RetiredGroupState,
        retire_local_group_state,
        settle_escrow_before_leave,
    )

    group_id = await client._resolve_group_async(handle_or_id, agent)
    extra, acting_agent_id = await _actor_for_removal_async(client, agent)
    if acting_agent_id is not None:
        leaver = acting_agent_id
        await with_sync_http(
            client,
            lambda http: settle_escrow_before_leave(
                http, client._config_dir, group_id, agent_id, leaver
            ),
        )

    path = f"/groups/{group_id}/members/{agent_id}"
    removal: MlsRemovalCommit | None = None
    try:
        await client._http.delete(path, extra_headers=extra)
    except Exception as err:
        if not _needs_removal_commit(err) or acting_agent_id is None:
            raise
        actor = acting_agent_id
        removal = await with_sync_http(
            client, lambda http: _evict(http, client._config_dir, actor, group_id, agent_id)
        )
        await client._http.delete(
            path, params={"mls_removal_epoch": removal.epoch}, extra_headers=extra
        )

    retired = (
        retire_local_group_state(client._config_dir, group_id, agent_id, acting_agent_id)
        if acting_agent_id is not None
        else RetiredGroupState(mls=False, sender_key=False)
    )
    return _result(handle_or_id, agent_id, acting_agent_id, removal, retired)


__all__ = ["remove_group_member", "remove_group_member_async"]
