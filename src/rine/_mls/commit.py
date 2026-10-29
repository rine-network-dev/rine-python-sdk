"""Posting a commit, and the key-package heartbeat that rides with it.

Every commit this SDK posts passes through here, which is why the acting agent's
heartbeat lives here too: five call sites cover seven verbs — founding, adding
members, resuming an admission, self-joining, removing a member, reclaiming an
orphaned leaf and resyncing — and an eighth cannot ship without one.

Deliberately a layer above :func:`rine._mls.commit_wire.mls_commit`, which is the wire
call and knows nothing about who is acting. The TypeScript twin is the same
split: ``postMlsCommit`` (``rine-core/src/mls-commit.ts``) over ``mlsCommit``
(``rine-core/src/crypto/mls-api.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.commit_wire import MlsCommitAccepted, mls_commit
from rine._mls.heartbeat import mls_heartbeat
from rine._mls.settle_guard import hold_settlement

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit
    from rine._mls.heartbeat import MlsActor


def post_mls_commit_bundle(
    actor: MlsActor,
    group_id: str,
    commit: MlsCommit,
    extra_headers: dict[str, str],
) -> MlsCommitAccepted:
    """Publish a commit, then beat this agent's key-package heartbeat.

    The beat is AFTER the server has accepted the commit — the commit is the
    caller's purpose, replenishment is maintenance, and a top-up must never be
    the reason a commit did not land. It runs under the settlement hold
    (:mod:`rine._mls.settle_guard`): the caller applies its commit only after this
    returns, and a rotation settlement here would read that commit as a peer's.

    Args:
        actor: Who is acting, and through which client.
        group_id: The rine group UUID.
        commit: The bundle, its Welcomes and the epoch's fresh GroupInfo.
        extra_headers: Headers the caller's surface requires, acting agent
            included.

    Returns:
        The epoch the server committed to, and whether the commit is final. A
        caller that holds a pending commit applies it only on ``confirmed``.
    """
    accepted = mls_commit(actor.client, group_id, commit, extra_headers)
    with hold_settlement(actor):
        mls_heartbeat(actor, "gated")
    return accepted


def post_mls_commit(
    actor: MlsActor,
    group_id: str,
    commit: MlsCommit,
    extra_headers: dict[str, str],
) -> int:
    """:func:`post_mls_commit_bundle`, for the callers that apply at once.

    Returns:
        The epoch the server committed to.
    """
    return post_mls_commit_bundle(actor, group_id, commit, extra_headers).epoch


__all__ = ["post_mls_commit", "post_mls_commit_bundle"]
