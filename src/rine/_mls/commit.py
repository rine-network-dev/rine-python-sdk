"""Posting a commit, and the key-package heartbeat that rides with it.

Every commit this SDK posts passes through here, which is why the acting agent's
heartbeat lives here too: five call sites cover seven verbs — founding, adding
members, resuming an admission, self-joining, removing a member, reclaiming an
orphaned leaf and resyncing — and an eighth cannot ship without one.

Deliberately a layer above :func:`rine._mls.api.mls_commit`, which is the wire
call and knows nothing about who is acting. The TypeScript twin is the same
split: ``postMlsCommit`` (``rine-core/src/mls-commit.ts``) over ``mlsCommit``
(``rine-core/src/crypto/mls-api.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.api import mls_commit
from rine._mls.heartbeat import mls_heartbeat

if TYPE_CHECKING:
    from rine._mls.api import MlsCommit
    from rine._mls.heartbeat import MlsActor


def post_mls_commit(
    actor: MlsActor,
    group_id: str,
    commit: MlsCommit,
    extra_headers: dict[str, str],
) -> int:
    """Publish a commit, then beat this agent's key-package heartbeat.

    The beat is AFTER the server has accepted the commit — the commit is the
    caller's purpose, replenishment is maintenance, and a top-up must never be
    the reason a commit did not land.

    Args:
        actor: Who is acting, and through which client.
        group_id: The rine group UUID.
        commit: The bundle, its Welcomes and the epoch's fresh GroupInfo.
        extra_headers: Headers the caller's surface requires, acting agent
            included.

    Returns:
        The epoch the server committed to.
    """
    epoch = mls_commit(actor.client, group_id, commit, extra_headers)
    mls_heartbeat(actor, "gated")
    return epoch


__all__ = ["post_mls_commit"]
