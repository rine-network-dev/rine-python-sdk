"""Joining a group by RFC 9420 external commit — the way in without a Welcome.

Used when an agent is a rine member of an MLS group that nobody minted a Welcome
for: open enrollment admits a joiner with no member in the loop. The joiner takes
the group's published GroupInfo, derives its own leaf against the group's
``external_pub``, and publishes a commit that admits it and advances the epoch
for everyone else.

A GroupInfo is single-use per epoch, and the server advances epochs by a strict
compare-and-set on ``current + 1``. So this is a race, and it is treated as one:
one rebuild against a freshly fetched GroupInfo, then a clear refusal. Retrying
forever against an epoch that keeps advancing is a denial of service an agent
inflicts on itself.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from rine._mls.api import MlsCommit, fetch_group_info, mls_commit
from rine._mls.binding import open_mls_client
from rine._mls.group_access import note_mls_state_changed
from rine._mls.wire import api_error_code
from rine.errors import CryptoError

#: A commit the server refused because the group had already moved on: someone
#: else's commit landed first, so ours no longer targeted ``current + 1``.
EPOCH_CONFLICT = "epoch_conflict"

#: The group's newest GroupInfo is still awaiting a peer's ACK, so the server has
#: no confirmed join capability to serve. Unlike an epoch conflict this resolves
#: on its own, so it gets its own short wait rather than the single rebuild.
PENDING_CONFIRMATION = "pending_confirmation"

PENDING_RETRY_LIMIT = 3
PENDING_RETRY_DELAY_S = 0.4


@dataclass(frozen=True)
class ExternalJoin:
    """Everything one external-join attempt needs, so a retry is the same call."""

    client: Any
    """Sync HTTP client."""

    config_dir: str
    agent_id: str

    group_id: str
    """The rine group UUID, which is also the MLS group id."""

    extra_headers: dict[str, str]
    """Acting-agent headers for the group requests."""

    cipher_suite: int | None = None
    """The group's own suite, when it is not the current default."""


def external_join_mls_group(join: ExternalJoin) -> int:
    """Self-join an MLS-active group, advancing its epoch.

    Returns:
        The epoch the group is now at.

    Raises:
        CryptoError: If the group publishes no GroupInfo, if its GroupInfo stays
            unconfirmed, or if a competing joiner keeps winning the epoch.
        RineApiError: If the server refuses the commit for any other reason.
    """
    first_error: BaseException
    for attempt in range(PENDING_RETRY_LIMIT):
        try:
            return _attempt(join)
        except Exception as err:
            if api_error_code(err) != PENDING_CONFIRMATION:
                first_error = err
                break
            if attempt == PENDING_RETRY_LIMIT - 1:
                raise CryptoError(
                    f"Cannot self-join MLS group {join.group_id}: its GroupInfo is still "
                    "awaiting confirmation by another member. Try again shortly."
                ) from err
            time.sleep(PENDING_RETRY_DELAY_S)
    else:  # pragma: no cover - the loop always returns, raises or breaks
        raise AssertionError("external join loop ended without an outcome")

    # Only an epoch conflict is worth repeating: a competing join advanced the
    # epoch, so our GroupInfo was stale and a current one is available now.
    # Anything else — no GroupInfo, no membership, a malformed blob — would fail
    # identically the second time, and an "epoch conflict" wrapper around it
    # would send the reader looking in the wrong place.
    if api_error_code(first_error) != EPOCH_CONFLICT:
        raise first_error
    try:
        return _attempt(join)
    except Exception as retry_error:
        raise CryptoError(
            f"External MLS self-join failed for group {join.group_id} after one retry — "
            f"another joiner keeps landing first: {retry_error}"
        ) from first_error


def _attempt(join: ExternalJoin) -> int:
    group_info = fetch_group_info(join.client, join.group_id, join.extra_headers).blob
    if group_info is None:
        raise CryptoError(
            f"Cannot self-join MLS group {join.group_id}: it has published no GroupInfo. "
            "An existing member must publish one before an agent can self-join."
        )

    mls = open_mls_client(join.config_dir, join.agent_id, cipher_suite=join.cipher_suite)
    group = mls.join_by_external_commit(group_info)
    bundle = group.last_commit()
    if bundle is None:  # pragma: no cover - an external join always commits
        raise CryptoError(f"External MLS self-join for group {join.group_id} produced no commit")

    epoch = mls_commit(
        join.client,
        join.group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=group.cipher_suite(),
        ),
        join.extra_headers,
    )
    # Only now: the server's epoch CAS is what decides whether this join happened
    # at all, so state adopted before it would be a fork no peer can see.
    group.save()
    # An accepted external commit is an establishment: invalidate at the mutation
    # rather than leaving it to whoever called the join.
    note_mls_state_changed(join.config_dir, join.agent_id, join.group_id)
    return epoch
