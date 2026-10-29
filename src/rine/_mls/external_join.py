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
from dataclasses import dataclass, field
from typing import Any

from rine._mls.allowed import admit_group_peers
from rine._mls.api import MlsCommit, fetch_group_info
from rine._mls.binding import DEFAULT_CIPHER_SUITE, PeerNotAdmittedError, open_mls_client
from rine._mls.commit import post_mls_commit
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
from rine._mls.escrow_settle import settle_escrow
from rine._mls.failures import is_epoch_conflict
from rine._mls.group_access import note_mls_state_changed
from rine._mls.heartbeat import MlsActor
from rine._mls.peer_refusal import peer_not_admitted_refusal
from rine._mls.wire import PENDING_CONFIRMATION, api_error_code
from rine.errors import CryptoError

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

    carry_unreported: bool = True
    """Whether the result reports what a background sweep lost in this group. A caller that
    drops the result sets it off, so the news waits for one that does not."""


@dataclass(frozen=True)
class ExternalJoinResult:
    """Where an external join left the group, and what is owed on its escrow."""

    epoch: int
    """The epoch the group is now at."""

    escrow: EscrowReport = field(default_factory=EscrowReport)
    """What settling the replaced state and draining the new one could not do."""


def external_join_mls_group(join: ExternalJoin) -> ExternalJoinResult:
    """Self-join an MLS-active group, advancing its epoch.

    Returns:
        The epoch the group is now at, and the escrow report of the replacement.

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
    if not is_epoch_conflict(first_error):
        raise first_error
    try:
        return _attempt(join)
    except Exception as retry_error:
        raise CryptoError(
            f"External MLS self-join failed for group {join.group_id} after one retry — "
            f"another joiner keeps landing first: {retry_error}"
        ) from first_error


def _attempt(join: ExternalJoin) -> ExternalJoinResult:
    group_info = fetch_group_info(join.client, join.group_id, join.extra_headers).blob
    if group_info is None:
        raise CryptoError(
            f"Cannot self-join MLS group {join.group_id}: it has published no GroupInfo. "
            "An existing member must publish one before an agent can self-join."
        )

    actor = MlsActor(client=join.client, config_dir=join.config_dir, agent_id=join.agent_id)
    # The external commit meets the group's leaves for the first time, so the
    # chain-verified peers must be admitted before it is built.
    admit_group_peers(actor, join.group_id)
    mls = open_mls_client(join.config_dir, join.agent_id)
    try:
        group = mls.join_by_external_commit(group_info)
    except PeerNotAdmittedError as err:
        raise peer_not_admitted_refusal(join.group_id) from err
    bundle = group.last_commit()
    if bundle is None:  # pragma: no cover - an external join always commits
        raise CryptoError(f"External MLS self-join for group {join.group_id} produced no commit")

    epoch = post_mls_commit(
        actor,
        join.group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=DEFAULT_CIPHER_SUITE,
        ),
        join.extra_headers,
    )
    # Only now: the server's epoch CAS is what decides whether this join happened
    # at all, so state adopted before it would be a fork no peer can see.
    settled = settle_escrow(actor, join.group_id)
    drained = drain_escrow(actor, join.group_id, group, carry_unreported=join.carry_unreported)
    # An accepted external commit is an establishment: invalidate at the mutation
    # rather than leaving it to whoever called the join.
    note_mls_state_changed(join.config_dir, join.agent_id, join.group_id)
    return ExternalJoinResult(epoch, settled.merge(drained.report()))
