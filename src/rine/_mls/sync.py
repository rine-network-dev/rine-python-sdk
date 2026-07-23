"""Catching a group's local state up with the commits its members published.

An MLS group advances by commits, and a member that has not applied them is at
the wrong epoch: it cannot read what peers send, and what it sends is readable
only by members that kept the older epoch's secrets. So every send and every
read passes through here first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._logging import logger
from rine._mls.api import fetch_group_info
from rine._mls.external_join import ExternalJoin, external_join_mls_group
from rine._mls.failures import is_unprocessable_commit
from rine._mls.group_access import open_mls_group
from rine._mls.sync_api import MlsHandshake, fetch_handshakes, mls_ack, mls_nack


@dataclass(frozen=True)
class MlsSyncResult:
    """Where a sync left the group."""

    epoch: int
    processed: int

    evicted: bool
    """True when the member is no longer in the group's ratchet tree.

    Eviction is the correct outcome of a valid Remove commit, not an error: the
    group keeps decrypting the backlog it already holds secrets for, but can no
    longer send or commit. In-session only — the core does not persist it, so a
    later process reloads the group as active and learns otherwise from the first
    operation that refuses.
    """


def sync_mls_group(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    *,
    cipher_suite: int | None = None,
) -> MlsSyncResult:
    """Apply every commit posted to the group since this agent's current epoch.

    Raises:
        NoMlsGroupStateError: When this agent holds no local state for the group.
        MlsStoreError: When the local store cannot be read or written — a failure
            of this process, which the next sync retries rather than blaming on
            the commit.
    """
    headers = {"X-Rine-Agent": agent_id}
    group = open_mls_group(config_dir, agent_id, group_id, cipher_suite=cipher_suite)
    handshakes = fetch_handshakes(client, group_id, group.epoch(), headers)

    epoch = group.epoch()
    processed = 0

    for handshake in handshakes:
        try:
            epoch = group.apply_commit(handshake.blob)
        except Exception as err:
            # Three causes must be told apart. A local failure (store I/O, a
            # retired handle) is not the commit's fault. Our OWN state may be
            # orphaned — our tentative self-join was rolled back, so no peer
            # commit can ever apply to our stale branch, and NACK-looping that
            # is a permanent per-member denial of participation. Only what is
            # left is a genuinely un-processable commit, which earns one NACK.
            if not is_unprocessable_commit(err):
                raise
            reconciled = _reconcile_if_orphaned(
                client, config_dir, agent_id, group_id, epoch, cipher_suite, headers
            )
            if reconciled is not None:
                return MlsSyncResult(epoch=reconciled, processed=processed, evicted=False)
            _emit_nack(client, group_id, handshake, err, headers)
            break
        processed += 1
        # Persist the advance BEFORE ACKing, so a crash mid-ACK never confirms an
        # epoch we did not save locally.
        group.save()
        _emit_ack(client, group_id, handshake.id, headers)
        if not group.is_active():
            return MlsSyncResult(epoch=epoch, processed=processed, evicted=True)

    return MlsSyncResult(epoch=epoch, processed=processed, evicted=not group.is_active())


def _reconcile_if_orphaned(
    client: Any,
    config_dir: str,
    agent_id: str,
    group_id: str,
    local_epoch: int,
    cipher_suite: int | None,
    headers: dict[str, str],
) -> int | None:
    """Re-bootstrap when our own local state, not the commit, is the problem.

    The orphan signal is the server's *confirmed* epoch being below our local
    one: that can only happen if our own tentative commit was rolled back, since
    the server cannot serve a confirmed token as high as an epoch we alone hold.

    Returns:
        The re-bootstrapped epoch, or ``None`` when the state is not orphaned and
        the caller should NACK the commit instead.
    """
    try:
        confirmed = fetch_group_info(client, group_id, headers).epoch
    except Exception:
        # pending_confirmation, or a transport hiccup: we cannot prove the state
        # is orphaned, so the commit gets the benefit of the doubt and a NACK.
        logger.debug("MLS orphan check failed for group %s", group_id, exc_info=True)
        return None
    if confirmed is None or confirmed >= local_epoch:
        return None
    return external_join_mls_group(
        ExternalJoin(
            client=client,
            config_dir=config_dir,
            agent_id=agent_id,
            group_id=group_id,
            extra_headers=headers,
            cipher_suite=cipher_suite,
        )
    )


def _emit_ack(client: Any, group_id: str, object_id: str, headers: dict[str, str]) -> None:
    """Fire-and-forget ACK; a failed ACK must never fail the sync."""
    try:
        mls_ack(client, group_id, object_id, headers)
    except Exception:
        # Best-effort: the commit still confirms once any peer ACKs.
        logger.debug("MLS ack failed for group %s", group_id, exc_info=True)


def _emit_nack(
    client: Any,
    group_id: str,
    handshake: MlsHandshake,
    err: BaseException,
    headers: dict[str, str],
) -> None:
    """Fire-and-forget NACK; a failed NACK must never fail the sync."""
    try:
        mls_nack(client, group_id, handshake, str(err), headers)
    except Exception:
        # Best-effort: a timeout-based rollback still self-heals the group.
        logger.debug("MLS nack failed for group %s", group_id, exc_info=True)
