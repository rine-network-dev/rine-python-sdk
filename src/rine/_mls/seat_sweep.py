"""Moving an agent's leaf in every group it is seated in, and settling a rotation.

A key rotation changes what the agent signs with and leaves every group's leaf
under the old key. :func:`self_update_stale_leaves` walks the groups this host
holds state for and moves each leaf (:mod:`rine._mls.self_update`).
:func:`settle_rotation` is the one entry both the rotation verb and the heartbeat
use: it republishes the KeyPackages and sweeps the seats, and remembers which key
generation it finished in a host-local marker (:mod:`rine._mls.rotation_marker`).

The TypeScript twin is ``rine-core/src/mls-seat-sweep.ts``; statuses, reasons and
the marker file are the same.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from rine._crypto.keys import load_agent_keys
from rine._logging import logger
from rine._mls.group_access import holds_mls_state
from rine._mls.key_current import disk_key_is_current
from rine._mls.key_not_current import is_mls_key_not_current
from rine._mls.key_package_cutover import drain_and_republish_mls_key_packages
from rine._mls.rotation_marker import RotationMarker, read_rotation_marker, write_rotation_marker
from rine._mls.seat_sweep_backoff import note_sweep, sweep_must_wait
from rine._mls.seated_groups import seated_mls_groups
from rine._mls.self_update import self_update_group
from rine._mls.settle_guard import hold_settlement
from rine._mls.store_probe import holds_mls_store
from rine._seat_update import (
    SeatDeferReason,
    SeatFailReason,
    SeatUpdate,
    SeatUpdateStatus,
    deferred,
    failed,
)

if TYPE_CHECKING:
    from rine._mls.actor import MlsActor


class KeyPackageRotation(StrEnum):
    """What a settlement did about the agent's KeyPackage pool."""

    CURRENT = "current"
    """Nothing to do: the pool already carries the key generation on disk."""

    REPUBLISHED = "republished"
    PENDING = "pending"
    KEY_NOT_CURRENT = "key_not_current"
    """This device holds an earlier key generation than the agent's current one."""

    NOT_HELD = "not_held"


@dataclass(frozen=True)
class RotationSettlement:
    """The KeyPackage outcome and the per-group seat outcomes of one settlement."""

    key_packages: KeyPackageRotation
    group_seats: list[SeatUpdate] = field(default_factory=list)


def self_update_stale_leaves(actor: MlsActor) -> list[SeatUpdate]:
    """Move the acting agent's leaf to the key on disk in every group this host holds.

    The disk key must be the agent's current published one, checked against a
    chain-verified read: a host holding superseded keys must never self-update.
    Groups the server lists with no local state here are skipped silently, since a
    Welcome owns those. Groups run one at a time, because the escrow drain does.

    Returns:
        One entry per group tried, or one entry with ``group_id`` ``None`` for a
        sweep that could not start.
    """
    try:
        if not disk_key_is_current(actor):
            return [failed(None, SeatFailReason.KEY_NOT_CURRENT)]
    except Exception as err:
        return [deferred(None, SeatDeferReason.UNREACHABLE, detail=str(err))]
    try:
        groups = seated_mls_groups(actor.client, actor.agent_id)
    except Exception as err:
        return [deferred(None, SeatDeferReason.UNREACHABLE, detail=str(err))]
    return [
        self_update_group(actor, str(group.id))
        for group in groups
        if holds_mls_state(actor.config_dir, actor.agent_id, str(group.id))
    ]


def settle_rotation(actor: MlsActor, *, background: bool = False) -> RotationSettlement:
    """Bring this host's KeyPackages and group seats up to the key generation on disk.

    Never raises: it runs behind a rotation the server already committed and
    inside a best-effort heartbeat. Each half advances its marker field only when
    it finished, so a half that failed is tried again by the next settlement.

    Args:
        actor: The agent being settled and the client it acts through.
        background: True for the heartbeat's own settlement, which honours the sweep's
            backoff (:mod:`rine._mls.seat_sweep_backoff`). The rotation verb and a person
            asking for it never wait.

    Returns:
        ``not_held`` with no seats when a settlement for this agent is already
        running here or this host holds none of its MLS state.
    """
    with hold_settlement(actor) as taken:
        if not taken:
            return RotationSettlement(KeyPackageRotation.NOT_HELD)
        return _settle(actor, background=background)


def _settle(actor: MlsActor, *, background: bool) -> RotationSettlement:
    try:
        if not holds_mls_store(actor.config_dir, actor.agent_id):
            return RotationSettlement(KeyPackageRotation.NOT_HELD)
        key_gen = load_agent_keys(actor.config_dir, actor.agent_id).key_gen
        marker = read_rotation_marker(actor.config_dir, actor.agent_id)
        packages = _settle_key_packages(actor, key_gen, marker)
        marker = read_rotation_marker(actor.config_dir, actor.agent_id)
        seats = _settle_seats(actor, key_gen, marker, background=background)
    except Exception as err:
        logger.warning("Rotation settlement for agent %s deferred: %s", actor.agent_id, err)
        unreachable = deferred(None, SeatDeferReason.UNREACHABLE, detail=str(err))
        return RotationSettlement(KeyPackageRotation.PENDING, [unreachable])
    return RotationSettlement(packages, seats)


def _settle_key_packages(
    actor: MlsActor, key_gen: int, marker: RotationMarker
) -> KeyPackageRotation:
    if marker.key_packages >= key_gen:
        return KeyPackageRotation.CURRENT
    try:
        drain_and_republish_mls_key_packages(actor.client, actor.config_dir, actor.agent_id)
    except Exception as err:
        logger.warning("KeyPackage republish for agent %s deferred: %s", actor.agent_id, err)
        if is_mls_key_not_current(err):
            return KeyPackageRotation.KEY_NOT_CURRENT
        return KeyPackageRotation.PENDING
    write_rotation_marker(actor.config_dir, actor.agent_id, replace(marker, key_packages=key_gen))
    return KeyPackageRotation.REPUBLISHED


def _settle_seats(
    actor: MlsActor, key_gen: int, marker: RotationMarker, *, background: bool
) -> list[SeatUpdate]:
    if marker.seats >= key_gen or (background and sweep_must_wait(actor)):
        return []
    seats = self_update_stale_leaves(actor)
    note_sweep(actor, deferred=any(seat.status is SeatUpdateStatus.DEFERRED for seat in seats))
    for seat in seats:
        if seat.status in (SeatUpdateStatus.FAILED, SeatUpdateStatus.DEFERRED):
            logger.warning(
                "Seat in group %s is %s (%s) for agent %s",
                seat.group_id,
                seat.status.value,
                seat.reason.value if seat.reason else "-",
                actor.agent_id,
            )
    if all(seat.status is not SeatUpdateStatus.DEFERRED for seat in seats):
        write_rotation_marker(
            actor.config_dir,
            actor.agent_id,
            replace(read_rotation_marker(actor.config_dir, actor.agent_id), seats=key_gen),
        )
    return seats


__all__ = [
    "KeyPackageRotation",
    "RotationSettlement",
    "self_update_stale_leaves",
    "settle_rotation",
]
