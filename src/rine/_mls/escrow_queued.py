"""The epochs a parked snapshot was holding, recorded beside it.

A parked snapshot (:mod:`rine._mls.escrow_snapshots`) holds the exports the settle could
not seal. When the snapshot can never be reopened, the epochs it held are lost, and only
the snapshot's own epoch is left to name them. So the settle writes a small sidecar next
to the snapshot, at park time, holding the snapshot's epoch, how many exports were
queued in it and how many the full queue pushed out: the epochs are that many ending at
the snapshot's epoch, the queued ones newest, the dropped ones just below them::

    escrow-backlog/<group_id>/<snapshot stem>.queued   {"epoch": 41, "queued": 3, "dropped": 0}

The sidecar also names the fork of each epoch it records, under ``fps``, so a give-up files
each lost epoch under the fork it held::

    {"epoch": 43, "queued": 3, "dropped": 0,
     "fps": {"41": "<32 hex>", "42": "<hex>", "43": "<hex>"}}

The ``fps`` key is present only when at least one fork is recorded. A fork fingerprint is a
domain-separated hash of the epoch authenticator, so the sidecar still holds no secret material.

The sidecar holds no secret material and is advisory: without a readable one, the lost
epochs are every epoch after the group's escrow head, through the snapshot's epoch, and
never more than the native queue can have held. A sidecar written before ``dropped``
existed reads as dropping none, and one without ``fps`` names no fork. The TypeScript twin is
``rine-core/src/mls-escrow-queued.ts``, with the same name and keys.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeGuard

from rine._mls.escrow_atomic import write_atomic
from rine._mls.escrow_head import read_head
from rine._mls.escrow_store import FP_HEX_LENGTH

if TYPE_CHECKING:
    from collections.abc import Mapping

QUEUED_SUFFIX = ".queued"

#: What the native core's read-export queue holds and how many pushed-out epochs it counts
#: (``rine-mls`` ``MAX_QUEUED_EPOCH_READ_EXPORTS`` and ``MAX_DROPPED_EPOCH_READ_EPOCHS``): no
#: snapshot can have held more epochs than their sum, so no range read from disk is longer.
MAX_QUEUED_EXPORTS = 32
MAX_DROPPED_EPOCHS = 1024
MAX_LOST_EPOCHS = MAX_QUEUED_EXPORTS + MAX_DROPPED_EPOCHS

_FP_HEX_RE = re.compile(rf"[0-9a-f]{{{FP_HEX_LENGTH}}}")


@dataclass(frozen=True, slots=True)
class _Recorded:
    """What a believable sidecar names: the epochs it held and the fork of some of them."""

    epochs: range
    forks: Mapping[int, bytes]


def _sidecar_path(snapshot_path: str) -> str:
    return f"{os.path.splitext(snapshot_path)[0]}{QUEUED_SUFFIX}"


def write_queued(
    snapshot_path: str,
    epoch: int,
    queued: int,
    dropped: int = 0,
    fps: Mapping[int, bytes] | None = None,
) -> None:
    """Record how many exports the snapshot at ``snapshot_path`` held at ``epoch``.

    ``dropped`` is how many older exports the full queue had already pushed out, and
    ``fps`` the fork each recorded epoch was held at.
    """
    record: dict[str, object] = {"epoch": epoch, "queued": queued, "dropped": dropped}
    if fps:
        record["fps"] = {str(e): fps[e].hex() for e in sorted(fps)}
    body = json.dumps(record, separators=(",", ":"))
    write_atomic(_sidecar_path(snapshot_path), body.encode("utf-8"))


def clear_queued(snapshot_path: str) -> None:
    """Remove a snapshot's sidecar; missing is success."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_sidecar_path(snapshot_path))


def _is_count(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _read_forks(value: object, snapshot_epoch: int) -> dict[int, bytes]:
    """The forks an ``fps`` map records, keeping only entries that name an epoch and a fork."""
    if not isinstance(value, dict):
        return {}
    forks: dict[int, bytes] = {}
    for key, fp in value.items():
        if not (isinstance(key, str) and key.isascii() and key.isdigit()):
            continue
        if int(key) <= snapshot_epoch and isinstance(fp, str) and _FP_HEX_RE.fullmatch(fp):
            forks[int(key)] = bytes.fromhex(fp)
    return forks


def _read_queued(snapshot_path: str, snapshot_epoch: int) -> _Recorded | None:
    """What the sidecar names, or ``None`` when it is absent or not believable.

    A sidecar is believed only when it names the snapshot's own epoch and no more exports
    than the native queue can hold; anything else is a corrupt or foreign file.
    """
    try:
        with open(_sidecar_path(snapshot_path), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    epoch, queued, dropped = data.get("epoch"), data.get("queued"), data.get("dropped", 0)
    if not (_is_count(epoch) and _is_count(queued) and _is_count(dropped)):
        return None
    if epoch != snapshot_epoch or queued > MAX_QUEUED_EXPORTS or dropped > MAX_DROPPED_EPOCHS:
        return None
    return _Recorded(
        _window(epoch, max(queued, 1) + dropped), _read_forks(data.get("fps"), snapshot_epoch)
    )


def _window(epoch: int, length: int) -> range:
    """The ``length`` epochs ending at ``epoch``, never more than a snapshot can have held."""
    return range(max(0, epoch - min(length, MAX_LOST_EPOCHS) + 1), epoch + 1)


def recorded_forks(snapshot_path: str, snapshot_epoch: int) -> Mapping[int, bytes]:
    """The fork of each epoch a believable sidecar names; empty when it names none."""
    recorded = _read_queued(snapshot_path, snapshot_epoch)
    return {} if recorded is None else recorded.forks


def lost_epochs(
    config_dir: str, agent_id: str, group_id: str, snapshot_path: str, snapshot_epoch: int
) -> range:
    """Every epoch an unreadable snapshot may have held; always includes its own epoch.

    The sidecar's range when there is a readable one. Otherwise the epochs after the
    group's escrow head through the snapshot's epoch, or just the snapshot's own epoch when
    the group has no head, and a full queue's worth ending at it when the head is already at
    or past it (a rejoin moved the head on, so it says nothing of the snapshot's epochs). Capped.
    """
    recorded = _read_queued(snapshot_path, snapshot_epoch)
    if recorded is not None:
        return recorded.epochs
    head = read_head(config_dir, agent_id, group_id)
    if head is None:
        return range(snapshot_epoch, snapshot_epoch + 1)
    if head.epoch >= snapshot_epoch:
        return _window(snapshot_epoch, MAX_QUEUED_EXPORTS)
    return _window(snapshot_epoch, snapshot_epoch - head.epoch)
